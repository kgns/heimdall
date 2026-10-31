"""Daily analysis of the samples, run by a scheduled Lambda for the
previous UTC day (or the day given as ``{"date": "YYYY-MM-DD"}``).

It writes gzip JSON lines under ``derived/<table>/dt=<day>/`` in the raw
bucket, read through the Glue tables of the same names:

``daily_service``
    Per device, service and measurement kind: percentiles, loss, jitter and
    the busy-hour inflation (evening median over night median, local time),
    the classic signature of an under-provisioned access or peering link.
``daily_compare``
    Per CPE service and hour: the CPE's and the AWS control probe's median
    relative to their best hour of the day. Hours where the CPE degrades
    alone are attributed to the access network or the ISP's path; hours
    where both degrade, to the service.
``ip_asn``
    The origin AS of every public router address seen in traceroutes,
    looked up in RIPEstat and carried over from earlier days.
``path_borders``
    Per device and target: where the most frequent path of the day leaves
    the device's own network, the next AS, and the latency added there.
``daily_client``
    Per CPE and LAN client: the LAN and WAN parts of the client's own
    connections, LAN pings, Wi-Fi signal, retries and roaming.
``daily_client_service``
    Per CPE, client and service: the WAN part of the client's connections
    next to the CPE's own TCP probe of the service.
``daily_crosscheck``
    Connections of a client device running heimdall-client, matched with
    the CPE's record of the same connections.
``daily_attribution``
    Per CPE, UTC hour and segment of the path (the Wi-Fi of the CPE's
    clients, the hop between an extender and its clients, the extender's
    backhaul, the ISP access, the part beyond the ISP): the hour's median
    next to the segment's day median, and whether the hour was degraded.
    The summary names, for every degraded hour, the segment to blame.

Probes on mesh extenders, which name their CPE as the site in their
heartbeats, are folded into their CPE: their clients' hop and signal join
the CPE's rows of the same clients in ``daily_client``, their backhaul and
incidents appear under the CPE in the summary.
``summary``
    One JSON document with the day's headline findings, for the report.

Every run overwrites the day's objects, so reruns are safe.
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import logging
import os
import statistics
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, date, datetime, timedelta
from typing import Any

from heimdall_cloud import external
from heimdall_cloud.schema import DEVICE_RE

log = logging.getLogger()
log.setLevel(logging.INFO)

# Local time of the probes (Türkiye, UTC+3, no daylight saving time).
LOCAL_OFFSET_H = 3
BUSY_HOURS = (20, 21, 22, 23)
NIGHT_HOURS = (3, 4, 5, 6)
DEGRADED_RATIO = 1.3
MAX_ASN_LOOKUPS = 600
MEASUREMENT_KINDS = ("icmp", "tcp", "http", "udp_echo", "stun")


class Athena:
    """Runs queries in the heimdall workgroup and returns rows as dicts."""

    def __init__(self, client: Any, workgroup: str, poll: float = 1.0):
        self.client, self.workgroup, self.poll = client, workgroup, poll

    def query(self, sql: str) -> list[dict[str, str | None]]:
        qid = self.client.start_query_execution(QueryString=sql, WorkGroup=self.workgroup)["QueryExecutionId"]
        while True:
            st = self.client.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
            if st["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"):
                break
            time.sleep(self.poll)
        if st["State"] != "SUCCEEDED":
            raise RuntimeError(f"athena query {qid} {st['State']}: {st.get('StateChangeReason', '')}")
        rows: list[dict[str, str | None]] = []
        header: list[str] | None = None
        for page in self.client.get_paginator("get_query_results").paginate(QueryExecutionId=qid):
            for r in page["ResultSet"]["Rows"]:
                vals = [c.get("VarCharValue") for c in r["Data"]]
                if header is None:
                    header = [v or "" for v in vals]
                    continue
                rows.append(dict(zip(header, vals, strict=True)))
        return rows


def _num(v: str | None) -> float | None:
    if v is None or v == "":
        return None
    try:
        return float(v)
    except ValueError:
        return None


def _int(v: str | None) -> int | None:
    f = _num(v)
    return None if f is None else int(f)


def day_filter(day: date) -> str:
    return f"dt = '{day.isoformat()}'"


def local_hour(col: str = "ts_ms") -> str:
    return f"hour(from_unixtime({col} / 1000 + {LOCAL_OFFSET_H * 3600}))"


def daily_service(athena: Athena, day: date) -> list[dict[str, Any]]:
    kinds = ", ".join(f"'{k}'" for k in MEASUREMENT_KINDS)
    busy = ", ".join(str(h) for h in BUSY_HOURS)
    night = ", ".join(str(h) for h in NIGHT_HOURS)
    rows = athena.query(f"""
        WITH s AS (
          SELECT device, category, service, kind, target_id, ts_ms, status, rtt_ms, {local_hour()} AS lh
          FROM heimdall.samples
          WHERE {day_filter(day)} AND kind IN ({kinds}) AND service IS NOT NULL AND category <> 'home'
            AND target_id NOT LIKE 'client/%'
        ),
        j AS (
          SELECT device, service, kind,
            abs(rtt_ms - lag(rtt_ms) OVER (PARTITION BY device, target_id, kind ORDER BY ts_ms)) AS d
          FROM s WHERE status = 'ok' AND rtt_ms IS NOT NULL
        ),
        jit AS (SELECT device, service, kind, avg(d) AS jitter_ms FROM j GROUP BY 1, 2, 3)
        SELECT s.device, arbitrary(s.category) AS category, s.service, s.kind, count(*) AS samples,
          approx_percentile(rtt_ms, 0.5) FILTER (WHERE status = 'ok') AS p50,
          approx_percentile(rtt_ms, 0.95) FILTER (WHERE status = 'ok') AS p95,
          approx_percentile(rtt_ms, 0.99) FILTER (WHERE status = 'ok') AS p99,
          100.0 * count_if(status <> 'ok') / count(*) AS loss_pct,
          approx_percentile(rtt_ms, 0.5) FILTER (WHERE status = 'ok' AND lh IN ({busy})) AS busy_p50,
          approx_percentile(rtt_ms, 0.5) FILTER (WHERE status = 'ok' AND lh IN ({night})) AS night_p50,
          100.0 * count_if(status <> 'ok' AND lh IN ({busy})) / nullif(count_if(lh IN ({busy})), 0) AS busy_loss_pct,
          arbitrary(jit.jitter_ms) AS jitter_ms,
          count(DISTINCT s.target_id) AS targets
        FROM s LEFT JOIN jit ON s.device = jit.device AND s.service = jit.service AND s.kind = jit.kind
        GROUP BY s.device, s.service, s.kind
    """)  # noqa: S608 - only dates, constants and validated device IDs are interpolated
    out = []
    for r in rows:
        rec: dict[str, Any] = {
            "device": r["device"],
            "category": r["category"],
            "service": r["service"],
            "kind": r["kind"],
            "samples": _int(r["samples"]),
            "targets": _int(r["targets"]),
        }
        for k in ("p50", "p95", "p99", "loss_pct", "busy_p50", "night_p50", "busy_loss_pct", "jitter_ms"):
            rec[k] = _num(r[k])
        busy_p50, night_p50 = rec["busy_p50"], rec["night_p50"]
        rec["busy_inflation"] = busy_p50 / night_p50 if busy_p50 and night_p50 else None
        out.append(rec)
    return out


def daily_compare(athena: Athena, day: date, control: str) -> list[dict[str, Any]]:
    """Hourly ICMP medians of every service from each CPE and from the
    control probe, each relative to its own best hour of the day."""
    rows = athena.query(f"""
        WITH h AS (
          SELECT device, service, hour(from_unixtime(ts_ms / 1000)) AS h,
            approx_percentile(rtt_ms, 0.5) AS p50
          FROM heimdall.samples
          WHERE {day_filter(day)} AND kind = 'icmp' AND status = 'ok' AND category NOT IN ('infra', 'home')
          GROUP BY 1, 2, 3
        ),
        r AS (SELECT device, service, h, p50, p50 / min(p50) OVER (PARTITION BY device, service) AS ratio FROM h)
        SELECT c.device, c.service, c.h AS hour, c.p50 AS cpe_p50, c.ratio AS cpe_ratio,
          a.p50 AS control_p50, a.ratio AS control_ratio
        FROM r c LEFT JOIN r a ON a.device = '{control}' AND a.service = c.service AND a.h = c.h
        WHERE c.device <> '{control}'
    """)  # noqa: S608 - only dates, constants and validated device IDs are interpolated
    out = []
    for r in rows:
        cpe_ratio, control_ratio = _num(r["cpe_ratio"]), _num(r["control_ratio"])
        if cpe_ratio is None or cpe_ratio < DEGRADED_RATIO:
            attribution = "normal"
        elif control_ratio is None:
            attribution = "no_control"
        elif control_ratio >= DEGRADED_RATIO:
            attribution = "service"
        else:
            attribution = "access_or_path"
        out.append(
            {
                "device": r["device"],
                "service": r["service"],
                "hour": _int(r["hour"]),
                "cpe_p50": _num(r["cpe_p50"]),
                "cpe_ratio": cpe_ratio,
                "control_p50": _num(r["control_p50"]),
                "control_ratio": control_ratio,
                "attribution": attribution,
            }
        )
    return out


# Thresholds for the per-client findings. A healthy Wi-Fi client answers a
# SYN-ACK within a few milliseconds; a wired one within one or two.
WEAK_RSSI_DBM = -75
SLOW_LINK_MBPS = 50.0
SLOW_LAN_P90_MS = 30.0
HIGH_RETRY_PCT = 20.0
MANY_ROAMS = 10
CLIENT_WAN_RATIO = 1.3
# What the backhaul and the extender may add to the LAN part of an
# extender client's connections (CPE's figure minus the extender's hop);
# a wired backhaul adds well under a millisecond.
SLOW_BACKHAUL_ADDED_MS = 5.0


def daily_client(athena: Athena, day: date) -> list[dict[str, Any]]:
    """Per CPE and LAN client: the LAN and WAN parts of the client's own
    connections (TCP handshakes seen by the CPE), LAN pings, Wi-Fi signal,
    retries and roaming."""
    busy = ", ".join(str(h) for h in BUSY_HOURS)
    night = ", ".join(str(h) for h in NIGHT_HOURS)
    rows = athena.query(f"""
        WITH f AS (
          SELECT device, json_extract_scalar(extra, '$.client') AS client,
            json_extract_scalar(extra, '$.proto') AS proto, status,
            CAST(json_extract_scalar(extra, '$.lan_ms') AS double) AS lan,
            CAST(json_extract_scalar(extra, '$.wan_ms') AS double) AS wan,
            coalesce(json_extract_scalar(extra, '$.node'), 'cpe') AS node,
            json_extract_scalar(extra, '$.medium') AS medium, json_extract_scalar(extra, '$.band') AS band,
            {local_hour()} AS lh
          FROM heimdall.samples WHERE {day_filter(day)} AND kind = 'flow'
        ),
        fa AS (
          SELECT device, client, count(*) AS flows, count_if(status = 'timeout') AS unanswered,
            approx_percentile(lan, 0.5) FILTER (WHERE proto = 'tcp' AND status = 'ok') AS lan_p50,
            approx_percentile(lan, 0.9) FILTER (WHERE proto = 'tcp' AND status = 'ok') AS lan_p90,
            approx_percentile(lan, 0.5) FILTER (WHERE proto = 'tcp' AND status = 'ok' AND lh IN ({busy}))
              AS lan_busy_p50,
            approx_percentile(lan, 0.5) FILTER (WHERE proto = 'tcp' AND status = 'ok' AND lh IN ({night}))
              AS lan_night_p50,
            approx_percentile(wan, 0.5) FILTER (WHERE status = 'ok') AS wan_p50,
            approx_percentile(wan, 0.9) FILTER (WHERE status = 'ok') AS wan_p90,
            max_by(node, lh) AS node, max_by(medium, lh) AS medium, max_by(band, lh) AS band
          FROM f WHERE client IS NOT NULL GROUP BY 1, 2
        ),
        w AS (
          SELECT device, json_extract_scalar(extra, '$.client') AS client,
            avg(CAST(json_extract_scalar(extra, '$.rssi') AS double)) AS rssi_avg,
            min(CAST(json_extract_scalar(extra, '$.rssi') AS double)) AS rssi_min,
            avg(CAST(json_extract_scalar(extra, '$.snr') AS double)) AS snr_avg,
            100.0 * sum(CAST(json_extract_scalar(extra, '$.tx_retries') AS double))
              / nullif(sum(CAST(json_extract_scalar(extra, '$.tx_sent') AS double)), 0) AS retry_pct,
            approx_percentile(CAST(json_extract_scalar(extra, '$.tx_rate_mbps') AS double), 0.5) AS tx_rate_p50,
            avg(CASE json_extract_scalar(extra, '$.ps') WHEN 'true' THEN 1.0 WHEN 'false' THEN 0.0 END) AS ps_share,
            max_by(json_extract_scalar(extra, '$.node'), ts_ms) AS wifi_node,
            max_by(json_extract_scalar(extra, '$.band'), ts_ms) AS wifi_band
          FROM heimdall.samples
          WHERE {day_filter(day)} AND kind = 'wifi_sta' AND json_extract_scalar(extra, '$.client') IS NOT NULL
          GROUP BY 1, 2
        ),
        p AS (
          SELECT device, substr(target_id, 5) AS client,
            approx_percentile(rtt_ms, 0.5) FILTER (WHERE status = 'ok') AS ping_p50,
            approx_percentile(rtt_ms, 0.95) FILTER (WHERE status = 'ok') AS ping_p95,
            approx_percentile(CAST(json_extract_scalar(extra, '$.burst_ms[0]') AS double), 0.5) AS ping_first_p50,
            100.0 * count_if(status <> 'ok') / count(*) AS ping_loss_pct,
            max_by(json_extract_scalar(extra, '$.medium'), ts_ms) AS ping_medium
          FROM heimdall.samples WHERE {day_filter(day)} AND kind = 'lan'
          GROUP BY 1, 2
        ),
        e AS (
          SELECT device, json_extract_scalar(extra, '$.client') AS client,
            count_if(json_extract_scalar(extra, '$.event') = 'wifi_roam') AS roams,
            count_if(json_extract_scalar(extra, '$.event') = 'wifi_leave') AS leaves
          FROM heimdall.samples
          WHERE {day_filter(day)} AND kind = 'event'
            AND json_extract_scalar(extra, '$.event') IN ('wifi_roam', 'wifi_leave')
          GROUP BY 1, 2
        ),
        k AS (
          SELECT device, client FROM fa UNION SELECT device, client FROM w UNION SELECT device, client FROM p
        )
        SELECT k.device, k.client, coalesce(fa.node, w.wifi_node, 'cpe') AS node,
          coalesce(fa.medium, p.ping_medium) AS medium,
          coalesce(w.wifi_band, fa.band) AS band, fa.flows, fa.unanswered, fa.lan_p50, fa.lan_p90,
          fa.lan_busy_p50, fa.lan_night_p50, fa.wan_p50, fa.wan_p90,
          w.rssi_avg, w.rssi_min, w.snr_avg, w.retry_pct, w.tx_rate_p50, w.ps_share,
          p.ping_p50, p.ping_p95, p.ping_first_p50, p.ping_loss_pct, e.roams, e.leaves
        FROM k
        LEFT JOIN fa ON fa.device = k.device AND fa.client = k.client
        LEFT JOIN w ON w.device = k.device AND w.client = k.client
        LEFT JOIN p ON p.device = k.device AND p.client = k.client
        LEFT JOIN e ON e.device = k.device AND e.client = k.client
    """)  # noqa: S608 - only dates, constants and validated device IDs are interpolated
    nums = (
        "lan_p50", "lan_p90", "lan_busy_p50", "lan_night_p50", "wan_p50", "wan_p90", "rssi_avg", "rssi_min",
        "snr_avg", "retry_pct", "tx_rate_p50", "ps_share", "ping_p50", "ping_p95", "ping_first_p50", "ping_loss_pct",
    )  # fmt: skip
    out = []
    for r in rows:
        rec: dict[str, Any] = {k: r[k] for k in ("device", "client", "node", "medium", "band")}
        for k in ("flows", "unanswered", "roams", "leaves"):
            rec[k] = _int(r[k]) or 0
        for k in nums:
            rec[k] = _num(r[k])
        out.append(rec)
    return out


def extender_sites(athena: Athena, day: date) -> dict[str, str]:
    """Probes on mesh extenders and the CPE each belongs to, from the site
    their heartbeats name."""
    rows = athena.query(f"""
        SELECT device, max(json_extract_scalar(extra, '$.site')) AS site
        FROM heimdall.samples
        WHERE {day_filter(day)} AND kind = 'heartbeat' AND json_extract_scalar(extra, '$.site') <> ''
        GROUP BY 1
    """)  # noqa: S608 - only dates are interpolated
    return {
        r["device"]: r["site"]
        for r in rows
        if r["device"] and r["site"] and DEVICE_RE.match(r["device"]) and DEVICE_RE.match(r["site"])
    }


def backhaul(athena: Athena, day: date, sites: dict[str, str]) -> list[dict[str, Any]]:
    """Per extender probe: its ping to the CPE over the day."""
    if not sites:
        return []
    ext_in = ", ".join(f"'{d}'" for d in sorted(sites))
    rows = athena.query(f"""
        SELECT device, count(*) AS samples,
          approx_percentile(rtt_ms, 0.5) FILTER (WHERE status = 'ok') AS p50,
          approx_percentile(rtt_ms, 0.95) FILTER (WHERE status = 'ok') AS p95,
          approx_percentile(rtt_ms, 0.99) FILTER (WHERE status = 'ok') AS p99,
          100.0 * count_if(status <> 'ok') / count(*) AS loss_pct
        FROM heimdall.samples
        WHERE {day_filter(day)} AND device IN ({ext_in}) AND kind = 'icmp' AND target_id = 'uplink'
        GROUP BY 1
    """)  # noqa: S608 - only dates and validated device IDs are interpolated
    return [
        {"device": r["device"], "site": sites.get(r["device"] or ""), "samples": _int(r["samples"]),
         **{k: _num(r[k]) for k in ("p50", "p95", "p99", "loss_pct")}}
        for r in rows
    ]  # fmt: skip


# What an extender's probe adds to the CPE's row of the same client. Its
# lan_ms is the hop between the extender and the client alone, and its
# Wi-Fi readings are the extender's own.
EXTENDER_FIELDS = {
    "lan_p50": "hop_p50",
    "lan_p90": "hop_p90",
    "flows": "hop_flows",
    "rssi_avg": "ext_rssi_avg",
    "rssi_min": "ext_rssi_min",
    "tx_rate_p50": "ext_tx_rate_p50",
    "ps_share": "ext_ps_share",
}


def merge_extenders(clients: list[dict[str, Any]], sites: dict[str, str]) -> list[dict[str, Any]]:
    """Fold the rows of extender probes into the rows of their CPE: every
    client keeps one row, under the CPE, with the extender's figures as
    the EXTENDER_FIELDS columns. A client only the extender saw gets a row
    of its own under the CPE."""
    out = [dict(c) for c in clients if c["device"] not in sites]
    by_key = {(c["device"], c["client"]): c for c in out}
    for e in clients:
        site = sites.get(e["device"])
        if not site:
            continue
        row = by_key.get((site, e["client"]))
        if row is None:
            row = {k: None for k in e}
            row.update(
                device=site, client=e["client"], node=e["node"], medium=e["medium"], band=e["band"], flows=0,
                unanswered=0, roams=0, leaves=0,
            )  # fmt: skip
            out.append(row)
            by_key[(site, e["client"])] = row
        for src, dst in EXTENDER_FIELDS.items():
            row[dst] = e.get(src)
        if row.get("node") in (None, "cpe") and e.get("node"):
            row["node"] = e["node"]
    for row in out:
        for dst in EXTENDER_FIELDS.values():
            row.setdefault(dst, None)
    return out


# The segments of a connection's round trip the daily attribution follows,
# in path order from the client. wifi: the LAN part of the connections of
# the CPE's own clients; ext_hop: the hop between the extender and its
# clients, measured on the extender; backhaul: the extender's ping to the
# CPE; access: the first hop into the ISP; beyond_isp: the server's part of
# the clients' connections minus the access.
SEGMENTS = ("wifi", "ext_hop", "backhaul", "access", "beyond_isp")
# A segment's hour is degraded when its median is DEGRADED_RATIO times its
# day median and at least this many milliseconds above it.
SEGMENT_MIN_ADDED_MS = {"wifi": 3.0, "ext_hop": 3.0, "backhaul": 2.0, "access": 3.0, "beyond_isp": 10.0}
# Fewest samples in an hour for its median to count.
SEGMENT_MIN_SAMPLES = 20


def segment_hours(athena: Athena, day: date, sites: dict[str, str]) -> list[dict[str, Any]]:
    """Hourly medians of every segment, per CPE; extender figures are
    filed under the CPE they belong to."""
    if sites:
        cases = " ".join(f"WHEN '{d}' THEN '{s}'" for d, s in sorted(sites.items()))
        site = f"CASE device {cases} ELSE device END"
        ext_in = ", ".join(f"'{d}'" for d in sorted(sites))
    else:
        site, ext_in = "device", "''"
    rows = athena.query(f"""
        WITH s AS (
          SELECT {site} AS site, hour(from_unixtime(ts_ms / 1000)) AS h,
            CASE
              WHEN kind = 'flow' AND device IN ({ext_in}) THEN 'ext_hop'
              WHEN kind = 'flow' AND coalesce(json_extract_scalar(extra, '$.node'), 'cpe') = 'cpe' THEN 'wifi'
              WHEN kind = 'icmp' AND device IN ({ext_in}) AND target_id = 'uplink' THEN 'backhaul'
              WHEN kind = 'icmp' AND target_id = 'isp-hop1' THEN 'access'
            END AS segment,
            CASE WHEN kind = 'flow' THEN CAST(json_extract_scalar(extra, '$.lan_ms') AS double) ELSE rtt_ms END AS v
          FROM heimdall.samples
          WHERE {day_filter(day)} AND status = 'ok' AND (
            (kind = 'flow' AND json_extract_scalar(extra, '$.proto') = 'tcp')
            OR (kind = 'icmp' AND target_id IN ('uplink', 'isp-hop1')))
          UNION ALL
          SELECT device, hour(from_unixtime(ts_ms / 1000)), 'wan',
            CAST(json_extract_scalar(extra, '$.wan_ms') AS double)
          FROM heimdall.samples
          WHERE {day_filter(day)} AND kind = 'flow' AND status = 'ok' AND device NOT IN ({ext_in})
        )
        SELECT site AS device, h AS hour, segment, approx_percentile(v, 0.5) AS p50, count(*) AS n
        FROM s WHERE segment IS NOT NULL AND v IS NOT NULL GROUP BY 1, 2, 3
    """)  # noqa: S608 - only dates and validated device IDs are interpolated
    return [
        {"device": r["device"], "hour": _int(r["hour"]), "segment": r["segment"], "p50": _num(r["p50"]),
         "n": _int(r["n"]) or 0}
        for r in rows
    ]  # fmt: skip


def attribute(
    hours: list[dict[str, Any]], compare: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Per CPE and UTC hour, which segment of the path made the round trip
    slower than usual, and per CPE the day's latency budget and verdict.

    Each segment's hour is judged against the segment's own day median. In
    a degraded hour the segment that added the most milliseconds is blamed;
    beyond the ISP, the control probe tells the ISP's path from the
    services themselves (daily_compare's attribution of that hour)."""
    by_dev: dict[str, dict[str, dict[int, tuple[float, int]]]] = defaultdict(lambda: defaultdict(dict))
    for r in hours:
        if r["p50"] is not None and r["hour"] is not None:
            by_dev[r["device"]][r["segment"]][r["hour"]] = (r["p50"], r["n"])
    side: dict[tuple[str, int], Counter[str]] = defaultdict(Counter)
    for c in compare:
        if c.get("hour") is not None:
            side[(c["device"], c["hour"])][c["attribution"]] += 1
    rows: list[dict[str, Any]] = []
    verdicts: dict[str, dict[str, Any]] = {}
    for dev, segs in sorted(by_dev.items()):
        # The part beyond the ISP: the servers' answer minus the access.
        wan, access = segs.pop("wan", {}), segs.get("access", {})
        segs["beyond_isp"] = {
            h: (v - access[h][0], n) for h, (v, n) in wan.items() if h in access and v - access[h][0] > 0
        }
        budget: dict[str, float] = {}
        per_hour: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for seg in SEGMENTS:
            vals = {h: v for h, (v, n) in segs.get(seg, {}).items() if n >= SEGMENT_MIN_SAMPLES}
            if not vals:
                continue
            base = statistics.median(vals.values())
            budget[seg] = round(base, 1)
            for h, v in sorted(vals.items()):
                added = v - base
                degraded = v >= DEGRADED_RATIO * base and added >= SEGMENT_MIN_ADDED_MS[seg]
                rec = {
                    "device": dev, "hour": h, "local_hour": (h + LOCAL_OFFSET_H) % 24, "segment": seg,
                    "p50": round(v, 2), "baseline": round(base, 2), "added_ms": round(added, 2), "degraded": degraded,
                }  # fmt: skip
                rows.append(rec)
                if degraded:
                    per_hour[h].append(rec)
        blamed: Counter[str] = Counter()
        worst = []
        for h, recs in sorted(per_hour.items()):
            top = max(recs, key=lambda r: r["added_ms"])
            blame = top["segment"]
            if blame == "beyond_isp":
                c = side.get((dev, h), Counter())
                blame = "service" if c["service"] > c["access_or_path"] else "isp_path"
            blamed[blame] += 1
            worst.append(
                {"local_hour": top["local_hour"], "blame": blame, "added_ms": top["added_ms"],
                 "segments": {r["segment"]: r["added_ms"] for r in recs}}
            )  # fmt: skip
        verdicts[dev] = {
            "latency_budget_ms": budget,
            "degraded_hours_by_cause": dict(blamed),
            "degraded_hours": sorted(worst, key=lambda w: -w["added_ms"])[:12],
        }
    return rows, verdicts


def client_services(athena: Athena, day: date) -> list[dict[str, Any]]:
    """Per CPE, LAN client and service: the WAN part of the client's own
    connections next to the CPE's own TCP probe of the same service. A
    client much slower than the CPE's probe reaches other servers (another
    CDN node) or meets queueing the probe does not."""
    rows = athena.query(f"""
        WITH f AS (
          SELECT device, json_extract_scalar(extra, '$.client') AS client, service, category,
            count(*) AS flows, approx_percentile(CAST(json_extract_scalar(extra, '$.wan_ms') AS double), 0.5) AS wan_p50
          FROM heimdall.samples
          WHERE {day_filter(day)} AND kind = 'flow' AND status = 'ok' AND service IS NOT NULL AND service <> 'other'
          GROUP BY 1, 2, 3, 4
        ),
        t AS (
          SELECT device, service, approx_percentile(rtt_ms, 0.5) AS cpe_tcp_p50
          FROM heimdall.samples
          WHERE {day_filter(day)} AND kind = 'tcp' AND status = 'ok' AND target_id NOT LIKE 'client/%'
          GROUP BY 1, 2
        )
        SELECT f.device, f.client, f.service, f.category, f.flows, f.wan_p50, t.cpe_tcp_p50
        FROM f LEFT JOIN t ON t.device = f.device AND t.service = f.service
    """)  # noqa: S608 - only dates, constants and validated device IDs are interpolated
    out = []
    for r in rows:
        wan, cpe = _num(r["wan_p50"]), _num(r["cpe_tcp_p50"])
        out.append(
            {
                "device": r["device"],
                "client": r["client"],
                "service": r["service"],
                "category": r["category"],
                "flows": _int(r["flows"]),
                "wan_p50": wan,
                "cpe_tcp_p50": cpe,
                "ratio": wan / cpe if wan and cpe else None,
            }
        )
    return out


def client_crosscheck(athena: Athena, day: date) -> list[dict[str, Any]]:
    """Connections a client device (heimdall-client) opened, matched with
    the CPE's record of the same connections by the client's address and
    port within a few seconds (a source port is not reused that soon): what
    the client measured next to the CPE's WAN and LAN parts."""
    rows = athena.query(f"""
        WITH c AS (
          SELECT device AS client_device, ts_ms, service, dst_ip, rtt_ms AS client_ms,
            json_extract_scalar(extra, '$.local_ip') AS ip,
            CAST(json_extract_scalar(extra, '$.local_port') AS integer) AS port
          FROM heimdall.samples
          WHERE {day_filter(day)} AND kind = 'tcp' AND target_id LIKE 'client/%' AND target_id <> 'client/gateway-tcp'
            AND status = 'ok'
        ),
        f AS (
          SELECT device, ts_ms, dst_ip, json_extract_scalar(extra, '$.client') AS client,
            json_extract_scalar(extra, '$.client_ip') AS ip,
            CAST(json_extract_scalar(extra, '$.client_port') AS integer) AS port,
            CAST(json_extract_scalar(extra, '$.wan_ms') AS double) AS wan,
            CAST(json_extract_scalar(extra, '$.lan_ms') AS double) AS lan
          FROM heimdall.samples
          WHERE {day_filter(day)} AND kind = 'flow' AND status = 'ok' AND json_extract_scalar(extra, '$.proto') = 'tcp'
        )
        SELECT f.device, c.client_device, arbitrary(f.client) AS client, c.service, count(*) AS matched,
          approx_percentile(c.client_ms, 0.5) AS client_p50,
          approx_percentile(f.wan, 0.5) AS cpe_wan_p50,
          approx_percentile(f.lan, 0.5) AS cpe_lan_p50,
          approx_percentile(c.client_ms - f.wan - f.lan, 0.5) AS gap_p50,
          approx_percentile(c.client_ms - f.wan - f.lan, 0.9) AS gap_p90
        FROM c JOIN f ON c.ip = f.ip AND c.port = f.port AND abs(c.ts_ms - f.ts_ms) < 5000
        GROUP BY f.device, c.client_device, c.service
    """)  # noqa: S608 - only dates, constants and validated device IDs are interpolated
    return [
        {
            "device": r["device"],
            "client_device": r["client_device"],
            "client": r["client"],
            "service": r["service"],
            "matched": _int(r["matched"]),
            **{k: _num(r[k]) for k in ("client_p50", "cpe_wan_p50", "cpe_lan_p50", "gap_p50", "gap_p90")},
        }
        for r in rows
    ]


def client_findings(clients: list[dict[str, Any]], services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Clients of one CPE, most connections first, with what stands out."""
    by_client: dict[str, list[float]] = defaultdict(list)
    for s in services:
        if s["ratio"] and (s["flows"] or 0) >= 5:
            by_client[s["client"]].append(s["ratio"])
    out = []
    for c in sorted(clients, key=lambda c: -(c["flows"] or 0)):
        flags = []
        # Through the CPE's mesh topology an extender reports a signal far
        # below what the client itself sees, so without the extender's own
        # probe its clients are judged by their link rate. The extender's
        # probe reads the signal from its radio directly.
        on_cpe = (c["node"] or "cpe") == "cpe"
        ext_rssi = c.get("ext_rssi_avg")
        if on_cpe and c["rssi_avg"] is not None and c["rssi_avg"] <= WEAK_RSSI_DBM:
            flags.append("weak_signal")
        if not on_cpe and ext_rssi is not None and ext_rssi <= WEAK_RSSI_DBM:
            flags.append("weak_signal")
        if not on_cpe and ext_rssi is None and c["tx_rate_p50"] is not None and c["tx_rate_p50"] < SLOW_LINK_MBPS:
            flags.append("weak_link")
        if c["lan_p90"] is not None and c["lan_p90"] >= SLOW_LAN_P90_MS:
            flags.append("slow_lan")
        hop50, hop90 = c.get("hop_p50"), c.get("hop_p90")
        if hop90 is not None and hop90 >= SLOW_LAN_P90_MS:
            flags.append("slow_extender_hop")
        if hop50 is not None and c["lan_p50"] is not None and c["lan_p50"] - hop50 >= SLOW_BACKHAUL_ADDED_MS:
            flags.append("slow_backhaul")
        if c["retry_pct"] is not None and c["retry_pct"] >= HIGH_RETRY_PCT:
            flags.append("many_retries")
        if c["roams"] >= MANY_ROAMS:
            flags.append("roaming")
        ratios = by_client.get(c["client"], [])
        wan_ratio = statistics.median(ratios) if ratios else None
        if wan_ratio is not None and wan_ratio >= CLIENT_WAN_RATIO:
            flags.append("wan_slower_than_cpe_probe")
        rec = {k: v for k, v in c.items() if k != "device" and v is not None}
        for k, v in rec.items():
            if isinstance(v, float):
                rec[k] = round(v, 1)
        if wan_ratio is not None:
            rec["wan_vs_cpe_probe"] = round(wan_ratio, 2)
        rec["flags"] = flags
        out.append(rec)
    return out


def hop_ips(athena: Athena, day: date) -> list[str]:
    rows = athena.query(f"""
        SELECT DISTINCT json_extract_scalar(hop, '$.ip') AS ip
        FROM heimdall.samples
        CROSS JOIN UNNEST(CAST(json_extract(extra, '$.hops') AS array(json))) AS u(hop)
        WHERE {day_filter(day)} AND kind = 'trace'
    """)  # noqa: S608 - only dates, constants and validated device IDs are interpolated
    return sorted({r["ip"] for r in rows if r["ip"] and _public(r["ip"])})


def _public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


class RIPEstat:
    """Origin AS and holder names from RIPEstat, with an in-memory cache."""

    URL = "https://stat.ripe.net/data/{call}/data.json?{query}&sourceapp=heimdall"

    def __init__(self, fetch: Callable[[str], dict[str, Any]] | None = None):
        self.fetch = fetch or self._fetch
        self._names: dict[int, str] = {}

    @staticmethod
    def _fetch(url: str) -> dict[str, Any]:
        with urllib.request.urlopen(url, timeout=10) as r:  # noqa: S310 - fixed https URL
            return json.load(r)

    def network(self, ip: str) -> dict[str, Any]:
        d = self.fetch(self.URL.format(call="network-info", query="resource=" + urllib.parse.quote(ip)))
        data = d.get("data") or {}
        asns = data.get("asns") or []
        return {"ip": ip, "asn": int(asns[0]) if asns else None, "prefix": data.get("prefix")}

    def holder(self, asn: int) -> str:
        if asn not in self._names:
            try:
                d = self.fetch(self.URL.format(call="as-overview", query=f"resource=AS{asn}"))
                self._names[asn] = (d.get("data") or {}).get("holder") or ""
            except Exception as e:  # a missing name is not worth failing the run
                log.warning("as-overview AS%s: %s", asn, e)
                self._names[asn] = ""
        return self._names[asn]


def ip_asn(ips: Iterable[str], known: dict[str, dict[str, Any]], ripe: RIPEstat) -> list[dict[str, Any]]:
    """Map addresses to origin ASes, looking up only addresses not known
    from earlier days."""
    todo = [ip for ip in ips if ip not in known][:MAX_ASN_LOOKUPS]

    def look(ip: str) -> dict[str, Any] | None:
        try:
            return ripe.network(ip)
        except Exception as e:
            log.warning("network-info %s: %s", ip, e)
            return None

    with ThreadPoolExecutor(8) as ex:
        found = [r for r in ex.map(look, todo) if r]
    merged = {**known, **{r["ip"]: r for r in found}}
    for r in merged.values():
        if r.get("asn") and not r.get("as_name"):
            r["as_name"] = ripe.holder(r["asn"])
    return sorted(merged.values(), key=lambda r: r["ip"])


def path_borders(
    athena: Athena, day: date, asn_of: dict[str, int | None], home_asn: dict[str, int]
) -> list[dict[str, Any]]:
    """For the most frequent path of each target, find the first hop outside
    the device's own network."""
    rows = athena.query(f"""
        WITH t AS (
          SELECT device, service, target_id, dst_ip, json_format(json_extract(extra, '$.hops')) AS hops,
            array_join(transform(CAST(json_extract(extra, '$.hops') AS array(json)),
              h -> coalesce(json_extract_scalar(h, '$.ip'), '*')), ' ') AS path
          FROM heimdall.samples
          WHERE {day_filter(day)} AND kind = 'trace' AND json_extract_scalar(extra, '$.reached') = 'true'
        ),
        c AS (
          SELECT device, service, target_id, path, count(*) AS n, arbitrary(hops) AS hops, arbitrary(dst_ip) AS dst_ip,
            row_number() OVER (PARTITION BY device, target_id ORDER BY count(*) DESC) AS rn,
            sum(count(*)) OVER (PARTITION BY device, target_id) AS total,
            count(*) OVER (PARTITION BY device, target_id) AS paths
          FROM t GROUP BY 1, 2, 3, 4
        )
        SELECT device, service, target_id, dst_ip, hops, n, total, paths
        FROM c WHERE rn = 1
    """)  # noqa: S608 - only dates, constants and validated device IDs are interpolated
    out = []
    for r in rows:
        hops = json.loads(r["hops"] or "[]")
        home = home_asn.get(r["device"])
        last_home: dict[str, Any] | None = None
        border: dict[str, Any] | None = None
        as_path: list[int] = []
        for h in hops:
            ip = h.get("ip")
            if not ip:
                continue
            asn = asn_of.get(ip) if _public(ip) else home
            if asn and (not as_path or as_path[-1] != asn):
                as_path.append(asn)
            if border is None:
                if asn is None or asn == home:
                    last_home = h
                else:
                    border = {**h, "asn": asn}
        rec: dict[str, Any] = {
            "device": r["device"],
            "service": r["service"],
            "target_id": r["target_id"],
            "dst_ip": r["dst_ip"],
            "traces": _int(r["total"]),
            "paths": _int(r["paths"]),
            "main_path_share": (_int(r["n"]) or 0) / max(_int(r["total"]) or 1, 1),
            "hop_count": len(hops),
            "as_path": as_path,
        }
        if border:
            rec.update(
                border_ttl=border["ttl"],
                border_ip=border["ip"],
                next_asn=border["asn"],
                border_rtt_ms=border.get("rtt_ms"),
                last_home_ip=(last_home or {}).get("ip"),
                last_home_rtt_ms=(last_home or {}).get("rtt_ms"),
            )
            if rec["border_rtt_ms"] is not None and rec["last_home_rtt_ms"] is not None:
                rec["border_jump_ms"] = rec["border_rtt_ms"] - rec["last_home_rtt_ms"]
        out.append(rec)
    return out


def incidents(athena: Athena, day: date) -> list[dict[str, Any]]:
    rows = athena.query(f"""
        SELECT device, json_extract_scalar(extra, '$.incident_id') AS id,
          arbitrary(json_extract_scalar(extra, '$.scope')) AS scope,
          arbitrary(json_extract_scalar(extra, '$.cause')) AS cause,
          max_by(json_format(json_extract(extra, '$.services')), ts_ms) AS services,
          coalesce(min(CAST(json_extract_scalar(extra, '$.started_ms') AS bigint)), min(ts_ms)) AS first_ms,
          max_by(CAST(json_extract_scalar(extra, '$.duration_s') AS bigint), ts_ms)
            FILTER (WHERE json_extract_scalar(extra, '$.duration_s') IS NOT NULL) AS duration_s
        FROM heimdall.samples
        WHERE {day_filter(day)} AND kind = 'event' AND json_extract_scalar(extra, '$.event') LIKE 'incident%'
        GROUP BY 1, 2
    """)  # noqa: S608 - only dates, constants and validated device IDs are interpolated
    return [
        {
            "device": r["device"],
            "incident_id": r["id"],
            "scope": r["scope"],
            "cause": r["cause"],
            "services": json.loads(r["services"] or "[]"),
            "first_ms": _int(r["first_ms"]),
            "duration_s": _int(r["duration_s"]),
        }
        for r in rows
    ]


def summarize(
    day: date,
    services: list[dict[str, Any]],
    compare: list[dict[str, Any]],
    borders: list[dict[str, Any]],
    incs: list[dict[str, Any]],
    asn_names: dict[int, str],
    control: str,
    clients: list[dict[str, Any]] | None = None,
    client_svc: list[dict[str, Any]] | None = None,
    crosscheck: list[dict[str, Any]] | None = None,
    sites: dict[str, str] | None = None,
    verdicts: dict[str, dict[str, Any]] | None = None,
    backhauls: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """The day's headline findings per CPE device. Extender probes (sites)
    are reported under their CPE."""
    sites = sites or {}
    devices = sorted({s["device"] for s in services if s["device"] != control and s["device"] not in sites})
    out: dict[str, Any] = {"date": day.isoformat(), "control_device": control, "devices": {}}
    for dev in devices:
        icmp = [s for s in services if s["device"] == dev and s["kind"] == "icmp" and s["category"] != "infra"]
        inflated = sorted(
            (s for s in icmp if s["busy_inflation"] and s["busy_inflation"] >= 1.2),
            key=lambda s: -s["busy_inflation"],
        )
        lossy = sorted((s for s in icmp if (s["loss_pct"] or 0) >= 1), key=lambda s: -(s["loss_pct"] or 0))
        attr: dict[str, Counter[str]] = defaultdict(Counter)
        for c in compare:
            if c["device"] == dev:
                attr[c["service"]][c["attribution"]] += 1
        next_as: Counter[int] = Counter()
        for b in borders:
            if b["device"] == dev and b.get("next_asn"):
                next_as[b["next_asn"]] += 1
        out["devices"][dev] = {
            "services_measured": len(icmp),
            "busy_hour_inflation": [
                {
                    "service": s["service"],
                    "ratio": round(s["busy_inflation"], 2),
                    "busy_p50": s["busy_p50"],
                    "night_p50": s["night_p50"],
                }
                for s in inflated[:10]
            ],
            "loss": [{"service": s["service"], "loss_pct": round(s["loss_pct"], 2)} for s in lossy[:10]],
            "degraded_hours": {
                svc: dict(c) for svc, c in sorted(attr.items()) if c.get("access_or_path") or c.get("service")
            },
            "next_as": [{"asn": a, "name": asn_names.get(a, ""), "targets": n} for a, n in next_as.most_common(10)],
            "large_border_jumps": [
                {k: b.get(k) for k in ("service", "target_id", "next_asn", "border_ip", "border_jump_ms")}
                for b in sorted(
                    (b for b in borders if b["device"] == dev and (b.get("border_jump_ms") or 0) >= 20),
                    key=lambda b: -(b.get("border_jump_ms") or 0),
                )[:10]
            ],
            "incidents": [
                {**i, "seen_by": "extender" if i["device"] in sites else "cpe"}
                for i in incs
                if i["device"] == dev or sites.get(i["device"]) == dev
            ],
        }
        if v := (verdicts or {}).get(dev):
            out["devices"][dev]["attribution"] = v
        exts = []
        for ext in sorted(d for d, site in sites.items() if site == dev):
            rec: dict[str, Any] = {"device": ext}
            if up := next((b for b in backhauls or [] if b["device"] == ext), None):
                rec["backhaul"] = {
                    k: round(up[k], 2) if isinstance(up[k], float) else up[k]
                    for k in ("p50", "p95", "p99", "loss_pct", "samples")
                }
            exts.append(rec)
        if exts:
            out["devices"][dev]["extenders"] = exts
        mine = [c for c in clients or [] if c["device"] == dev]
        if mine:
            out["devices"][dev]["lan_clients"] = client_findings(
                mine, [s for s in client_svc or [] if s["device"] == dev]
            )[:15]
        cross = [
            {k: (round(v, 1) if isinstance(v, float) else v) for k, v in x.items() if k != "device"}
            for x in crosscheck or []
            if x["device"] == dev
        ]
        if cross:
            out["devices"][dev]["client_crosscheck"] = cross
    return out


class Store:
    """Reads and writes the derived tables in S3."""

    def __init__(self, s3: Any, bucket: str, prefix: str = "derived"):
        self.s3, self.bucket, self.prefix = s3, bucket, prefix

    def key(self, table: str, day: date, name: str = "part-0.json.gz") -> str:
        return f"{self.prefix}/{table}/dt={day.isoformat()}/{name}"

    def put_rows(self, table: str, day: date, rows: list[dict[str, Any]]) -> str:
        body = gzip.compress("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows).encode())
        k = self.key(table, day)
        self.s3.put_object(Bucket=self.bucket, Key=k, Body=body, ContentType="application/json", ContentEncoding="gzip")
        return k

    def put_doc(self, table: str, day: date, doc: dict[str, Any]) -> str:
        k = self.key(table, day, "summary.json")
        self.s3.put_object(
            Bucket=self.bucket, Key=k, Body=json.dumps(doc, indent=1).encode(), ContentType="application/json"
        )
        return k

    def get_rows(self, table: str, day: date) -> list[dict[str, Any]]:
        try:
            obj = self.s3.get_object(Bucket=self.bucket, Key=self.key(table, day))
        except self.s3.exceptions.NoSuchKey:
            return []
        return [json.loads(line) for line in gzip.decompress(obj["Body"].read()).decode().splitlines() if line]


def external_context(
    device: str,
    services: list[dict[str, Any]],
    atlas: list[dict[str, Any]],
    events: list[dict[str, Any]],
    asn: int | None,
) -> dict[str, Any]:
    """The CPE's root-server latency next to the other Atlas probes in its
    ISP, and the outage events IODA saw for the ISP and the country."""

    def inflation(rows: list[dict[str, Any]]) -> float | None:
        def hours(hs: tuple[int, ...]) -> list[float]:
            return [r["p50"] for r in rows if r["p50"] and (r["hour"] + LOCAL_OFFSET_H) % 24 in hs]

        busy, night = hours(BUSY_HOURS), hours(NIGHT_HOURS)
        if not busy or not night:
            return None
        return round(statistics.median(busy) / statistics.median(night), 3)

    out: dict[str, Any] = {
        "atlas_asn": asn,
        "ioda_events": [e for e in events if e["entity"] == f"asn/{asn}" or e["entity"].startswith("country/")],
    }
    for target in external.ATLAS_PINGS:
        mine = next(
            (s for s in services if s["device"] == device and s["service"] == target and s["kind"] == "icmp"), None
        )
        peers = [r for r in atlas if r["target"] == target and r["asn"] == asn]
        by_probe: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for r in peers:
            by_probe[r["probe_id"]].append(r)
        p50s = [r["p50"] for r in peers if r["p50"]]
        infl = [i for i in (inflation(rs) for rs in by_probe.values()) if i]
        out[target] = {
            "cpe_p50": mine["p50"] if mine else None,
            "cpe_busy_inflation": mine["busy_inflation"] if mine else None,
            "peer_probes": len(by_probe),
            "peer_p50": round(statistics.median(p50s), 3) if p50s else None,
            "peer_busy_inflation": round(statistics.median(infl), 3) if infl else None,
        }
    return out


def run(
    day: date,
    athena: Athena,
    store: Store,
    ripe: RIPEstat,
    control: str,
    home_asn: dict[str, int],
    country: str = "TR",
    fetch: external.Fetch = external.http_json,
) -> dict[str, Any]:
    if not DEVICE_RE.match(control):
        raise ValueError(f"invalid control device {control!r}")
    services = daily_service(athena, day)
    store.put_rows("daily_service", day, services)
    compare = daily_compare(athena, day, control)
    store.put_rows("daily_compare", day, compare)

    known = {r["ip"]: r for r in store.get_rows("ip_asn", day - timedelta(days=1))}
    asn_rows = ip_asn(hop_ips(athena, day), known, ripe)
    store.put_rows("ip_asn", day, asn_rows)
    asn_of = {r["ip"]: r.get("asn") for r in asn_rows}
    names = {r["asn"]: r.get("as_name", "") for r in asn_rows if r.get("asn")}

    borders = path_borders(athena, day, asn_of, home_asn)
    store.put_rows("path_borders", day, borders)
    incs = incidents(athena, day)

    cpe_asns = sorted({a for d, a in home_asn.items() if d != control})
    atlas = [r for a in cpe_asns for r in external.atlas_ping(day, a, fetch)]
    store.put_rows("atlas_ping", day, atlas)
    events = external.ioda_day(day, [("asn", str(a)) for a in cpe_asns] + [("country", country)], fetch)
    store.put_rows("external_events", day, events)

    sites = extender_sites(athena, day)
    clients = merge_extenders(daily_client(athena, day), sites)
    store.put_rows("daily_client", day, clients)
    client_svc = client_services(athena, day)
    store.put_rows("daily_client_service", day, client_svc)
    crosscheck = client_crosscheck(athena, day)
    store.put_rows("daily_crosscheck", day, crosscheck)
    attribution, verdicts = attribute([h for h in segment_hours(athena, day, sites) if h["device"] != control], compare)
    store.put_rows("daily_attribution", day, attribution)

    backhauls = backhaul(athena, day, sites)
    summary = summarize(
        day, services, compare, borders, incs, names, control, clients, client_svc, crosscheck, sites, verdicts,
        backhauls,
    )  # fmt: skip
    for dev, s in summary["devices"].items():
        s["external"] = external_context(dev, services, atlas, events, home_asn.get(dev))
    store.put_doc("summary", day, summary)
    counts = {
        "daily_service": len(services),
        "daily_compare": len(compare),
        "ip_asn": len(asn_rows),
        "path_borders": len(borders),
        "incidents": len(incs),
        "atlas_ping": len(atlas),
        "external_events": len(events),
        "daily_client": len(clients),
        "daily_client_service": len(client_svc),
        "daily_crosscheck": len(crosscheck),
        "daily_attribution": len(attribution),
        "extenders": len(sites),
    }
    log.info(json.dumps({"day": day.isoformat(), **counts}))
    return {"day": day.isoformat(), **counts}


def start_report(day: date, function: str) -> None:
    """Start the report Lambda for day without waiting for it."""
    import boto3

    boto3.client("lambda").invoke(
        FunctionName=function, InvocationType="Event", Payload=json.dumps({"date": day.isoformat()}).encode()
    )


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    import boto3

    day = date.fromisoformat(event["date"]) if event.get("date") else (datetime.now(UTC) - timedelta(days=1)).date()
    result = run(
        day,
        Athena(boto3.client("athena"), os.environ["WORKGROUP"]),
        Store(boto3.client("s3"), os.environ["BUCKET"]),
        RIPEstat(),
        control=os.environ["CONTROL_DEVICE"],
        home_asn=json.loads(os.environ.get("HOME_ASN", "{}")),
        country=os.environ.get("COUNTRY", "TR"),
    )
    if (fn := os.environ.get("REPORT_FUNCTION")) and event.get("report", True):
        start_report(day, fn)
    return result
