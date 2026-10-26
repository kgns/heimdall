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
          min(ts_ms) AS first_ms, max(CAST(json_extract_scalar(extra, '$.duration_s') AS bigint)) AS duration_s
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
) -> dict[str, Any]:
    """The day's headline findings per CPE device."""
    devices = sorted({s["device"] for s in services if s["device"] != control})
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
            "incidents": [i for i in incs if i["device"] == dev],
        }
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

    summary = summarize(day, services, compare, borders, incs, names, control)
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
    }
    log.info(json.dumps({"day": day.isoformat(), **counts}))
    return {"day": day.isoformat(), **counts}


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    import boto3

    day = date.fromisoformat(event["date"]) if event.get("date") else (datetime.now(UTC) - timedelta(days=1)).date()
    return run(
        day,
        Athena(boto3.client("athena"), os.environ["WORKGROUP"]),
        Store(boto3.client("s3"), os.environ["BUCKET"]),
        RIPEstat(),
        control=os.environ["CONTROL_DEVICE"],
        home_asn=json.loads(os.environ.get("HOME_ASN", "{}")),
        country=os.environ.get("COUNTRY", "TR"),
    )
