#!/usr/bin/env python3
"""Generates the Grafana dashboards in grafana/dashboards/ from the panel
definitions below. Run it after changing a panel and commit the JSON:

    python3 grafana/gen_dashboards.py

Every query reads heimdall.samples through the Athena data source. In the SQL
templates, {R} expands to the device, partition and time range filter and {B}
to the panel's time bucket. Partition pruning on dt keeps the scanned bytes
proportional to the dashboard's time range.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

OUT = Path(__file__).resolve().parent / "dashboards"
DS = {"type": "grafana-athena-datasource", "uid": "athena"}
CONN = {"region": "__default", "catalog": "__default", "database": "__default"}

RANGE = (
    "device = '$device'"
    " AND dt BETWEEN $__rawTimeFrom('yyyy-MM-dd') AND $__rawTimeTo('yyyy-MM-dd')"
    " AND ts_ms BETWEEN ${__from} AND ${__to}"
)
BUCKET = "CAST(from_unixtime((ts_ms / $__interval_ms) * $__interval_ms / 1000.0) AS timestamp)"
# The same range for every device, for comparisons between the CPE and the
# cloud probe.
RANGE_ALL = (
    "dt BETWEEN $__rawTimeFrom('yyyy-MM-dd') AND $__rawTimeTo('yyyy-MM-dd') AND ts_ms BETWEEN ${__from} AND ${__to}"
)
CLOUD_DEVICE = "aws-euc1"
# Services measured from the CPE; infra (ISP hops, resolvers, CPE counters)
# and home (LAN clients) have their own dashboard.
SERVICES = "category NOT IN ('infra', 'home')"
TIME_SERIES, TABLE = 0, 1


def sql(text: str, **subs: str) -> str:
    """Expands the placeholders and collapses whitespace. Values are fixed
    strings from this file or Grafana variables, never user input."""
    # Expanded first because it contains {R}.
    if "{INC}" in text:
        text = text.replace("{INC}", INCIDENTS)
    subs = {"RA": RANGE_ALL, "R": RANGE, "B": BUCKET, "S": SERVICES, "CLOUD": CLOUD_DEVICE, **subs}
    for k, v in subs.items():
        text = text.replace("{" + k + "}", v)
    return " ".join(text.split())


def target(text: str, fmt: int, ref: str = "A") -> dict[str, Any]:
    return {"refId": ref, "datasource": DS, "format": fmt, "rawSQL": sql(text), "connectionArgs": CONN}


class Layout:
    """Places panels left to right in rows of 24 grid columns."""

    def __init__(self) -> None:
        self.x = self.y = self.row_h = 0
        self.next_id = 1

    def place(self, panel: dict[str, Any], w: int, h: int) -> dict[str, Any]:
        if self.x + w > 24:
            self.x, self.y, self.row_h = 0, self.y + self.row_h, 0
        panel["gridPos"] = {"x": self.x, "y": self.y, "w": w, "h": h}
        panel["id"] = self.next_id
        self.next_id += 1
        self.x += w
        self.row_h = max(self.row_h, h)
        return panel

    def row(self, title: str) -> dict[str, Any]:
        if self.x:
            self.x, self.y, self.row_h = 0, self.y + self.row_h, 0
        p = {"type": "row", "title": title, "collapsed": False, "panels": [], "id": self.next_id}
        p["gridPos"] = {"x": 0, "y": self.y, "w": 24, "h": 1}
        self.next_id += 1
        self.y += 1
        return p


def series(
    title: str,
    text: str,
    unit: str,
    description: str = "",
    long: bool = True,
    bars: bool = False,
    min0: bool = True,
) -> dict[str, Any]:
    """A time series panel. With long=True the query returns
    (time, metric, value) rows and each distinct metric becomes a series."""
    defaults: dict[str, Any] = {
        "unit": unit,
        "custom": {
            "drawStyle": "bars" if bars else "line",
            "lineWidth": 1,
            "fillOpacity": 60 if bars else 0,
            "showPoints": "never",
            "spanNulls": False,
            "stacking": {"mode": "normal" if bars else "none"},
        },
    }
    if min0:
        defaults["min"] = 0
    if long:
        defaults["displayName"] = "${__field.labels.metric}"
    return {
        "type": "timeseries",
        "title": title,
        "description": description,
        "datasource": DS,
        "interval": "1m",
        "maxDataPoints": 400,
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {
            "legend": {"displayMode": "table", "placement": "right", "calcs": ["mean", "max"], "sortBy": "Max"},
            "tooltip": {"mode": "multi", "sort": "desc"},
        },
        "targets": [target(text, TIME_SERIES)],
    }


def table(title: str, text: str, description: str = "", units: dict[str, str] | None = None) -> dict[str, Any]:
    overrides = [
        {"matcher": {"id": "byName", "options": col}, "properties": [{"id": "unit", "value": unit}]}
        for col, unit in (units or {}).items()
    ]
    return {
        "type": "table",
        "title": title,
        "description": description,
        "datasource": DS,
        "fieldConfig": {"defaults": {"decimals": 1}, "overrides": overrides},
        "options": {"showHeader": True, "cellHeight": "sm"},
        "targets": [target(text, TABLE)],
    }


def var(name: str, text: str, label: str | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "label": label or name,
        "type": "query",
        "datasource": DS,
        "query": {"refId": name, "format": TABLE, "rawSQL": sql(text), "connectionArgs": CONN},
        "definition": sql(text),
        # Refresh with the time range so the lists follow the partitions the
        # panels read.
        "refresh": 2,
        "sort": 1,
        "multi": False,
        "includeAll": False,
        "current": {},
    }


DEVICE = var(
    "device",
    "SELECT DISTINCT device FROM heimdall.samples WHERE dt = $__rawTimeTo('yyyy-MM-dd') AND kind = 'heartbeat'",
)
CATEGORY = var(
    "category",
    "SELECT DISTINCT category FROM heimdall.samples WHERE device = '$device'"
    " AND dt = $__rawTimeTo('yyyy-MM-dd') AND kind IN ('icmp', 'tcp', 'http') AND {S} ORDER BY 1",
)
SERVICE = var(
    "service",
    "SELECT DISTINCT service FROM heimdall.samples WHERE device = '$device'"
    " AND dt = $__rawTimeTo('yyyy-MM-dd') AND category = '$category' ORDER BY 1",
)


def dashboard(uid: str, title: str, panels: list[dict[str, Any]], variables: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "uid": uid,
        "title": title,
        "tags": ["heimdall"],
        "timezone": "browser",
        "editable": False,
        "graphTooltip": 1,
        "schemaVersion": 41,
        "time": {"from": "now-6h", "to": "now"},
        "refresh": "",
        "templating": {"list": variables},
        "annotations": {"list": []},
        "links": [{"type": "dashboards", "tags": ["heimdall"], "asDropdown": False, "title": "heimdall"}],
        "panels": panels,
    }


# Per-sample RTT divided by the median of the same (service, destination)
# over the dashboard range. A rise in every category at once points at the
# access network; a rise in one service at that service's path. Normalising
# per destination keeps DNS-driven destination changes from showing as
# latency changes.
RELATIVE = """
WITH s AS (
  SELECT {GROUP} AS metric, service, dst_ip, {B} AS time, rtt_ms
  FROM heimdall.samples
  WHERE {R} AND kind = 'icmp' AND status = 'ok' AND {FILTER}
),
b AS (SELECT service, dst_ip, approx_percentile(rtt_ms, 0.5) AS base FROM s GROUP BY 1, 2)
SELECT s.time, s.metric, approx_percentile(s.rtt_ms / b.base, 0.5) AS value
FROM s JOIN b ON s.service = b.service AND s.dst_ip = b.dst_ip
WHERE b.base > 0
GROUP BY 1, 2 ORDER BY 1
"""


# One row per incident in the range, from its start, update and end events.
INCIDENTS = """
WITH e AS (
  SELECT ts_ms, json_extract_scalar(extra, '$.event') AS ev, json_extract_scalar(extra, '$.incident_id') AS id,
    json_extract_scalar(extra, '$.scope') AS scope, json_extract_scalar(extra, '$.cause') AS cause,
    array_join(CAST(json_extract(extra, '$.services') AS array(varchar)), ', ') AS services,
    CAST(json_extract_scalar(extra, '$.duration_s') AS bigint) AS duration_s,
    CAST(json_extract_scalar(extra, '$.anomalous_series') AS integer) AS series,
    json_extract_scalar(extra, '$.targets[0].target_id') AS top_target,
    CAST(json_extract_scalar(extra, '$.targets[0].current_ms') AS double) AS top_current_ms,
    CAST(json_extract_scalar(extra, '$.targets[0].baseline_ms') AS double) AS top_baseline_ms
  FROM heimdall.samples
  WHERE {R} AND kind = 'event' AND json_extract_scalar(extra, '$.event') LIKE 'incident\\_%' ESCAPE '\\'
),
i AS (
  SELECT id,
    CAST(from_unixtime(min(ts_ms) FILTER (WHERE ev = 'incident_start') / 1000.0) AS timestamp) AS start_time,
    CAST(from_unixtime(max(ts_ms) FILTER (WHERE ev = 'incident_end') / 1000.0) AS timestamp) AS end_time,
    arbitrary(scope) AS scope, arbitrary(cause) AS cause, max_by(services, ts_ms) AS services,
    max(duration_s) AS duration_s, max(series) AS series,
    max_by(top_target, ts_ms) FILTER (WHERE top_target IS NOT NULL) AS top_target,
    max_by(top_current_ms, ts_ms) FILTER (WHERE top_target IS NOT NULL) AS top_current_ms,
    max_by(top_baseline_ms, ts_ms) FILTER (WHERE top_target IS NOT NULL) AS top_baseline_ms
  FROM e GROUP BY id
)
"""


def overview() -> dict[str, Any]:
    L = Layout()
    p = [
        L.place(
            table(
                "Services over the range",
                """
                SELECT category, service,
                  approx_percentile(rtt_ms, 0.5) FILTER (WHERE kind = 'icmp' AND status = 'ok') AS icmp_p50,
                  approx_percentile(rtt_ms, 0.95) FILTER (WHERE kind = 'icmp' AND status = 'ok') AS icmp_p95,
                  100.0 * count_if(kind = 'icmp' AND status <> 'ok') / nullif(count_if(kind = 'icmp'), 0) AS icmp_loss,
                  approx_percentile(rtt_ms, 0.5) FILTER (WHERE kind = 'tcp' AND status = 'ok') AS tcp_p50,
                  approx_percentile(CAST(json_extract_scalar(extra, '$.ttfb_ms') AS double), 0.5)
                    FILTER (WHERE kind = 'http' AND status = 'ok') AS ttfb_p50,
                  100.0 * count_if(kind = 'http' AND status <> 'ok') / nullif(count_if(kind = 'http'), 0) AS http_fail,
                  count(DISTINCT dst_ip) AS dsts
                FROM heimdall.samples
                WHERE {R} AND kind IN ('icmp', 'tcp', 'http') AND {S}
                GROUP BY 1, 2 ORDER BY 1, 2
                """,
                "ICMP echo, TCP connect and HTTPS time to first byte per service. "
                "Loss and failure columns are percentages; dsts counts the destination addresses seen.",
                units={
                    "icmp_p50": "ms",
                    "icmp_p95": "ms",
                    "tcp_p50": "ms",
                    "ttfb_p50": "ms",
                    "icmp_loss": "percent",
                    "http_fail": "percent",
                },
            ),
            24,
            12,
        ),
        L.place(
            series(
                "Relative ICMP RTT by category",
                sql(RELATIVE, GROUP="category", FILTER=SERVICES),
                "x",
                "1.0 is each destination's median over the range. Categories rising together point at the "
                "access network; one category alone at its services' paths.",
                min0=False,
            ),
            12,
            9,
        ),
        L.place(
            series(
                "ISP hops RTT p50",
                """
                SELECT {B} AS time, target_id AS metric, approx_percentile(rtt_ms, 0.5) AS value
                FROM heimdall.samples
                WHERE {R} AND kind = 'icmp' AND status = 'ok' AND service = 'isp-hop'
                GROUP BY 1, 2 ORDER BY 1
                """,
                "ms",
                "TTL-limited echoes towards 1.1.1.1: the first routers of the access network.",
            ),
            12,
            9,
        ),
        L.place(
            series(
                "ICMP RTT p50 by category",
                """
                SELECT {B} AS time, category AS metric, approx_percentile(rtt_ms, 0.5) AS value
                FROM heimdall.samples
                WHERE {R} AND kind = 'icmp' AND status = 'ok' AND {S}
                GROUP BY 1, 2 ORDER BY 1
                """,
                "ms",
            ),
            12,
            9,
        ),
        L.place(
            series(
                "ICMP loss by category",
                """
                SELECT {B} AS time, category AS metric,
                  100.0 * count_if(status <> 'ok') / count(*) AS value
                FROM heimdall.samples
                WHERE {R} AND kind = 'icmp' AND {S}
                GROUP BY 1, 2 ORDER BY 1
                """,
                "percent",
            ),
            12,
            9,
        ),
        L.place(
            series(
                "TCP connect p50 by category",
                """
                SELECT {B} AS time, category AS metric, approx_percentile(rtt_ms, 0.5) AS value
                FROM heimdall.samples
                WHERE {R} AND kind = 'tcp' AND status = 'ok' AND {S}
                GROUP BY 1, 2 ORDER BY 1
                """,
                "ms",
            ),
            12,
            9,
        ),
        L.place(
            series(
                "HTTPS time to first byte p50 by category",
                """
                SELECT {B} AS time, category AS metric,
                  approx_percentile(CAST(json_extract_scalar(extra, '$.ttfb_ms') AS double), 0.5) AS value
                FROM heimdall.samples
                WHERE {R} AND kind = 'http' AND status = 'ok' AND {S}
                GROUP BY 1, 2 ORDER BY 1
                """,
                "ms",
                "From the start of the request on a fresh connection, so it includes TCP and TLS setup.",
            ),
            12,
            9,
        ),
        L.place(
            series(
                "HTTPS failures by service",
                """
                SELECT {B} AS time, service AS metric, count(*) AS value
                FROM heimdall.samples
                WHERE {R} AND kind = 'http' AND status <> 'ok' AND {S}
                GROUP BY 1, 2 ORDER BY 1
                """,
                "short",
                bars=True,
            ),
            12,
            9,
        ),
        L.place(
            series(
                "Destination changes by category",
                """
                SELECT {B} AS time, category AS metric, count(*) AS value
                FROM heimdall.samples
                WHERE {R} AND kind = 'event' AND json_extract_scalar(extra, '$.event') = 'dst_change'
                GROUP BY 1, 2 ORDER BY 1
                """,
                "short",
                "A service's address left the DNS answer and the probe moved to a new one. "
                "Latency changes at the same time are explained by the move.",
                bars=True,
            ),
            12,
            9,
        ),
    ]
    p.append(
        L.place(
            table(
                "Incidents",
                """
                {INC}
                SELECT start_time, end_time, scope, cause, services, duration_s, series, top_target,
                  top_current_ms, top_baseline_ms
                FROM i ORDER BY start_time DESC LIMIT 100
                """,
                "Detected by the probe: anomalies grouped by scope (access network, one service, DNS) with "
                "a likely cause. Open incidents have no end time. Slack gets the same events.",
                units={"top_current_ms": "ms", "top_baseline_ms": "ms", "duration_s": "s"},
            ),
            24,
            8,
        )
    )
    p.append(
        L.place(
            table(
                "Discovered servers",
                """
                SELECT service, arbitrary(json_extract_scalar(extra, '$.endpoint')) AS endpoint, dst_ip, kind,
                  approx_percentile(rtt_ms, 0.5) FILTER (WHERE status = 'ok') AS p50,
                  approx_percentile(rtt_ms, 0.95) FILTER (WHERE status = 'ok') AS p95,
                  100.0 * count_if(status <> 'ok') / count(*) AS no_answer
                FROM heimdall.samples
                WHERE {R} AND kind IN ('icmp', 'tcp', 'udp_echo', 'stun')
                  AND json_extract_scalar(extra, '$.endpoint') IS NOT NULL
                GROUP BY service, dst_ip, kind ORDER BY service, p50
                """,
                "Where the traffic of these services actually goes: the video caches this line is mapped to, "
                "game relays, voice regions, GameLift beacons and STUN servers.",
                units={"p50": "ms", "p95": "ms", "no_answer": "percent"},
            ),
            24,
            10,
        )
    )
    d = dashboard("heimdall-overview", "heimdall / overview", p, [DEVICE])
    d["annotations"]["list"].append(
        {
            "name": "Incidents",
            "datasource": DS,
            "enable": True,
            "iconColor": "red",
            "target": target(
                """
                {INC}
                SELECT coalesce(start_time, CAST(from_unixtime(${__from} / 1000.0) AS timestamp)) AS time,
                  coalesce(end_time, CAST(from_unixtime(${__to} / 1000.0) AS timestamp)) AS timeend,
                  scope || ': ' || cause || ' (' || coalesce(services, '') || ')' AS text
                FROM i ORDER BY time
                """,
                TABLE,
                "Anno",
            ),
        }
    )
    return d


def per_dst(title: str, kind: str, agg: str, unit: str, description: str = "") -> dict[str, Any]:
    query = """
        SELECT {B} AS time, dst_ip AS metric, {AGG} AS value
        FROM heimdall.samples
        WHERE {R} AND kind = '{KIND}' AND service = '$service' AND {OK}
        GROUP BY 1, 2 ORDER BY 1
        """
    ok = "status = 'ok'" if agg.startswith("approx") else "true"
    return series(title, sql(query, AGG=agg, KIND=kind, OK=ok), unit, description)


def service() -> dict[str, Any]:
    L = Layout()
    p = [
        L.place(per_dst("ICMP RTT p50 by destination", "icmp", "approx_percentile(rtt_ms, 0.5)", "ms"), 12, 9),
        L.place(per_dst("ICMP RTT p95 by destination", "icmp", "approx_percentile(rtt_ms, 0.95)", "ms"), 12, 9),
        L.place(
            per_dst("ICMP loss by destination", "icmp", "100.0 * count_if(status <> 'ok') / count(*)", "percent"),
            12,
            9,
        ),
        L.place(per_dst("TCP connect p50 by destination", "tcp", "approx_percentile(rtt_ms, 0.5)", "ms"), 12, 9),
        L.place(
            series(
                "HTTPS phases p50",
                """
                SELECT {B} AS time,
                  approx_percentile(CAST(json_extract_scalar(extra, '$.connect_ms') AS double), 0.5) AS connect,
                  approx_percentile(CAST(json_extract_scalar(extra, '$.tls_ms') AS double), 0.5) AS tls,
                  approx_percentile(CAST(json_extract_scalar(extra, '$.ttfb_ms') AS double), 0.5) AS ttfb,
                  approx_percentile(CAST(json_extract_scalar(extra, '$.total_ms') AS double), 0.5) AS total
                FROM heimdall.samples
                WHERE {R} AND kind = 'http' AND status = 'ok' AND service = '$service'
                GROUP BY 1 ORDER BY 1
                """,
                "ms",
                "connect and tls are the handshake durations; ttfb and total are measured from the start "
                "of the request. TLS much slower than connect points at a TLS-terminating edge or filtering.",
                long=False,
            ),
            12,
            9,
        ),
        L.place(
            series(
                "Relative ICMP RTT for services in $category",
                sql(RELATIVE, GROUP="service", FILTER="category = '$category'"),
                "x",
                "1.0 is each destination's median over the range. One service rising alone points at its path "
                "or its servers.",
                min0=False,
            ),
            12,
            9,
        ),
        L.place(
            series(
                "ICMP RTT p50: this device and the AWS control",
                """
                SELECT {B} AS time, device AS metric, approx_percentile(rtt_ms, 0.5) AS value
                FROM heimdall.samples
                WHERE {RA} AND device IN ('$device', '{CLOUD}') AND kind = 'icmp' AND status = 'ok'
                  AND service = '$service'
                GROUP BY 1, 2 ORDER BY 1
                """,
                "ms",
                "The same service measured from AWS eu-central-1. A change in both lines is the service's own; "
                "a change only from the CPE is in the access network or the ISP's path to the service.",
            ),
            12,
            9,
        ),
        L.place(
            series(
                "HTTPS time to first byte p50: this device and the AWS control",
                """
                SELECT {B} AS time, device AS metric,
                  approx_percentile(CAST(json_extract_scalar(extra, '$.ttfb_ms') AS double), 0.5) AS value
                FROM heimdall.samples
                WHERE {RA} AND device IN ('$device', '{CLOUD}') AND kind = 'http' AND status = 'ok'
                  AND service = '$service'
                GROUP BY 1, 2 ORDER BY 1
                """,
                "ms",
            ),
            12,
            9,
        ),
        L.place(
            table(
                "Latest path per target",
                """
                WITH t AS (
                  SELECT target_id, extra,
                    row_number() OVER (PARTITION BY target_id ORDER BY ts_ms DESC) AS rn
                  FROM heimdall.samples
                  WHERE {R} AND kind = 'trace' AND service = '$service'
                )
                SELECT target_id, CAST(json_extract_scalar(hop, '$.ttl') AS integer) AS ttl,
                  json_extract_scalar(hop, '$.ip') AS ip,
                  CAST(json_extract_scalar(hop, '$.rtt_ms') AS double) AS rtt_ms,
                  CAST(json_extract_scalar(hop, '$.answers') AS integer) AS answers,
                  json_format(json_extract(hop, '$.other')) AS other
                FROM t CROSS JOIN UNNEST(CAST(json_extract(extra, '$.hops') AS array(json))) AS u(hop)
                WHERE rn = 1
                ORDER BY target_id, ttl
                """,
                "The most recent traceroute to each target of the service. Silent hops have no ip; "
                "other lists further routers seen at the same TTL (load balancing).",
                units={"rtt_ms": "ms"},
            ),
            12,
            12,
        ),
        L.place(
            table(
                "Path changes",
                """
                WITH t AS (
                  SELECT target_id, ts_ms, CAST(json_extract_scalar(extra, '$.hop_count') AS integer) AS hops,
                    json_extract_scalar(extra, '$.reached') = 'true' AS reached,
                    array_join(transform(CAST(json_extract(extra, '$.hops') AS array(json)),
                      h -> coalesce(json_extract_scalar(h, '$.ip'), '*')), ' ') AS path
                  FROM heimdall.samples
                  WHERE {R} AND kind = 'trace' AND service = '$service'
                )
                SELECT target_id, count(*) AS traces, count(DISTINCT path) AS paths,
                  min(hops) AS min_hops, max(hops) AS max_hops,
                  100.0 * count_if(NOT reached) / count(*) AS unreached,
                  CAST(from_unixtime(max(ts_ms) / 1000.0) AS timestamp) AS last_trace
                FROM t GROUP BY target_id ORDER BY paths DESC, target_id
                """,
                "Distinct router sequences seen per target. Silent hops count as '*', so rate-limited "
                "routers can add paths that are not real changes.",
                units={"unreached": "percent"},
            ),
            12,
            12,
        ),
        L.place(
            table(
                "Discovered servers",
                """
                SELECT target_id, arbitrary(json_extract_scalar(extra, '$.endpoint')) AS endpoint, dst_ip, kind,
                  approx_percentile(rtt_ms, 0.5) FILTER (WHERE status = 'ok') AS p50,
                  approx_percentile(rtt_ms, 0.95) FILTER (WHERE status = 'ok') AS p95,
                  100.0 * count_if(status <> 'ok') / count(*) AS no_answer, count(*) AS samples
                FROM heimdall.samples
                WHERE {R} AND service = '$service' AND kind IN ('icmp', 'tcp', 'udp_echo', 'stun')
                  AND json_extract_scalar(extra, '$.endpoint') IS NOT NULL
                GROUP BY target_id, dst_ip, kind ORDER BY target_id, kind
                """,
                "The caches, relays, voice regions, beacons and STUN servers the service's own endpoints "
                "pointed this line to. Empty for services without discovery.",
                units={"p50": "ms", "p95": "ms", "no_answer": "percent"},
            ),
            24,
            7,
        ),
        L.place(
            table(
                "HTTPS edges",
                """
                SELECT target_id, dst_ip,
                  json_extract_scalar(extra, '$.cdn') AS cdn, json_extract_scalar(extra, '$.pop') AS pop,
                  json_extract_scalar(extra, '$.proto') AS proto, json_extract_scalar(extra, '$.kex') AS kex,
                  count(*) AS requests,
                  approx_percentile(CAST(json_extract_scalar(extra, '$.tls_ms') AS double), 0.5) AS tls_p50,
                  approx_percentile(CAST(json_extract_scalar(extra, '$.ttfb_ms') AS double), 0.5) AS ttfb_p50
                FROM heimdall.samples
                WHERE {R} AND kind = 'http' AND status = 'ok' AND service = '$service'
                GROUP BY 1, 2, 3, 4, 5, 6 ORDER BY requests DESC
                """,
                "Where each destination terminated the HTTPS request, from the response headers.",
                units={"tls_p50": "ms", "ttfb_p50": "ms"},
            ),
            24,
            7,
        ),
        L.place(
            table(
                "HTTPS and TCP failures",
                """
                SELECT CAST(from_unixtime(ts_ms / 1000.0) AS timestamp) AS time, kind, target_id, dst_ip, status,
                  json_extract_scalar(extra, '$.phase') AS phase, json_extract_scalar(extra, '$.reason') AS reason,
                  json_extract_scalar(extra, '$.code') AS code,
                  CAST(json_extract_scalar(extra, '$.connect_ms') AS double) AS connect_ms
                FROM heimdall.samples
                WHERE {R} AND kind IN ('http', 'tcp') AND status <> 'ok' AND service = '$service'
                ORDER BY ts_ms DESC LIMIT 200
                """,
                "A TLS-phase timeout or reset after a successful connect is typical of SNI filtering.",
                units={"connect_ms": "ms"},
            ),
            12,
            9,
        ),
        L.place(
            table(
                "Destination changes",
                """
                SELECT CAST(from_unixtime(ts_ms / 1000.0) AS timestamp) AS time,
                  json_extract_scalar(extra, '$.host') AS host, json_extract_scalar(extra, '$.prev') AS prev,
                  dst_ip AS new_dst, resolver_id,
                  json_array_length(json_extract(extra, '$.answers')) AS answers,
                  CAST(json_extract_scalar(extra, '$.resolve_ms') AS double) AS resolve_ms
                FROM heimdall.samples
                WHERE {R} AND kind = 'event' AND service = '$service'
                  AND json_extract_scalar(extra, '$.event') = 'dst_change'
                ORDER BY ts_ms DESC LIMIT 200
                """,
                units={"resolve_ms": "ms"},
            ),
            12,
            9,
        ),
    ]
    return dashboard("heimdall-service", "heimdall / service", p, [DEVICE, CATEGORY, SERVICE])


def network() -> dict[str, Any]:
    L = Layout()
    p = [L.row("Access network")]
    p += [
        L.place(
            series(
                "ISP hops RTT p50 and p95",
                """
                SELECT {B} AS time, target_id || ' p50' AS metric, approx_percentile(rtt_ms, 0.5) AS value
                FROM heimdall.samples
                WHERE {R} AND kind = 'icmp' AND status = 'ok' AND service = 'isp-hop'
                GROUP BY 1, 2
                UNION ALL
                SELECT {B} AS time, target_id || ' p95' AS metric, approx_percentile(rtt_ms, 0.95) AS value
                FROM heimdall.samples
                WHERE {R} AND kind = 'icmp' AND status = 'ok' AND service = 'isp-hop'
                GROUP BY 1, 2
                ORDER BY 1
                """,
                "ms",
            ),
            12,
            9,
        ),
        L.place(
            series(
                "ISP hops without answer",
                """
                SELECT {B} AS time, target_id AS metric, 100.0 * count_if(status <> 'ok') / count(*) AS value
                FROM heimdall.samples
                WHERE {R} AND kind = 'icmp' AND service = 'isp-hop'
                GROUP BY 1, 2 ORDER BY 1
                """,
                "percent",
                "Routers rate-limit time-exceeded replies, so a hop without answers while later hops and "
                "services are clean is not packet loss.",
            ),
            12,
            9,
        ),
        L.place(
            series(
                "WAN throughput",
                """
                SELECT {B} AS time,
                  avg(CAST(json_extract_scalar(extra, '$.rx_bps') AS double)) AS rx_avg,
                  max(CAST(json_extract_scalar(extra, '$.rx_bps') AS double)) AS rx_max,
                  avg(CAST(json_extract_scalar(extra, '$.tx_bps') AS double)) AS tx_avg,
                  max(CAST(json_extract_scalar(extra, '$.tx_bps') AS double)) AS tx_max
                FROM heimdall.samples
                WHERE {R} AND kind = 'wan'
                GROUP BY 1 ORDER BY 1
                """,
                "bps",
                "Traffic on the WAN interface from all LAN devices, per second. Latency that rises with "
                "throughput points at queueing in the CPE or the access link.",
                long=False,
            ),
            12,
            9,
        ),
        L.place(
            series(
                "CPE CPU",
                """
                SELECT {B} AS time,
                  avg(CAST(json_extract_scalar(extra, '$.busy_pct') AS double)) AS busy,
                  avg(CAST(json_extract_scalar(extra, '$.softirq_pct') AS double)) AS softirq,
                  max(CAST(json_extract_scalar(extra, '$.busy_pct') AS double)) AS busy_max
                FROM heimdall.samples
                WHERE {R} AND kind = 'cpu'
                GROUP BY 1 ORDER BY 1
                """,
                "percent",
                long=False,
            ),
            12,
            9,
        ),
    ]
    p.append(L.row("DNS"))
    p += [
        L.place(
            series(
                "DNS lookup p50 by layer",
                """
                SELECT {B} AS time, json_extract_scalar(extra, '$.layer') AS metric,
                  approx_percentile(rtt_ms, 0.5) AS value
                FROM heimdall.samples
                WHERE {R} AND kind = 'dns' AND status = 'ok'
                GROUP BY 1, 2 ORDER BY 1
                """,
                "ms",
            ),
            12,
            9,
        ),
        L.place(
            table(
                "Resolvers seen",
                """
                SELECT json_extract_scalar(extra, '$.resolver') AS resolver, count(*) AS answers,
                  min(CAST(from_unixtime(ts_ms / 1000.0) AS timestamp)) AS first_seen,
                  max(CAST(from_unixtime(ts_ms / 1000.0) AS timestamp)) AS last_seen
                FROM heimdall.samples
                WHERE {R} AND kind = 'dns' AND json_extract_scalar(extra, '$.layer') = 'identity'
                  AND json_extract_scalar(extra, '$.fresh') = 'true'
                GROUP BY 1 ORDER BY last_seen DESC
                """,
                "Upstream resolvers that answered identity queries without a cached answer.",
            ),
            12,
            9,
        ),
        L.place(
            series(
                "dnscrypt-proxy memory",
                """
                SELECT {B} AS time,
                  max(CAST(json_extract_scalar(extra, '$.mem_usage') AS double)) AS mem_usage,
                  max(CAST(json_extract_scalar(extra, '$.mem_limit') AS double)) AS mem_limit
                FROM heimdall.samples
                WHERE {R} AND kind = 'dnshealth'
                GROUP BY 1 ORDER BY 1
                """,
                "bytes",
                long=False,
            ),
            12,
            9,
        ),
        L.place(
            series(
                "CPE clock offset",
                """
                SELECT {B} AS time, avg(CAST(json_extract_scalar(extra, '$.offset_ms') AS double)) AS clock_offset
                FROM heimdall.samples
                WHERE {R} AND kind = 'clock'
                GROUP BY 1 ORDER BY 1
                """,
                "ms",
                "Positive means the CPE clock is behind.",
                long=False,
                min0=False,
            ),
            12,
            9,
        ),
    ]
    p.append(L.row("Home network"))
    p += [
        L.place(
            series(
                "LAN client RTT p50 by medium",
                """
                SELECT {B} AS time, json_extract_scalar(extra, '$.medium') AS metric,
                  approx_percentile(rtt_ms, 0.5) AS value
                FROM heimdall.samples
                WHERE {R} AND kind = 'lan' AND status = 'ok'
                GROUP BY 1, 2 ORDER BY 1
                """,
                "ms",
            ),
            12,
            9,
        ),
        L.place(
            table(
                "LAN clients",
                """
                SELECT target_id AS client, arbitrary(json_extract_scalar(extra, '$.medium')) AS medium,
                  arbitrary(json_extract_scalar(extra, '$.port')) AS port,
                  approx_percentile(rtt_ms, 0.5) FILTER (WHERE status = 'ok') AS rtt_p50,
                  approx_percentile(rtt_ms, 0.95) FILTER (WHERE status = 'ok') AS rtt_p95,
                  100.0 * count_if(status <> 'ok') / count(*) AS no_answer
                FROM heimdall.samples
                WHERE {R} AND kind = 'lan'
                GROUP BY 1 ORDER BY rtt_p95 DESC
                """,
                "Sleeping Wi-Fi devices answer late or not at all; that is power saving, not a network problem.",
                units={"rtt_p50": "ms", "rtt_p95": "ms", "no_answer": "percent"},
            ),
            12,
            9,
        ),
    ]
    p.append(L.row("Probe"))
    p += [
        L.place(
            series(
                "Ingest delay",
                """
                SELECT {B} AS time, avg(recv_ts_ms - ts_ms) AS avg_delay, max(recv_ts_ms - ts_ms) AS max_delay
                FROM heimdall.samples
                WHERE {R}
                GROUP BY 1 ORDER BY 1
                """,
                "ms",
                "Time from measurement to ingest. Grows during upload outages while the probe buffers.",
                long=False,
            ),
            12,
            9,
        ),
        L.place(
            series(
                "Probe process",
                """
                SELECT {B} AS time,
                  avg(CAST(json_extract_scalar(extra, '$.cpu_pct') AS double)) AS cpu_pct,
                  max(CAST(json_extract_scalar(extra, '$.goroutines') AS double)) AS goroutines,
                  max(CAST(json_extract_scalar(extra, '$.heap_alloc') AS double)) / 1048576 AS heap_mib
                FROM heimdall.samples
                WHERE {R} AND kind = 'self'
                GROUP BY 1 ORDER BY 1
                """,
                "short",
                long=False,
            ),
            12,
            9,
        ),
    ]
    p.append(L.row("Path to AWS (STAMP reflector)"))
    p += [
        L.place(
            series(
                "Reflector RTT",
                """
                SELECT {B} AS time, kind || ' p50' AS metric, approx_percentile(rtt_ms, 0.5) AS value
                FROM heimdall.samples
                WHERE {R} AND service = 'aws-reflector' AND status = 'ok' AND kind IN ('udp_echo', 'icmp', 'tcp')
                GROUP BY 1, 2
                UNION ALL
                SELECT {B} AS time, kind || ' p95' AS metric, approx_percentile(rtt_ms, 0.95) AS value
                FROM heimdall.samples
                WHERE {R} AND service = 'aws-reflector' AND status = 'ok' AND kind = 'udp_echo'
                GROUP BY 1, 2
                ORDER BY 1
                """,
                "ms",
                "udp_echo is STAMP without the reflector's turnaround; icmp and tcp go to the same instance.",
            ),
            12,
            9,
        ),
        L.place(
            series(
                "Queueing delay by direction",
                """
                WITH s AS (
                  SELECT {B} AS time,
                    CAST(json_extract_scalar(extra, '$.fwd_ms') AS double) AS fwd,
                    CAST(json_extract_scalar(extra, '$.rev_ms') AS double) AS rev
                  FROM heimdall.samples
                  WHERE {R} AND kind = 'udp_echo' AND status = 'ok'
                ),
                m AS (SELECT min(fwd) AS f0, min(rev) AS r0 FROM s)
                SELECT time,
                  approx_percentile(fwd - f0, 0.5) AS up_p50, approx_percentile(fwd - f0, 0.95) AS up_p95,
                  approx_percentile(rev - r0, 0.5) AS down_p50, approx_percentile(rev - r0, 0.95) AS down_p95
                FROM s CROSS JOIN m
                GROUP BY 1 ORDER BY 1
                """,
                "ms",
                "One-way delay above its minimum over the range. The clocks' constant offset cancels out, so "
                "this shows in which direction packets wait: up is CPE to AWS, down is AWS to CPE.",
                long=False,
            ),
            12,
            9,
        ),
        L.place(
            series(
                "Loss by direction",
                """
                SELECT {B} AS time,
                  sum(CAST(json_extract_scalar(extra, '$.lost_up') AS bigint)) AS lost_up,
                  sum(CAST(json_extract_scalar(extra, '$.lost_down') AS bigint)) AS lost_down,
                  count_if(status <> 'ok') AS timeouts
                FROM heimdall.samples
                WHERE {R} AND kind = 'udp_echo'
                GROUP BY 1 ORDER BY 1
                """,
                "short",
                "Requests that never reached the reflector (up) and replies that never came back (down).",
                long=False,
                bars=True,
            ),
            12,
            9,
        ),
        L.place(
            series(
                "Forward hop count",
                """
                SELECT {B} AS time,
                  min(CAST(json_extract_scalar(extra, '$.fwd_hops') AS bigint)) AS min_hops,
                  max(CAST(json_extract_scalar(extra, '$.fwd_hops') AS bigint)) AS max_hops
                FROM heimdall.samples
                WHERE {R} AND kind = 'udp_echo' AND status = 'ok'
                GROUP BY 1 ORDER BY 1
                """,
                "short",
                "Routers between the CPE and the reflector; a step is a route change.",
                long=False,
            ),
            12,
            9,
        ),
    ]
    return dashboard("heimdall-network", "heimdall / network", p, [DEVICE])


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, build in (("overview", overview), ("service", service), ("network", network)):
        (OUT / f"{name}.json").write_text(json.dumps(build(), indent=2) + "\n")


if __name__ == "__main__":
    main()
