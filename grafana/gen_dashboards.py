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
# The selected CPE and its extender probe together.
RANGE_SITE = (
    "device IN ('$device', '$ext')"
    " AND dt BETWEEN $__rawTimeFrom('yyyy-MM-dd') AND $__rawTimeTo('yyyy-MM-dd')"
    " AND ts_ms BETWEEN ${__from} AND ${__to}"
)
# The range of the extender probe of the selected CPE ($ext, "none" when
# it has none).
RANGE_EXT = (
    "device = '$ext'"
    " AND dt BETWEEN $__rawTimeFrom('yyyy-MM-dd') AND $__rawTimeTo('yyyy-MM-dd')"
    " AND ts_ms BETWEEN ${__from} AND ${__to}"
)
CLOUD_DEVICE = "aws-euc1"
# Services measured from the CPE; infra (ISP hops, resolvers, CPE counters)
# and home (LAN clients) have their own dashboard.
SERVICES = "category NOT IN ('infra', 'home')"
# DHCP hostnames that do not tell one device from another: none ("*" in the
# lease file), interface names, and names made of a MAC or other hex digits.
# The notifier keeps the same list (GENERIC_HOSTNAME in notify.py).
GENERIC_HOSTNAME = (
    r"^(\*|localhost|unknown|none|wlan[0-9]*|eth[0-9]*|android[-_]?[0-9a-f]*|esp[-_][0-9a-f]+|espressif"
    r"|[0-9a-f]{8,}|([0-9a-f]{2}[-:]?){6})$"
)
# nm: each LAN client's display name over the range, from the DHCP hostname
# the CPE reports with its samples (collectors.lan.hostnames). Clients with
# a generic hostname or none keep their ID; a hostname two clients share gets
# the start of the ID ("iPhone #6be1"). Names come from the CPE only, so the
# extender's samples are named through the shared client ID.
NAMES = """
nh AS (
  SELECT coalesce(json_extract_scalar(extra, '$.client'), substr(target_id, 5)) AS client,
    max_by(json_extract_scalar(extra, '$.client_name'), ts_ms) AS host
  FROM heimdall.samples
  WHERE {R} AND kind IN ('lan', 'flow') AND json_extract_scalar(extra, '$.client_name') IS NOT NULL
  GROUP BY 1
),
nm AS (
  SELECT client, CASE WHEN count(*) OVER (PARTITION BY lower(host)) > 1 THEN host || ' #' || substr(client, 1, 4)
    ELSE host END AS label
  FROM nh WHERE NOT regexp_like(lower(host), '{GH}')
)
"""
# sel: the ID of the client $client names; a value that is no display name
# is taken as an ID. Needs {NM} before it.
SEL = "sel AS (SELECT coalesce(max(client), '$client') AS id FROM nm WHERE label = '$client')"
TIME_SERIES, TABLE = 0, 1


def sql(text: str, **subs: str) -> str:
    """Expands the placeholders and collapses whitespace. Values are fixed
    strings from this file or Grafana variables, never user input."""
    # Expanded first because it contains {R}.
    if "{INC}" in text:
        text = text.replace("{INC}", INCIDENTS)
    if "{FLOWS}" in text or "{M}" in text:
        text = text.replace("{FLOWS}", FLOWS).replace("{M}", MATCHED)
    if "{NM}" in text:
        text = text.replace("{NM}", NAMES).replace("{SEL}", SEL)
    if "{D}" in text or "{ASN}" in text:
        text = text.replace("{D}", DAYS).replace("{ASN}", AS_NAMES)
    subs = {
        "RA": RANGE_ALL,
        "RE": RANGE_EXT,
        "RS": RANGE_SITE,
        "R": RANGE,
        "B": BUCKET,
        "S": SERVICES,
        "CLOUD": CLOUD_DEVICE,
        "GH": GENERIC_HOSTNAME,
        **subs,
    }
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
# Only CPE probes see LAN clients, so the client dashboards list the devices
# that sent client pings today and do not open on a cloud probe.
LAN_DEVICE = var(
    "device",
    "SELECT DISTINCT device FROM heimdall.samples WHERE dt = $__rawTimeTo('yyyy-MM-dd') AND kind = 'lan'",
)
# The probe on the CPE's mesh extender, which names the CPE as its site in
# its heartbeat, or "none". The topology takes one extender per home.
EXT = var(
    "ext",
    "SELECT coalesce(max(device), 'none') AS ext FROM heimdall.samples WHERE dt = $__rawTimeTo('yyyy-MM-dd')"
    " AND kind = 'heartbeat' AND device NOT IN ('$device', '{CLOUD}') AND json_extract_scalar(extra, '$.site') = '$device'",
)
EXT["hide"] = 2
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
    CAST(json_extract_scalar(extra, '$.started_ms') AS bigint) AS started_ms,
    CAST(json_extract_scalar(extra, '$.ended_ms') AS bigint) AS ended_ms,
    CAST(json_extract_scalar(extra, '$.anomalous_series') AS integer) AS series,
    json_extract_scalar(extra, '$.targets[0].target_id') AS top_target,
    CAST(json_extract_scalar(extra, '$.targets[0].current_ms') AS double) AS top_current_ms,
    CAST(json_extract_scalar(extra, '$.targets[0].baseline_ms') AS double) AS top_baseline_ms
  FROM heimdall.samples
  WHERE {R} AND kind = 'event' AND json_extract_scalar(extra, '$.event') LIKE 'incident\\_%' ESCAPE '\\'
),
i AS (
  SELECT id,
    CAST(from_unixtime(coalesce(min(started_ms), min(ts_ms) FILTER (WHERE ev = 'incident_start')) / 1000.0)
      AS timestamp) AS start_time,
    CAST(from_unixtime(max(coalesce(ended_ms, ts_ms)) FILTER (WHERE ev = 'incident_end') / 1000.0) AS timestamp)
      AS end_time,
    arbitrary(scope) AS scope, arbitrary(cause) AS cause, max_by(services, ts_ms) AS services,
    max_by(duration_s, ts_ms) FILTER (WHERE duration_s IS NOT NULL) AS duration_s, max(series) AS series,
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


DAYS = "device = '$device' AND dt BETWEEN $__rawTimeFrom('yyyy-MM-dd') AND $__rawTimeTo('yyyy-MM-dd')"
AS_NAMES = """
  (SELECT asn, arbitrary(as_name) AS as_name FROM heimdall.ip_asn
   WHERE dt BETWEEN $__rawTimeFrom('yyyy-MM-dd') AND $__rawTimeTo('yyyy-MM-dd') GROUP BY asn)
"""


def budget_series(title: str, text: str, unit: str, description: str = "") -> dict[str, Any]:
    """A series of one point per day, drawn with its points."""
    s = series(title, text, unit, description)
    s["fieldConfig"]["defaults"]["custom"]["showPoints"] = "always"
    s["fieldConfig"]["defaults"]["custom"]["pointSize"] = 6
    return s


def daily() -> dict[str, Any]:
    """Results of the daily analysis (heimdall_cloud.analytics), one row per
    day and item; the time range selects the days."""
    L = Layout()
    p = [
        L.place(
            table(
                "Busy-hour inflation",
                """
                SELECT service, category, count(*) AS days,
                  avg(night_p50) AS night_p50, avg(busy_p50) AS busy_p50, avg(busy_inflation) AS inflation,
                  max(busy_inflation) AS worst_day, avg(busy_loss_pct) AS busy_loss_pct, avg(jitter_ms) AS jitter_ms
                FROM heimdall.daily_service
                WHERE {D} AND kind = 'icmp' AND category <> 'infra'
                GROUP BY service, category ORDER BY inflation DESC NULLS LAST
                """,
                "Median RTT 20-24h local over 03-07h local. Above about 1.2, the evening load is "
                "slowing that service down: an access link, aggregation or peering link near capacity.",
                units={"night_p50": "ms", "busy_p50": "ms", "busy_loss_pct": "percent", "jitter_ms": "ms"},
            ),
            12,
            10,
        ),
        L.place(
            table(
                "Who is to blame: degraded hours",
                """
                SELECT service, count_if(attribution = 'access_or_path') AS isp_side_hours,
                  count_if(attribution = 'service') AS service_side_hours,
                  count_if(attribution = 'no_control') AS no_control_hours, count(*) AS hours,
                  max(cpe_ratio) AS worst_ratio
                FROM heimdall.daily_compare
                WHERE {D}
                GROUP BY service
                HAVING count_if(attribution IN ('access_or_path', 'service')) > 0
                ORDER BY isp_side_hours DESC, service_side_hours DESC
                """,
                "Hours where the service's median was 30% above its best hour of the day. ISP side: the AWS "
                "control saw no such rise. Service side: the control rose as well.",
            ),
            12,
            10,
        ),
        L.place(
            table(
                "Where paths leave the ISP",
                """
                SELECT b.next_asn, n.as_name, count(DISTINCT b.target_id) AS targets,
                  array_join(array_agg(DISTINCT b.service), ', ') AS services,
                  approx_percentile(b.border_jump_ms, 0.5) AS jump_p50_ms, max(b.border_jump_ms) AS jump_max_ms
                FROM heimdall.path_borders b LEFT JOIN {ASN} n ON n.asn = b.next_asn
                WHERE b.{D} AND b.next_asn IS NOT NULL
                GROUP BY b.next_asn, n.as_name ORDER BY targets DESC
                """,
                "The first network after the ISP on the most frequent traceroute path to each target, and "
                "the latency added at that border. Transit networks with large jumps for nearby services "
                "suggest missing or distant peering.",
                units={"jump_p50_ms": "ms", "jump_max_ms": "ms"},
            ),
            12,
            10,
        ),
        L.place(
            table(
                "Path borders per target",
                """
                SELECT b.dt, b.service, b.target_id, b.dst_ip, b.border_ip, b.next_asn, n.as_name,
                  array_join(transform(b.as_path, a -> CAST(a AS varchar)), ' > ') AS as_path,
                  b.last_home_rtt_ms, b.border_rtt_ms, b.border_jump_ms, b.paths, b.main_path_share, b.traces
                FROM heimdall.path_borders b LEFT JOIN {ASN} n ON n.asn = b.next_asn
                WHERE b.{D}
                ORDER BY b.dt DESC, b.border_jump_ms DESC NULLS LAST
                LIMIT 300
                """,
                units={
                    "last_home_rtt_ms": "ms",
                    "border_rtt_ms": "ms",
                    "border_jump_ms": "ms",
                    "main_path_share": "percentunit",
                },
            ),
            12,
            10,
        ),
    ]
    p += [
        L.place(
            series(
                "k.root RTT: this line and other lines of the ISP (RIPE Atlas)",
                """
                SELECT date_add('hour', hour, CAST(date_parse(dt, '%Y-%m-%d') AS timestamp)) AS time,
                  'atlas probe ' || CAST(probe_id AS varchar) AS metric, p50 AS value
                FROM heimdall.atlas_ping
                WHERE dt BETWEEN $__rawTimeFrom('yyyy-MM-dd') AND $__rawTimeTo('yyyy-MM-dd') AND target = 'k-root'
                UNION ALL
                SELECT date_trunc('hour', CAST(from_unixtime(ts_ms / 1000.0) AS timestamp)) AS time,
                  '$device' AS metric, approx_percentile(rtt_ms, 0.5) AS value
                FROM heimdall.samples
                WHERE {R} AND kind = 'icmp' AND status = 'ok' AND service = 'k-root'
                GROUP BY 1, 2
                ORDER BY 1
                """,
                "ms",
                "Hourly median to k.root-servers.net from the other RIPE Atlas probes in the same ISP, next to "
                "this CPE. All lines rising together means an ISP-wide issue; this line alone, a local one. "
                "Atlas rows come from the daily analysis, so the current day is missing.",
            ),
            24,
            10,
        ),
        L.place(
            table(
                "Degraded hours: which part of the path",
                """
                WITH a AS (SELECT * FROM heimdall.daily_attribution WHERE {D}),
                top AS (
                  SELECT dt, hour, max_by(segment, added_ms) AS segment, max(added_ms) AS added_ms,
                    array_join(array_agg(segment || ' +' || CAST(round(added_ms, 1) AS varchar)), ', ') AS segments,
                    arbitrary(local_hour) AS local_hour
                  FROM a WHERE degraded GROUP BY dt, hour
                )
                SELECT dt AS day, local_hour, CASE segment WHEN 'wifi' THEN 'home Wi-Fi'
                    WHEN 'ext_hop' THEN 'extender Wi-Fi' WHEN 'backhaul' THEN 'extender backhaul'
                    WHEN 'access' THEN 'ISP access' WHEN 'beyond_isp' THEN 'beyond the ISP' ELSE segment END AS blame,
                  added_ms, segments
                FROM top ORDER BY dt DESC, added_ms DESC
                """,
                "From the daily analysis: hours (local time) where a part of the path was 30% and a few ms above "
                "its own day median, with the part that added the most named. segments lists every degraded part. "
                "Beyond the ISP, the daily summary uses the AWS control to tell the ISP's path from the services.",
                units={"added_ms": "ms"},
            ),
            24,
            8,
        ),
        L.place(
            budget_series(
                "Where the time goes, by day",
                """
                SELECT CAST(date_parse(dt, '%Y-%m-%d') AS timestamp) AS time,
                  CASE segment WHEN 'wifi' THEN 'home Wi-Fi' WHEN 'ext_hop' THEN 'extender Wi-Fi'
                    WHEN 'backhaul' THEN 'extender backhaul' WHEN 'access' THEN 'ISP access'
                    WHEN 'beyond_isp' THEN 'beyond the ISP' ELSE segment END AS metric,
                  arbitrary(baseline) AS value
                FROM heimdall.daily_attribution WHERE {D} GROUP BY 1, 2 ORDER BY 1
                """,
                "ms",
                "Each part's median over the day: where a typical connection's round trip is spent. The home "
                "Wi-Fi and the extender's Wi-Fi are different clients, so the parts do not add up.",
            ),
            24,
            8,
        ),
        L.place(
            table(
                "Outage events from IODA",
                """
                SELECT entity, datasource, method, score,
                  CAST(from_unixtime(start_s) AS timestamp) AS start_time,
                  CAST(from_unixtime(end_s) AS timestamp) AS end_time
                FROM heimdall.external_events
                WHERE dt BETWEEN $__rawTimeFrom('yyyy-MM-dd') AND $__rawTimeTo('yyyy-MM-dd')
                ORDER BY start_s DESC
                """,
                "Outages IODA (Georgia Tech) detected for the ISP's AS and the country, from active probing, "
                "BGP and darknet traffic.",
            ),
            24,
            6,
        ),
    ]
    d = dashboard("heimdall-daily", "heimdall / daily analysis", p, [LAN_DEVICE])
    d["time"] = {"from": "now-7d", "to": "now"}
    return d


# LAN client connections seen by the CPE's flow collector. lan is the client's
# reply time to the server's SYN-ACK, wan the server's answer to the SYN.
# QUIC LAN times include the client's handshake processing, so LAN panels use
# TCP only.
FLOWS = """
SELECT ts_ms, {B} AS time, service, category,
  json_extract_scalar(extra, '$.client') AS client,
  coalesce(json_extract_scalar(extra, '$.node'), 'cpe') AS node,
  json_extract_scalar(extra, '$.medium') AS medium,
  json_extract_scalar(extra, '$.band') AS band,
  json_extract_scalar(extra, '$.proto') AS proto,
  CAST(json_extract_scalar(extra, '$.lan_ms') AS double) AS lan,
  CAST(json_extract_scalar(extra, '$.wan_ms') AS double) AS wan,
  CAST(json_extract_scalar(extra, '$.rssi') AS integer) AS rssi,
  status
FROM heimdall.samples
WHERE {R} AND kind = 'flow'
"""
# The clients with connections in the range, by display name. The Athena
# data source takes a variable's first column as its value, so the panels
# turn the name back into the client ID with SEL.
CLIENT = var(
    "client",
    """
    WITH {NM}
    SELECT DISTINCT coalesce(nm.label, json_extract_scalar(extra, '$.client')) AS client
    FROM heimdall.samples LEFT JOIN nm ON nm.client = json_extract_scalar(extra, '$.client')
    WHERE {R} AND kind = 'flow' ORDER BY 1
    """,
)
CLIENT_DEVICE = var(
    "clientdev",
    "SELECT DISTINCT device FROM heimdall.samples WHERE dt BETWEEN $__rawTimeFrom('yyyy-MM-dd') AND $__rawTimeTo('yyyy-MM-dd')"
    " AND kind = 'tcp' AND target_id LIKE 'client/%' ORDER BY 1",
    "client device",
)
# The client device's own TCP connects, matched with the CPE's record of
# the same connection by the client's address and port within a few
# seconds.
MATCHED = """
WITH c AS (
  SELECT ts_ms, service, rtt_ms AS client_ms,
    json_extract_scalar(extra, '$.local_ip') AS ip,
    CAST(json_extract_scalar(extra, '$.local_port') AS integer) AS port
  FROM heimdall.samples
  WHERE device = '$clientdev' AND {RA} AND kind = 'tcp' AND target_id LIKE 'client/%' AND status = 'ok'
    AND target_id <> 'client/gateway-tcp'
),
f AS (
  SELECT ts_ms,
    json_extract_scalar(extra, '$.client_ip') AS ip,
    CAST(json_extract_scalar(extra, '$.client_port') AS integer) AS port,
    CAST(json_extract_scalar(extra, '$.wan_ms') AS double) AS wan,
    CAST(json_extract_scalar(extra, '$.lan_ms') AS double) AS lan
  FROM heimdall.samples
  WHERE {R} AND kind = 'flow' AND status = 'ok' AND json_extract_scalar(extra, '$.proto') = 'tcp'
),
m AS (
  SELECT c.ts_ms, c.service, c.client_ms, f.wan, f.lan
  FROM c JOIN f ON c.ip = f.ip AND c.port = f.port AND abs(c.ts_ms - f.ts_ms) < 5000
)
"""


def clients() -> dict[str, Any]:
    L = Layout()
    p = [L.row("Connections of LAN clients (passive, every TCP and QUIC handshake)")]
    p += [
        L.place(
            table(
                "Clients over the range",
                """
                WITH {NM}, f AS ({FLOWS})
                SELECT coalesce(arbitrary(nm.label), f.client) AS name, f.client AS client, arbitrary(node) AS node,
                  arbitrary(medium) AS medium, arbitrary(band) AS band, count(*) AS flows,
                  approx_percentile(lan, 0.5) FILTER (WHERE proto = 'tcp' AND status = 'ok') AS lan_p50,
                  approx_percentile(lan, 0.9) FILTER (WHERE proto = 'tcp' AND status = 'ok') AS lan_p90,
                  approx_percentile(wan, 0.5) FILTER (WHERE status = 'ok') AS wan_p50,
                  100.0 * count_if(status = 'timeout') / count(*) AS unanswered,
                  avg(rssi) AS rssi
                FROM f LEFT JOIN nm ON nm.client = f.client GROUP BY f.client ORDER BY flows DESC
                """,
                "lan is the client's reply time to the server's SYN-ACK, measured at the CPE: the Wi-Fi or "
                "Ethernet round trip plus the client's own delay. wan is SYN to SYN-ACK. unanswered are SYNs "
                "the server never answered.",
                units={"lan_p50": "ms", "lan_p90": "ms", "wan_p50": "ms", "unanswered": "percent", "rssi": "dBm"},
            ),
            24,
            8,
        ),
        L.place(
            series(
                "LAN round trip p50 by client (TCP)",
                """
                WITH {NM}, f AS ({FLOWS})
                SELECT time, coalesce(nm.label, f.client) || ' ' || node AS metric, approx_percentile(lan, 0.5) AS value
                FROM f LEFT JOIN nm ON nm.client = f.client WHERE proto = 'tcp' AND status = 'ok' GROUP BY 1, 2 ORDER BY 1
                """,
                "ms",
            ),
            12,
            9,
        ),
        L.place(
            series(
                "WAN round trip p50 by client",
                """
                WITH {NM}, f AS ({FLOWS})
                SELECT time, coalesce(nm.label, f.client) || ' ' || node AS metric, approx_percentile(wan, 0.5) AS value
                FROM f LEFT JOIN nm ON nm.client = f.client WHERE status = 'ok' GROUP BY 1, 2 ORDER BY 1
                """,
                "ms",
            ),
            12,
            9,
        ),
    ]
    p.append(L.row("One client: $client"))
    p += [
        L.place(
            series(
                "LAN, WAN and LAN ping of $client",
                """
                WITH {NM}, {SEL}, f AS ({FLOWS})
                SELECT time, 'lan (tcp handshake)' AS metric, approx_percentile(lan, 0.5) AS value
                FROM f WHERE client = (SELECT id FROM sel) AND proto = 'tcp' AND status = 'ok' GROUP BY 1, 2
                UNION ALL
                SELECT time, 'wan (tcp handshake)', approx_percentile(wan, 0.5)
                FROM f WHERE client = (SELECT id FROM sel) AND status = 'ok' GROUP BY 1, 2
                UNION ALL
                SELECT {B}, 'lan ping (best of burst)', approx_percentile(rtt_ms, 0.5)
                FROM heimdall.samples
                WHERE {R} AND kind = 'lan' AND status = 'ok' AND target_id = 'lan/' || (SELECT id FROM sel) GROUP BY 1, 2
                UNION ALL
                SELECT {B}, 'lan ping (first of burst)',
                  approx_percentile(CAST(json_extract_scalar(extra, '$.burst_ms[0]') AS double), 0.5)
                FROM heimdall.samples WHERE {R} AND kind = 'lan' AND target_id = 'lan/' || (SELECT id FROM sel) GROUP BY 1, 2
                ORDER BY 1
                """,
                "ms",
                "The first echo of a burst waits for a client in power save to wake for a beacon; the rest show "
                "the awake round trip.",
            ),
            12,
            9,
        ),
        L.place(
            table(
                "Services of $client",
                """
                WITH {NM}, {SEL}, f AS ({FLOWS})
                SELECT category, service, count(*) AS flows,
                  approx_percentile(wan, 0.5) FILTER (WHERE status = 'ok') AS wan_p50,
                  approx_percentile(wan, 0.9) FILTER (WHERE status = 'ok') AS wan_p90,
                  approx_percentile(lan, 0.5) FILTER (WHERE proto = 'tcp' AND status = 'ok') AS lan_p50,
                  count_if(status = 'timeout') AS unanswered
                FROM f WHERE client = (SELECT id FROM sel) GROUP BY 1, 2 ORDER BY flows DESC
                """,
                units={"wan_p50": "ms", "wan_p90": "ms", "lan_p50": "ms"},
            ),
            12,
            9,
        ),
    ]
    p.append(L.row("Wi-Fi"))
    p += [
        L.place(
            series(
                "Signal (RSSI) by client",
                """
                WITH {NM}
                SELECT {B} AS time, coalesce(nm.label, json_extract_scalar(extra, '$.client')) || ' '
                  || json_extract_scalar(extra, '$.node') || ' ' || json_extract_scalar(extra, '$.band') AS metric,
                  avg(CAST(json_extract_scalar(extra, '$.rssi') AS double)) AS value
                FROM heimdall.samples LEFT JOIN nm ON nm.client = json_extract_scalar(extra, '$.client')
                WHERE {R} AND kind = 'wifi_sta' AND json_extract_scalar(extra, '$.rssi') IS NOT NULL
                GROUP BY 1, 2 ORDER BY 1
                """,
                "dBm",
                "Clients of the CPE come from wl; clients of mesh extenders from the EasyMesh topology.",
                min0=False,
            ),
            12,
            9,
        ),
        L.place(
            series(
                "Transmit retries to clients of the CPE",
                """
                WITH {NM}
                SELECT {B} AS time, coalesce(nm.label, json_extract_scalar(extra, '$.client')) AS metric,
                  100.0 * sum(CAST(json_extract_scalar(extra, '$.tx_retries') AS double))
                    / nullif(sum(CAST(json_extract_scalar(extra, '$.tx_sent') AS double)), 0) AS value
                FROM heimdall.samples LEFT JOIN nm ON nm.client = json_extract_scalar(extra, '$.client')
                WHERE {R} AND kind = 'wifi_sta' AND json_extract_scalar(extra, '$.source') = 'wl'
                GROUP BY 1, 2 ORDER BY 1
                """,
                "percent",
            ),
            12,
            9,
        ),
        L.place(
            series(
                "Radio airtime",
                """
                SELECT {B} AS time, json_extract_scalar(extra, '$.band') || ' ' || m.name AS metric, avg(m.v) AS value
                FROM heimdall.samples
                CROSS JOIN UNNEST(
                  ARRAY['busy', 'obss', 'inbss', 'tx'],
                  ARRAY[CAST(json_extract_scalar(extra, '$.chanim_busy') AS double),
                        CAST(json_extract_scalar(extra, '$.chanim_obss') AS double),
                        CAST(json_extract_scalar(extra, '$.chanim_inbss') AS double),
                        CAST(json_extract_scalar(extra, '$.chanim_tx') AS double)]) AS m(name, v)
                WHERE {R} AND kind = 'wifi_radio'
                GROUP BY 1, 2 ORDER BY 1
                """,
                "percent",
                "busy: channel busy; obss: neighbouring networks; inbss: this network's clients; tx: the CPE "
                "transmitting.",
            ),
            12,
            9,
        ),
        L.place(
            series(
                "PHY rate to clients",
                """
                WITH {NM}
                SELECT {B} AS time, coalesce(nm.label, json_extract_scalar(extra, '$.client')) || ' '
                  || json_extract_scalar(extra, '$.node') AS metric,
                  avg(CAST(json_extract_scalar(extra, '$.tx_rate_mbps') AS double)) AS value
                FROM heimdall.samples LEFT JOIN nm ON nm.client = json_extract_scalar(extra, '$.client')
                WHERE {R} AND kind = 'wifi_sta'
                GROUP BY 1, 2 ORDER BY 1
                """,
                "Mbits",
            ),
            12,
            9,
        ),
        L.place(
            table(
                "Wi-Fi events",
                """
                WITH {NM}
                SELECT CAST(from_unixtime(ts_ms / 1000.0) AS timestamp) AS time,
                  json_extract_scalar(extra, '$.event') AS event,
                  coalesce(nm.label, json_extract_scalar(extra, '$.client')) AS client,
                  json_extract_scalar(extra, '$.node') AS node, json_extract_scalar(extra, '$.band') AS band,
                  coalesce(json_extract_scalar(extra, '$.from'), json_extract_scalar(extra, '$.prev_chanspec')) AS before,
                  json_extract_scalar(extra, '$.chanspec') AS chanspec
                FROM heimdall.samples LEFT JOIN nm ON nm.client = json_extract_scalar(extra, '$.client')
                WHERE {R} AND kind = 'event' AND json_extract_scalar(extra, '$.event') LIKE 'wifi\\_%' ESCAPE '\\'
                ORDER BY ts_ms DESC LIMIT 200
                """,
            ),
            24,
            8,
        ),
    ]
    p.append(L.row("Cross-check with a client device ($clientdev)"))
    p += [
        L.place(
            series(
                "Connect time: client vs CPE split",
                """
                {M}
                SELECT {B} AS time, 'client connect' AS metric, approx_percentile(client_ms, 0.5) AS value FROM m GROUP BY 1, 2
                UNION ALL SELECT {B}, 'cpe wan + lan', approx_percentile(wan + lan, 0.5) FROM m GROUP BY 1, 2
                UNION ALL SELECT {B}, 'cpe wan', approx_percentile(wan, 0.5) FROM m GROUP BY 1, 2
                UNION ALL SELECT {B}, 'cpe lan', approx_percentile(lan, 0.5) FROM m GROUP BY 1, 2
                ORDER BY 1
                """,
                "ms",
                "The client device's TCP connects and the CPE's record of the same connections.",
            ),
            12,
            9,
        ),
        L.place(
            table(
                "Client vs CPE by service",
                """
                {M}
                SELECT service, count(*) AS matched,
                  approx_percentile(client_ms, 0.5) AS client_p50,
                  approx_percentile(wan, 0.5) AS cpe_wan_p50,
                  approx_percentile(lan, 0.5) AS cpe_lan_p50,
                  approx_percentile(client_ms - wan - lan, 0.5) AS gap_p50
                FROM m GROUP BY 1 ORDER BY 1
                """,
                "gap is what the client sees beyond the CPE's split: its own network stack and the parts of the "
                "LAN path the handshake does not cover.",
                units={"client_p50": "ms", "cpe_wan_p50": "ms", "cpe_lan_p50": "ms", "gap_p50": "ms"},
            ),
            12,
            9,
        ),
        L.place(
            series(
                "Client to CPE: client's view vs CPE's view",
                """
                SELECT {B} AS time, 'client icmp to cpe' AS metric, approx_percentile(rtt_ms, 0.5) AS value
                FROM heimdall.samples WHERE device = '$clientdev' AND {RA} AND target_id = 'client/gateway' AND status = 'ok'
                GROUP BY 1, 2
                UNION ALL
                SELECT {B}, 'client tcp to cpe', approx_percentile(rtt_ms, 0.5)
                FROM heimdall.samples WHERE device = '$clientdev' AND {RA} AND target_id = 'client/gateway-tcp' AND status = 'ok'
                GROUP BY 1, 2
                UNION ALL
                SELECT {B}, 'cpe lan (handshakes of client)', approx_percentile(lan, 0.5)
                FROM ({M} SELECT ts_ms, lan FROM m) GROUP BY 1, 2
                ORDER BY 1
                """,
                "ms",
            ),
            12,
            9,
        ),
        L.place(
            series(
                "Client's own Wi-Fi reading",
                """
                SELECT {B} AS time, m.name AS metric, avg(m.v) AS value
                FROM heimdall.samples
                CROSS JOIN UNNEST(
                  ARRAY['rssi', 'noise'],
                  ARRAY[CAST(json_extract_scalar(extra, '$.rssi') AS double),
                        CAST(json_extract_scalar(extra, '$.noise') AS double)]) AS m(name, v)
                WHERE device = '$clientdev' AND {RA} AND kind = 'wifi_sta' AND target_id = 'client/wifi'
                GROUP BY 1, 2 ORDER BY 1
                """,
                "dBm",
                min0=False,
            ),
            12,
            9,
        ),
    ]
    d = dashboard("heimdall-clients", "heimdall / LAN clients", p, [LAN_DEVICE, CLIENT, CLIENT_DEVICE])
    d["time"] = {"from": "now-3h", "to": "now"}
    return d


# Per LAN client over the range: where it is attached, the LAN part of its
# TCP handshakes, its ping, the WAN part of its connections and its signal.
# Clients that opened no connection still appear through their pings. The
# mesh extenders themselves answer pings like clients and are left out; x
# lists the extenders from the mesh topology and any a client was seen
# behind. The extender's own probe ($ext) adds, for its clients, the hop
# between the extender and the client (e: the client's part of the
# handshakes the extender bridges) and the signal the extender receives
# (ew); the CPE's LAN figure minus the hop is the backhaul and the
# extender. Queries are collapsed onto one line, so they hold no SQL
# comments.
TOPO_CLIENTS = """
{NM},
f AS (
  SELECT ts_ms, json_extract_scalar(extra, '$.client') AS client,
    coalesce(json_extract_scalar(extra, '$.node'), 'cpe') AS node,
    json_extract_scalar(extra, '$.medium') AS medium, json_extract_scalar(extra, '$.band') AS band,
    json_extract_scalar(extra, '$.proto') AS proto, status,
    CAST(json_extract_scalar(extra, '$.lan_ms') AS double) AS lan,
    CAST(json_extract_scalar(extra, '$.wan_ms') AS double) AS wan
  FROM heimdall.samples WHERE {R} AND kind = 'flow'
),
fc AS (
  SELECT client, max_by(node, ts_ms) AS node, max_by(medium, ts_ms) AS medium, max_by(band, ts_ms) AS band,
    count(*) AS flows,
    count(lan) FILTER (WHERE proto = 'tcp' AND status = 'ok') AS lann,
    approx_percentile(lan, 0.5) FILTER (WHERE proto = 'tcp' AND status = 'ok') AS lan50,
    approx_percentile(lan, 0.9) FILTER (WHERE proto = 'tcp' AND status = 'ok') AS lan90,
    approx_percentile(wan, 0.5) FILTER (WHERE status = 'ok') AS wan50
  FROM f GROUP BY 1
),
e AS (
  SELECT json_extract_scalar(extra, '$.client') AS client,
    max_by(json_extract_scalar(extra, '$.node'), ts_ms) AS node,
    max_by(json_extract_scalar(extra, '$.medium'), ts_ms) AS medium,
    max_by(json_extract_scalar(extra, '$.band'), ts_ms) AS band,
    count(*) FILTER (WHERE json_extract_scalar(extra, '$.lan_ms') IS NOT NULL
      AND json_extract_scalar(extra, '$.proto') = 'tcp' AND status = 'ok') AS hopn,
    approx_percentile(CAST(json_extract_scalar(extra, '$.lan_ms') AS double), 0.5)
      FILTER (WHERE json_extract_scalar(extra, '$.proto') = 'tcp' AND status = 'ok') AS hop50,
    approx_percentile(CAST(json_extract_scalar(extra, '$.lan_ms') AS double), 0.9)
      FILTER (WHERE json_extract_scalar(extra, '$.proto') = 'tcp' AND status = 'ok') AS hop90
  FROM heimdall.samples WHERE {RE} AND kind = 'flow' GROUP BY 1
),
ew AS (
  SELECT json_extract_scalar(extra, '$.client') AS client,
    max_by(json_extract_scalar(extra, '$.node'), ts_ms) AS node,
    max_by(json_extract_scalar(extra, '$.band'), ts_ms) AS band,
    avg(CAST(json_extract_scalar(extra, '$.rssi') AS double)) AS rssi
  FROM heimdall.samples WHERE {RE} AND kind = 'wifi_sta' GROUP BY 1
),
eu AS (
  SELECT approx_percentile(rtt_ms, 0.5) AS v FROM heimdall.samples
  WHERE {RE} AND kind = 'icmp' AND target_id = 'uplink' AND status = 'ok'
),
p AS (
  SELECT substr(target_id, 5) AS client, max_by(dst_ip, ts_ms) AS ip,
    max_by(coalesce(json_extract_scalar(extra, '$.node'), 'cpe'), ts_ms) AS node,
    max_by(json_extract_scalar(extra, '$.medium'), ts_ms) AS medium,
    max_by(json_extract_scalar(extra, '$.band'), ts_ms) AS band,
    approx_percentile(rtt_ms, 0.5) FILTER (WHERE status = 'ok') AS ping50
  FROM heimdall.samples WHERE {R} AND kind = 'lan' GROUP BY 1
),
w AS (
  SELECT json_extract_scalar(extra, '$.client') AS client,
    avg(CAST(json_extract_scalar(extra, '$.rssi') AS double)) AS rssi,
    100.0 * sum(CAST(json_extract_scalar(extra, '$.tx_retries') AS double))
      / nullif(sum(CAST(json_extract_scalar(extra, '$.tx_sent') AS double)), 0) AS retry_pct
  FROM heimdall.samples WHERE {R} AND kind = 'wifi_sta' GROUP BY 1
),
m AS (
  SELECT json_extract_scalar(extra, '$.node') AS node, max_by(dst_ip, ts_ms) AS ip,
    max_by(json_extract_scalar(extra, '$.node_mode'), ts_ms) AS mode,
    max_by(json_extract_scalar(extra, '$.backhaul'), ts_ms) AS backhaul,
    max_by(json_extract_scalar(extra, '$.parent'), ts_ms) AS parent
  FROM heimdall.samples WHERE {R} AND kind = 'mesh_node' GROUP BY 1
),
c AS (
  SELECT k.client, nm.label AS name,
    coalesce(fc.node, p.node, e.node, ew.node, 'cpe') AS node,
    coalesce(fc.medium, p.medium, e.medium) AS medium, coalesce(ew.band, fc.band, p.band, e.band) AS band,
    coalesce(fc.flows, 0) AS flows, coalesce(fc.lann, 0) AS lann, fc.lan50, fc.lan90, fc.wan50, p.ping50,
    coalesce(ew.rssi, w.rssi) AS rssi, w.retry_pct, coalesce(e.hopn, 0) AS hopn, e.hop50, e.hop90
  FROM (SELECT client FROM fc UNION SELECT client FROM p UNION SELECT client FROM e) k
  LEFT JOIN fc ON fc.client = k.client LEFT JOIN p ON p.client = k.client LEFT JOIN w ON w.client = k.client
  LEFT JOIN e ON e.client = k.client LEFT JOIN ew ON ew.client = k.client LEFT JOIN nm ON nm.client = k.client
  WHERE k.client IS NOT NULL AND coalesce(p.ip, '') NOT IN (SELECT coalesce(ip, '') FROM m)
),
x AS (
  SELECT n.node, m.ip, m.backhaul
  FROM (SELECT node FROM m WHERE mode = 'AP' UNION SELECT node FROM c WHERE node <> 'cpe') n
  LEFT JOIN m ON m.node = n.node
)
"""
# A node or edge stat in milliseconds, or "" when unknown.
MS = "CASE WHEN {v} IS NULL THEN '' ELSE format('%.1f ms', {v}) END"
# What a client's colour is judged by: the p90 of its handshakes' LAN part
# when it opened at least LAN_MIN_FLOWS connections, else its ping. A p90
# of one or two connections is one sample, and a device that sleeps
# between rare connections (a smart plug) answers the first one late.
LAN_MIN_FLOWS = 5
LAN_METRIC = f"coalesce(CASE WHEN lann >= {LAN_MIN_FLOWS} THEN lan90 END, ping50)"
# Green, yellow, red by LAN_METRIC: a few ms is normal for Wi-Fi, tens of
# ms is not; grey without enough data.
LAN_COLOR = (
    f"CASE WHEN {LAN_METRIC} IS NULL THEN '#8e8e8e' WHEN {LAN_METRIC} < 10 THEN '#73bf69'"
    f" WHEN {LAN_METRIC} < 30 THEN '#fade2a' ELSE '#f2495c' END"
)


def ms(v: str) -> str:
    return MS.format(v=v)


# Plain names of the probe's causes for home incidents; the notifier's
# CAUSES has the longer Slack wording.
CAUSE_TEXT = (
    "CASE cause WHEN 'roaming' THEN 'moved between access points' WHEN 'weak_signal' THEN 'weak Wi-Fi signal' "
    "WHEN 'retransmissions' THEN 'Wi-Fi retransmissions' WHEN 'radio_retransmissions' THEN 'busy or noisy radio' "
    "WHEN 'channel_busy' THEN 'busy Wi-Fi channel' WHEN 'extender' THEN 'behind the extender' "
    "WHEN 'weak_link_extender' THEN 'slow link to the extender' WHEN 'extender_wide' THEN 'extender, several clients' "
    "WHEN 'wired_lan' THEN 'wired LAN' WHEN 'lan_latency' THEN 'LAN path, no Wi-Fi sign' "
    "WHEN 'lan_wide' THEN 'whole home network' WHEN 'backhaul' THEN 'extender backhaul' ELSE cause END"
)
# The kind of an extender's link to the CPE, from the mesh topology's media
# type. Only the kind: the WX5600 reports "IEEE 802.3u" (Fast Ethernet)
# for a link that runs at 2.5 Gbit/s.
BACKHAUL = (
    "CASE WHEN backhaul LIKE 'IEEE 802.3%' THEN 'wired backhaul' WHEN backhaul LIKE 'IEEE 802.11%' "
    "THEN 'Wi-Fi backhaul' ELSE 'backhaul' END"
)


# Where each node of the topology is drawn. The CPE, the ISP and the
# internet form one row, left to right, with the categories the CPE
# measures in a row above the internet. The CPE's own clients sit in a row
# under the CPE, and each mesh extender in the same row, under the ISP or,
# when the CPE's clients reach that far, just right of the last of them.
# An extender's clients sit in a row under it. The node graph's layered
# layout only runs left to right, so the positions are fixed here (fixedx,
# fixedy); every node needs one. The panel opens centred on (0, 0), so the
# whole drawing is moved to centre on it.
TOPO_X, TOPO_Y = 150, 170
# Services listed in a category node's details, one per row.
TOPO_SERVICES = 10


def _service_names() -> str:
    """A SQL expression that turns the service ID in `service` into the
    catalog's display name."""
    ids, names = [], []
    for line in (OUT.parent.parent / "catalog" / "targets.yaml").read_text().splitlines():
        s = line.strip()
        if s.startswith("- id: "):
            ids.append(s[6:].strip())
        elif s.startswith("name: ") and len(names) < len(ids):
            names.append(s[6:].strip().strip("'\""))
    cases = " ".join(f"WHEN '{i}' THEN '{n.replace(chr(39), chr(39) * 2)}'" for i, n in zip(ids, names, strict=False))
    return f"CASE service {cases} ELSE service END"


# The gap between the CPE, the ISP and the internet.
TOPO_GAP = 2 * TOPO_X
TOPO_POSITIONS = f"""
cc AS (
  SELECT 'client:' || client AS id,
    (row_number() OVER (ORDER BY coalesce(name, client)) - (count(*) OVER () + 1) / 2.0) * {TOPO_X} AS x
  FROM c WHERE node = 'cpe'
),
xn AS (
  SELECT 'node:' || node AS id, node,
    greatest({TOPO_GAP}.0, coalesce((SELECT max(x) FROM cc), 0.0) + {TOPO_X}) + (row_number() OVER (ORDER BY node) - 1)
      * {TOPO_GAP} AS x
  FROM x
),
raw AS (
  SELECT 'cpe' AS id, 0.0 AS x, 0.0 AS y
  UNION ALL SELECT 'isp', {TOPO_GAP}.0, 0.0
  UNION ALL SELECT 'internet', {2 * TOPO_GAP}.0, 0.0
  UNION ALL SELECT 'cat:' || category,
    {2 * TOPO_GAP} + (row_number() OVER (ORDER BY category) - (count(*) OVER () + 1) / 2.0) * {TOPO_X}, -{TOPO_Y}.0
  FROM cat
  UNION ALL SELECT id, x, {TOPO_Y}.0 FROM cc
  UNION ALL SELECT id, x, {TOPO_Y}.0 FROM xn
  UNION ALL SELECT 'client:' || c.client,
    xn.x + (row_number() OVER (PARTITION BY c.node ORDER BY coalesce(c.name, c.client))
      - (count(*) OVER (PARTITION BY c.node) + 1) / 2.0) * {TOPO_X},
    {2 * TOPO_Y}.0
  FROM c JOIN xn ON xn.node = c.node
),
pos AS (
  SELECT id, x - (max(x) OVER () + min(x) OVER ()) / 2 AS x, y - (max(y) OVER () + min(y) OVER ()) / 2 AS y
  FROM raw
)
"""


def topology() -> dict[str, Any]:
    # Nodes and edges come from one query, as rows tagged with the frame
    # they belong to, and the panel splits them. With two queries the edges
    # could arrive first, and the node graph would draw the nodes it derives
    # from them with its own layout until the positioned nodes arrived.
    details = ", ".join(f"element_at(svcs, {i}) AS detail__{i}" for i in range(1, TOPO_SERVICES + 1))
    no_details = ", ".join(f"CAST(NULL AS varchar) AS detail__{i}" for i in range(1, TOPO_SERVICES + 1))
    graph_sql = f"""
    WITH {TOPO_CLIENTS},
    isp AS (
      SELECT approx_percentile(rtt_ms, 0.5) AS v FROM heimdall.samples
      WHERE {{R}} AND kind = 'icmp' AND status = 'ok' AND target_id = 'isp-hop1'
    ),
    cs AS (
      SELECT category, service, approx_percentile(rtt_ms, 0.5) AS v
      FROM heimdall.samples WHERE {{R}} AND kind = 'tcp' AND status = 'ok' AND {{S}} AND target_id NOT LIKE 'client/%'
      GROUP BY 1, 2
    ),
    cat AS (
      SELECT category, approx_percentile(rtt_ms, 0.5) AS v, count(DISTINCT service) AS services
      FROM heimdall.samples WHERE {{R}} AND kind = 'tcp' AND status = 'ok' AND {{S}} AND target_id NOT LIKE 'client/%'
      GROUP BY 1
    ),
    cl AS (
      SELECT category, array_agg(format('%s · %.0f ms', {_service_names()}, v) ORDER BY v DESC) AS svcs
      FROM cs GROUP BY 1
    ),
    {TOPO_POSITIONS},
    ext AS (
      SELECT x.node, x.backhaul, approx_percentile(s.rtt_ms, 0.5) AS v
      FROM x LEFT JOIN heimdall.samples s ON s.dst_ip = x.ip AND {{R}} AND s.kind = 'lan' AND s.status = 'ok'
      GROUP BY 1, 2
    ),
    n AS (
    SELECT 'internet' AS id, 'Internet' AS title, 'servers clients reached' AS subtitle,
      {ms("(SELECT approx_percentile(wan50, 0.5) FROM c)")} AS mainstat, 'clients, WAN p50' AS secondarystat,
      '#5794f2' AS color
    UNION ALL
    SELECT 'isp', 'ISP', 'first hop', {ms("v")}, 'CPE to ISP', '#5794f2' FROM isp
    UNION ALL
    SELECT 'cpe', 'CPE', 'router', format('%d clients', (SELECT count(*) FROM c)), '', '#b877d9'
    UNION ALL
    SELECT 'node:' || node, node, 'mesh extender', format('%d clients', (SELECT count(*) FROM c WHERE c.node = x.node)),
      {BACKHAUL}, '#b877d9' FROM x
    UNION ALL
    SELECT 'client:' || client, coalesce(name, client),
      concat_ws(' ', coalesce(band, medium), CASE WHEN rssi IS NULL THEN NULL ELSE format('%.0f dBm', rssi) END),
      {ms("coalesce(lan50, ping50)")}, CASE WHEN wan50 IS NULL THEN '' ELSE 'wan ' || {ms("wan50")} END,
      {LAN_COLOR}
    FROM c
    UNION ALL
    SELECT 'cat:' || category, category, format('%d services, CPE probe', services), {ms("v")}, 'TCP connect p50',
      '#ff9830' FROM cat
    ),
    ed AS (
    SELECT 'e:' || client AS id, 'client:' || client AS source,
      CASE WHEN node = 'cpe' THEN 'cpe' ELSE 'node:' || node END AS target,
      CASE WHEN hop50 IS NOT NULL AND node <> 'cpe' THEN 'hop ' || {ms("hop50")}
        ELSE {ms("coalesce(lan50, ping50)")} END AS mainstat,
      CASE WHEN hop90 IS NOT NULL AND node <> 'cpe' THEN 'hop p90 ' || {ms("hop90")}
        WHEN lan90 IS NOT NULL THEN 'p90 ' || {ms("lan90")} ELSE '' END AS secondarystat,
      {LAN_COLOR} AS color
    FROM c
    UNION ALL
    SELECT 'e:node:' || node, 'node:' || node, 'cpe',
      {ms("coalesce(CASE WHEN node = (SELECT max(node) FROM ew) THEN (SELECT v FROM eu) END, v)")},
      {BACKHAUL}, '#b877d9' FROM ext
    UNION ALL
    SELECT 'e:isp', 'cpe', 'isp', {ms("v")}, 'first hop', '#5794f2' FROM isp
    UNION ALL
    SELECT 'e:internet', 'isp', 'internet', {ms("(SELECT approx_percentile(wan50, 0.5) FROM c)")},
      'clients, WAN p50', '#5794f2'
    UNION ALL
    SELECT 'e:cat:' || category, 'internet', 'cat:' || category, '', '', '#ff9830' FROM cat
    )
    SELECT 'nodes' AS frame, n.id, n.title, n.subtitle, n.mainstat, n.secondarystat, n.color,
      pos.x AS fixedx, pos.y AS fixedy, {details},
      CAST(NULL AS varchar) AS source, CAST(NULL AS varchar) AS target
    FROM n JOIN pos ON pos.id = n.id LEFT JOIN cl ON n.id = 'cat:' || cl.category
    UNION ALL
    SELECT 'edges', id, CAST(NULL AS varchar), CAST(NULL AS varchar), mainstat, secondarystat, color,
      CAST(NULL AS double), CAST(NULL AS double), {no_details}, source, target
    FROM ed
    """
    graph = {
        "type": "nodeGraph",
        "title": "Topology: clients to the CPE, the CPE to the internet",
        "description": "Client nodes show the LAN round trip measured at the CPE (p50 of their TCP handshakes, "
        "else their ping) and the WAN part of their connections. They are coloured by LAN p90 once a client "
        f"opened {LAN_MIN_FLOWS} connections, else by its ping: green under 10 ms, yellow under 30 ms, red above, "
        "grey without data. A client behind an extender that runs the probe has its own hop on its edge: the "
        "round trip between the extender and the client alone. The extender's edge to the CPE is the backhaul, "
        "the extender's ping to the CPE (else the CPE's ping to the extender). Category nodes show the CPE's own "
        "TCP probes.",
        "datasource": DS,
        "options": {"layoutAlgorithm": "layered", "nodes": {}, "edges": {}, "zoomMode": "cooperative"},
        "targets": [target(graph_sql, TABLE, "graph")],
        "transformations": [
            # One frame per value of `frame`, named "nodes" and "edges".
            {
                "id": "partitionByValues",
                "options": {"fields": ["frame"], "keepFields": False, "naming": {"asLabels": False}},
            },
            # Each frame keeps only the columns it uses: a nodes frame with a
            # source column would be taken for edges. A column without a
            # value has no first non-null value; the allIsNull reducer does
            # not do here, since it counts only numbers and calls every text
            # column empty.
            {
                "id": "filterFields",
                "options": {
                    "exclude": {"id": "byValue", "options": {"reducer": "firstNotNull", "op": "eq", "value": None}}
                },
            },
        ],
        # Each service of a category node is one row of its details.
        "fieldConfig": {
            "defaults": {},
            "overrides": [
                {
                    "matcher": {"id": "byName", "options": f"detail__{i}"},
                    "properties": [{"id": "displayName", "value": str(i)}],
                }
                for i in range(1, TOPO_SERVICES + 1)
            ],
        },
    }
    path = series(
        "Latency by part of the path",
        """
        SELECT {B} AS time, 'home Wi-Fi (CPE clients)' AS metric,
          approx_percentile(CAST(json_extract_scalar(extra, '$.lan_ms') AS double), 0.5) AS value
        FROM heimdall.samples
        WHERE {R} AND kind = 'flow' AND status = 'ok' AND json_extract_scalar(extra, '$.proto') = 'tcp'
          AND coalesce(json_extract_scalar(extra, '$.node'), 'cpe') = 'cpe'
        GROUP BY 1, 2
        UNION ALL
        SELECT {B}, 'extender Wi-Fi (its clients)',
          approx_percentile(CAST(json_extract_scalar(extra, '$.lan_ms') AS double), 0.5)
        FROM heimdall.samples
        WHERE {RE} AND kind = 'flow' AND status = 'ok' AND json_extract_scalar(extra, '$.proto') = 'tcp'
        GROUP BY 1, 2
        UNION ALL
        SELECT {B}, 'extender backhaul', approx_percentile(rtt_ms, 0.5)
        FROM heimdall.samples WHERE {RE} AND kind = 'icmp' AND target_id = 'uplink' AND status = 'ok'
        GROUP BY 1, 2
        UNION ALL
        SELECT {B}, 'ISP access', approx_percentile(rtt_ms, 0.5)
        FROM heimdall.samples WHERE {R} AND kind = 'icmp' AND target_id = 'isp-hop1' AND status = 'ok'
        GROUP BY 1, 2
        UNION ALL
        SELECT {B}, 'servers (WAN part)', approx_percentile(CAST(json_extract_scalar(extra, '$.wan_ms') AS double), 0.5)
        FROM heimdall.samples WHERE {R} AND kind = 'flow' AND status = 'ok'
        GROUP BY 1, 2
        ORDER BY 1
        """,
        "ms",
        "Medians over time of each part of a connection's round trip, in path order: the LAN part of the "
        "connections of the CPE's own clients, the extender's hop to its clients, the extender's ping to the "
        "CPE, the first hop into the ISP, and the servers' answer to the clients' connections (which includes "
        "the ISP access). The part that rises when things get slow is where the problem is.",
    )
    path["fieldConfig"]["defaults"]["custom"]["scaleDistribution"] = {"type": "log", "log": 10}
    L = Layout()
    p = [
        L.place(graph, 24, 22),
        L.place(path, 24, 9),
        L.place(
            table(
                "Clients",
                f"""
                WITH {TOPO_CLIENTS}
                SELECT coalesce(name, client) AS client, client AS id, node, coalesce(band, medium) AS link,
                  round(rssi) AS rssi, lan50 AS lan_p50, lan90 AS lan_p90, hop50 AS hop_p50, hop90 AS hop_p90,
                  ping50 AS ping_p50, wan50 AS wan_p50, coalesce(lan50, ping50) + wan50 AS total_p50, retry_pct,
                  flows
                FROM c ORDER BY flows DESC
                """,
                "lan: the client's reply to the server's SYN-ACK, measured at the CPE (Wi-Fi or Ethernet round "
                "trip, and for clients of an extender also the backhaul and the extender). hop: the same reply "
                "measured at the extender the client is attached to, which is the extender-to-client hop alone, "
                "so lan - hop is what the backhaul and the extender add. ping: the CPE's ping, best of a burst. "
                "wan: the server's answer to the client's SYN. total: what the client waits for a connection, "
                "about lan + wan. rssi is the signal the access point receives from the client.",
                units={
                    "rssi": "dBm",
                    "lan_p50": "ms",
                    "lan_p90": "ms",
                    "hop_p50": "ms",
                    "hop_p90": "ms",
                    "ping_p50": "ms",
                    "wan_p50": "ms",
                    "total_p50": "ms",
                    "retry_pct": "percent",
                },
            ),
            24,
            14,
        ),
    ]
    p.append(
        L.place(
            table(
                "Home network incidents",
                f"""
                WITH {{NM}},
                names AS (SELECT map_agg(client, label) AS mp FROM nm),
                e AS (
                  SELECT device, ts_ms, json_extract_scalar(extra, '$.event') AS ev,
                    json_extract_scalar(extra, '$.incident_id') AS id, json_extract_scalar(extra, '$.scope') AS scope,
                    json_extract_scalar(extra, '$.cause') AS cause,
                    CAST(json_extract(extra, '$.services') AS array(varchar)) AS services,
                    CAST(json_extract_scalar(extra, '$.duration_s') AS bigint) AS duration_s,
                    CAST(json_extract_scalar(extra, '$.started_ms') AS bigint) AS started_ms,
                    CAST(json_extract_scalar(extra, '$.ended_ms') AS bigint) AS ended_ms,
                    CAST(json_extract_scalar(extra, '$.confirmed') AS boolean) AS confirmed,
                    CAST(json_extract_scalar(extra, '$.targets[0].current_ms') AS double) AS cur,
                    CAST(json_extract_scalar(extra, '$.targets[0].baseline_ms') AS double) AS base
                  FROM heimdall.samples
                  WHERE {{RS}} AND kind = 'event' AND json_extract_scalar(extra, '$.event') LIKE 'incident\\_%' ESCAPE '\\'
                    AND json_extract_scalar(extra, '$.scope') IN ('client', 'home', 'backhaul')
                ),
                i AS (
                  SELECT id, arbitrary(device) AS device,
                    coalesce(min(started_ms), min(ts_ms) FILTER (WHERE ev = 'incident_start')) AS start_ms,
                    max(coalesce(ended_ms, ts_ms)) FILTER (WHERE ev = 'incident_end') AS end_ms,
                    arbitrary(scope) AS scope, max_by(cause, ts_ms) AS cause, max_by(services, ts_ms) AS services,
                    max_by(duration_s, ts_ms) FILTER (WHERE duration_s IS NOT NULL) AS duration_s,
                    bool_or(coalesce(confirmed, true)) AS confirmed,
                    max_by(cur, ts_ms) FILTER (WHERE cur IS NOT NULL) AS cur,
                    max_by(base, ts_ms) FILTER (WHERE base IS NOT NULL) AS base
                  FROM e GROUP BY id
                )
                SELECT CAST(from_unixtime(start_ms / 1000.0) AS timestamp) AS start_time,
                  CAST(from_unixtime(end_ms / 1000.0) AS timestamp) AS end_time,
                  coalesce(duration_s, CAST((to_unixtime(now()) * 1000 - start_ms) / 1000 AS bigint)) AS duration,
                  CASE WHEN device = '$ext' THEN 'extender' ELSE 'cpe' END AS seen_by, scope, {CAUSE_TEXT} AS cause,
                  array_join(transform(services, s -> coalesce(element_at(names.mp, s), s)), ', ') AS clients,
                  cur AS current_ms, base AS baseline_ms, confirmed
                FROM i CROSS JOIN names WHERE start_ms IS NOT NULL ORDER BY start_ms DESC LIMIT 50
                """,
                "Incidents of the home network, from the CPE's probe and the extender's: one client (its LAN round "
                "trip, or on the extender its hop), several clients at once (home), or the extender's backhaul to "
                "the CPE. Open incidents have no end time; their duration runs to now. Only confirmed incidents "
                "(narrow ones that lasted 10 minutes) go to Slack. current and baseline are the worst member's "
                "latency now and normally.",
                units={"duration": "s", "current_ms": "ms", "baseline_ms": "ms"},
            ),
            24,
            9,
        )
    )
    d = dashboard("heimdall-topology", "heimdall / topology", p, [LAN_DEVICE, EXT])
    d["time"] = {"from": "now-30m", "to": "now"}
    # Samples reach Athena through Firehose's 5-minute buffer, so a faster
    # refresh only repeats the same queries.
    d["refresh"] = "5m"
    return d


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, build in (
        ("overview", overview),
        ("service", service),
        ("network", network),
        ("daily", daily),
        ("clients", clients),
        ("topology", topology),
    ):
        (OUT / f"{name}.json").write_text(json.dumps(build(), indent=2) + "\n")


if __name__ == "__main__":
    main()
