"""Public measurements from outside heimdall that put a CPE's own results in
context.

* RIPE Atlas: the built-in pings to the root servers from the other Atlas
  probes in the same ISP. If those lines degrade at the same hours as the
  CPE, the cause is ISP-wide; if they do not, it is closer to the CPE.
* IODA (Georgia Tech): outage events detected for the ISP's AS and the
  country from active probing, BGP and darknet traffic.

Only public, unauthenticated APIs are used.
"""

from __future__ import annotations

import json
import logging
import statistics
import urllib.parse
import urllib.request
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from typing import Any

log = logging.getLogger()

ATLAS = "https://atlas.ripe.net/api/v2"
IODA = "https://api.ioda.inetintel.cc.gatech.edu/v2"
# Built-in Atlas measurements: ping to k.root-servers.net and
# f.root-servers.net from every probe, every 240 s.
ATLAS_PINGS = {"k-root": 1001, "f-root": 1004}

Fetch = Callable[[str], Any]


def http_json(url: str, timeout: float = 30) -> Any:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "heimdall-analytics (latency research)"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - fixed https URLs
        return json.load(r)


def _day_bounds(day: date) -> tuple[int, int]:
    start = datetime(day.year, day.month, day.day, tzinfo=UTC)
    return int(start.timestamp()), int((start + timedelta(days=1)).timestamp())


def atlas_probes(asn: int, fetch: Fetch = http_json) -> list[dict[str, Any]]:
    """Connected Atlas probes whose IPv4 address is in asn."""
    url = f"{ATLAS}/probes/?asn_v4={asn}&status=1&page_size=500&fields=id,is_anchor,geometry,address_v4"
    out = []
    while url:
        d = fetch(url)
        out += d.get("results") or []
        url = d.get("next")
    return out


def atlas_ping(day: date, asn: int, fetch: Fetch = http_json) -> list[dict[str, Any]]:
    """Hourly median of the per-result minimum RTT, and loss, of each Atlas
    probe in asn towards the root servers in ATLAS_PINGS."""
    probes = atlas_probes(asn, fetch)
    if not probes:
        return []
    ids = ",".join(str(p["id"]) for p in probes)
    start, stop = _day_bounds(day)
    out = []
    for target, msm in ATLAS_PINGS.items():
        q = urllib.parse.urlencode({"start": start, "stop": stop - 1, "probe_ids": ids, "format": "json"})
        try:
            results = fetch(f"{ATLAS}/measurements/{msm}/results/?{q}")
        except Exception as e:
            log.warning("atlas msm %s: %s", msm, e)
            continue
        by: dict[tuple[int, int], dict[str, list[float] | int]] = defaultdict(
            lambda: {"rtts": [], "sent": 0, "rcvd": 0}
        )
        for r in results:
            ts, prb = r.get("timestamp"), r.get("prb_id")
            if ts is None or prb is None:
                continue
            b = by[(prb, datetime.fromtimestamp(ts, UTC).hour)]
            b["sent"] += int(r.get("sent") or 0)
            b["rcvd"] += int(r.get("rcvd") or 0)
            rtt = r.get("min")
            if isinstance(rtt, int | float) and rtt > 0:
                b["rtts"].append(float(rtt))
        for (prb, hour), b in sorted(by.items()):
            rtts = b["rtts"]
            out.append(
                {
                    "probe_id": prb,
                    "asn": asn,
                    "target": target,
                    "msm_id": msm,
                    "hour": hour,
                    "p50": statistics.median(rtts) if rtts else None,
                    "min": min(rtts) if rtts else None,
                    "results": len(rtts),
                    "loss_pct": 100.0 * (1 - b["rcvd"] / b["sent"]) if b["sent"] else None,
                }
            )
    return out


def ioda_events(
    start_s: int, end_s: int, entities: list[tuple[str, str]], fetch: Fetch = http_json
) -> list[dict[str, Any]]:
    """IODA outage events overlapping [start_s, end_s) for (type, code)
    entities such as ("asn", "34984") or ("country", "TR")."""
    out = []
    for etype, code in entities:
        q = urllib.parse.urlencode(
            {"entityType": etype, "entityCode": code, "from": start_s, "until": end_s, "limit": 200}
        )
        try:
            d = fetch(f"{IODA}/outages/events?{q}")
        except Exception as e:
            log.warning("ioda %s/%s: %s", etype, code, e)
            continue
        for ev in d.get("data") or []:
            s = int(ev.get("start") or 0)
            out.append(
                {
                    "source": "ioda",
                    "entity": f"{etype}/{code}",
                    "start_s": s,
                    "end_s": s + int(ev.get("duration") or 0),
                    "datasource": ev.get("datasource"),
                    "method": ev.get("method"),
                    "score": ev.get("score"),
                }
            )
    return out


def ioda_day(day: date, entities: list[tuple[str, str]], fetch: Fetch = http_json) -> list[dict[str, Any]]:
    return ioda_events(*_day_bounds(day), entities, fetch)
