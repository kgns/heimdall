"""Incident notifier, invoked asynchronously by the ingest Lambda with the
incident events of a batch.

Probes detect incidents themselves (``incident_start``, ``incident_update``,
``incident_end`` events). The notifier keeps the open ones per device in
DynamoDB, and for an incident on a CPE checks whether the cloud control
probe has an open incident for the same services at the same time: if it
does, the problem is most likely on the service's side; if it does not, it
is in the access network or the ISP's path to the service. It then posts to
Slack when a webhook URL is stored in SSM.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from typing import Any

log = logging.getLogger()
log.setLevel(logging.INFO)

RETENTION_DAYS = 30
WEBHOOK_CACHE_SECONDS = 300
OPEN_MAX_AGE_S = 24 * 3600

CAUSES = {
    "access_network": "access network: the ISP hops or most services degraded together",
    "path": "this service's path or servers",
    "destination_change": "DNS moved the service to another server shortly before",
    "dns_latency": "DNS resolution slowed down",
    "tls_blocked": "TLS handshakes fail after TCP connects (SNI filtering?)",
}


def incident_events(samples: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pick the incident events out of ingested samples, with extra decoded."""
    out = []
    for s in samples:
        if s.get("kind") != "event" or not s.get("extra"):
            continue
        extra = json.loads(s["extra"]) if isinstance(s["extra"], str) else s["extra"]
        if str(extra.get("event", "")).startswith("incident_"):
            out.append({**s, "extra": extra})
    return out


class Webhook:
    """Reads the Slack webhook URL from SSM, caching the answer."""

    def __init__(self, ssm: Any, name: str, clock: Callable[[], float] = time.monotonic):
        self.ssm, self.name, self.clock = ssm, name, clock
        self._at: float | None = None
        self._url: str | None = None

    def url(self) -> str | None:
        if self._at is None or self.clock() - self._at > WEBHOOK_CACHE_SECONDS:
            try:
                self._url = self.ssm.get_parameter(Name=self.name, WithDecryption=True)["Parameter"]["Value"].strip()
            except self.ssm.exceptions.ParameterNotFound:
                self._url = None
            self._at = self.clock()
        return self._url or None


def post_slack(url: str, text: str) -> None:
    body = json.dumps({"text": text}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")  # noqa: S310
    with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 - URL from SSM, https only
        r.read()


def _fmt_ms(v: Any) -> str:
    try:
        return f"{float(v):.0f} ms"
    except (TypeError, ValueError):
        return "?"


def _fmt_duration(s: int) -> str:
    if s < 90:
        return f"{s}s"
    if s < 5400:
        return f"{round(s / 60)}m"
    return f"{s / 3600:.1f}h"


def ioda_note(asn: int, now_s: int, fetch: Callable[[str], Any] | None = None) -> str:
    """One line on whether IODA sees an outage of the ISP right now."""
    from heimdall_cloud import external

    kw = {"fetch": fetch} if fetch else {}
    try:
        events = external.ioda_events(now_s - 3 * 3600, now_s, [("asn", str(asn))], **kw)
    except Exception as e:
        return f"IODA: not reachable ({e})"
    if not events:
        return f"IODA: no outage signal for AS{asn} in the last 3 hours"
    worst = max(events, key=lambda e: e.get("score") or 0)
    return f"IODA: outage signal for AS{asn} ({worst.get('datasource')}, score {worst.get('score'):.0f})"


def format_message(
    device: str, ev: dict[str, Any], control: list[dict[str, Any]] | None, grafana: str, note: str | None = None
) -> str:
    x = ev["extra"]
    name = x["event"]
    services = ", ".join(x.get("services") or []) or "-"
    cause = CAUSES.get(x.get("cause", ""), x.get("cause", "unknown"))
    if name == "incident_end":
        return (
            f":large_green_circle: *{device}* resolved after {_fmt_duration(int(x.get('duration_s', 0)))}: "
            f"{x.get('scope')} incident ({services})"
        )
    icon = ":no_entry:" if x.get("cause") == "tls_blocked" else ":red_circle:"
    verb = "incident" if name == "incident_start" else "incident update"
    lines = [f"{icon} *{device}* {verb}: {x.get('scope')} - {services}", f"Likely cause: {cause}"]
    for t in (x.get("targets") or [])[:5]:
        detail = f"{_fmt_ms(t.get('current_ms'))} vs {_fmt_ms(t.get('baseline_ms'))}"
        if "loss" in (t.get("reason") or ""):
            detail += f", loss {100 * float(t.get('loss', 0)):.0f}%"
        lines.append(f"- {t.get('target_id')} ({t.get('kind')}, {t.get('dst_ip')}): {detail}")
    if control is not None and x.get("scope") != "access":
        if control:
            lines.append("AWS control: also degraded from eu-central-1, so probably the service itself")
        else:
            lines.append("AWS control: normal from eu-central-1, so probably the ISP's path to the service")
    if note:
        lines.append(note)
    if grafana:
        lines.append(f"{grafana}d/heimdall-overview")
    return "\n".join(lines)


class Notifier:
    def __init__(
        self,
        table: Any,
        webhook: Webhook,
        control_device: str,
        grafana_url: str = "",
        post: Callable[[str, str], None] = post_slack,
        now: Callable[[], float] = time.time,
        device_asn: dict[str, int] | None = None,
        access_note: Callable[[int, int], str] = ioda_note,
    ):
        self.table, self.webhook, self.control = table, webhook, control_device
        self.grafana, self.post, self.now = grafana_url, post, now
        self.device_asn, self.access_note = device_asn or {}, access_note

    def open_services(self, device: str) -> set[str]:
        """Services in the device's open incidents. Incidents that started
        more than a day ago are left out: a probe that stopped without
        ending them leaves them open."""
        from boto3.dynamodb.conditions import Attr, Key

        since_ms = int((self.now() - OPEN_MAX_AGE_S) * 1000)
        resp = self.table.query(
            KeyConditionExpression=Key("device").eq(device),
            FilterExpression=Attr("status").eq("open") & Attr("started_ms").gte(since_ms),
        )
        out: set[str] = set()
        for item in resp.get("Items", []):
            out.update(item.get("services") or [])
        return out

    def record(self, device: str, ev: dict[str, Any]) -> None:
        x = ev["extra"]
        name = x["event"]
        item_key = {"device": device, "incident_id": x["incident_id"]}
        ttl = int(self.now()) + RETENTION_DAYS * 86400
        if name == "incident_start":
            self.table.put_item(
                Item={
                    **item_key,
                    "status": "open",
                    "scope": x.get("scope", ""),
                    "cause": x.get("cause", ""),
                    "services": list(x.get("services") or []),
                    "started_ms": int(x.get("started_ms") or ev.get("ts_ms") or 0),
                    "ttl": ttl,
                }
            )
        elif name == "incident_update":
            self.table.update_item(
                Key=item_key,
                UpdateExpression="SET services = :s, #t = :ttl",
                ExpressionAttributeNames={"#t": "ttl"},
                ExpressionAttributeValues={":s": list(x.get("services") or []), ":ttl": ttl},
            )
        elif name == "incident_end":
            self.table.update_item(
                Key=item_key,
                UpdateExpression="SET #s = :c, ended_ms = :e, duration_s = :d, #t = :ttl",
                ExpressionAttributeNames={"#s": "status", "#t": "ttl"},
                ExpressionAttributeValues={
                    ":c": "closed",
                    ":e": int(ev.get("ts_ms") or 0),
                    ":d": int(x.get("duration_s") or 0),
                    ":ttl": ttl,
                },
            )

    def __call__(self, event: dict[str, Any], context: Any = None) -> dict[str, Any]:
        device = event["device"]
        posted = 0
        for ev in event.get("events", []):
            x = ev["extra"]
            self.record(device, ev)
            if device == self.control:
                continue
            control = None
            note = None
            if x["event"] != "incident_end" and x.get("scope") == "service":
                control = sorted(self.open_services(self.control) & set(x.get("services") or []))
            url = self.webhook.url()
            if url and x["event"] == "incident_start" and x.get("scope") == "access" and device in self.device_asn:
                note = self.access_note(self.device_asn[device], int(self.now()))
            text = format_message(device, ev, control, self.grafana, note)
            log.info(
                json.dumps({"device": device, "event": x["event"], "id": x.get("incident_id"), "slack": bool(url)})
            )
            if not url:
                continue
            try:
                self.post(url, text)
                posted += 1
            except (urllib.error.URLError, TimeoutError) as e:
                log.warning("slack post failed: %s", e)
        return {"posted": posted}


_notifier: Notifier | None = None


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    global _notifier
    if _notifier is None:
        import boto3

        _notifier = Notifier(
            table=boto3.resource("dynamodb").Table(os.environ["TABLE"]),
            webhook=Webhook(boto3.client("ssm"), os.environ["WEBHOOK_PARAMETER"]),
            control_device=os.environ["CONTROL_DEVICE"],
            grafana_url=os.environ.get("GRAFANA_URL", ""),
            device_asn=json.loads(os.environ.get("DEVICE_ASN", "{}")),
        )
    return _notifier(event, context)
