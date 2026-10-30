"""Incident notifier, invoked asynchronously by the ingest Lambda with the
incident events of a batch.

Probes detect incidents themselves (``incident_start``,
``incident_confirmed``, ``incident_update``, ``incident_end`` events). The
notifier keeps them per device in DynamoDB, and for an incident on a CPE
checks whether the cloud control probe has an open incident for the same
services at the same time: if it does, the problem is most likely on the
service's side; if it does not, it is in the access network or the ISP's
path to the service.

It posts to Slack, when a webhook URL is stored in SSM, only incidents
worth a message: broad ones (access, home) from their start, narrow ones
(one service, one client, DNS) once the probe confirms they lasted. An
incident like one already posted in the last REPEAT_WINDOW_S is not posted
again, so a condition that comes and goes, or a blocked service that
reopens after every probe restart, does not repeat. Updates and the end of
an incident are posted only when its start was.
"""

from __future__ import annotations

import json
import logging
import os
import re
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
REPEAT_WINDOW_S = 6 * 3600

CAUSES = {
    "access_network": "access network: the ISP hops or most services degraded together",
    "path": "this service's path or servers",
    "destination_change": "DNS moved the service to another server shortly before",
    "dns_latency": "DNS resolution slowed down",
    "tls_blocked": "TLS handshakes fail after TCP connects (SNI filtering?)",
    "roaming": "the client moved between radios or mesh nodes",
    "weak_signal": "weak Wi-Fi signal between the client and its access point",
    "retransmissions": "many Wi-Fi retransmissions to the client",
    "radio_retransmissions": "many retransmissions on the access point's radio (interference or a congested channel)",
    "channel_busy": "the Wi-Fi channel is busy (neighbouring networks or heavy use)",
    "extender": "the client is behind a mesh extender (its radio or backhaul)",
    "weak_link_extender": "low link rate between the client and its mesh extender",
    "wired_lan": "wired LAN (cable, switch or the client itself)",
    "lan_latency": "the client's LAN path; the CPE's Wi-Fi readings show nothing unusual",
    "lan_wide": "several clients at once: the CPE or the whole home network",
    "extender_wide": "several clients of the mesh extender at once: its radios or the extender itself",
    "backhaul": "the link between the mesh extender and the CPE",
}

# Scopes about the home network rather than the internet.
HOME_SCOPES = ("client", "home", "backhaul")


def device_label(device: str, sites: dict[str, str]) -> str:
    """A probe on a mesh extender is named after the CPE it belongs to."""
    site = sites.get(device)
    return f"{site} (extender {device})" if site else device


# DHCP hostnames that do not tell one device from another: none ("*" in the
# lease file), interface names, and names made of a MAC or other hex digits.
# The dashboards keep the same list (GENERIC_HOSTNAME in gen_dashboards.py).
GENERIC_HOSTNAME = re.compile(
    r"^(\*|localhost|unknown|none|wlan[0-9]*|eth[0-9]*|android[-_]?[0-9a-f]*|esp[-_][0-9a-f]+|espressif"
    r"|[0-9a-f]{8,}|([0-9a-f]{2}[-:]?){6})$"
)


def names_key(device: str) -> str:
    """The incidents table's partition that holds the client names of a
    CPE, as the ingest records them."""
    return f"names#{device}"


def client_label(client: str, cx: dict[str, Any]) -> str:
    """The client's DHCP hostname with its ID, or the ID alone when the
    probe reports no hostname or a generic one."""
    name = str(cx.get("client_name") or "").strip()
    if not name or GENERIC_HOSTNAME.match(name.lower()):
        return client
    return f"{name} ({client})"


def _client_line(client: str, cx: dict[str, Any]) -> str:
    parts = [str(cx.get("node") or "?")]
    for key, fmt in (
        ("band", "{}"),
        ("rssi", "{} dBm"),
        ("retry_pct", "{}% retries"),
        ("radio_busy", "radio {}% busy"),
    ):
        if cx.get(key) is not None:
            parts.append(fmt.format(cx[key]))
    if cx.get("tx_rate_mbps") is not None:
        parts.append(f"{float(cx['tx_rate_mbps']):.0f} Mbit/s")
    if cx.get("backhaul"):
        parts.append(f"backhaul {cx['backhaul']}")
    return f"- client {client_label(client, cx)}: " + ", ".join(parts)


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
    device: str,
    ev: dict[str, Any],
    control: list[dict[str, Any]] | None,
    grafana: str,
    note: str | None = None,
    extender: bool = False,
) -> str:
    """The Slack text of an incident event. device is the label to show;
    extender is set for a probe on a mesh extender, whose client figures
    are the hop between the extender and the client."""
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
    verb = "incident" if name in ("incident_start", "incident_confirmed") else "incident update"
    head = f"{icon} *{device}* {verb}: {x.get('scope')} - {services}"
    if name == "incident_confirmed" and x.get("duration_s"):
        head += f" (ongoing for {_fmt_duration(int(x['duration_s']))})"
    lines = [head, f"Likely cause: {cause}"]
    home = x.get("scope") in HOME_SCOPES
    for t in (x.get("targets") or [])[:5]:
        detail = f"{_fmt_ms(t.get('current_ms'))} vs {_fmt_ms(t.get('baseline_ms'))}"
        if "loss" in (t.get("reason") or ""):
            detail += f", loss {100 * float(t.get('loss', 0)):.0f}%"
        if home and t.get("kind") == "flow":
            what = "hop between the extender and the client" if extender else "LAN part of its connections"
            lines.append(f"- {t.get('target_id')}: {what} {detail}")
        elif home:
            lines.append(f"- {t.get('target_id')} ({t.get('kind')}, {t.get('dst_ip')}): {detail}")
        else:
            lines.append(f"- {t.get('target_id')} ({t.get('kind')}, {t.get('dst_ip')}): {detail}")
    for client, cx in list((x.get("clients") or {}).items())[:5]:
        lines.append(_client_line(client, cx or {}))
    if control is not None and x.get("scope") != "access":
        if control:
            lines.append("AWS control: also degraded from eu-central-1, so probably the service itself")
        else:
            lines.append("AWS control: normal from eu-central-1, so probably the ISP's path to the service")
    if note:
        lines.append(note)
    if grafana:
        lines.append(f"{grafana}d/{'heimdall-topology' if home else 'heimdall-overview'}")
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
        extender_sites: dict[str, str] | None = None,
    ):
        self.table, self.webhook, self.control = table, webhook, control_device
        self.grafana, self.post, self.now = grafana_url, post, now
        self.device_asn, self.access_note = device_asn or {}, access_note
        self.sites = extender_sites or {}

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

    @staticmethod
    def signature(x: dict[str, Any]) -> str:
        """What makes two incidents the same for notifications."""
        return "|".join([x.get("scope", ""), x.get("cause", ""), ",".join(sorted(x.get("services") or []))])

    def add_names(self, device: str, x: dict[str, Any]) -> None:
        """Fill in the DHCP hostname of the clients in an incident whose
        context has none, as the ingest recorded it from the CPE of the
        device's home (the device itself, or the CPE an extender belongs
        to)."""
        site = self.sites.get(device, device)
        for client, cx in (x.get("clients") or {}).items():
            if not isinstance(cx, dict) or cx.get("client_name"):
                continue
            try:
                name = self.item(names_key(site), client).get("name")
            except Exception as e:  # a missing name never stops a notification
                log.warning("name lookup failed for %s: %s", client, e)
                continue
            if name:
                cx["client_name"] = name

    def item(self, device: str, incident_id: str) -> dict[str, Any]:
        resp = self.table.get_item(Key={"device": device, "incident_id": incident_id})
        return resp.get("Item") or {}

    def recently_posted(self, device: str, x: dict[str, Any]) -> bool:
        """Whether an incident with the same signature was posted within
        REPEAT_WINDOW_S."""
        from boto3.dynamodb.conditions import Attr, Key

        since_ms = int((self.now() - REPEAT_WINDOW_S) * 1000)
        resp = self.table.query(
            KeyConditionExpression=Key("device").eq(device),
            FilterExpression=Attr("signature").eq(self.signature(x))
            & Attr("notified").eq(True)
            & Attr("posted_ms").gte(since_ms)
            & Attr("incident_id").ne(x.get("incident_id", "")),
        )
        return bool(resp.get("Items"))

    def mark_posted(self, device: str, incident_id: str) -> None:
        self.table.update_item(
            Key={"device": device, "incident_id": incident_id},
            UpdateExpression="SET notified = :t, posted_ms = :p",
            ExpressionAttributeValues={":t": True, ":p": int(self.now() * 1000)},
        )

    def should_post(self, device: str, ev: dict[str, Any]) -> bool:
        x = ev["extra"]
        name = x["event"]
        if name in ("incident_start", "incident_confirmed"):
            # Probes before confirmation existed send no "confirmed" field;
            # their starts are posted as before.
            if name == "incident_start" and x.get("confirmed") is False:
                return False
            if self.item(device, x["incident_id"]).get("notified"):
                return False
            return not self.recently_posted(device, x)
        return bool(self.item(device, x["incident_id"]).get("notified"))

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
                    "signature": self.signature(x),
                    "confirmed": x.get("confirmed", True),
                    "started_ms": int(x.get("started_ms") or ev.get("ts_ms") or 0),
                    "ttl": ttl,
                }
            )
        elif name == "incident_confirmed":
            self.table.update_item(
                Key=item_key,
                UpdateExpression="SET confirmed = :c, services = :s, signature = :g, #t = :ttl",
                ExpressionAttributeNames={"#t": "ttl"},
                ExpressionAttributeValues={
                    ":c": True,
                    ":s": list(x.get("services") or []),
                    ":g": self.signature(x),
                    ":ttl": ttl,
                },
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
            if (
                url
                and x["event"] in ("incident_start", "incident_confirmed")
                and x.get("scope") == "access"
                and device in self.device_asn
            ):
                note = self.access_note(self.device_asn[device], int(self.now()))
            post = bool(url) and self.should_post(device, ev)
            log.info(
                json.dumps(
                    {
                        "device": device,
                        "event": x["event"],
                        "id": x.get("incident_id"),
                        "slack": bool(url),
                        "post": post,
                    }
                )
            )
            if not post:
                continue
            if x.get("scope") in HOME_SCOPES:
                self.add_names(device, x)
            text = format_message(
                device_label(device, self.sites), ev, control, self.grafana, note, extender=device in self.sites
            )
            try:
                self.post(url, text)
                posted += 1
                if x["event"] in ("incident_start", "incident_confirmed"):
                    self.mark_posted(device, x["incident_id"])
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
            extender_sites=json.loads(os.environ.get("EXTENDER_SITES", "{}")),
        )
    return _notifier(event, context)
