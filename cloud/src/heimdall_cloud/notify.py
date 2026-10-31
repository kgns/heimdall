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
    "lan_latency": "the client's LAN path; the access point's Wi-Fi readings show nothing unusual",
    "lan_wide": "several clients at once: the CPE or the whole home network",
    "extender_wide": "several clients of the mesh extender at once: its radios or the extender itself",
    "backhaul": "the link between the mesh extender and the CPE",
    "extender_unreachable": "the mesh extender stopped answering the CPE (powered off, rebooting or disconnected)",
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
    """Where the client is attached, or its name alone when the probe knows
    nothing about that."""
    parts = []
    if cx.get("node"):
        parts.append(str(cx["node"]))
    if cx.get("medium") == "wired":
        parts.append(f"wired ({cx['port']})" if cx.get("port") else "wired")
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
    line = f"- client {client_label(client, cx)}"
    return f"{line}: " + ", ".join(parts) if parts else line


def _labels(x: dict[str, Any]) -> dict[str, str]:
    """The display label of each client in an incident's context."""
    return {c: client_label(c, cx or {}) for c, cx in (x.get("clients") or {}).items()}


def incident_events(samples: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pick the incident events out of ingested samples, with extra decoded,
    and the probe's start event, which ends what an earlier run left open."""
    out = []
    for s in samples:
        if s.get("kind") != "event" or not s.get("extra"):
            continue
        extra = json.loads(s["extra"]) if isinstance(s["extra"], str) else s["extra"]
        name = str(extra.get("event", ""))
        if name.startswith("incident_") or name == "start":
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
    status_link: str = "",
) -> str:
    """The Slack text of an incident event. device is the label to show;
    extender is set for a probe on a mesh extender, whose client figures
    are the hop between the extender and the client."""
    x = ev["extra"]
    name = x["event"]
    # The services of a client or home incident are its clients.
    labels = _labels(x)
    services = ", ".join(labels.get(s, s) for s in x.get("services") or []) or "-"
    cause = CAUSES.get(x.get("cause", ""), x.get("cause", "unknown"))
    if name == "incident_end":
        text = (
            f":large_green_circle: *{device}* resolved after {_fmt_duration(int(x.get('duration_s', 0)))}: "
            f"{x.get('scope')} incident - {services}" + (" :zap:" if x.get("mode") == "fast" else "")
        )
        return f"{text}\nStatus page: {status_link}" if status_link else text
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
            loss = f"loss {100 * float(t.get('loss', 0)):.0f}%"
            # Without a single reply in the window there is no latency.
            if t.get("current_ms"):
                detail += f", {loss}"
            else:
                detail = f"no reply (normally {_fmt_ms(t.get('baseline_ms'))}), {loss}"
        if home and t.get("kind") == "flow":
            what = "hop between the extender and the client" if extender else "LAN part of its connections"
            target = str(t.get("target_id") or "")
            client = target.removeprefix("flow/")
            lines.append(f"- {labels.get(client, target)}: {what} {detail}")
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
    if x.get("mode") == "fast":
        lines.append(":zap: Fast detection (demo mode, 5-second buckets)")
    if status_link:
        lines.append(f"Status page for the ISP and the customer: {status_link}")
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
        status_url: str = "",
        link_secret: Any = None,
    ):
        self.status_url, self.link_secret = status_url, link_secret
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

    def close_left_open(self, device: str, start_ms: int) -> int:
        """Closes the device's incidents that were open when its probe
        started again. A probe that lost power never sent their end, so they
        end at the restart; nothing is posted, since the real end is not
        known."""
        from boto3.dynamodb.conditions import Attr, Key

        kw: dict[str, Any] = {
            "KeyConditionExpression": Key("device").eq(device),
            "FilterExpression": Attr("status").eq("open") & Attr("started_ms").lt(start_ms),
        }
        closed = 0
        for _ in range(5):
            resp = self.table.query(**kw)
            for item in resp.get("Items", []):
                self.table.update_item(
                    Key={"device": device, "incident_id": item["incident_id"]},
                    UpdateExpression="SET #s = :c, ended_ms = :e, duration_s = :d, end_reason = :r",
                    ExpressionAttributeNames={"#s": "status"},
                    ExpressionAttributeValues={
                        ":c": "closed",
                        ":e": start_ms,
                        ":d": max(0, (start_ms - int(item.get("started_ms") or start_ms)) // 1000),
                        ":r": "probe_restarted",
                    },
                )
                closed += 1
            if "LastEvaluatedKey" not in resp:
                break
            kw["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
        return closed

    @staticmethod
    def signature(x: dict[str, Any]) -> str:
        """What makes two incidents the same for notifications. Those of the
        fast detector never match the regular detector's."""
        parts = [x.get("scope", ""), x.get("cause", ""), ",".join(sorted(x.get("services") or []))]
        if x.get("mode"):
            parts.insert(0, str(x["mode"]))
        return "|".join(parts)

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
        # A filter cannot test the sort key (incident_id), so the incident
        # itself is left out here.
        resp = self.table.query(
            KeyConditionExpression=Key("device").eq(device),
            FilterExpression=Attr("signature").eq(self.signature(x))
            & Attr("notified").eq(True)
            & Attr("posted_ms").gte(since_ms),
        )
        return any(i.get("incident_id") != x.get("incident_id") for i in resp.get("Items", []))

    def save_detail(self, device: str, x: dict[str, Any], control: list[str] | None) -> None:
        """Keep what the status page shows beyond the incident's fields:
        the worst measurements, the clients and the reference probe's
        view, as of the latest event."""
        from heimdall_cloud.status import incident_detail

        detail = incident_detail(x, control, extender=device in self.sites)
        try:
            self.table.update_item(
                Key={"device": device, "incident_id": x["incident_id"]},
                UpdateExpression="SET detail = :d",
                ExpressionAttributeValues={":d": json.dumps(detail, default=str)},
            )
        except Exception as e:  # the page's details never stop a notification
            log.warning("saving incident detail failed: %s", e)

    def status_link(self, device: str, incident_id: str) -> str:
        """The share link of an incident's status page, or "" when status
        pages are not configured."""
        if not self.status_url or self.link_secret is None or not incident_id:
            return ""
        from heimdall_cloud.status import LINK_TTL_S, make_token

        try:
            secret = self.link_secret.value()
        except Exception as e:
            log.warning("link secret unreadable: %s", e)
            return ""
        token = make_token(secret, device, incident_id, int(self.now()) + LINK_TTL_S)
        return f"{self.status_url}i/{token}"

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
            # A demonstration is repeated on purpose, so the fast detector's
            # incidents are not held back as repeats.
            if x.get("mode") == "fast":
                return True
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
                    "mode": x.get("mode") or "regular",
                    "confirmed": x.get("confirmed", True),
                    "started_ms": int(x.get("started_ms") or ev.get("ts_ms") or 0),
                    "detected_ms": int(x.get("detected_ms") or ev.get("ts_ms") or 0),
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
                    ":e": int(x.get("ended_ms") or ev.get("ts_ms") or 0),
                    ":d": int(x.get("duration_s") or 0),
                    ":ttl": ttl,
                },
            )

    def __call__(self, event: dict[str, Any], context: Any = None) -> dict[str, Any]:
        if event.get("warmup"):
            # Opens the connections a first post needs, so that one comes
            # out as fast as later ones (scripts/demo on).
            self.webhook.url()
            self.item("warmup", "warmup")
            return {"posted": 0}
        device = event["device"]
        posted = 0
        for ev in event.get("events", []):
            x = ev["extra"]
            if x["event"] == "start":
                closed = self.close_left_open(device, int(ev.get("ts_ms") or self.now() * 1000))
                log.info(json.dumps({"device": device, "event": "start", "closed": closed}))
                continue
            self.record(device, ev)
            if device == self.control:
                continue
            control = None
            note = None
            if x["event"] != "incident_end" and x.get("scope") == "service":
                control = sorted(self.open_services(self.control) & set(x.get("services") or []))
            if x["event"] != "incident_end":
                if x.get("scope") in HOME_SCOPES:
                    self.add_names(device, x)
                self.save_detail(device, x, control)
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
            if x["event"] == "incident_end" and x.get("scope") in HOME_SCOPES:
                self.add_names(device, x)
            text = format_message(
                device_label(device, self.sites),
                ev,
                control,
                self.grafana,
                note,
                extender=device in self.sites,
                status_link=self.status_link(device, x.get("incident_id", "")),
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
        if (url := os.environ.get("STATUS_URL")) and (param := os.environ.get("LINK_SECRET_PARAMETER")):
            from heimdall_cloud.status import Secret

            _notifier.status_url = url
            _notifier.link_secret = Secret(_notifier.webhook.ssm, param)
    return _notifier(event, context)
