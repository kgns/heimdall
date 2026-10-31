"""Status pages: one page per incident, for the ISP and its customer, that
says what happened, why, who should act and what the fix is.

The page is reached through a share link that the notifier puts in its
Slack posts. A link names one incident and expires; it is signed with a
secret kept in SSM, so it cannot be guessed or altered. The Lambda behind
the status API serves the page itself (static files in ``status_web``) and
the incident's report as JSON, read from the incidents table, which the
notifier keeps up to date within a second of each event.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import mimetypes
import os
import re
import time
from collections.abc import Callable
from importlib import resources
from typing import Any

from heimdall_cloud.notify import CAUSES, GENERIC_HOSTNAME, client_label

log = logging.getLogger()
log.setLevel(logging.INFO)

LINK_TTL_S = 30 * 24 * 3600
SECRET_CACHE_SECONDS = 300

_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_INCIDENT = re.compile(r"^[0-9a-f]{8,32}$")


class LinkError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(secret: bytes, device: str, incident_id: str, expires_s: int) -> str:
    """A share link token for one incident, valid until expires_s."""
    payload = f"{device}|{incident_id}|{expires_s}".encode()
    sig = hmac.new(secret, payload, hashlib.sha256).digest()[:18]
    return f"{_b64(payload)}.{_b64(sig)}"


def read_token(secret: bytes, token: str, now_s: float) -> tuple[str, str]:
    """The (device, incident_id) a token names. Raises LinkError 404 for a
    token that is malformed or not ours, 410 for an expired one."""
    try:
        p64, s64 = token.split(".")
        payload, sig = _unb64(p64), _unb64(s64)
        device, incident_id, exp = payload.decode().split("|")
        expires = int(exp)
    except ValueError as e:
        raise LinkError(404, "unknown link") from e
    want = hmac.new(secret, payload, hashlib.sha256).digest()[:18]
    if not hmac.compare_digest(sig, want) or not _ID.match(device) or not _INCIDENT.match(incident_id):
        raise LinkError(404, "unknown link")
    if now_s > expires:
        raise LinkError(410, "this link has expired")
    return device, incident_id


class Secret:
    """The link secret from SSM, cached."""

    def __init__(self, ssm: Any, name: str, clock: Callable[[], float] = time.monotonic):
        self.ssm, self.name, self.clock = ssm, name, clock
        self._at: float | None = None
        self._value = b""

    def value(self) -> bytes:
        if self._at is None or self.clock() - self._at > SECRET_CACHE_SECONDS:
            raw = self.ssm.get_parameter(Name=self.name, WithDecryption=True)["Parameter"]["Value"]
            self._value, self._at = raw.strip().encode(), self.clock()
        return self._value


# Who should act, by the part of the path at fault.
PARTIES = {
    "customer": "The customer's home network",
    "equipment": "The home gateway or extender (ISP-provided equipment)",
    "isp_access": "The ISP's access network",
    "isp_path": "The ISP's route to the service",
    "isp_dns": "The ISP's DNS resolvers",
    "isp_policy": "Filtering in the ISP's network",
    "service": "The service provider",
    "unknown": "Not determined yet",
}

# The path from a home device to an internet service, in order. "wifi" is
# the device's own link (Wi-Fi or cable), "backhaul" the extender's link to
# the gateway.
SEGMENTS = [
    ("device", "Device"),
    ("wifi", "Wi-Fi / LAN"),
    ("backhaul", "Extender link"),
    ("gateway", "Home gateway"),
    ("access", "ISP access"),
    ("path", "ISP route"),
    ("service", "Service"),
]


def _client_words(names: list[str]) -> str:
    if not names:
        return "a device"
    if len(names) == 1:
        return names[0]
    return f"{len(names)} devices ({', '.join(names[:3])}{', ...' if len(names) > 3 else ''})"


def verdict(item: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    """What happened, why, who should act and the fix, from the incident's
    cause and, for a service, the AWS control probe's view."""
    cause = item.get("cause") or ""
    scope = item.get("scope") or ""
    services = list(item.get("services") or [])
    clients = [c["label"] for c in detail.get("clients") or []] or services
    who = _client_words(clients) if scope in ("client", "home") else ", ".join(services) or "a service"
    svc = ", ".join(services) or "the service"
    node = next((c.get("node") for c in detail.get("clients") or [] if c.get("node")), "the access point")
    control = detail.get("control")

    def v(party: str, segment: str, headline: str, why: str, fixes: list[str]) -> dict[str, Any]:
        isp = {
            "customer": "No fault in the ISP's network. Share the advice below with the customer.",
            "service": "No fault in the ISP's network or the home.",
        }.get(party, "The ISP should act on the advice below.")
        return {
            "party": party,
            "party_label": PARTIES[party],
            "segment": segment,
            "headline": headline,
            "why": why,
            "fixes": fixes,
            "isp_note": isp,
        }

    home_fix = "Restart the device's network connection and check it for heavy load, a VPN or power saving"
    table: dict[str, Callable[[], dict[str, Any]]] = {
        "access_network": lambda: v(
            "isp_access",
            "access",
            "The ISP's access network slowed down",
            "The ISP's first hops, or most services at once, got slower together, so the delay was between "
            "the home and the ISP's core network.",
            [
                "Check the access segment serving this line (OLT, DSLAM or BNG) for congestion or errors at that time",
                "Compare with other lines on the same segment",
                "If it recurs at busy hours, review the segment's capacity",
            ],
        ),
        "path": lambda: (
            v(
                "service",
                "service",
                f"{svc} itself was slow",
                f"{svc} was slower from this home and also from our reference probe in AWS Frankfurt, so the "
                "service's own servers were the cause.",
                ["No action needed from the ISP or the customer", "Check the service's status page"],
            )
            if control
            else v(
                "isp_path",
                "path",
                f"The ISP's route to {svc} slowed down",
                f"Only {svc} was slower, and our reference probe in AWS Frankfurt reached it normally at the "
                "same time, so the delay was on the ISP's route to the service.",
                [
                    f"Check the peering, transit link or cache that serves {svc}",
                    f"Check whether traffic to {svc} took another route at that time",
                ],
            )
            if control is not None
            else v(
                "isp_path",
                "path",
                f"The route to {svc} slowed down",
                f"Only {svc} was slower; the reference probe could not tell whether the service itself was slow.",
                [f"Check the ISP's route to {svc}", "Check the service's status page"],
            )
        ),
        "destination_change": lambda: v(
            "isp_path",
            "path",
            f"{svc} traffic was sent to a farther server",
            f"Just before {svc} got slower, DNS started answering with another server address, and that "
            "server is farther away.",
            [
                "Check how the ISP's resolvers map this service (EDNS client subnet, cache nodes)",
                f"Check whether the nearer {svc} cache was down or full",
            ],
        ),
        "dns_latency": lambda: v(
            "isp_dns",
            "access",
            "Name lookups (DNS) were slow",
            "Resolving names took much longer than usual, which delays every new connection.",
            ["Check the load and health of the ISP's DNS resolvers at that time"],
        ),
        "tls_blocked": lambda: v(
            "isp_policy",
            "path",
            f"Secure connections to {svc} are blocked",
            f"Connections to {svc} open, then fail during the TLS handshake, which points at filtering by "
            "server name (SNI).",
            ["Check the filtering rules applied to this service"],
        ),
        "weak_signal": lambda: v(
            "customer",
            "wifi",
            f"Weak Wi-Fi signal at {who}",
            f"The Wi-Fi signal between {who} and {node} was weak, so data had to be resent and slowed down.",
            [
                "Move the device closer to the access point, or the access point to a more central place",
                "Add a mesh extender, or move the existing one, to cover that room",
            ],
        ),
        "retransmissions": lambda: v(
            "customer",
            "wifi",
            f"Many Wi-Fi retransmissions to {who}",
            f"Many frames to {who} had to be sent again, a sign of interference or a marginal signal.",
            [
                "Move the device or the access point away from walls, metal and microwave ovens",
                "Try another Wi-Fi channel",
            ],
        ),
        "radio_retransmissions": lambda: v(
            "customer",
            "wifi",
            f"Interference on {node}'s radio",
            "The access point's radio had to resend many frames to all its devices, a sign of interference.",
            ["Switch the access point to a less crowded channel", "Prefer the 5 GHz band where it reaches"],
        ),
        "channel_busy": lambda: v(
            "customer",
            "wifi",
            "The Wi-Fi channel was crowded",
            "The radio channel was busy most of the time, with neighbouring networks or heavy use.",
            ["Switch to a less crowded channel", "Prefer the 5 GHz band where it reaches"],
        ),
        "roaming": lambda: v(
            "customer",
            "wifi",
            f"{who} was switching between access points",
            f"{who} moved between the gateway and the extender while the delay was measured.",
            ["Usually temporary; if it repeats in one place, adjust the extender's position"],
        ),
        "extender": lambda: v(
            "customer",
            "wifi",
            f"Slow link for {who} through the mesh extender",
            f"{who} is connected through the mesh extender, and the delay was on that part of the network.",
            ["Move the device closer to the extender, or the extender closer to the gateway"],
        ),
        "weak_link_extender": lambda: v(
            "customer",
            "wifi",
            f"Low link speed between {who} and the extender",
            f"The link between {who} and the extender ran at a low rate.",
            ["Move the device closer to the extender"],
        ),
        "backhaul": lambda: v(
            "customer",
            "backhaul",
            "The extender's link to the gateway slowed down",
            "Every device behind the mesh extender goes through this link, so all of them were affected.",
            [
                "Move the extender closer to the gateway, halfway to the area it covers",
                "Connect the extender to the gateway with a cable if possible",
            ],
        ),
        "wired_lan": lambda: v(
            "customer",
            "wifi",
            f"The wired connection of {who} slowed down",
            f"{who} is connected by cable and the delay was on that connection, so the cable, a switch "
            "in between or the device itself is the likely cause.",
            ["Check or replace the cable and any switch in between", home_fix],
        ),
        "lan_latency": lambda: v(
            "customer",
            "wifi",
            f"{who}'s connection inside the home slowed down",
            f"The delay was between {node} and {who}. The radio readings look normal, so the device itself "
            "is the likely cause.",
            [home_fix, "If it persists, move the device closer to the access point to rule out the signal"],
        ),
        "lan_wide": lambda: v(
            "equipment",
            "gateway",
            "Several devices slowed down at once: the home gateway",
            "Devices in different places slowed down together, which points at the gateway they share.",
            ["Restart the home gateway", "Check its load and firmware version remotely"],
        ),
        "extender_wide": lambda: v(
            "equipment",
            "backhaul",
            "Every device on the mesh extender slowed down",
            "All devices connected to the extender slowed down together, which points at the extender.",
            ["Restart the extender", "Check its link to the gateway and its firmware"],
        ),
    }
    if cause in table:
        return table[cause]()
    return v("unknown", "", f"{scope or 'An'} incident", CAUSES.get(cause, cause or "Cause not determined."), [])


def _scope_segment(scope: str, cause: str) -> str:
    if scope in ("client", "home"):
        return "gateway" if cause == "lan_wide" else "wifi"
    return {"backhaul": "backhaul", "access": "access", "dns": "access", "service": "path"}.get(scope, "")


def overlapping(table: Any, device: str, start_ms: int, end_ms: int) -> list[dict[str, Any]]:
    """The incidents of device that were open at some point in
    [start_ms, end_ms]."""
    from boto3.dynamodb.conditions import Attr, Key

    kw: dict[str, Any] = {
        "KeyConditionExpression": Key("device").eq(device),
        "FilterExpression": Attr("started_ms").lte(end_ms)
        & (Attr("ended_ms").not_exists() | Attr("ended_ms").gte(start_ms)),
    }
    out: list[dict[str, Any]] = []
    for _ in range(5):
        resp = table.query(**kw)
        out += resp.get("Items", [])
        if "LastEvaluatedKey" not in resp:
            break
        kw["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return out


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def report(
    table: Any,
    device: str,
    incident_id: str,
    sites: dict[str, str],
    control_device: str,
    now_ms: int,
) -> dict[str, Any] | None:
    """The status page's content for one incident, or None when the
    incident is not in the table (expired, or a wrong link)."""
    item = table.get_item(Key={"device": device, "incident_id": incident_id}).get("Item")
    if not item:
        return None
    detail = json.loads(item.get("detail") or "{}")
    started = int(item.get("started_ms") or 0)
    ended = int(item["ended_ms"]) if item.get("ended_ms") is not None else None
    is_open = item.get("status") != "closed"
    site = sites.get(device, device)
    extender = device in sites
    v = verdict(item, detail)

    # What else was wrong at the same time, on this home's probes and on
    # the reference probe in the cloud.
    window_end = ended if ended is not None else now_ms
    homes = [site, *[d for d, s in sites.items() if s == site]]
    others: list[tuple[str, dict[str, Any]]] = []
    for d in dict.fromkeys([*homes, control_device]):
        for o in overlapping(table, d, started, window_end):
            if not (d == device and o["incident_id"] == incident_id):
                others.append((d, o))
    affected = {_scope_segment(o.get("scope", ""), o.get("cause", "")) for d, o in others if d != control_device}

    has_backhaul = extender or bool(detail.get("via_extender"))
    path = []
    for seg, label in SEGMENTS:
        if seg == "backhaul" and not has_backhaul:
            continue
        state = "normal"
        if seg == v["segment"]:
            state = "fault"
        elif seg in affected:
            state = "affected"
        path.append({"id": seg, "label": label, "state": state})

    checks = []
    if item.get("scope") in ("client", "home"):
        checks.append(
            {
                "label": "ISP access network",
                "state": "affected" if "access" in affected else "normal",
                "note": "the ISP's first hops at the same time",
            }
        )
        checks.append(
            {
                "label": "Internet services",
                "state": "affected" if "path" in affected else "normal",
                "note": "the services measured from this home",
            }
        )
        if has_backhaul:
            checks.append(
                {
                    "label": "Extender link to the gateway",
                    "state": "affected" if "backhaul" in affected else "normal",
                    "note": "the extender's own round trip to the gateway",
                }
            )
    else:
        checks.append(
            {
                "label": "Home network",
                "state": "affected" if affected & {"wifi", "gateway", "backhaul"} else "normal",
                "note": "the devices' own connections inside the home",
            }
        )
    if detail.get("control") is not None:
        checks.append(
            {
                "label": "Reference probe in AWS Frankfurt",
                "state": "affected" if detail["control"] else "normal",
                "note": "the same services measured from the cloud",
            }
        )

    measurements = []
    for t in detail.get("targets") or []:
        cur, base = _num(t.get("current_ms")), _num(t.get("baseline_ms"))
        measurements.append(
            {
                "label": t.get("label") or t.get("target_id"),
                "what": t.get("what") or t.get("kind"),
                "current_ms": cur,
                "baseline_ms": base,
                "loss": _num(t.get("loss")),
            }
        )

    return {
        "incident": {
            "id": incident_id,
            "site": site,
            "seen_by": "extender" if extender else ("cloud" if device == control_device else "gateway"),
            "device": device,
            "scope": item.get("scope"),
            "cause": item.get("cause"),
            "status": "open" if is_open else "resolved",
            "mode": item.get("mode") or "regular",
            "confirmed": bool(item.get("confirmed", True)),
            "started_ms": started,
            "detected_ms": int(item.get("detected_ms") or started),
            "ended_ms": ended,
            "duration_s": int(item["duration_s"]) if item.get("duration_s") is not None else None,
        },
        "verdict": v,
        "path": path,
        "checks": checks,
        "measurements": measurements,
        "clients": detail.get("clients") or [],
        "updated_ms": now_ms,
    }


KIND_WORDS = {
    "icmp": "ping round trip",
    "udp_echo": "round trip",
    "tcp": "connection setup",
    "http": "web request",
    "dns": "name lookup",
    "stun": "round trip",
}
TARGET_NAMES = {"isp-hop": "ISP router", "isp-gateway": "ISP gateway", "uplink": "Home gateway"}


def incident_detail(x: dict[str, Any], control: list[str] | None, extender: bool) -> dict[str, Any]:
    """What the status page needs from an incident event beyond the
    incidents table's fields: the worst measurements, the clients and the
    reference probe's view. The notifier stores it with the incident."""
    clients = []
    via_extender = False
    for cid, cx in (x.get("clients") or {}).items():
        cx = cx or {}
        where = []
        if cx.get("node"):
            where.append(str(cx["node"]))
            if str(cx["node"]).lower() != "cpe":
                via_extender = True
        if cx.get("medium") == "wired":
            where.append("cable")
        elif cx.get("band"):
            where.append(f"Wi-Fi {cx['band']}")
        if cx.get("rssi") is not None:
            where.append(f"{cx['rssi']} dBm")
        if cx.get("tx_rate_mbps") is not None:
            where.append(f"{float(cx['tx_rate_mbps']):.0f} Mbit/s")
        name = str(cx.get("client_name") or "")
        clients.append(
            {
                "id": cid,
                "label": name if name and not GENERIC_HOSTNAME.match(name.lower()) else cid,
                "full_label": client_label(cid, cx),
                "node": cx.get("node"),
                "where": ", ".join(where),
            }
        )
    labels = {c["id"]: c["label"] for c in clients}
    targets = []
    for t in (x.get("targets") or [])[:5]:
        tid = str(t.get("target_id") or "")
        if t.get("kind") == "flow":
            cid = tid.removeprefix("flow/")
            label = labels.get(cid, cid)
            what = "round trip to the extender" if extender else "round trip inside the home"
        else:
            # Target IDs are "<service>/<host>" or a bare name such as
            # "isp-hop1" or "uplink".
            label = tid.split("/", 1)[1] if "/" in tid else TARGET_NAMES.get(tid.rstrip("0123456789"), tid)
            what = KIND_WORDS.get(str(t.get("kind")), str(t.get("kind") or "measurement"))
        targets.append(
            {
                "target_id": tid,
                "label": label,
                "what": what,
                "kind": t.get("kind"),
                "current_ms": t.get("current_ms"),
                "baseline_ms": t.get("baseline_ms"),
                "loss": t.get("loss"),
            }
        )
    return {"clients": clients, "targets": targets, "control": control, "via_extender": via_extender}


# Responses

WEB = "status_web"
SECURITY_HEADERS = {
    # The token is in the URL: never send it on as a referrer.
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "content-security-policy": "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'",
    "strict-transport-security": "max-age=31536000",
}


def _resp(status: int, body: str, ctype: str, cache: str = "no-store") -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"content-type": ctype, "cache-control": cache, **SECURITY_HEADERS},
        "body": body,
    }


def _json(status: int, doc: dict[str, Any]) -> dict[str, Any]:
    return _resp(status, json.dumps(doc, default=str), "application/json")


def _static(name: str) -> dict[str, Any]:
    try:
        body = resources.files("heimdall_cloud").joinpath(WEB, name).read_text()
    except (FileNotFoundError, IsADirectoryError):
        return _resp(404, "not found", "text/plain")
    ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
    if ctype.startswith("text/") or ctype == "application/javascript":
        ctype += "; charset=utf-8"
    return _resp(200, body, ctype, "public, max-age=300" if name != "index.html" else "no-store")


class StatusAPI:
    def __init__(
        self,
        table: Any,
        secret: Secret,
        sites: dict[str, str],
        control_device: str,
        now: Callable[[], float] = time.time,
    ):
        self.table, self.secret, self.sites, self.control, self.now = table, secret, sites, control_device, now

    def __call__(self, event: dict[str, Any], context: Any = None) -> dict[str, Any]:
        method = (event.get("requestContext") or {}).get("http", {}).get("method", "GET")
        path = event.get("rawPath") or "/"
        if method not in ("GET", "HEAD"):
            return _resp(405, "method not allowed", "text/plain")
        if path.startswith("/i/"):
            return _static("index.html")
        if path.startswith("/assets/") and re.fullmatch(r"/assets/[a-z0-9-]+\.(js|css|svg)", path):
            return _static(path.removeprefix("/assets/"))
        if path.startswith("/api/i/"):
            return self.api(path.removeprefix("/api/i/"))
        if path in ("/", "/favicon.ico"):
            return _resp(404, "Heimdall status pages are reached through a share link.", "text/plain")
        return _resp(404, "not found", "text/plain")

    def api(self, token: str) -> dict[str, Any]:
        try:
            device, incident_id = read_token(self.secret.value(), token, self.now())
        except LinkError as e:
            return _json(e.status, {"error": str(e)})
        doc = report(self.table, device, incident_id, self.sites, self.control, int(self.now() * 1000))
        if doc is None:
            return _json(404, {"error": "this incident is no longer available"})
        return _json(200, doc)


_api: StatusAPI | None = None


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    global _api
    if _api is None:
        import boto3

        _api = StatusAPI(
            table=boto3.resource("dynamodb").Table(os.environ["TABLE"]),
            secret=Secret(boto3.client("ssm"), os.environ["LINK_SECRET_PARAMETER"]),
            sites=json.loads(os.environ.get("EXTENDER_SITES", "{}")),
            control_device=os.environ.get("CONTROL_DEVICE", ""),
        )
    try:
        return _api(event, context)
    except Exception:
        log.exception("status request failed")
        return _json(500, {"error": "internal error"})
