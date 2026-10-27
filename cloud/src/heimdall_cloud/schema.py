"""Batch envelope and sample validation shared by the cloud components.

A batch is a gzip-compressed JSON object:

    {"device": "...", "probe_version": "...", "run_id": "...", "batch_seq": 1,
     "dropped_since_last": 0, "clock_offset_ms": -386.0, "samples": [...]}

Samples follow the probe's sample schema. The ingest flattens each sample
into a record whose columns match the Glue table: ``extra`` becomes a JSON
string, and partition fields ``device``, ``dt`` and ``hour`` are added for
Firehose dynamic partitioning.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

DEVICE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

KINDS = frozenset(
    {
        "icmp",
        "tcp",
        "http",
        "dns",
        "udp_echo",
        "stun",
        "udp_beacon",
        "trace",
        "wan",
        "cpu",
        "lan",
        "flow",
        "wifi_sta",
        "wifi_radio",
        "dnshealth",
        "clock",
        "event",
        "heartbeat",
        "self",
    }
)

MAX_SAMPLES = 20_000
MAX_STR = 256
MAX_EXTRA_JSON = 8192
# Samples more than this far from the receive time are rejected; the probe
# buffers at most a few hours of data during outages.
MAX_SKEW_MS = 7 * 24 * 3600 * 1000

STRING_FIELDS = ("kind", "category", "service", "target_id", "dst_ip", "status", "resolver_id")


class ValidationError(ValueError):
    """The batch does not match the schema."""


@dataclass
class Batch:
    device: str
    probe_version: str
    run_id: str
    batch_seq: int
    dropped_since_last: int
    clock_offset_ms: float | None
    samples: list[dict[str, Any]] = field(default_factory=list)
    rejected: int = 0


def _str(v: Any, name: str, *, required: bool = False, limit: int = MAX_STR) -> str | None:
    if v is None:
        if required:
            raise ValidationError(f"{name} is required")
        return None
    if not isinstance(v, str):
        raise ValidationError(f"{name} must be a string")
    if len(v) > limit:
        raise ValidationError(f"{name} longer than {limit}")
    return v


def _int(v: Any, name: str, *, required: bool = False, lo: int | None = None) -> int | None:
    if v is None:
        if required:
            raise ValidationError(f"{name} is required")
        return None
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValidationError(f"{name} must be an integer")
    if lo is not None and v < lo:
        raise ValidationError(f"{name} must be >= {lo}")
    return v


def _num(v: Any, name: str) -> float | None:
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int | float):
        raise ValidationError(f"{name} must be a number")
    return float(v)


def parse_batch(doc: Any, now_ms: int) -> Batch:
    """Validate the envelope and keep the samples that are valid.

    Envelope errors reject the whole batch. Individual malformed samples are
    dropped and counted in ``Batch.rejected``, so one bad sample does not
    make the probe resend everything.
    """
    if not isinstance(doc, dict):
        raise ValidationError("batch must be a JSON object")
    device = _str(doc.get("device"), "device", required=True)
    if not DEVICE_RE.match(device):
        raise ValidationError("device has invalid characters")
    run_id = _str(doc.get("run_id"), "run_id") or ""
    if run_id and not RUN_ID_RE.match(run_id):
        raise ValidationError("run_id has invalid characters")
    raw = doc.get("samples")
    if not isinstance(raw, list):
        raise ValidationError("samples must be a list")
    if len(raw) > MAX_SAMPLES:
        raise ValidationError(f"more than {MAX_SAMPLES} samples")

    batch = Batch(
        device=device,
        probe_version=_str(doc.get("probe_version"), "probe_version", limit=64) or "",
        run_id=run_id,
        batch_seq=_int(doc.get("batch_seq"), "batch_seq", lo=0) or 0,
        dropped_since_last=_int(doc.get("dropped_since_last"), "dropped_since_last", lo=0) or 0,
        clock_offset_ms=_num(doc.get("clock_offset_ms"), "clock_offset_ms"),
    )
    for s in raw:
        try:
            batch.samples.append(_sample(s, device, now_ms))
        except ValidationError:
            batch.rejected += 1
    return batch


def _sample(s: Any, device: str, now_ms: int) -> dict[str, Any]:
    if not isinstance(s, dict):
        raise ValidationError("sample must be an object")
    out: dict[str, Any] = {}
    ts = _int(s.get("ts_ms"), "ts_ms", required=True, lo=1)
    if abs(ts - now_ms) > MAX_SKEW_MS:
        raise ValidationError("ts_ms too far from receive time")
    out["ts_ms"] = ts
    out["seq"] = _int(s.get("seq"), "seq", lo=0)
    for name in STRING_FIELDS:
        out[name] = _str(s.get(name), name)
    if out["kind"] not in KINDS:
        raise ValidationError("unknown kind")
    if not out["status"]:
        raise ValidationError("status is required")
    port = _int(s.get("dst_port"), "dst_port", lo=0)
    out["dst_port"] = port if port else None
    out["rtt_ms"] = _num(s.get("rtt_ms"), "rtt_ms")
    extra = s.get("extra")
    if extra is not None:
        if not isinstance(extra, dict):
            raise ValidationError("extra must be an object")
        encoded = json.dumps(extra, separators=(",", ":"), sort_keys=True)
        if len(encoded) > MAX_EXTRA_JSON:
            raise ValidationError("extra too large")
        out["extra"] = encoded
    else:
        out["extra"] = None
    # The device comes from the authenticated envelope, never from the sample.
    out["device"] = device
    return out


def to_record(sample: dict[str, Any], batch: Batch, recv_ms: int, src_ip: str, src_asn: int | None) -> bytes:
    """Serialize one sample as a newline-terminated JSON record for Firehose."""
    t = datetime.fromtimestamp(sample["ts_ms"] / 1000, UTC)
    rec = dict(sample)
    rec.update(
        recv_ts_ms=recv_ms,
        src_ip=src_ip,
        src_asn=src_asn,
        run_id=batch.run_id,
        batch_seq=batch.batch_seq,
        probe_version=batch.probe_version,
        clock_offset_ms=batch.clock_offset_ms,
        dt=t.strftime("%Y-%m-%d"),
        hour=t.strftime("%H"),
    )
    return (json.dumps(rec, separators=(",", ":")) + "\n").encode()
