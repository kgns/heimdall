"""Ingest Lambda behind the HTTP API: authenticates a device, validates its
batch and forwards the samples to Firehose.

Request: ``POST /v1/batch`` with ``Authorization: Bearer <token>``,
``Content-Encoding: gzip`` and the batch envelope as the body. The token is
checked against the SHA-256 digest stored in the SSM SecureString
``<prefix>/<device>/token_sha256``.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import time
import urllib.request
import zlib
from collections.abc import Callable, Iterable
from typing import Any

from heimdall_cloud.notify import incident_events
from heimdall_cloud.schema import Batch, ValidationError, parse_batch, to_record

log = logging.getLogger()
log.setLevel(logging.INFO)

MAX_COMPRESSED = 2 * 1024 * 1024
MAX_DECOMPRESSED = 16 * 1024 * 1024
FIREHOSE_MAX_RECORDS = 500
FIREHOSE_MAX_BYTES = 4 * 1024 * 1024 - 64 * 1024
TOKEN_CACHE_SECONDS = 300
ASN_CACHE_SECONDS = 6 * 3600


class HTTPError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def response(status: int, body: dict[str, Any]) -> dict[str, Any]:
    return {"statusCode": status, "headers": {"content-type": "application/json"}, "body": json.dumps(body)}


def decode_body(event: dict[str, Any]) -> bytes:
    """Return the decompressed request body, refusing oversized payloads."""
    body = event.get("body") or ""
    raw = base64.b64decode(body) if event.get("isBase64Encoded") else body.encode()
    if len(raw) > MAX_COMPRESSED:
        raise HTTPError(413, "body too large")
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    if headers.get("content-encoding", "").lower() != "gzip":
        if len(raw) > MAX_DECOMPRESSED:
            raise HTTPError(413, "body too large")
        return raw
    # Decompress in bounded steps so a small malicious payload cannot expand
    # without limit.
    d = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(raw, MAX_DECOMPRESSED + 1)
    except zlib.error as e:
        raise HTTPError(400, "invalid gzip body") from e
    if len(out) > MAX_DECOMPRESSED or d.unconsumed_tail:
        raise HTTPError(413, "decompressed body too large")
    if not d.eof:
        raise HTTPError(400, "truncated gzip body")
    return out


def bearer_token(event: dict[str, Any]) -> str:
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    scheme, _, token = headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPError(401, "missing bearer token")
    return token.strip()


class TokenStore:
    """Looks up and caches per-device token digests in SSM Parameter Store."""

    def __init__(self, ssm: Any, prefix: str, clock: Callable[[], float] = time.monotonic):
        self.ssm = ssm
        self.prefix = prefix.rstrip("/")
        self.clock = clock
        self._cache: dict[str, tuple[float, str | None]] = {}

    def digest(self, device: str) -> str | None:
        hit = self._cache.get(device)
        if hit and self.clock() - hit[0] < TOKEN_CACHE_SECONDS:
            return hit[1]
        name = f"{self.prefix}/{device}/token_sha256"
        try:
            value = self.ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"].strip().lower()
        except self.ssm.exceptions.ParameterNotFound:
            value = None
        self._cache[device] = (self.clock(), value)
        return value

    def check(self, device: str, token: str) -> bool:
        want = self.digest(device)
        got = hashlib.sha256(token.encode()).hexdigest()
        # Compare against a dummy digest for unknown devices so that timing
        # does not reveal which device names exist.
        return hmac.compare_digest(got, want or "0" * 64) and want is not None


class ASNLookup:
    """Best-effort origin ASN of the source address via RIPEstat, cached."""

    URL = "https://stat.ripe.net/data/network-info/data.json?resource={ip}&sourceapp=heimdall"

    def __init__(
        self, fetch: Callable[[str], dict[str, Any]] | None = None, clock: Callable[[], float] = time.monotonic
    ):
        self.fetch = fetch or self._fetch
        self.clock = clock
        self._cache: dict[str, tuple[float, int | None]] = {}

    @staticmethod
    def _fetch(url: str) -> dict[str, Any]:
        with urllib.request.urlopen(url, timeout=1.5) as r:  # noqa: S310 - fixed https URL
            return json.load(r)

    def asn(self, ip: str) -> int | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if not addr.is_global:
            return None
        hit = self._cache.get(ip)
        if hit and self.clock() - hit[0] < ASN_CACHE_SECONDS:
            return hit[1]
        value = None
        try:
            asns = self.fetch(self.URL.format(ip=ip)).get("data", {}).get("asns") or []
            value = int(asns[0]) if asns else None
        except Exception as e:  # lookups never fail the ingest
            log.warning("asn lookup failed for %s: %s", ip, e)
        self._cache[ip] = (self.clock(), value)
        return value


def chunk_records(records: Iterable[bytes]) -> Iterable[list[bytes]]:
    """Group records into PutRecordBatch calls within the API limits."""
    batch: list[bytes] = []
    size = 0
    for r in records:
        if batch and (len(batch) == FIREHOSE_MAX_RECORDS or size + len(r) > FIREHOSE_MAX_BYTES):
            yield batch
            batch, size = [], 0
        batch.append(r)
        size += len(r)
    if batch:
        yield batch


def put_all(firehose: Any, stream: str, records: list[bytes], attempts: int = 3) -> int:
    """Send records, retrying the ones Firehose rejects. Returns how many
    could not be delivered."""
    failed = 0
    for group in chunk_records(records):
        pending = group
        for attempt in range(attempts):
            resp = firehose.put_record_batch(DeliveryStreamName=stream, Records=[{"Data": r} for r in pending])
            if resp.get("FailedPutCount", 0) == 0:
                pending = []
                break
            pending = [r for r, res in zip(pending, resp["RequestResponses"], strict=True) if res.get("ErrorCode")]
            time.sleep(0.1 * (2**attempt))
        failed += len(pending)
    return failed


class Handler:
    def __init__(
        self,
        ssm: Any,
        firehose: Any,
        stream: str,
        token_prefix: str,
        asn: ASNLookup | None = None,
        now_ms: Callable[[], int] = lambda: int(time.time() * 1000),
        notify: Callable[[str, list[dict[str, Any]]], None] | None = None,
    ):
        self.tokens = TokenStore(ssm, token_prefix)
        self.firehose = firehose
        self.stream = stream
        self.asn = asn or ASNLookup()
        self.now_ms = now_ms
        self.notify = notify

    def __call__(self, event: dict[str, Any], context: Any = None) -> dict[str, Any]:
        try:
            return self.handle(event)
        except HTTPError as e:
            if e.status >= 500:
                log.error("ingest failed: %s", e.message)
            return response(e.status, {"error": e.message})

    def handle(self, event: dict[str, Any]) -> dict[str, Any]:
        token = bearer_token(event)
        try:
            doc = json.loads(decode_body(event))
        except (ValueError, UnicodeDecodeError) as e:
            raise HTTPError(400, "body is not JSON") from e
        recv = self.now_ms()
        try:
            batch: Batch = parse_batch(doc, recv)
        except ValidationError as e:
            raise HTTPError(400, str(e)) from e
        if not self.tokens.check(batch.device, token):
            raise HTTPError(401, "invalid token")

        src_ip = (event.get("requestContext") or {}).get("http", {}).get("sourceIp", "")
        src_asn = self.asn.asn(src_ip)
        records = [to_record(s, batch, recv, src_ip, src_asn) for s in batch.samples]
        failed = put_all(self.firehose, self.stream, records) if records else 0
        log.info(
            json.dumps(
                {
                    "device": batch.device,
                    "run_id": batch.run_id,
                    "batch_seq": batch.batch_seq,
                    "samples": len(records),
                    "rejected": batch.rejected,
                    "failed": failed,
                    "dropped_since_last": batch.dropped_since_last,
                    "src_ip": src_ip,
                    "src_asn": src_asn,
                }
            )
        )
        if failed:
            # The probe resends the whole batch; duplicates are removed
            # downstream by (device, run_id, seq).
            raise HTTPError(503, f"{failed} records not delivered")
        if self.notify:
            events = incident_events(batch.samples)
            if events:
                try:
                    self.notify(batch.device, events)
                except Exception as e:  # notifications never fail the ingest
                    log.error("notify failed: %s", e)
        return response(200, {"accepted": len(records), "rejected": batch.rejected})


_handler: Handler | None = None


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    global _handler
    if _handler is None:
        import boto3

        notify = None
        if fn := os.environ.get("NOTIFIER_FUNCTION"):
            lam = boto3.client("lambda")

            def notify(device: str, events: list[dict[str, Any]]) -> None:
                payload = json.dumps({"device": device, "events": events}).encode()
                lam.invoke(FunctionName=fn, InvocationType="Event", Payload=payload)

        _handler = Handler(
            ssm=boto3.client("ssm"),
            firehose=boto3.client("firehose"),
            stream=os.environ["FIREHOSE_STREAM"],
            token_prefix=os.environ["TOKEN_PREFIX"],
            notify=notify,
        )
    return _handler(event, context)


def gzip_batch(doc: dict[str, Any]) -> bytes:
    """Encode a batch the way the probe does; used by tests and tools."""
    return gzip.compress(json.dumps(doc).encode())
