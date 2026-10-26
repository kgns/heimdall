import base64
import gzip
import hashlib
import json
import os

import boto3
import pytest
from moto import mock_aws

from heimdall_cloud import ingest
from heimdall_cloud.schema import MAX_SKEW_MS, ValidationError, parse_batch

NOW = 1_793_020_000_000
TOKEN = "s3cret-token-for-tests"
os.environ.setdefault("AWS_DEFAULT_REGION", "eu-central-1")


def sample(**kw):
    s = {
        "ts_ms": NOW - 1000,
        "device": "ignored",
        "seq": 1,
        "kind": "icmp",
        "category": "infra",
        "service": "isp-hop",
        "target_id": "isp-hop1",
        "dst_ip": "10.234.0.1",
        "rtt_ms": 3.6,
        "status": "ok",
        "extra": {"ttl": 255},
    }
    s.update(kw)
    return s


def batch(**kw):
    b = {
        "device": "ex7501-home",
        "probe_version": "abc123",
        "run_id": "r1",
        "batch_seq": 7,
        "dropped_since_last": 0,
        "clock_offset_ms": 386.5,
        "samples": [sample()],
    }
    b.update(kw)
    return b


def event(doc=None, token=TOKEN, gz=True, raw=None, b64=True, ip="88.230.12.34"):
    body = raw if raw is not None else json.dumps(doc).encode()
    if gz and raw is None:
        body = gzip.compress(body)
    headers = {"Content-Type": "application/octet-stream"}
    if gz:
        headers["Content-Encoding"] = "gzip"
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return {
        "headers": headers,
        "body": base64.b64encode(body).decode() if b64 else body.decode(),
        "isBase64Encoded": b64,
        "requestContext": {"http": {"sourceIp": ip, "method": "POST", "path": "/v1/batch"}},
    }


class FakeFirehose:
    def __init__(self, fail_first=0):
        self.calls = []
        self.fail_first = fail_first

    def put_record_batch(self, DeliveryStreamName, Records):
        self.calls.append(Records)
        resps = []
        for _ in Records:
            if self.fail_first > 0:
                self.fail_first -= 1
                resps.append({"ErrorCode": "ServiceUnavailableException"})
            else:
                resps.append({"RecordId": "x"})
        return {"FailedPutCount": sum(1 for r in resps if "ErrorCode" in r), "RequestResponses": resps}

    def records(self):
        out = []
        for call in self.calls:
            out += [json.loads(r["Data"]) for r in call]
        return out


@pytest.fixture
def ssm():
    with mock_aws():
        c = boto3.client("ssm", region_name="eu-central-1")
        c.put_parameter(
            Name="/heimdall/devices/ex7501-home/token_sha256",
            Type="SecureString",
            Value=hashlib.sha256(TOKEN.encode()).hexdigest(),
        )
        yield c


def handler(ssm, fh=None, asn=65000):
    return ingest.Handler(
        ssm=ssm,
        firehose=fh or FakeFirehose(),
        stream="heimdall-samples",
        token_prefix="/heimdall/devices",
        asn=ingest.ASNLookup(fetch=lambda _: {"data": {"asns": [asn]}}),
        now_ms=lambda: NOW,
    )


def test_accepts_valid_batch(ssm):
    fh = FakeFirehose()
    resp = handler(ssm, fh)(event(batch()))
    assert resp["statusCode"] == 200, resp
    assert json.loads(resp["body"]) == {"accepted": 1, "rejected": 0}
    [rec] = fh.records()
    assert rec["device"] == "ex7501-home"
    assert rec["extra"] == '{"ttl":255}'
    assert rec["src_ip"] == "88.230.12.34" and rec["src_asn"] == 65000
    assert rec["recv_ts_ms"] == NOW and rec["run_id"] == "r1" and rec["batch_seq"] == 7
    assert rec["clock_offset_ms"] == 386.5 and rec["probe_version"] == "abc123"
    assert rec["dt"] == "2026-10-26" and rec["hour"] == "13"
    assert fh.calls[0][0]["Data"].endswith(b"\n")


def test_plain_body_without_gzip(ssm):
    resp = handler(ssm)(event(batch(), gz=False, b64=False))
    assert resp["statusCode"] == 200


@pytest.mark.parametrize("token", [None, "wrong", ""])
def test_rejects_bad_token(ssm, token):
    fh = FakeFirehose()
    resp = handler(ssm, fh)(event(batch(), token=token))
    assert resp["statusCode"] == 401
    assert fh.calls == []


def test_rejects_unknown_device(ssm):
    resp = handler(ssm)(event(batch(device="other-device")))
    assert resp["statusCode"] == 401


def test_token_cache(ssm):
    h = handler(ssm)
    h(event(batch()))
    ssm.delete_parameter(Name="/heimdall/devices/ex7501-home/token_sha256")
    assert h(event(batch()))["statusCode"] == 200


@pytest.mark.parametrize(
    "raw,status",
    [(b"\x1f\x8b\x08\x00garbage", 400), (gzip.compress(b"not json"), 400), (gzip.compress(b"[1,2]"), 400)],
)
def test_rejects_bad_bodies(ssm, raw, status):
    assert handler(ssm)(event(raw=raw))["statusCode"] == status


def test_rejects_gzip_bomb(ssm):
    bomb = gzip.compress(b"{" + b" " * (ingest.MAX_DECOMPRESSED + 10) + b"}")
    assert len(bomb) < ingest.MAX_COMPRESSED
    assert handler(ssm)(event(raw=bomb))["statusCode"] == 413


def test_rejects_oversized_body(ssm):
    big = os.urandom(ingest.MAX_COMPRESSED + 1)
    assert handler(ssm)(event(raw=big))["statusCode"] == 413


def test_drops_bad_samples_keeps_good(ssm):
    fh = FakeFirehose()
    samples = [
        sample(),
        sample(kind="bogus"),
        sample(ts_ms=NOW - MAX_SKEW_MS - 1),
        sample(rtt_ms="fast"),
        sample(extra=[1, 2]),
        sample(status=None),
        "not an object",
        sample(kind="event", rtt_ms=None, extra={"event": "start"}),
    ]
    resp = handler(ssm, fh)(event(batch(samples=samples)))
    assert json.loads(resp["body"]) == {"accepted": 2, "rejected": 6}
    assert len(fh.records()) == 2


def test_sample_device_cannot_be_spoofed(ssm):
    fh = FakeFirehose()
    handler(ssm, fh)(event(batch(samples=[sample(device="someone-else")])))
    assert fh.records()[0]["device"] == "ex7501-home"


def test_envelope_validation():
    for bad in [
        [],
        {"device": "Bad Name", "samples": []},
        {"device": "x"},
        {"device": "x", "samples": {}},
        {"device": "x", "samples": [], "run_id": "../../etc"},
        {"device": "x", "samples": [], "batch_seq": -1},
    ]:
        with pytest.raises(ValidationError):
            parse_batch(bad, NOW)


def test_firehose_chunking_and_retry(ssm):
    fh = FakeFirehose(fail_first=3)
    samples = [sample(seq=i) for i in range(1203)]
    resp = handler(ssm, fh)(event(batch(samples=samples)))
    assert resp["statusCode"] == 200
    sizes = [len(c) for c in fh.calls]
    # The three records rejected in the first call are retried right away.
    assert sizes == [500, 3, 500, 203]
    assert sorted(r["seq"] for r in fh.records())[-1] == 1202


def test_firehose_persistent_failure_returns_503(ssm):
    fh = FakeFirehose(fail_first=10**6)
    resp = handler(ssm, fh)(event(batch()))
    assert resp["statusCode"] == 503


def test_chunk_respects_byte_limit():
    big = b"x" * (1024 * 1024)
    groups = list(ingest.chunk_records([big] * 9))
    assert all(sum(map(len, g)) <= ingest.FIREHOSE_MAX_BYTES for g in groups)
    assert sum(len(g) for g in groups) == 9


def test_asn_lookup_skips_private_and_caches():
    calls = []
    lookup = ingest.ASNLookup(fetch=lambda url: calls.append(url) or {"data": {"asns": [34984]}})
    assert lookup.asn("10.0.0.1") is None
    assert lookup.asn("88.230.12.34") == 34984
    assert lookup.asn("88.230.12.34") == 34984
    assert len(calls) == 1

    def boom(_):
        raise TimeoutError("slow")

    assert ingest.ASNLookup(fetch=boom).asn("88.230.12.34") is None


def test_lambda_handler_with_moto(monkeypatch):
    with mock_aws():
        region = "eu-central-1"
        s3 = boto3.client("s3", region_name=region)
        s3.create_bucket(Bucket="raw", CreateBucketConfiguration={"LocationConstraint": region})
        fh = boto3.client("firehose", region_name=region)
        fh.create_delivery_stream(
            DeliveryStreamName="heimdall-samples",
            ExtendedS3DestinationConfiguration={
                "RoleARN": "arn:aws:iam::123456789012:role/firehose",
                "BucketARN": "arn:aws:s3:::raw",
            },
        )
        boto3.client("ssm", region_name=region).put_parameter(
            Name="/heimdall/devices/ex7501-home/token_sha256",
            Type="SecureString",
            Value=hashlib.sha256(TOKEN.encode()).hexdigest(),
        )
        monkeypatch.setenv("FIREHOSE_STREAM", "heimdall-samples")
        monkeypatch.setenv("TOKEN_PREFIX", "/heimdall/devices")
        monkeypatch.setattr(ingest, "_handler", None)
        monkeypatch.setattr(ingest.ASNLookup, "_fetch", staticmethod(lambda url: {"data": {"asns": []}}))
        resp = ingest.lambda_handler(event(batch(samples=[sample(ts_ms=0)])), None)
        assert resp["statusCode"] == 200


def test_incident_events_are_forwarded(ssm):
    calls = []
    h = handler(ssm)
    h.notify = lambda device, events: calls.append((device, events))
    inc = sample(
        kind="event",
        seq=2,
        target_id=None,
        dst_ip=None,
        rtt_ms=None,
        extra={"event": "incident_start", "incident_id": "abc", "scope": "service", "services": ["netflix"]},
    )
    other = sample(kind="event", seq=3, target_id=None, dst_ip=None, rtt_ms=None, extra={"event": "dst_change"})
    resp = h(event(batch(samples=[sample(), inc, other])))
    assert resp["statusCode"] == 200
    [(device, events)] = calls
    assert device == "ex7501-home" and len(events) == 1
    assert events[0]["extra"]["incident_id"] == "abc" and events[0]["seq"] == 2

    # A batch without incidents does not notify, and a failing notifier
    # does not fail the ingest.
    calls.clear()
    assert h(event(batch()))["statusCode"] == 200 and not calls

    def boom(device, events):
        raise RuntimeError("lambda throttled")

    h.notify = boom
    assert h(event(batch(samples=[inc])))["statusCode"] == 200
