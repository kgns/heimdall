import gzip
import json
import os
from datetime import date

import boto3
from moto import mock_aws

from heimdall_cloud import analytics

DAY = date(2026, 10, 26)
os.environ.setdefault("AWS_DEFAULT_REGION", "eu-central-1")


class FakeAthena:
    """Answers each query by the first registered marker found in its SQL."""

    def __init__(self, answers):
        self.answers = answers
        self.queries = []

    def query(self, sql):
        self.queries.append(sql)
        for marker, rows in self.answers.items():
            if marker in sql:
                return rows
        raise AssertionError(f"unexpected query: {sql[:200]}")


def test_daily_compare_attribution():
    rows = [
        {
            "device": "home",
            "service": "a",
            "hour": "20",
            "cpe_p50": "40",
            "cpe_ratio": "2.0",
            "control_p50": "10",
            "control_ratio": "1.0",
        },
        {
            "device": "home",
            "service": "b",
            "hour": "20",
            "cpe_p50": "40",
            "cpe_ratio": "2.0",
            "control_p50": "20",
            "control_ratio": "1.8",
        },
        {
            "device": "home",
            "service": "c",
            "hour": "20",
            "cpe_p50": "21",
            "cpe_ratio": "1.05",
            "control_p50": None,
            "control_ratio": None,
        },
        {
            "device": "home",
            "service": "d",
            "hour": "20",
            "cpe_p50": "50",
            "cpe_ratio": "1.5",
            "control_p50": None,
            "control_ratio": None,
        },
    ]
    out = analytics.daily_compare(FakeAthena({"control_ratio": rows}), DAY, "aws-euc1")
    assert [r["attribution"] for r in out] == ["access_or_path", "service", "normal", "no_control"]


def test_path_borders():
    hops = [
        {"ttl": 1, "ip": "10.234.0.1", "rtt_ms": 3.0},
        {"ttl": 2, "ip": None, "rtt_ms": None},
        {"ttl": 3, "ip": "195.175.1.1", "rtt_ms": 4.0},
        {"ttl": 4, "ip": "80.231.1.1", "rtt_ms": 30.0},
        {"ttl": 5, "ip": "52.93.1.1", "rtt_ms": 45.0},
    ]
    rows = [
        {
            "device": "home",
            "service": "s",
            "target_id": "s/x",
            "dst_ip": "52.93.1.1",
            "hops": json.dumps(hops),
            "n": "3",
            "total": "4",
            "paths": "2",
        }
    ]
    asn_of = {"195.175.1.1": 34984, "80.231.1.1": 6453, "52.93.1.1": 16509}
    [b] = analytics.path_borders(FakeAthena({"main_path": rows, "reached": rows}), DAY, asn_of, {"home": 34984})
    assert b["border_ip"] == "80.231.1.1" and b["next_asn"] == 6453 and b["border_jump_ms"] == 26.0
    assert b["as_path"] == [34984, 6453, 16509] and b["main_path_share"] == 0.75 and b["paths"] == 2


def test_ip_asn_uses_known_and_names():
    calls = []

    def fetch(url):
        calls.append(url)
        if "network-info" in url:
            return {"data": {"asns": ["6453"], "prefix": "80.231.0.0/16"}}
        return {"data": {"holder": "TATA"}}

    known = {"1.1.1.1": {"ip": "1.1.1.1", "asn": 13335, "as_name": "CLOUDFLARENET"}}
    out = analytics.ip_asn(["1.1.1.1", "80.231.1.1"], known, analytics.RIPEstat(fetch))
    assert [r["ip"] for r in out] == ["1.1.1.1", "80.231.1.1"]
    assert out[1] == {"ip": "80.231.1.1", "asn": 6453, "prefix": "80.231.0.0/16", "as_name": "TATA"}
    assert sum("network-info" in c for c in calls) == 1


def test_summarize():
    services = [
        {
            "device": "home",
            "category": "streaming",
            "service": "a",
            "kind": "icmp",
            "loss_pct": 2.5,
            "busy_inflation": 1.6,
            "busy_p50": 32.0,
            "night_p50": 20.0,
        },
        {
            "device": "home",
            "category": "streaming",
            "service": "b",
            "kind": "icmp",
            "loss_pct": 0.0,
            "busy_inflation": 1.05,
            "busy_p50": 21.0,
            "night_p50": 20.0,
        },
        {
            "device": "aws-euc1",
            "category": "streaming",
            "service": "a",
            "kind": "icmp",
            "loss_pct": 0.0,
            "busy_inflation": 1.0,
            "busy_p50": 5.0,
            "night_p50": 5.0,
        },
    ]
    compare = [
        {"device": "home", "service": "a", "attribution": "access_or_path"},
        {"device": "home", "service": "a", "attribution": "access_or_path"},
        {"device": "home", "service": "b", "attribution": "normal"},
    ]
    borders = [
        {
            "device": "home",
            "service": "a",
            "target_id": "a/x",
            "next_asn": 6453,
            "border_ip": "80.231.1.1",
            "border_jump_ms": 26.0,
        }
    ]
    s = analytics.summarize(DAY, services, compare, borders, [], {6453: "TATA"}, "aws-euc1")
    d = s["devices"]["home"]
    assert list(s["devices"]) == ["home"] and d["services_measured"] == 2
    assert d["busy_hour_inflation"] == [{"service": "a", "ratio": 1.6, "busy_p50": 32.0, "night_p50": 20.0}]
    assert d["loss"] == [{"service": "a", "loss_pct": 2.5}]
    assert d["degraded_hours"] == {"a": {"access_or_path": 2}}
    assert d["next_as"] == [{"asn": 6453, "name": "TATA", "targets": 1}]
    assert d["large_border_jumps"][0]["border_jump_ms"] == 26.0


def test_store_round_trip():
    with mock_aws():
        s3 = boto3.client("s3", region_name="eu-central-1")
        s3.create_bucket(Bucket="heimdall-test", CreateBucketConfiguration={"LocationConstraint": "eu-central-1"})
        st = analytics.Store(s3, "heimdall-test")
        assert st.get_rows("ip_asn", DAY) == []
        k = st.put_rows("ip_asn", DAY, [{"ip": "1.1.1.1", "asn": 13335}])
        assert k == "derived/ip_asn/dt=2026-10-26/part-0.json.gz"
        assert st.get_rows("ip_asn", DAY) == [{"ip": "1.1.1.1", "asn": 13335}]
        body = s3.get_object(Bucket="heimdall-test", Key=k)["Body"].read()
        assert gzip.decompress(body).decode().endswith("\n")
        assert st.put_doc("summary", DAY, {"x": 1}) == "derived/summary/dt=2026-10-26/summary.json"


def test_atlas_ping_and_context():
    def fetch(url):
        if "/probes/" in url:
            return {"results": [{"id": 1}, {"id": 2}], "next": None}
        if "/measurements/1001/" in url:
            out = []
            # Probe 1: 10 ms at night (00 UTC = 03 local), 15 ms in the
            # evening (18 UTC = 21 local); probe 2 flat at 20 ms.
            for hour, rtt1, rtt2 in ((0, 10.0, 20.0), (18, 15.0, 20.0)):
                ts = 1_792_972_800 + hour * 3600
                out.append({"prb_id": 1, "timestamp": ts, "min": rtt1, "sent": 3, "rcvd": 3})
                out.append({"prb_id": 2, "timestamp": ts, "min": rtt2, "sent": 3, "rcvd": 2})
            return out
        return []

    from heimdall_cloud import external

    rows = external.atlas_ping(DAY, 34984, fetch)
    k = [r for r in rows if r["target"] == "k-root"]
    assert len(k) == 4 and {r["probe_id"] for r in k} == {1, 2}
    assert next(r for r in k if r["probe_id"] == 2)["loss_pct"] == 100 / 3
    services = [{"device": "home", "service": "k-root", "kind": "icmp", "p50": 12.0, "busy_inflation": 1.4}]
    ctx = analytics.external_context("home", services, rows, [{"entity": "asn/34984", "start_s": 1}], 34984)
    assert ctx["k-root"] == {
        "cpe_p50": 12.0,
        "cpe_busy_inflation": 1.4,
        "peer_probes": 2,
        "peer_p50": 17.5,
        "peer_busy_inflation": 1.25,
    }
    assert ctx["f-root"]["peer_probes"] == 0 and len(ctx["ioda_events"]) == 1
