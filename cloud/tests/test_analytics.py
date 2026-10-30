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


def test_daily_client_and_findings():
    client_rows = [
        {
            "device": "home", "client": "aaa", "node": "WX5600", "medium": "wifi", "band": "5GHz",
            "flows": "120", "unanswered": "3", "lan_p50": "4.0", "lan_p90": "45.0", "lan_busy_p50": "6",
            "lan_night_p50": "3", "wan_p50": "40", "wan_p90": "60", "rssi_avg": "-78.5", "rssi_min": "-84",
            "snr_avg": "12", "retry_pct": "25", "tx_rate_p50": "300", "ps_share": "0.4", "ping_p50": "3",
            "ping_p95": "20", "ping_first_p50": "30", "ping_loss_pct": "1", "roams": "12", "leaves": "1",
        },
        {
            "device": "home", "client": "bbb", "node": "cpe", "medium": "wired", "band": None,
            "flows": "300", "unanswered": "0", "lan_p50": "1.5", "lan_p90": "2.0", "lan_busy_p50": None,
            "lan_night_p50": None, "wan_p50": "40", "wan_p90": "50", "rssi_avg": None, "rssi_min": None,
            "snr_avg": None, "retry_pct": None, "tx_rate_p50": None, "ps_share": None, "ping_p50": "0.4",
            "ping_p95": "1", "ping_first_p50": "0.5", "ping_loss_pct": "0", "roams": None, "leaves": None,
        },
    ]  # fmt: skip
    clients = analytics.daily_client(FakeAthena({"wifi_roam": client_rows}), DAY)
    assert clients[0]["rssi_avg"] == -78.5 and clients[1]["roams"] == 0 and clients[1]["band"] is None

    svc_rows = [
        {"device": "home", "client": "aaa", "service": "netflix", "category": "streaming", "flows": "10",
         "wan_p50": "80", "cpe_tcp_p50": "40"},
        {"device": "home", "client": "bbb", "service": "netflix", "category": "streaming", "flows": "10",
         "wan_p50": "41", "cpe_tcp_p50": "40"},
    ]  # fmt: skip
    svc = analytics.client_services(FakeAthena({"cpe_tcp_p50": svc_rows}), DAY)
    assert svc[0]["ratio"] == 2.0

    found = analytics.client_findings(clients, svc)
    # On the CPE the same signal is weak; on an extender the link rate decides.
    on_cpe = analytics.client_findings([{**clients[0], "node": "cpe"}], [])
    slow_link = analytics.client_findings([{**clients[0], "tx_rate_p50": 24.0}], [])
    assert "weak_signal" in on_cpe[0]["flags"] and "weak_link" in slow_link[0]["flags"]
    assert [f["client"] for f in found] == ["bbb", "aaa"]
    assert found[0]["flags"] == []
    assert found[1]["flags"] == ["slow_lan", "many_retries", "roaming", "wan_slower_than_cpe_probe"]
    assert found[1]["wan_vs_cpe_probe"] == 2.0 and "band" not in found[0]

    cross_rows = [
        {"device": "home", "client_device": "mbp", "client": "aaa", "service": "google", "matched": "30",
         "client_p50": "18", "cpe_wan_p50": "12", "cpe_lan_p50": "3", "gap_p50": "3", "gap_p90": "5"},
    ]  # fmt: skip
    cross = analytics.client_crosscheck(FakeAthena({"client_device": cross_rows}), DAY)
    s = analytics.summarize(DAY, [{"device": "home", "kind": "icmp", "category": "x", "service": "y",
                                   "busy_inflation": None, "loss_pct": 0}], [], [], [], {}, "aws-euc1",
                            clients, svc, cross)  # fmt: skip
    dev = s["devices"]["home"]
    assert [c["client"] for c in dev["lan_clients"]] == ["bbb", "aaa"]
    assert dev["client_crosscheck"][0]["gap_p50"] == 3.0 and "device" not in dev["client_crosscheck"][0]


def test_extender_sites_and_merge():
    sites = analytics.extender_sites(
        FakeAthena({"'$.site'": [{"device": "ext1", "site": "home"}, {"device": "bad id", "site": "home"}]}), DAY
    )
    assert sites == {"ext1": "home"}
    empty = ("medium", "band", "lan_busy_p50", "lan_night_p50", "wan_p50", "wan_p90", "rssi_min", "snr_avg",
             "retry_pct", "ping_p50", "ping_p95", "ping_first_p50", "ping_loss_pct")  # fmt: skip
    base = {**dict.fromkeys(empty), "node": "WX5600", "unanswered": 0, "roams": 0, "leaves": 0}
    cpe_row = {**base, "device": "home", "client": "aaa", "flows": 50, "lan_p50": 12.0, "lan_p90": 40.0,
               "rssi_avg": -95.0, "tx_rate_p50": 300.0, "ps_share": None}  # fmt: skip
    ext_row = {**base, "device": "ext1", "client": "aaa", "flows": 40, "lan_p50": 4.0, "lan_p90": 35.0,
               "rssi_avg": -79.0, "tx_rate_p50": 200.0, "ps_share": 0.5}  # fmt: skip
    only_ext = {**ext_row, "client": "bbb", "lan_p50": 2.0, "lan_p90": 3.0, "rssi_avg": -50.0}
    merged = analytics.merge_extenders([cpe_row, ext_row, only_ext], sites)
    assert [(r["device"], r["client"]) for r in merged] == [("home", "aaa"), ("home", "bbb")]
    a, b = merged
    assert a["hop_p50"] == 4.0 and a["hop_flows"] == 40 and a["ext_rssi_avg"] == -79.0 and a["lan_p50"] == 12.0
    assert b["flows"] == 0 and b["hop_p50"] == 2.0 and b["node"] == "WX5600" and b["lan_p50"] is None

    # The extender's own signal decides; the CPE adds 8 ms beyond the hop.
    [fa] = analytics.client_findings([a], [])
    assert {"weak_signal", "slow_lan", "slow_extender_hop", "slow_backhaul"} <= set(fa["flags"])
    assert "weak_link" not in fa["flags"]


def test_attribution():
    def hours(seg, values, n=100):
        return [{"device": "home", "hour": h, "segment": seg, "p50": v, "n": n} for h, v in values.items()]

    flat = dict.fromkeys(range(10), 4.0)
    rows = (
        hours("wifi", {**flat, 20: 20.0})
        + hours("access", {**dict.fromkeys(range(10), 3.0), 20: 3.0, 21: 3.0, 22: 30.0})
        + hours("wan", {**dict.fromkeys(range(10), 40.0), 20: 40.0, 21: 90.0, 22: 60.0})
        + hours("backhaul", {1: 50.0}, n=5)
    )
    compare = [{"device": "home", "hour": 21, "service": "x", "attribution": "access_or_path"}]
    recs, verdicts = analytics.attribute(rows, compare)
    v = verdicts["home"]
    assert v["latency_budget_ms"] == {"wifi": 4.0, "access": 3.0, "beyond_isp": 37.0}
    # 20h: the home Wi-Fi; 21h: beyond the ISP, which the control probe did
    # not see, so the ISP's path; 22h: the access network.
    assert v["degraded_hours_by_cause"] == {"wifi": 1, "isp_path": 1, "access": 1}
    worst = {w["local_hour"]: w["blame"] for w in v["degraded_hours"]}
    assert worst == {23: "wifi", 0: "isp_path", 1: "access"}
    assert not any(r["segment"] == "backhaul" for r in recs)
    assert next(r for r in recs if r["segment"] == "wifi" and r["hour"] == 20)["degraded"]


def test_summary_with_extender():
    services = [{"device": "home", "kind": "icmp", "category": "x", "service": "y", "busy_inflation": None,
                 "loss_pct": 0}]  # fmt: skip
    incs = [
        {"device": "home", "incident_id": "1", "scope": "service"},
        {"device": "ext1", "incident_id": "2", "scope": "client"},
    ]
    s = analytics.summarize(
        DAY, services, [], [], incs, {}, "aws-euc1", sites={"ext1": "home"},
        verdicts={"home": {"latency_budget_ms": {"wifi": 3.0}}},
        backhauls=[{"device": "ext1", "site": "home", "samples": 86000, "p50": 1.04, "p95": 2.0, "p99": 9.0,
                    "loss_pct": 0.0}],
    )  # fmt: skip
    d = s["devices"]["home"]
    assert list(s["devices"]) == ["home"]
    assert [(i["incident_id"], i["seen_by"]) for i in d["incidents"]] == [("1", "cpe"), ("2", "extender")]
    assert d["attribution"]["latency_budget_ms"] == {"wifi": 3.0}
    assert d["extenders"] == [{"device": "ext1", "backhaul": {"p50": 1.04, "p95": 2.0, "p99": 9.0, "loss_pct": 0.0,
                                                               "samples": 86000}}]  # fmt: skip
