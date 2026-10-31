import json

import pytest
from test_notify import WEBHOOK, ev, notifier

from heimdall_cloud import status
from heimdall_cloud.status import LinkError, StatusAPI, make_token, read_token, report

SECRET = b"k" * 32
NOW_S = 1_793_020_100


class FixedSecret:
    def value(self):
        return SECRET


def test_token_roundtrip_tamper_and_expiry():
    t = make_token(SECRET, "wx5600-ap-17479", "ab193cadc360bffa", NOW_S + 60)
    assert read_token(SECRET, t, NOW_S) == ("wx5600-ap-17479", "ab193cadc360bffa")
    with pytest.raises(LinkError) as e:
        read_token(SECRET, t, NOW_S + 61)
    assert e.value.status == 410
    # Another incident in the payload breaks the signature.
    sig = t.split(".")[1]
    other = make_token(SECRET, "wx5600-ap-17479", "0000000000000000", NOW_S + 60).split(".")[0]
    for bad in (f"{other}.{sig}", make_token(b"x" * 32, "ex7501-home", "ab193cadc360bffa", NOW_S + 60), "x", "a.b.c"):
        with pytest.raises(LinkError) as e:
            read_token(SECRET, bad, NOW_S)
        assert e.value.status == 404


def _incident(n, device, **kw):
    client = {"node": "WX5600-AP-17479", "band": "5GHz", "rssi": -29, "client_name": "kagan-pc"}
    x = {"scope": "client", "cause": "lan_latency", "services": ["aaa"], "confirmed": True, "mode": "fast",
         "started_ms": 1_793_020_000_000, "detected_ms": 1_793_020_005_000,
         "targets": [{"target_id": "flow/aaa", "kind": "flow", "current_ms": 41.2, "baseline_ms": 1.3}],
         "clients": {"aaa": client}}  # fmt: skip
    x.update(kw)
    n({"device": device, "events": [ev("incident_start", **x)]})
    return x


def test_report_for_an_extender_client(aws):
    table, ssm = aws
    posts = []
    n = notifier(table, ssm, posts)
    n.sites = {"wx5600-ap-17479": "ex7501-home"}
    _incident(n, "wx5600-ap-17479", incident_id="e1")
    # A service incident on the CPE at the same time shows up as degraded.
    _incident(n, "ex7501-home", incident_id="s1", scope="service", cause="path", services=["youtube"], clients=None,
              mode="regular", targets=[])  # fmt: skip
    r = report(table, "wx5600-ap-17479", "e1", n.sites, "aws-euc1", 1_793_020_010_000)
    assert r["incident"]["status"] == "open" and r["incident"]["seen_by"] == "extender"
    assert r["incident"]["site"] == "ex7501-home" and r["incident"]["mode"] == "fast"
    assert r["incident"]["detected_ms"] == 1_793_020_005_000
    assert r["verdict"]["party"] == "customer" and "kagan-pc" in r["verdict"]["headline"]
    states = {p["id"]: p["state"] for p in r["path"]}
    assert states["wifi"] == "fault" and states["path"] == "affected" and states["access"] == "normal"
    assert "backhaul" in states
    checks = {c["label"]: c["state"] for c in r["checks"]}
    assert checks["ISP access network"] == "normal" and checks["Internet services"] == "affected"
    assert r["measurements"][0]["label"] == "kagan-pc" and r["measurements"][0]["current_ms"] == 41.2
    assert r["clients"][0]["where"] == "WX5600-AP-17479, Wi-Fi 5GHz, -29 dBm"

    end = ev("incident_end", incident_id="e1", duration_s=20, ended_ms=1_793_020_020_000, scope="client")
    n({"device": "wx5600-ap-17479", "events": [end]})
    r = report(table, "wx5600-ap-17479", "e1", n.sites, "aws-euc1", 1_793_020_030_000)
    assert r["incident"]["status"] == "resolved" and r["incident"]["duration_s"] == 20
    assert report(table, "wx5600-ap-17479", "nope", n.sites, "aws-euc1", 0) is None


@pytest.mark.parametrize(
    ("control", "party"),
    [(["youtube"], "service"), ([], "isp_path"), (None, "isp_path")],
)
def test_service_verdict_follows_the_control_probe(control, party):
    v = status.verdict({"scope": "service", "cause": "path", "services": ["youtube"]}, {"control": control})
    assert v["party"] == party


def test_extender_offline_seen_by_the_gateway(aws):
    table, ssm = aws
    n = notifier(table, ssm, [])
    n.sites = {"wx5600-ap-17479": "ex7501-home"}
    _incident(n, "ex7501-home", incident_id="x1", scope="backhaul", cause="extender_unreachable",
              services=["extender"], clients=None,
              targets=[{"target_id": "extender", "kind": "icmp", "dst_ip": "192.168.1.2", "current_ms": 0,
                        "baseline_ms": 1.2, "loss": 0.53, "reason": "loss"}])  # fmt: skip
    r = report(table, "ex7501-home", "x1", n.sites, "aws-euc1", 1_793_020_010_000)
    assert r["incident"]["seen_by"] == "gateway"
    assert r["verdict"]["party"] == "equipment" and r["verdict"]["headline"] == "The mesh extender went offline"
    states = {p["id"]: p["state"] for p in r["path"]}
    assert states["backhaul"] == "fault" and states["wifi"] == "normal"


def test_every_cause_has_a_verdict():
    from heimdall_cloud.notify import CAUSES

    for cause in CAUSES:
        v = status.verdict({"scope": "client", "cause": cause, "services": ["aaa"]}, {})
        assert v["party"] != "unknown" and v["fixes"], cause


def api_event(path, method="GET"):
    return {"rawPath": path, "requestContext": {"http": {"method": method}}}


def test_api_routes(aws):
    table, ssm = aws
    n = notifier(table, ssm, [])
    _incident(n, "ex7501-home", incident_id="00000000000000c1")
    api = StatusAPI(table, FixedSecret(), {}, "aws-euc1", now=lambda: NOW_S)
    token = make_token(SECRET, "ex7501-home", "00000000000000c1", NOW_S + 60)

    page = api(api_event(f"/i/{token}"))
    assert page["statusCode"] == 200 and page["headers"]["content-type"].startswith("text/html")
    assert page["headers"]["referrer-policy"] == "no-referrer" and "/assets/app.js" in page["body"]
    for asset, ctype in (("app.js", "javascript"), ("app.css", "text/css"), ("mark.svg", "image/svg")):
        r = api(api_event(f"/assets/{asset}"))
        assert r["statusCode"] == 200 and ctype in r["headers"]["content-type"], asset

    r = api(api_event(f"/api/i/{token}"))
    assert r["statusCode"] == 200 and json.loads(r["body"])["incident"]["id"] == "00000000000000c1"
    assert api(api_event("/api/i/garbage"))["statusCode"] == 404
    expired = make_token(SECRET, "ex7501-home", "00000000000000c1", NOW_S - 1)
    assert api(api_event(f"/api/i/{expired}"))["statusCode"] == 410
    missing = make_token(SECRET, "ex7501-home", "0123456789abcdef", NOW_S + 60)
    assert api(api_event(f"/api/i/{missing}"))["statusCode"] == 404
    assert api(api_event("/assets/../status.py"))["statusCode"] == 404
    assert api(api_event(f"/api/i/{token}", "POST"))["statusCode"] == 405


def test_slack_posts_link_to_the_status_page(aws):
    table, ssm = aws
    ssm.put_parameter(Name=WEBHOOK, Type="SecureString", Value="https://hooks.slack.com/services/T/B/x")
    posts = []
    n = notifier(table, ssm, posts)
    n.status_url, n.link_secret = "https://status.example/", FixedSecret()
    _incident(n, "ex7501-home", incident_id="00000000000000c2")
    line = next(ln for ln in posts[0][1].splitlines() if ln.startswith("Status page"))
    token = line.rsplit("/i/", 1)[1]
    assert read_token(SECRET, token, n.now()) == ("ex7501-home", "00000000000000c2")


def test_customer_view_speaks_to_the_customer():
    home = status.verdict({"scope": "client", "cause": "weak_signal", "services": ["aaa"]}, {})
    assert home["customer_label"] == "You can fix this yourself" and home["customer_fixes"] == home["fixes"]
    isp = status.verdict({"scope": "access", "cause": "access_network", "services": []}, {})
    assert isp["customer_label"] == "Your provider is responsible"
    assert not any("OLT" in f for f in isp["customer_fixes"])


def _summary(s3, day, budget, flags):
    doc = {"devices": {"ex7501-home": {
        "attribution": {"latency_budget_ms": budget, "degraded_hours_by_cause": {"ext_hop": 2}},
        "lan_clients": [{"client": "aaa", "node": "WX5600-AP-17479", "medium": "wifi", "flags": flags},
                        {"client": "bbb", "node": "cpe", "medium": "wired", "flags": []}]}}}  # fmt: skip
    s3.put_object(Bucket="raw", Key=f"derived/summary/dt={day}/summary.json", Body=json.dumps(doc).encode())


def test_home_report(aws):
    import boto3

    table, ssm = aws
    s3 = boto3.client("s3", region_name="eu-central-1")
    s3.create_bucket(Bucket="raw", CreateBucketConfiguration={"LocationConstraint": "eu-central-1"})
    now_s = 1_793_020_000  # 2026-10-26 14:26 UTC
    _summary(s3, "2026-10-25", {"wifi": 2.0, "access": 4.0, "beyond_isp": 30.0}, ["weak_signal"])
    _summary(s3, "2026-10-24", {"wifi": 4.0, "access": 4.0, "beyond_isp": 40.0}, [])
    table.put_item(Item={"device": "names#ex7501-home", "incident_id": "aaa", "name": "kagan-pc"})

    n = notifier(table, ssm, [])
    n.sites = {"wx5600-ap-17479": "ex7501-home"}
    _incident(n, "wx5600-ap-17479", incident_id="00000000000000e1", started_ms=(now_s - 3600) * 1000, mode="regular")
    _incident(n, "ex7501-home", incident_id="00000000000000a1", scope="access", cause="access_network",
              services=[], clients=None, targets=[], started_ms=(now_s - 7200) * 1000, mode="regular")  # fmt: skip
    _incident(n, "wx5600-ap-17479", incident_id="00000000000000f1", started_ms=(now_s - 60) * 1000)

    api = StatusAPI(table, FixedSecret(), n.sites, "aws-euc1", now=lambda: now_s, s3=s3, bucket="raw")
    token = make_token(SECRET, "ex7501-home", "home", now_s + 60)
    page = api(api_event(f"/h/{token}"))
    assert page["statusCode"] == 200 and "/assets/home.js" in page["body"]
    r = json.loads(api(api_event(f"/api/h/{token}"))["body"])
    assert r["period"] == {"from": "2026-10-19", "to": "2026-10-25"}
    parts = {p["id"]: p["ms"] for p in r["delay"]["parts"]}
    assert parts == {"wifi": 3.0, "access": 4.0, "beyond_isp": 35.0} and r["delay"]["total_ms"] == 42.0
    assert [d["slow_hours"] for d in r["days"] if d["analysed"]] == [2, 2]
    assert r["counts"] == {"home": 1, "equipment": 0, "isp": 1, "service": 0}
    # The demo incident is listed but not counted.
    assert [i["demo"] for i in r["incidents"]] == [True, False, False]
    assert r["incidents"][1]["link"].startswith("/i/") and r["incidents"][1]["link"].endswith("?view=customer")
    devs = {d["label"]: d for d in r["devices"]}
    assert devs["kagan-pc"]["tips"][0]["issue"] == "Weak Wi-Fi signal" and devs["Device bbb"]["ok"]

    # A home link does not open an incident, nor an incident link a home.
    assert api(api_event(f"/api/i/{token}"))["statusCode"] == 404
    inc = make_token(SECRET, "ex7501-home", "00000000000000a1", now_s + 60)
    assert api(api_event(f"/api/h/{inc}"))["statusCode"] == 404
    doc = json.loads(api(api_event(f"/api/i/{inc}"))["body"])
    assert doc["home_link"].startswith("/h/")
