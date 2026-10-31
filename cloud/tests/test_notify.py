import os

from heimdall_cloud.notify import Notifier, Webhook, client_label, format_message, incident_events

os.environ.setdefault("AWS_DEFAULT_REGION", "eu-central-1")
WEBHOOK = "/heimdall/slack/webhook_url"


def ev(event, incident_id="i1", device_ts=1_793_020_000_000, **extra):
    x = {"event": event, "incident_id": incident_id, "scope": "service", "cause": "path", "services": ["netflix"]}
    x.update(extra)
    return {"kind": "event", "ts_ms": device_ts, "extra": x}


def notifier(table, ssm, posts):
    return Notifier(
        table=table,
        webhook=Webhook(ssm, WEBHOOK),
        control_device="aws-euc1",
        grafana_url="https://heimdall.kgns.dev/",
        post=lambda url, text: posts.append((url, text)),
        now=lambda: 1_793_020_000,
    )


def test_incident_lifecycle_and_control(aws):
    table, ssm = aws
    posts = []
    n = notifier(table, ssm, posts)

    # Without a webhook the incident is stored but not posted.
    n({"device": "ex7501-home", "events": [ev("incident_start", targets=[{"target_id": "netflix/x", "kind": "icmp"}])]})
    assert table.get_item(Key={"device": "ex7501-home", "incident_id": "i1"})["Item"]["status"] == "open"
    assert posts == []

    ssm.put_parameter(Name=WEBHOOK, Type="SecureString", Value="https://hooks.slack.com/services/T/B/x")
    n.webhook._at = None
    # The control probe sees netflix too: stored, never posted.
    n({"device": "aws-euc1", "events": [ev("incident_start", incident_id="c1")]})
    assert posts == []
    n({"device": "ex7501-home", "events": [ev("incident_start", incident_id="i2")]})
    [(url, text)] = posts
    assert url.startswith("https://hooks.slack.com/") and "also degraded from eu-central-1" in text
    assert "ex7501-home" in text and "netflix" in text and "d/heimdall-overview" in text

    n({"device": "aws-euc1", "events": [ev("incident_end", incident_id="c1", duration_s=300)]})
    # An incident the control left open two days ago does not count.
    n({"device": "aws-euc1", "events": [ev("incident_start", incident_id="c0", started_ms=1_792_840_000_000)]})
    # Another cause, so not a repeat of i2.
    n({"device": "ex7501-home", "events": [ev("incident_start", incident_id="i3", cause="destination_change")]})
    assert "normal from eu-central-1" in posts[-1][1]

    n({"device": "ex7501-home", "events": [ev("incident_end", incident_id="i3", duration_s=420)]})
    item = table.get_item(Key={"device": "ex7501-home", "incident_id": "i3"})["Item"]
    assert item["status"] == "closed" and item["duration_s"] == 420
    assert "resolved after 7m" in posts[-1][1]


def test_format_access_and_tls():
    text = format_message(
        "ex7501-home",
        ev(
            "incident_start",
            scope="access",
            cause="access_network",
            services=["a", "b", "c"],
            targets=[
                {
                    "target_id": "isp-hop2",
                    "kind": "icmp",
                    "dst_ip": "10.36.7.234",
                    "current_ms": 40,
                    "baseline_ms": 4,
                    "reason": "latency+loss",
                    "loss": 0.2,
                }
            ],
        ),
        [],
        "",
    )
    assert "access network" in text and "40 ms vs 4 ms, loss 20%" in text and "AWS control" not in text
    assert ":no_entry:" in format_message("x", ev("incident_start", cause="tls_blocked"), None, "")


def test_incident_events_filter():
    samples = [
        {"kind": "event", "extra": '{"event":"incident_end","incident_id":"a"}'},
        {"kind": "event", "extra": '{"event":"dst_change"}'},
        {"kind": "icmp", "extra": '{"event":"incident_start"}'},
        {"kind": "event", "extra": None},
        {"kind": "event", "extra": {"event": "start", "version": "x"}},
    ]
    got, start = incident_events(samples)
    assert got["extra"]["incident_id"] == "a" and start["extra"]["event"] == "start"


def test_access_incident_gets_ioda_note(aws):
    table, ssm = aws
    ssm.put_parameter(Name=WEBHOOK, Type="SecureString", Value="https://hooks.slack.com/services/T/B/x")
    posts, asked = [], []
    n = notifier(table, ssm, posts)
    n.device_asn = {"ex7501-home": 34984}
    n.access_note = lambda asn, now: asked.append(asn) or f"IODA: no outage signal for AS{asn}"
    n({"device": "ex7501-home", "events": [ev("incident_start", scope="access", cause="access_network")]})
    assert asked == [34984] and "IODA: no outage signal for AS34984" in posts[-1][1]
    n({"device": "ex7501-home", "events": [ev("incident_start", incident_id="s1")]})
    assert asked == [34984]


def test_ioda_note():
    from heimdall_cloud.notify import ioda_note

    assert "no outage" in ioda_note(34984, 1_793_020_000, fetch=lambda url: {"data": []})
    hit = {"data": [{"start": 1_793_019_000, "duration": 600, "datasource": "bgp", "score": 812.4}]}
    assert ioda_note(34984, 1_793_020_000, fetch=lambda url: hit) == "IODA: outage signal for AS34984 (bgp, score 812)"

    def down(url):
        raise TimeoutError("timed out")

    # A failing fetch inside ioda_events is logged and treated as no events.
    assert "no outage" in ioda_note(34984, 1_793_020_000, fetch=down)


def test_format_client_incident():
    ev = {
        "extra": {
            "event": "incident_start",
            "scope": "client",
            "cause": "weak_signal",
            "services": ["aaa"],
            "targets": [
                {"target_id": "flow/aaa", "kind": "flow", "current_ms": 40, "baseline_ms": 3, "reason": "latency"}
            ],
            "clients": {"aaa": {"node": "cpe", "band": "5GHz", "rssi": -80, "tx_rate_mbps": 52.0}},
        }
    }
    text = format_message("home", ev, None, "https://g/")
    assert "client - aaa" in text and "weak Wi-Fi signal" in text
    assert "- aaa: LAN part of its connections 40 ms vs 3 ms" in text
    assert "- client aaa: cpe, 5GHz, -80 dBm, 52 Mbit/s" in text
    assert "AWS control" not in text and text.endswith("https://g/d/heimdall-topology")


def test_client_label():
    assert client_label("aaa", {"client_name": "kagan-pc"}) == "kagan-pc (aaa)"
    for generic in ("wlan0", "*", "android-3f2a9c1d0b", "ESP_1A2B3C", "a1b2c3d4e5f6", "AA-BB-CC-DD-EE-FF", ""):
        assert client_label("aaa", {"client_name": generic}) == "aaa", generic
    assert client_label("aaa", {}) == "aaa"
    ev = {
        "extra": {
            "event": "incident_start",
            "scope": "client",
            "cause": "weak_signal",
            "services": ["aaa"],
            "clients": {"aaa": {"node": "cpe", "client_name": "roborock-vacuum-a147"}},
        }
    }
    assert "- client roborock-vacuum-a147 (aaa): cpe" in format_message("home", ev, None, "")


def test_format_extender_incidents():
    hop = {
        "extra": {
            "event": "incident_confirmed",
            "scope": "client",
            "cause": "radio_retransmissions",
            "services": ["aaa"],
            "duration_s": 660,
            "targets": [
                {"target_id": "flow/aaa", "kind": "flow", "current_ms": 30, "baseline_ms": 3, "reason": "latency"}
            ],
            "clients": {"aaa": {"node": "WX5600-AP-17479", "band": "2.4GHz", "rssi": -50, "client_name": "kagan-pc"}},
        }
    }
    text = format_message("ex7501-home (extender wx5600-ap-17479)", hop, None, "", extender=True)
    assert text.startswith(
        ":red_circle: *ex7501-home (extender wx5600-ap-17479)* incident: client - kagan-pc (aaa) (ongoing for 11m)"
    )
    assert "- kagan-pc (aaa): hop between the extender and the client 30 ms vs 3 ms" in text
    assert "retransmissions on the access point's radio" in text
    backhaul = {
        "extra": {
            "event": "incident_confirmed",
            "scope": "backhaul",
            "cause": "backhaul",
            "services": ["backhaul"],
            "targets": [
                {
                    "target_id": "uplink",
                    "kind": "icmp",
                    "dst_ip": "192.168.1.1",
                    "current_ms": 25,
                    "baseline_ms": 1,
                    "reason": "latency",
                }
            ],
        }
    }
    text = format_message("x", backhaul, None, "https://g/", extender=True)
    assert "the link between the mesh extender and the CPE" in text
    assert "- uplink (icmp, 192.168.1.1): 25 ms vs 1 ms" in text and text.endswith("d/heimdall-topology")


def test_format_extender_unreachable():
    offline = {
        "extra": {
            "event": "incident_start",
            "scope": "backhaul",
            "cause": "extender_unreachable",
            "services": ["extender"],
            "mode": "fast",
            "targets": [
                {
                    "target_id": "extender",
                    "kind": "icmp",
                    "dst_ip": "192.168.1.2",
                    "current_ms": 0,
                    "baseline_ms": 1.2,
                    "loss": 0.53,
                    "reason": "loss",
                }
            ],
        }
    }
    text = format_message("ex7501-home", offline, None, "")
    assert text.startswith(":red_circle: *ex7501-home* incident: backhaul - extender")
    assert "Likely cause: the mesh extender stopped answering the CPE" in text
    assert "- extender (icmp, 192.168.1.2): no reply (normally 1 ms), loss 53%" in text


def test_extender_incident_posted_under_its_site(aws):
    table, ssm = aws
    ssm.put_parameter(Name=WEBHOOK, Type="SecureString", Value="https://hooks.slack.com/services/T/B/x")
    posts = []
    n = notifier(table, ssm, posts)
    n.sites = {"wx5600-ap-17479": "ex7501-home"}
    start = ev("incident_start", scope="backhaul", cause="backhaul", services=["backhaul"], confirmed=True)
    n({"device": "wx5600-ap-17479", "events": [start]})
    assert len(posts) == 1 and "*ex7501-home (extender wx5600-ap-17479)*" in posts[0][1]


def test_only_confirmed_incidents_are_posted(aws):
    table, ssm = aws
    ssm.put_parameter(Name=WEBHOOK, Type="SecureString", Value="https://hooks.slack.com/services/T/B/x")
    posts = []
    n = notifier(table, ssm, posts)
    home = "ex7501-home"

    # A short blip: started and ended unconfirmed, never posted.
    n({"device": home, "events": [ev("incident_start", incident_id="b1", confirmed=False)]})
    n({"device": home, "events": [ev("incident_end", incident_id="b1", confirmed=False, duration_s=180)]})
    assert posts == []
    assert table.get_item(Key={"device": home, "incident_id": "b1"})["Item"]["status"] == "closed"

    # A lasting one is posted when confirmed, with its update and end.
    n({"device": home, "events": [ev("incident_start", incident_id="l1", confirmed=False)]})
    n({"device": home, "events": [ev("incident_confirmed", incident_id="l1", confirmed=True, duration_s=600)]})
    assert len(posts) == 1 and "ongoing for 10m" in posts[0][1]
    n({"device": home, "events": [ev("incident_update", incident_id="l1", confirmed=True, services=["netflix", "x"])]})
    n({"device": home, "events": [ev("incident_end", incident_id="l1", confirmed=True, duration_s=1500)]})
    assert len(posts) == 3 and "resolved after 25m" in posts[-1][1]

    # The same condition again within the repeat window: recorded, not posted,
    # and neither is its end.
    n({"device": home, "events": [ev("incident_start", incident_id="l2", confirmed=False)]})
    n({"device": home, "events": [ev("incident_confirmed", incident_id="l2", confirmed=True, duration_s=600)]})
    n({"device": home, "events": [ev("incident_end", incident_id="l2", confirmed=True, duration_s=900)]})
    assert len(posts) == 3

    # Broad incidents are confirmed at the start and posted at once.
    n(
        {
            "device": home,
            "events": [ev("incident_start", incident_id="a1", scope="access", cause="access_network", confirmed=True)],
        }
    )
    assert len(posts) == 4 and "access" in posts[-1][1]


def test_extender_incident_named_from_the_cpe(aws):
    from heimdall_cloud.ingest import NameStore
    from heimdall_cloud.schema import parse_batch

    table, ssm = aws
    ssm.put_parameter(Name=WEBHOOK, Type="SecureString", Value="https://hooks.slack.com/services/T/B/x")
    store = NameStore(table, now=lambda: 1_793_020_000)
    lan = {"ts_ms": 1_793_020_000_000, "kind": "lan", "status": "ok", "target_id": "lan/aaa",
           "extra": {"client_name": "kagan-pc"}}  # fmt: skip
    flow = {"ts_ms": 1_793_020_000_000, "kind": "flow", "status": "ok", "target_id": "flow/bbb",
            "extra": {"client": "bbb", "client_name": "iPhone"}}  # fmt: skip
    samples = parse_batch({"device": "ex7501-home", "samples": [lan, flow]}, 1_793_020_000_000).samples
    assert store.observe("ex7501-home", samples) == 2
    # Names already written are not written again.
    assert store.observe("ex7501-home", samples) == 0

    posts = []
    n = notifier(table, ssm, posts)
    n.sites = {"wx5600-ap-17479": "ex7501-home"}
    start = ev(
        "incident_start", scope="client", cause="weak_signal", services=["aaa"], confirmed=True,
        clients={"aaa": {"node": "WX5600-AP-17479", "rssi": -80}},
    )  # fmt: skip
    n({"device": "wx5600-ap-17479", "events": [start]})
    assert len(posts) == 1 and "- client kagan-pc (aaa): WX5600-AP-17479" in posts[0][1]
    assert "incident: client - kagan-pc (aaa)" in posts[0][1]
    end = ev(
        "incident_end", scope="client", services=["aaa"], confirmed=True, duration_s=2040,
        ended_ms=1_793_020_100_000, clients={"aaa": {}},
    )  # fmt: skip
    n({"device": "wx5600-ap-17479", "events": [end]})
    assert len(posts) == 2 and posts[1][1].endswith("resolved after 34m: client incident - kagan-pc (aaa)")
    item = table.get_item(Key={"device": "wx5600-ap-17479", "incident_id": start["extra"]["incident_id"]})["Item"]
    assert item["ended_ms"] == 1_793_020_100_000


def test_format_wired_and_unknown_clients():
    def line(cx):
        x = {"event": "incident_confirmed", "scope": "client", "cause": "wired_lan", "services": ["aaa"],
             "clients": {"aaa": cx}}  # fmt: skip
        return format_message("x", {"extra": x}, None, "", extender=True).splitlines()[-1]

    assert line({"node": "WX5600-AP-17479", "medium": "wired", "port": "eth1", "client_name": "kagan-pc"}) == (
        "- client kagan-pc (aaa): WX5600-AP-17479, wired (eth1)"
    )
    assert line({}) == "- client aaa"


def test_fast_incidents_are_posted_every_time(aws):
    table, ssm = aws
    ssm.put_parameter(Name=WEBHOOK, Type="SecureString", Value="https://hooks.slack.com/services/T/B/x")
    posts = []
    n = notifier(table, ssm, posts)
    home = "ex7501-home"
    fast = {"scope": "client", "cause": "lan_latency", "services": ["aaa"], "confirmed": True, "mode": "fast"}
    for i in ("f1", "f2"):
        n({"device": home, "events": [ev("incident_start", incident_id=i, **fast)]})
        n({"device": home, "events": [ev("incident_end", incident_id=i, duration_s=40, **fast)]})
    assert len(posts) == 4
    assert ":zap: Fast detection" in posts[0][1] and posts[1][1].endswith(":zap:")
    # A regular incident like them is not held back by them either.
    regular = {k: v for k, v in fast.items() if k != "mode"}
    n({"device": home, "events": [ev("incident_start", incident_id="r1", **regular)]})
    assert len(posts) == 5 and "Fast detection" not in posts[-1][1]
    assert table.get_item(Key={"device": home, "incident_id": "f1"})["Item"]["mode"] == "fast"


def test_warmup_posts_nothing(aws):
    table, ssm = aws
    posts = []
    assert notifier(table, ssm, posts)({"warmup": True}) == {"posted": 0} and posts == []
