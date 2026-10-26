import os

import boto3
import pytest
from moto import mock_aws

from heimdall_cloud.notify import Notifier, Webhook, format_message, incident_events

os.environ.setdefault("AWS_DEFAULT_REGION", "eu-central-1")
WEBHOOK = "/heimdall/slack/webhook_url"


def ev(event, incident_id="i1", device_ts=1_793_020_000_000, **extra):
    x = {"event": event, "incident_id": incident_id, "scope": "service", "cause": "path", "services": ["netflix"]}
    x.update(extra)
    return {"kind": "event", "ts_ms": device_ts, "extra": x}


@pytest.fixture
def aws():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="eu-central-1")
        table = ddb.create_table(
            TableName="heimdall-incidents",
            KeySchema=[
                {"AttributeName": "device", "KeyType": "HASH"},
                {"AttributeName": "incident_id", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "device", "AttributeType": "S"},
                {"AttributeName": "incident_id", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table, boto3.client("ssm", region_name="eu-central-1")


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
    n({"device": "ex7501-home", "events": [ev("incident_start", incident_id="i3")]})
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
    ]
    [got] = incident_events(samples)
    assert got["extra"]["incident_id"] == "a"
