import json
import os
from datetime import date

import boto3
import pytest
from moto import mock_aws

from heimdall_cloud.analytics import Store
from heimdall_cloud.report import Reporter, build_prompt, fallback_report, headline

DAY = date(2026, 10, 27)
os.environ.setdefault("AWS_DEFAULT_REGION", "eu-central-1")

SUMMARY = {
    "date": "2026-10-27",
    "control_device": "aws-euc1",
    "devices": {
        "ex7501-home": {
            "services_measured": 40,
            "busy_hour_inflation": [{"service": "netflix", "ratio": 1.6, "busy_p50": 32.0, "night_p50": 20.0}],
            "loss": [{"service": "whatsapp", "loss_pct": 6.5}],
            "degraded_hours": {"netflix": {"access_or_path": 3}, "steam": {"service": 1}},
            "next_as": [{"asn": 6453, "name": "TATA", "targets": 10}],
            "large_border_jumps": [],
            "incidents": [{"scope": "service", "cause": "tls_blocked", "services": ["discord"]}],
            "external": {"k-root": {"cpe_p50": 17.0, "peer_p50": 18.4, "peer_probes": 8}},
        }
    },
}


class FakeBedrock:
    def __init__(self, fail=False):
        self.fail, self.calls = fail, []

    def converse(self, **kw):
        self.calls.append(kw)
        if self.fail:
            raise RuntimeError("AccessDeniedException: model access")
        return {"output": {"message": {"content": [{"text": "# Report\nAll fine."}]}}, "usage": {"inputTokens": 900}}


class FakeWebhook:
    def __init__(self, url):
        self._url = url

    def url(self):
        return self._url


@pytest.fixture
def store():
    with mock_aws():
        s3 = boto3.client("s3", region_name="eu-central-1")
        s3.create_bucket(Bucket="heimdall-test", CreateBucketConfiguration={"LocationConstraint": "eu-central-1"})
        st = Store(s3, "heimdall-test")
        st.put_doc("summary", DAY, SUMMARY)
        prev = json.loads(json.dumps(SUMMARY))
        prev["date"] = "2026-10-26"
        st.put_doc("summary", date(2026, 10, 26), prev)
        yield st


def test_report_with_model(store):
    bedrock, posts = FakeBedrock(), []
    r = Reporter(
        store,
        bedrock,
        "eu.anthropic.claude-sonnet-5-5",
        FakeWebhook("https://hooks.slack.com/x"),
        post=lambda url, text: posts.append(text),
    )
    out = r(DAY)
    rep = out["reports"]["ex7501-home"]
    assert rep == {"key": "derived/report/dt=2026-10-27/ex7501-home.md", "model": True, "posted": True, "chars": 19}
    body = store.s3.get_object(Bucket="heimdall-test", Key=rep["key"])["Body"].read().decode()
    assert body == "# Report\nAll fine.\n" and posts == [body]
    [call] = bedrock.calls
    assert call["modelId"] == "eu.anthropic.claude-sonnet-5-5"
    prompt = call["messages"][0]["content"][0]["text"]
    assert '"trend"' in prompt and "2026-10-26" in prompt and "TATA" in prompt


def test_report_falls_back_without_model(store):
    r = Reporter(store, FakeBedrock(fail=True), "m", FakeWebhook(None))
    rep = r(DAY)["reports"]["ex7501-home"]
    assert rep["model"] is False and rep["posted"] is False
    body = store.s3.get_object(Bucket="heimdall-test", Key=rep["key"])["Body"].read().decode()
    assert "without the language model" in body and "netflix x1.6" in body and "whatsapp 6.5%" in body


def test_missing_summary(store):
    with pytest.raises(RuntimeError):
        Reporter(store, FakeBedrock(), "m", None)(date(2026, 1, 1))


def test_headline_and_prompt():
    h = headline(SUMMARY, "ex7501-home")
    assert h["isp_side_hours"] == 3 and h["service_side_hours"] == 1 and h["incidents"] == 1
    p = build_prompt(SUMMARY, "ex7501-home", [h])
    assert "busy_hour_inflation" in p and "Verdict" in p
    assert "k.root: this line 17.0 ms" in fallback_report(SUMMARY, "ex7501-home")
