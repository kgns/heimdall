"""Daily report: turns the analysis summary of a day into a short written
report with Claude on Amazon Bedrock, stores it next to the summary and
posts it to Slack when a webhook is configured.

Invoked by the analytics Lambda after it wrote the day's summary, with
``{"date": "YYYY-MM-DD"}``. If Bedrock is unavailable, a plain report built
from the same numbers is stored and posted instead, marked as such.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import date, timedelta
from typing import Any

from heimdall_cloud.analytics import Store
from heimdall_cloud.notify import Webhook, post_slack

log = logging.getLogger()
log.setLevel(logging.INFO)

TREND_DAYS = 6
SLACK_LIMIT = 3500

SYSTEM = """You are a network performance analyst. You write the daily report of heimdall, a system that \
measures latency, loss and paths from a home router (the CPE) on a residential fiber line to internet \
services, together with a control probe in AWS eu-central-1 that measures the same services, and public \
data from RIPE Atlas probes of the same ISP and from IODA.

The question the report answers: are problems caused by one service, or general? Is the ISP's routing or \
peering poor for some services? Base every statement on the numbers given; do not invent measurements. \
Say when the data is too thin for a conclusion. Be concise and specific: name services, ASes and numbers."""

GLOSSARY = """Field guide:
- busy_hour_inflation: median RTT 20-24h local over 03-07h local, per service (ICMP). Above about 1.2 means \
evening load slows that service down (access, aggregation or peering congestion).
- loss: ICMP loss percentage per service over the day.
- degraded_hours: per service, UTC hours where the CPE's median was 30% above its best hour. access_or_path: \
the AWS control did not degrade at the same time (points at the ISP or its path); service: the control \
degraded too (points at the service); no_control: the control does not measure it.
- next_as: the first network after the ISP on traceroute paths, with how many targets use it.
- large_border_jumps: latency added at the hop where the path leaves the ISP.
- incidents: what the probe detected in real time (scope, cause, services, duration).
- external.k-root / f-root: this CPE's median RTT and busy-hour inflation towards the root servers, next \
to the median of the other RIPE Atlas probes in the same ISP. external.ioda_events: outages IODA detected \
for the ISP's AS or the country.
- trend: the same headline numbers for the previous days, oldest first."""

INSTRUCTIONS = """Write the report in Markdown, at most about 350 words, with these parts:
1. Verdict: one or two sentences. Was there an ISP-side problem, a service-side problem, or nothing notable?
2. Findings: bullet points, most important first: evening congestion, loss, ISP-side versus service-side \
degraded hours, peering and transit observations, incidents, comparison with other lines of the ISP.
3. Worth raising with the ISP: only concrete, evidenced items (service, time, numbers, AS), or "nothing".
Use the device name and the date in the title."""


def headline(summary: dict[str, Any], device: str) -> dict[str, Any]:
    d = summary.get("devices", {}).get(device, {})
    ext = d.get("external", {}) or {}
    return {
        "date": summary.get("date"),
        "busy_hour_inflation": d.get("busy_hour_inflation", [])[:5],
        "loss": d.get("loss", [])[:5],
        "isp_side_hours": sum(v.get("access_or_path", 0) for v in d.get("degraded_hours", {}).values()),
        "service_side_hours": sum(v.get("service", 0) for v in d.get("degraded_hours", {}).values()),
        "incidents": len(d.get("incidents", [])),
        "k_root": ext.get("k-root"),
    }


def build_prompt(summary: dict[str, Any], device: str, trend: list[dict[str, Any]]) -> str:
    doc = {"device": device, **summary.get("devices", {}).get(device, {}), "trend": trend}
    return f"{GLOSSARY}\n\nData for {summary.get('date')}:\n```json\n{json.dumps(doc, indent=1)}\n```\n\n{INSTRUCTIONS}"


def fallback_report(summary: dict[str, Any], device: str) -> str:
    """A plain report from the numbers, used when Bedrock is unavailable."""
    h = headline(summary, device)
    lines = [
        f"# heimdall daily report: {device}, {summary.get('date')}",
        "",
        "_Generated without the language model._",
        "",
    ]
    lines.append(f"- ISP-side degraded hours: {h['isp_side_hours']}; service-side: {h['service_side_hours']}")
    if h["busy_hour_inflation"]:
        worst = ", ".join(f"{x['service']} x{x['ratio']}" for x in h["busy_hour_inflation"])
        lines.append(f"- Evening slowdown (busy/night median): {worst}")
    if h["loss"]:
        lines.append("- Loss: " + ", ".join(f"{x['service']} {x['loss_pct']}%" for x in h["loss"]))
    lines.append(f"- Incidents detected: {h['incidents']}")
    if k := h.get("k_root"):
        lines.append(
            f"- k.root: this line {k.get('cpe_p50')} ms, other lines of the ISP {k.get('peer_p50')} ms "
            f"({k.get('peer_probes')} Atlas probes)"
        )
    return "\n".join(lines) + "\n"


class Reporter:
    def __init__(self, store: Store, bedrock: Any, model_id: str, webhook: Webhook | None, post=post_slack):
        self.store, self.bedrock, self.model_id, self.webhook, self.post = store, bedrock, model_id, webhook, post

    def summary(self, day: date) -> dict[str, Any] | None:
        try:
            obj = self.store.s3.get_object(Bucket=self.store.bucket, Key=self.store.key("summary", day, "summary.json"))
        except self.store.s3.exceptions.NoSuchKey:
            return None
        return json.loads(obj["Body"].read())

    def write(self, summary: dict[str, Any], device: str, trend: list[dict[str, Any]]) -> tuple[str, bool]:
        try:
            resp = self.bedrock.converse(
                modelId=self.model_id,
                system=[{"text": SYSTEM}],
                messages=[{"role": "user", "content": [{"text": build_prompt(summary, device, trend)}]}],
                inferenceConfig={"maxTokens": 1500, "temperature": 0.2},
            )
            text = "".join(c.get("text", "") for c in resp["output"]["message"]["content"])
            usage = resp.get("usage", {})
            log.info(json.dumps({"device": device, "model": self.model_id, "usage": usage}))
            return text.strip() + "\n", True
        except Exception as e:  # the plain report is better than none
            log.error("bedrock: %s", e)
            return fallback_report(summary, device), False

    def __call__(self, day: date) -> dict[str, Any]:
        summary = self.summary(day)
        if summary is None:
            raise RuntimeError(f"no summary for {day}")
        results = {}
        for device in summary.get("devices", {}):
            trend = []
            for back in range(TREND_DAYS, 0, -1):
                prev = self.summary(day - timedelta(days=back))
                if prev and device in prev.get("devices", {}):
                    trend.append(headline(prev, device))
            text, by_model = self.write(summary, device, trend)
            key = self.store.key("report", day, f"{device}.md")
            self.store.s3.put_object(Bucket=self.store.bucket, Key=key, Body=text.encode(), ContentType="text/markdown")
            posted = False
            url = self.webhook.url() if self.webhook else None
            if url:
                body = text if len(text) <= SLACK_LIMIT else text[:SLACK_LIMIT] + "\n..."
                try:
                    self.post(url, body)
                    posted = True
                except Exception as e:
                    log.warning("slack post failed: %s", e)
            results[device] = {"key": key, "model": by_model, "posted": posted, "chars": len(text)}
        log.info(json.dumps({"day": day.isoformat(), "reports": results}))
        return {"day": day.isoformat(), "reports": results}


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    import boto3

    reporter = Reporter(
        store=Store(boto3.client("s3"), os.environ["BUCKET"]),
        bedrock=boto3.client("bedrock-runtime"),
        model_id=os.environ["MODEL_ID"],
        webhook=Webhook(boto3.client("ssm"), os.environ["WEBHOOK_PARAMETER"]),
    )
    return reporter(date.fromisoformat(event["date"]))
