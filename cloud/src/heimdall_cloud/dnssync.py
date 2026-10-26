"""Keeps the proxied Cloudflare record of an ECS service pointed at the
public IP of its current task.

Fargate gives a task a new public address each time it is replaced, so the
record cannot be managed by Terraform. This Lambda runs on ECS task state
changes and on a schedule, picks the task that should serve traffic and
updates the record's content when it differs.

The Cloudflare token can edit the whole zone, so the client here only reads
and patches the single record whose ID it is configured with, and only after
checking that the record's name and type match the configured ones.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger()
log.setLevel(logging.INFO)

API = "https://api.cloudflare.com/client/v4"
EPOCH = datetime.fromtimestamp(0, UTC)


class RecordMismatch(Exception):
    pass


class CloudflareRecord:
    """Read and update the content of one DNS record."""

    def __init__(
        self,
        zone_id: str,
        record_id: str,
        name: str,
        allowed_suffix: str,
        token: Callable[[], str],
        opener: Callable[..., Any] = urllib.request.urlopen,
    ):
        if not (name == allowed_suffix or name.endswith("." + allowed_suffix)):
            raise ValueError(f"record {name} is outside {allowed_suffix}")
        self.url = f"{API}/zones/{zone_id}/dns_records/{record_id}"
        self.name = name
        self.token = token
        self.opener = opener

    def _call(self, method: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        req = urllib.request.Request(  # noqa: S310 - fixed https URL
            self.url,
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self.token()}", "Content-Type": "application/json"},
        )
        try:
            with self.opener(req, timeout=10) as r:
                doc = json.load(r)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"cloudflare {method} returned HTTP {e.code}") from e
        if not doc.get("success"):
            raise RuntimeError(f"cloudflare {method} failed: {doc.get('errors')}")
        return doc["result"]

    def content(self) -> str:
        rec = self._call("GET")
        if rec.get("name") != self.name or rec.get("type") != "A":
            raise RecordMismatch(f"record is {rec.get('type')} {rec.get('name')}, expected A {self.name}")
        return rec.get("content", "")

    def set_content(self, ip: str) -> None:
        if ipaddress.ip_address(ip).version != 4 or not ipaddress.ip_address(ip).is_global:
            raise ValueError(f"refusing to point {self.name} at {ip}")
        self.content()
        self._call("PATCH", {"content": ip})


def pick_task(tasks: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Choose the running task that should receive traffic: healthy tasks
    first, then the most recently started one.

    During a deployment the old task stays healthy while the new one starts,
    so the record moves only once the new task passes its health check or the
    old one stops.
    """
    running = [t for t in tasks if t.get("lastStatus") == "RUNNING"]
    if not running:
        return None
    return max(running, key=lambda t: (t.get("healthStatus") == "HEALTHY", t.get("startedAt") or EPOCH))


def eni_id(task: dict[str, Any]) -> str | None:
    for att in task.get("attachments") or []:
        if att.get("type") != "ElasticNetworkInterface":
            continue
        for d in att.get("details") or []:
            if d.get("name") == "networkInterfaceId":
                return d.get("value")
    return None


class Syncer:
    def __init__(self, ecs: Any, ec2: Any, record: CloudflareRecord, cluster: str, service: str):
        self.ecs = ecs
        self.ec2 = ec2
        self.record = record
        self.cluster = cluster
        self.service = service

    def task_ip(self) -> tuple[str | None, str | None]:
        arns = self.ecs.list_tasks(cluster=self.cluster, serviceName=self.service, desiredStatus="RUNNING")["taskArns"]
        if not arns:
            return None, None
        tasks = self.ecs.describe_tasks(cluster=self.cluster, tasks=arns)["tasks"]
        task = pick_task(tasks)
        if task is None:
            return None, None
        eni = eni_id(task)
        if eni is None:
            return task["taskArn"], None
        nis = self.ec2.describe_network_interfaces(NetworkInterfaceIds=[eni])["NetworkInterfaces"]
        ip = (nis[0].get("Association") or {}).get("PublicIp") if nis else None
        return task["taskArn"], ip

    def __call__(self, event: dict[str, Any] | None = None) -> dict[str, Any]:
        task, ip = self.task_ip()
        if ip is None:
            # Leave the record alone: pointing it nowhere would not help, and
            # the next task start triggers another sync.
            log.warning(json.dumps({"msg": "no running task with a public IP", "task": task}))
            return {"changed": False, "ip": None, "task": task}
        current = self.record.content()
        if current == ip:
            return {"changed": False, "ip": ip, "task": task}
        self.record.set_content(ip)
        log.info(
            json.dumps({"msg": "record updated", "name": self.record.name, "from": current, "to": ip, "task": task})
        )
        return {"changed": True, "ip": ip, "previous": current, "task": task}


class SSMToken:
    def __init__(self, ssm: Any, name: str):
        self.ssm = ssm
        self.name = name
        self._value: str | None = None

    def __call__(self) -> str:
        if self._value is None:
            self._value = self.ssm.get_parameter(Name=self.name, WithDecryption=True)["Parameter"]["Value"].strip()
        return self._value


_syncer: Syncer | None = None


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    global _syncer
    if _syncer is None:
        import boto3

        record = CloudflareRecord(
            zone_id=os.environ["ZONE_ID"],
            record_id=os.environ["RECORD_ID"],
            name=os.environ["RECORD_NAME"],
            allowed_suffix=os.environ["ALLOWED_SUFFIX"],
            token=SSMToken(boto3.client("ssm"), os.environ["TOKEN_PARAMETER"]),
        )
        _syncer = Syncer(
            ecs=boto3.client("ecs"),
            ec2=boto3.client("ec2"),
            record=record,
            cluster=os.environ["CLUSTER"],
            service=os.environ["SERVICE"],
        )
    return _syncer(event)
