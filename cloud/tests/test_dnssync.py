import io
import json
from datetime import UTC, datetime

import pytest

from heimdall_cloud import dnssync
from heimdall_cloud.dnssync import CloudflareRecord, RecordMismatch, Syncer, pick_task

NAME = "grafana.lat.kgns.dev"


def task(arn, status="RUNNING", health="UNKNOWN", started=1, eni="eni-1"):
    t = {
        "taskArn": arn,
        "lastStatus": status,
        "healthStatus": health,
        "startedAt": datetime.fromtimestamp(started, UTC),
        "attachments": [],
    }
    if eni:
        t["attachments"] = [
            {"type": "ElasticNetworkInterface", "details": [{"name": "networkInterfaceId", "value": eni}]}
        ]
    return t


class FakeCloudflare:
    def __init__(self, name=NAME, type_="A", content="192.0.2.1"):
        self.record = {"name": name, "type": type_, "content": content}
        self.calls = []

    def __call__(self, req, timeout):
        body = json.loads(req.data) if req.data else None
        self.calls.append((req.get_method(), req.full_url, body, req.get_header("Authorization")))
        if req.get_method() == "PATCH":
            self.record.update(body)
        return io.BytesIO(json.dumps({"success": True, "result": self.record}).encode())


class FakeECS:
    def __init__(self, tasks):
        self.tasks = tasks

    def list_tasks(self, cluster, serviceName, desiredStatus):
        return {"taskArns": [t["taskArn"] for t in self.tasks]}

    def describe_tasks(self, cluster, tasks):
        return {"tasks": [t for t in self.tasks if t["taskArn"] in tasks]}


class FakeEC2:
    def __init__(self, ips):
        self.ips = ips

    def describe_network_interfaces(self, NetworkInterfaceIds):
        return {
            "NetworkInterfaces": [
                {"Association": {"PublicIp": self.ips[i]}} if self.ips.get(i) else {} for i in NetworkInterfaceIds
            ]
        }


def record(cf):
    return CloudflareRecord("zone1", "rec1", NAME, "lat.kgns.dev", token=lambda: "tkn", opener=cf)


def test_pick_task_prefers_healthy_then_newest():
    old = task("old", health="HEALTHY", started=1)
    new = task("new", health="UNKNOWN", started=2)
    assert pick_task([old, new])["taskArn"] == "old"
    assert pick_task([old, task("new", health="HEALTHY", started=2)])["taskArn"] == "new"
    assert pick_task([task("a", started=1), task("b", started=3)])["taskArn"] == "b"
    assert pick_task([task("p", status="PROVISIONING")]) is None
    assert pick_task([]) is None


def test_updates_record_when_ip_changes():
    cf = FakeCloudflare(content="3.120.0.1")
    s = Syncer(FakeECS([task("t1")]), FakeEC2({"eni-1": "3.120.0.2"}), record(cf), "c", "s")
    out = s()
    assert out == {"changed": True, "ip": "3.120.0.2", "previous": "3.120.0.1", "task": "t1"}
    methods = [c[0] for c in cf.calls]
    assert methods == ["GET", "GET", "PATCH"]
    assert cf.calls[-1][1].endswith("/zones/zone1/dns_records/rec1")
    assert cf.calls[-1][2] == {"content": "3.120.0.2"}
    assert cf.calls[-1][3] == "Bearer tkn"


def test_no_change_when_ip_matches():
    cf = FakeCloudflare(content="3.120.0.2")
    s = Syncer(FakeECS([task("t1")]), FakeEC2({"eni-1": "3.120.0.2"}), record(cf), "c", "s")
    assert s()["changed"] is False
    assert [c[0] for c in cf.calls] == ["GET"]


def test_leaves_record_without_running_task():
    cf = FakeCloudflare()
    s = Syncer(FakeECS([]), FakeEC2({}), record(cf), "c", "s")
    assert s() == {"changed": False, "ip": None, "task": None}
    s = Syncer(FakeECS([task("t1")]), FakeEC2({}), record(cf), "c", "s")
    assert s()["ip"] is None
    assert cf.calls == []


def test_refuses_record_with_other_name_or_type():
    for cf in (FakeCloudflare(name="www.kgns.dev"), FakeCloudflare(type_="CNAME")):
        s = Syncer(FakeECS([task("t1")]), FakeEC2({"eni-1": "3.120.0.2"}), record(cf), "c", "s")
        with pytest.raises(RecordMismatch):
            s()
        assert "PATCH" not in [c[0] for c in cf.calls]


def test_refuses_name_outside_suffix():
    with pytest.raises(ValueError):
        CloudflareRecord("z", "r", "www.kgns.dev", "lat.kgns.dev", token=lambda: "t")
    with pytest.raises(ValueError):
        CloudflareRecord("z", "r", "evil-lat.kgns.dev", "lat.kgns.dev", token=lambda: "t")


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.0.2.1", "2a05:d014::1"])
def test_refuses_non_public_ipv4(ip):
    cf = FakeCloudflare()
    with pytest.raises(ValueError):
        record(cf).set_content(ip)
    assert cf.calls == []


def test_cloudflare_error_is_raised():
    def failing(req, timeout):
        return io.BytesIO(json.dumps({"success": False, "errors": [{"code": 10000}]}).encode())

    with pytest.raises(RuntimeError):
        CloudflareRecord("z", "r", NAME, "lat.kgns.dev", token=lambda: "t", opener=failing).content()


def test_ssm_token_is_cached():
    class SSM:
        calls = 0

        def get_parameter(self, Name, WithDecryption):
            SSM.calls += 1
            assert WithDecryption
            return {"Parameter": {"Value": " tkn \n"}}

    tok = dnssync.SSMToken(SSM(), "/heimdall/cloudflare/api_token")
    assert tok() == "tkn" and tok() == "tkn"
    assert SSM.calls == 1
