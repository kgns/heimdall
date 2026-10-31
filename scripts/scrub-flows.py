"""Removes server hostnames and addresses from the stored flow samples.

Probes that recorded flows with ``collectors.flows.names: raw`` stored, for
every connection a LAN client opened, the server's name (``extra.name``),
its address and port (``dst_ip``, ``dst_port``) and the client's own
address and port (``extra.client_ip``, ``extra.client_port``). This script
finds the Parquet files that hold such rows (through Athena's ``$path``),
rewrites each one without those fields and uploads it under the same key.
The raw bucket is not versioned, so the old content is gone afterwards.
Every other row and field stays as it was.

With --src-ip it also blanks ``src_ip``, the public address each batch
came from, in every row of every file of the devices given.

    uv run --with boto3==1.43.118 --with pyarrow==22.0.0 scripts/scrub-flows.py            # dry run
    uv run --with boto3==1.43.118 --with pyarrow==22.0.0 scripts/scrub-flows.py --apply

Run it only after the probes stopped recording raw names, and wait for
Firehose's buffer (5 minutes) so that no new such file arrives.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import time

import boto3
import pyarrow as pa
import pyarrow.parquet as pq

BUCKET = "heimdall-raw-359519776451"
WORKGROUP = "heimdall"
EXTRA_KEYS = ("name", "client_ip", "client_port")
DEVICE_OK = set("abcdefghijklmnopqrstuvwxyz0123456789-_.")


def athena_rows(athena, sql: str) -> list[list[str]]:
    qid = athena.start_query_execution(QueryString=sql, WorkGroup=WORKGROUP)["QueryExecutionId"]
    while True:
        st = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        if st["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(1)
    if st["State"] != "SUCCEEDED":
        sys.exit(f"query failed: {st.get('StateChangeReason')}")
    out, token = [], None
    while True:
        kw = {"QueryExecutionId": qid, **({"NextToken": token} if token else {})}
        page = athena.get_query_results(**kw)
        out += [[c.get("VarCharValue", "") for c in r["Data"]] for r in page["ResultSet"]["Rows"]]
        token = page.get("NextToken")
        if not token:
            return out[1:]


def files_to_scrub(athena, devices: list[str], src_ip: bool) -> list[str]:
    devs = ", ".join(f"'{d}'" for d in devices)
    flow = (
        "kind = 'flow' AND (dst_ip IS NOT NULL OR dst_port IS NOT NULL"
        + "".join(f" OR json_extract_scalar(extra, '$.{k}') IS NOT NULL" for k in EXTRA_KEYS)
        + ")"
    )
    cond = f"({flow}) OR src_ip IS NOT NULL" if src_ip else flow
    sql = f'SELECT DISTINCT "$path" FROM heimdall.samples WHERE device IN ({devs}) AND ({cond})'
    return sorted(r[0] for r in athena_rows(athena, sql))


def scrub(table: pa.Table, src_ip: bool) -> tuple[pa.Table, int]:
    rows = table.to_pylist()
    changed = 0
    for r in rows:
        before = (r.get("dst_ip"), r.get("dst_port"), r.get("extra"), r.get("src_ip"))
        if r.get("kind") == "flow":
            r["dst_ip"], r["dst_port"] = None, None
            if r.get("extra"):
                x = json.loads(r["extra"])
                for k in EXTRA_KEYS:
                    x.pop(k, None)
                r["extra"] = json.dumps(x, separators=(",", ":"))
        if src_ip:
            r["src_ip"] = None
        if (r.get("dst_ip"), r.get("dst_port"), r.get("extra"), r.get("src_ip")) != before:
            changed += 1
    return pa.Table.from_pylist(rows, schema=table.schema), changed


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--apply", action="store_true", help="rewrite the files (default: only list them)")
    p.add_argument("--src-ip", action="store_true", help="also blank src_ip in every row")
    p.add_argument("--devices", default="ex7501-home,wx5600-ap-17479")
    p.add_argument("--profile", default="kgns")
    p.add_argument("--region", default="eu-central-1")
    a = p.parse_args()
    devices = [d.strip() for d in a.devices.split(",") if d.strip()]
    if not devices or any(set(d) - DEVICE_OK for d in devices):
        sys.exit("invalid --devices")

    s = boto3.Session(profile_name=a.profile, region_name=a.region)
    athena, s3 = s.client("athena"), s.client("s3")
    paths = files_to_scrub(athena, devices, a.src_ip)
    prefix = f"s3://{BUCKET}/"
    keys = [x.removeprefix(prefix) for x in paths if x.startswith(prefix)]
    if len(keys) != len(paths):
        sys.exit("a file is outside the raw bucket; refusing")
    print(f"{len(keys)} files to rewrite" + ("" if a.apply else " (dry run; --apply rewrites them)"))
    if not a.apply:
        for k in keys[:10]:
            print("  ", k)
        if len(keys) > 10:
            print(f"   ... and {len(keys) - 10} more")
        return

    total = 0
    for i, key in enumerate(keys, 1):
        obj = s3.get_object(Bucket=BUCKET, Key=key)
        table = pq.read_table(io.BytesIO(obj["Body"].read()))
        new, changed = scrub(table, a.src_ip)
        if new.num_rows != table.num_rows or new.schema != table.schema:
            sys.exit(f"{key}: rewritten file differs in rows or schema; stopping")
        buf = io.BytesIO()
        pq.write_table(new, buf, compression="snappy")
        s3.put_object(Bucket=BUCKET, Key=key, Body=buf.getvalue(), ServerSideEncryption="AES256")
        total += changed
        if i % 50 == 0 or i == len(keys):
            print(f"{i}/{len(keys)} files, {total} rows scrubbed")
    left = files_to_scrub(athena, devices, a.src_ip)
    print("done; files still holding such rows:", len(left))


if __name__ == "__main__":
    main()
