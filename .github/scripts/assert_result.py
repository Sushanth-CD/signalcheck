#!/usr/bin/env python3
"""Assert analysis schema, findings, and Redis job key cleanup."""

from __future__ import annotations

import json
import subprocess
import sys


def assert_result(job_id: str, result_file: str = "/tmp/job_result.json") -> None:
    try:
        with open(result_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        print(f"FAILED: Could not read result file {result_file}: {exc}", file=sys.stderr)
        sys.exit(1)

    result = data.get("result", {})
    if not isinstance(result, dict):
        print(f"FAILED: result field is missing or not a dict in {result_file}!", file=sys.stderr)
        sys.exit(1)

    schema_ver = result.get("analysis_version")
    print(f"Analysis version: {schema_ver}")
    if schema_ver != "apk-static-v1":
        print(f"FAILED: schema_version is '{schema_ver}', expected 'apk-static-v1'!", file=sys.stderr)
        sys.exit(1)

    findings = result.get("findings")
    if not isinstance(findings, list):
        print("FAILED: findings list is missing!", file=sys.stderr)
        sys.exit(1)
    findings_count = len(findings)
    print(f"Findings count: {findings_count}")
    if findings_count < 0:
        print("FAILED: findings list is missing!", file=sys.stderr)
        sys.exit(1)

    # Assert that after reaching 'done', the job key no longer exists in Redis
    print("Checking Redis payload cleanup...")
    proc = subprocess.run(
        ["docker", "exec", "signalcheck-redis", "redis-cli", "exists", f"rq:job:{job_id}"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(f"FAILED: redis-cli exists failed: {proc.stderr}", file=sys.stderr)
        sys.exit(1)

    job_key_exists = proc.stdout.strip()
    print(f"Redis job key exists: {job_key_exists}")
    if job_key_exists != "0":
        print(f"FAILED: Job key 'rq:job:{job_id}' still exists in Redis after reaching terminal 'done' state!", file=sys.stderr)
        sys.exit(1)

    print("Schema assertions and Redis job key cleanup verified successfully.")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python assert_result.py <job_id> [result_file]", file=sys.stderr)
        sys.exit(1)

    job_id = sys.argv[1]
    result_file = sys.argv[2] if len(sys.argv) > 2 else "/tmp/job_result.json"
    assert_result(job_id, result_file)


if __name__ == "__main__":
    main()
