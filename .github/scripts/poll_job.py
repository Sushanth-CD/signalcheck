#!/usr/bin/env python3
"""Poll for APK analysis job completion via backend API inside container stack."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

POLL_CODE_TEMPLATE = """
import urllib.request

req = urllib.request.Request(
    'http://127.0.0.1:8000/api/apk/jobs/{job_id}',
    headers={{'Cookie': 'signalcheck_apk_sid=ci_integration_test_session_token_1234567890'}},
)
with urllib.request.urlopen(req) as resp:
    print(resp.read().decode())
"""


def poll_job(job_id: str, max_attempts: int = 30) -> dict:
    code = POLL_CODE_TEMPLATE.format(job_id=job_id).strip()

    for attempt in range(1, max_attempts + 1):
        proc = subprocess.run(
            ["docker", "exec", "-i", "signalcheck-backend", "python", "-"],
            input=code,
            text=True,
            capture_output=True,
        )
        if proc.returncode != 0:
            print(f"Poll attempt {attempt}: docker exec failed: {proc.stderr.strip()}", file=sys.stderr)
            time.sleep(1)
            continue

        raw = proc.stdout.strip()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            print(f"Poll attempt {attempt}: non-JSON output: {raw}", file=sys.stderr)
            time.sleep(1)
            continue

        status = data.get("status")
        print(f"Poll attempt {attempt}: status = {status}")

        if status == "done":
            return data
        if status in ("failed", "timeout"):
            print(f"FAILED: Job entered terminal failure state: {status}", file=sys.stderr)
            sys.exit(1)

        time.sleep(1)

    print(f"FAILED: Job did not complete within {max_attempts} seconds!", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python poll_job.py <job_id> [output_file]", file=sys.stderr)
        sys.exit(1)

    job_id = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "/tmp/job_result.json"

    data = poll_job(job_id)

    dirname = os.path.dirname(os.path.abspath(output_file))
    if dirname:
        os.makedirs(dirname, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"Job completed successfully. Saved result to {output_file}")


if __name__ == "__main__":
    main()
