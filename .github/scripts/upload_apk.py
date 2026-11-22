#!/usr/bin/env python3
"""Submit test APK fixture to the running backend service inside container stack."""

from __future__ import annotations

import json
import subprocess
import sys

UPLOAD_CODE = """
import urllib.request, json

with open('/tmp/TestActivity.apk', 'rb') as f:
    data = f.read()

boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
body = (
    f'--{boundary}\\r\\n'
    'Content-Disposition: form-data; name="file"; filename="TestActivity.apk"\\r\\n'
    'Content-Type: application/vnd.android.package-archive\\r\\n\\r\\n'
).encode() + data + f'\\r\\n--{boundary}--\\r\\n'.encode()

req = urllib.request.Request(
    'http://127.0.0.1:8000/api/apk/analyze?async_mode=true',
    data=body,
    headers={
        'Content-Type': f'multipart/form-data; boundary={boundary}',
        'Cookie': 'signalcheck_apk_sid=ci_integration_test_session_token_1234567890',
    },
    method='POST',
)

with urllib.request.urlopen(req) as resp:
    print(resp.read().decode())
"""


def main() -> None:
    proc = subprocess.run(
        ["docker", "exec", "-i", "signalcheck-backend", "python", "-"],
        input=UPLOAD_CODE.strip(),
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        print(f"FAILED: docker exec error submitting APK: {proc.stderr}", file=sys.stderr)
        sys.exit(proc.returncode)

    raw_output = proc.stdout.strip()
    try:
        payload = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        print(f"FAILED: Malformed JSON from backend enqueue: {raw_output} ({exc})", file=sys.stderr)
        sys.exit(1)

    job_id = payload.get("job_id")
    if not job_id or job_id == "null":
        print(f"FAILED: Did not obtain valid job_id from enqueue endpoint: {raw_output}", file=sys.stderr)
        sys.exit(1)

    print(f"Enqueue response: {raw_output}", file=sys.stderr)
    print(job_id)


if __name__ == "__main__":
    main()
