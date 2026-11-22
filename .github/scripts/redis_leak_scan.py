#!/usr/bin/env python3
"""Type-aware raw scan across all Redis keys with positive control assertion."""

from __future__ import annotations

import subprocess
import sys

SCAN_CODE = """
import redis, zlib

with open('/tmp/TestActivity.apk', 'rb') as f:
    first_64 = f.read(64)
assert len(first_64) == 64, 'Fixture read failed to obtain 64 bytes'

r = redis.from_url('redis://redis:6379/0')

def scan_redis_for_target_bytes(conn, target):
    matched_keys = []
    for k in conn.keys('*'):
        k_type = conn.type(k)
        if isinstance(k_type, bytes):
            k_type = k_type.decode('utf-8')
        raw_blobs = []
        if k_type == 'string':
            val = conn.get(k)
            if val:
                raw_blobs.append(val)
        elif k_type == 'hash':
            h = conn.hgetall(k)
            for f_val in h.values():
                raw_blobs.append(f_val)
                try:
                    raw_blobs.append(zlib.decompress(f_val))
                except Exception:
                    pass
        elif k_type == 'list':
            raw_blobs.extend(conn.lrange(k, 0, -1))
        elif k_type == 'set':
            raw_blobs.extend(conn.smembers(k))
        elif k_type == 'zset':
            raw_blobs.extend(conn.zrange(k, 0, -1))
        for blob in raw_blobs:
            if target in blob:
                matched_keys.append(k)
                break
    return matched_keys

# Step 1: Positive Control - Prove the type-aware scan detects fixture bytes when present
print('Running positive control check...')
probe_key = 'test:probe:positive_control'
r.hset(probe_key, 'data', zlib.compress(b'prefix_' + first_64 + b'_suffix'))
control_matches = scan_redis_for_target_bytes(r, first_64)
print('Positive control matches:', control_matches)
r.delete(probe_key)
assert any(probe_key.encode() in m or probe_key in str(m) for m in control_matches), \\
    'Positive control failed: scan did not detect deliberately injected fixture bytes in Redis hash'
print('Positive control verified: scanner reliably detects fixture bytes in Redis.')

# Step 2: Live Cleanliness Scan - Assert complete absence of fixture bytes across all Redis keys
live_matches = scan_redis_for_target_bytes(r, first_64)
if live_matches:
    raise SystemExit(f'FAILED: Upload bytes found in live Redis keys after job completion: {live_matches}')
print('Redis type-aware scan verified: 0 upload bytes detected across all keys.')
"""


def main() -> None:
    proc = subprocess.run(
        ["docker", "exec", "-i", "signalcheck-backend", "python", "-"],
        input=SCAN_CODE.strip(),
        text=True,
    )
    if proc.returncode != 0:
        sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
