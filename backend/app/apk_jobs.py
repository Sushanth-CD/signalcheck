"""apk_jobs.py - Asynchronous job execution and isolation layer for APK static analysis.

Supports two worker execution engines:
1. Redis Queue (RQ): Used when `REDIS_URL` is configured.
2. Local Subprocess Fallback: Used when `REDIS_URL` is unset or empty (e.g. native Windows dev without Docker).
   Spawns `python -m app.apk_worker` in an isolated child process with a hard 30s timeout and SIGKILL.

Jobs are tracked in-memory (and via RQ when Redis is active) with terminal states:
- queued
- running
- done
- failed
- timeout
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, Dict, Optional, Tuple

JOB_TIMEOUT_SECONDS = 30

# In-memory registry for jobs (accessible across threads in the API process)
_LOCAL_JOBS: Dict[str, Dict[str, Any]] = {}
_LOCAL_JOBS_LOCK = threading.Lock()


def get_redis_url() -> Optional[str]:
    """Retrieve REDIS_URL from environment if configured and non-empty."""
    raw = os.getenv("REDIS_URL", "").strip()
    return raw if raw else None


def get_job_status(job_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve the current status and payload of a job.

    Returns None if job_id is unknown.
    """
    redis_url = get_redis_url()
    if redis_url:
        try:
            import redis
            from rq.job import Job
            conn = redis.from_url(redis_url)
            rq_job = Job.fetch(job_id, connection=conn)
            status_str = rq_job.get_status()
            if status_str in ("queued", "deferred"):
                state = "queued"
            elif status_str == "started":
                state = "running"
            elif status_str == "finished":
                state = "done"
            elif status_str == "failed":
                # Check if failure was caused by timeout
                exc_info = str(rq_job.exc_info or "")
                state = "timeout" if "JobTimeoutException" in exc_info or "Timeout" in exc_info else "failed"
            else:
                state = status_str or "unknown"

            res = rq_job.result if state == "done" else None
            meta = rq_job.meta or {}
            err = None
            if state in ("failed", "timeout"):
                err = meta.get("error") or "Job execution failed or timed out in RQ worker."

            return {
                "job_id": job_id,
                "status": state,
                "result": res,
                "error": err,
                "created_at": meta.get("created_at", time.time()),
                "duration_sec": meta.get("duration_sec"),
            }
        except Exception:
            # Fall back to local registry in case it was a local job
            pass

    with _LOCAL_JOBS_LOCK:
        job = _LOCAL_JOBS.get(job_id)
        if not job:
            return None
        return dict(job)


def _execute_subprocess_job(job_id: str, file_path: str, sha256_hash: str, file_size: int, on_complete_cb=None):
    """Worker thread runner that executes `python -m app.apk_worker` under hard timeout."""
    start_time = time.monotonic()
    with _LOCAL_JOBS_LOCK:
        if job_id in _LOCAL_JOBS:
            _LOCAL_JOBS[job_id]["status"] = "running"
            _LOCAL_JOBS[job_id]["started_at"] = time.time()

    cmd = [
        sys.executable,
        "-m",
        "app.apk_worker",
        file_path,
        sha256_hash,
        str(file_size),
    ]

    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    env = dict(os.environ)
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{backend_dir}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else backend_dir

    proc = None
    outcome = "failed"
    result_data = None
    error_msg = None

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        try:
            stdout, stderr = proc.communicate(timeout=JOB_TIMEOUT_SECONDS)
            if proc.returncode == 0:
                result_data = json.loads(stdout)
                outcome = "done"
            else:
                outcome = "failed"
                try:
                    err_json = json.loads(stderr)
                    error_msg = err_json.get("message") or err_json.get("error") or stderr.strip()
                except Exception:
                    error_msg = stderr.strip() or f"Process failed with exit code {proc.returncode}"
        except subprocess.TimeoutExpired:
            outcome = "timeout"
            error_msg = f"Static analysis worker timed out after {JOB_TIMEOUT_SECONDS} seconds."
            if proc:
                try:
                    proc.kill()
                    proc.communicate(timeout=2)
                except Exception:
                    pass
    except Exception as exc:
        outcome = "failed"
        error_msg = f"Worker subprocess error: {exc}"
        if proc:
            try:
                proc.kill()
            except Exception:
                pass
    finally:
        # Guarantee ephemeral deletion of uploaded temporary file in all outcomes
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass

        duration = round(time.monotonic() - start_time, 4)
        if on_complete_cb:
            try:
                on_complete_cb(job_id, outcome, result_data, error_msg, duration)
            except Exception as cb_exc:
                print(f"Warning: on_complete_cb raised {cb_exc}")

        # Update job dict with any enrichment (like record id) performed by on_complete_cb
        with _LOCAL_JOBS_LOCK:
            if job_id in _LOCAL_JOBS:
                _LOCAL_JOBS[job_id]["status"] = outcome
                _LOCAL_JOBS[job_id]["result"] = result_data
                _LOCAL_JOBS[job_id]["error"] = error_msg
                _LOCAL_JOBS[job_id]["duration_sec"] = duration


def enqueue_apk_job(
    file_path: Optional[str],
    sha256_hash: str,
    file_size: int,
    session_hash: str,
    upload_bytes: Optional[bytes] = None,
    on_complete_cb=None,
) -> str:
    """Enqueue an APK static analysis job.

    In Redis/RQ container mode:
    - Sends the raw uploaded bytes (upload_bytes) directly as the job argument.
    - Does not rely on or require a shared filesystem between containers.

    In Local Subprocess Fallback mode:
    - Runs a child process pointing to the local temporary file_path.

    Returns the unique job_id. Raises an exception if Redis enqueue fails when REDIS_URL is configured.
    """
    job_id = str(uuid.uuid4())
    redis_url = get_redis_url()

    if redis_url:
        import redis
        from rq import Queue
        conn = redis.from_url(redis_url)
        q = Queue("apk-analysis", connection=conn)
        from app.apk_worker import execute_rq_apk_job

        payload_bytes = upload_bytes
        if payload_bytes is None and file_path and os.path.exists(file_path):
            with open(file_path, "rb") as f:
                payload_bytes = f.read()

        if payload_bytes is None:
            raise ValueError("No upload bytes or file provided to enqueue_apk_job.")

        rq_job = q.enqueue(
            execute_rq_apk_job,
            payload_bytes,
            sha256_hash,
            file_size,
            job_id=job_id,
            job_timeout=JOB_TIMEOUT_SECONDS,
            result_ttl=3600,
        )
        rq_job.meta["session_hash"] = session_hash
        rq_job.meta["created_at"] = time.time()
        rq_job.save_meta()
        return job_id

    # Local Subprocess Fallback (when REDIS_URL is unset)
    if not file_path or not os.path.exists(file_path):
        raise ValueError("file_path is required for local subprocess worker execution.")

    with _LOCAL_JOBS_LOCK:
        _LOCAL_JOBS[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "result": None,
            "error": None,
            "created_at": time.time(),
            "session_hash": session_hash,
            "sha256": sha256_hash,
            "file_size": file_size,
        }

    thread = threading.Thread(
        target=_execute_subprocess_job,
        args=(job_id, file_path, sha256_hash, file_size, on_complete_cb),
        daemon=True,
    )
    thread.start()
    return job_id
