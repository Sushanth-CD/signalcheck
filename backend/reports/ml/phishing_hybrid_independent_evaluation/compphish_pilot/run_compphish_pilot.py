"""Parent supervisor script for CompPhish V4 Pilot.

Guarantees:
- Runs worker.py as a separate subprocess using backend/.venv/Scripts/python.exe -u (unbuffered).
- Enforces hard subprocess timeout (timeout=300 seconds).
- Terminates and kills subprocess cleanly if timeout expires.
- Streams stdout/stderr in real-time.
"""
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(r"C:\Projects\cyber-security-awareness-platform")
PYTHON_EXE = PROJECT_ROOT / "backend/.venv/Scripts/python.exe"
WORKER_SCRIPT = PROJECT_ROOT / "backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_pilot/worker.py"
TIMEOUT_SECONDS = 300


def main():
    start_time = time.time()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{now_str}] [PARENT] Starting CompPhish V4 Pilot Supervisor...", flush=True)
    print(f"[{now_str}] [PARENT] Python executable: {PYTHON_EXE}", flush=True)
    print(f"[{now_str}] [PARENT] Worker script: {WORKER_SCRIPT}", flush=True)
    print(f"[{now_str}] [PARENT] Subprocess timeout ceiling: {TIMEOUT_SECONDS} seconds.", flush=True)

    cmd = [str(PYTHON_EXE), "-u", str(WORKER_SCRIPT)]

    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=str(PROJECT_ROOT)
        )

        for line in proc.stdout:
            print(f"  [WORKER] {line}", end="", flush=True)

        proc.wait(timeout=TIMEOUT_SECONDS)
        exit_code = proc.returncode
        elapsed = time.time() - start_time
        print(f"\n[PARENT] Subprocess finished with exit code {exit_code} in {elapsed:.2f} seconds.", flush=True)

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start_time
        print(f"\n[PARENT TIMEOUT] Worker exceeded {TIMEOUT_SECONDS}s ceiling (elapsed: {elapsed:.2f}s). Terminating...", flush=True)
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=10)
                print("[PARENT] Worker terminated cleanly.", flush=True)
            except subprocess.TimeoutExpired:
                print("[PARENT] Termination timed out. Force-killing worker...", flush=True)
                proc.kill()
                proc.wait()
                print("[PARENT] Worker killed.", flush=True)
        sys.exit(1)
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"\n[PARENT ERROR] Supervisor encountered error: {e}", flush=True)
        if proc:
            proc.kill()
        sys.exit(2)


if __name__ == "__main__":
    main()
