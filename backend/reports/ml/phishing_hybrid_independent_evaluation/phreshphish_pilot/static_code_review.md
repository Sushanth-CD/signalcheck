# Static Code Review: `run_bounded_pilot.py`

**Review Subject:** `backend/reports/ml/phishing_hybrid_independent_evaluation/phreshphish_pilot/run_bounded_pilot.py`  
**Execution Failure Profile:** Previous execution ran for 32+ minutes without completing or terminating despite an intended 5-minute (300-second) ceiling.  
**Review Mode:** Strict Read-Only Static Analysis (zero code execution, zero network requests, zero process generation).

---

## 1. Executive Summary of Root Causes

The static code review reveals why the script ran for 32+ minutes and failed to terminate at the 5-minute mark:

1. **Unbuffered I/O vs. Background Task Capturing (Apparent Hang):**
   Standard Python buffers `stdout` in block mode when stdout is redirected to a pipe or file (as done by background runners). In `main()`, `print(...)` statements are not followed by `sys.stdout.flush()` nor is the script invoked with `-u`. Output remained stuck in memory buffers until termination.
2. **Phase 2 In-Memory Indexing Latency (Blocking Before Streaming Starts):**
   Lines 131–150 load all 77,677 JSON records from `combined_reduced.json`, compute character 5-grams and SHA-256 digests per shingle, and build a 4-table multi-index SimHash data structure in pure Python before any candidate acquisition or network streaming begins. This computation alone takes 1.5–3+ minutes on Windows CPU without yielding progress or checking the timeout.
3. **The HF Streaming Generator Network Timeout & Retry Freeze (The Core Bottleneck):**
   Line 156 (`ds = load_dataset(repo_id, split="test", streaming=True)`) and Line 166 (`for row in ds:`) invoke the Hugging Face `IterableDataset` abstraction over HTTP/fsspec. 
   - Neither `load_dataset` nor the underlying `fsspec`/`huggingface_hub`/`httpx`/`urllib3` transport is passed an explicit HTTP connection or read timeout.
   - When Hugging Face endpoints reset connections (observed repeatedly as `[WinError 10054]`), Hugging Face Hub enters an internal retry and exponential backoff loop.
   - **Crucially: Line 166 (`for row in ds:`) is a blocking generator call.** The timeout check at Line 171 (`if elapsed >= MAX_TIME_SECONDS:`) is placed **inside the body of the loop**. If the generator blocks waiting for a parquet chunk over a stalled or throttled socket, the loop body **never executes**, rendering the inside-the-loop timer completely inoperative.
4. **Parquet Column Inefficiency:**
   Parquet stores columns separately. In `test-000.parquet`, the non-HTML metadata columns are only ~75 KB total, whereas the `html` column is ~54 MB compressed (~306 MB uncompressed). Calling `load_dataset(..., streaming=True)` retrieves full records including all columns over the stream rather than projecting metadata first.

---

## 2. Detailed Technical Investigation

### Investigation 1: Whether Hugging Face Streaming Scans the Entire Dataset
* **Finding:** No, streaming does not unconditionally download all 21 shards upfront. It streams rows via a generator from the parquet shards sequentially.
* **Mechanism:** It opens `data/test-000.parquet`, yields rows one by one, and only advances to `data/test-001.parquet` when row 1,000 is reached.
* **Vulnerability:** While it does not download all 21 shards at once, it downloads row groups of the active shard chunk-by-chunk over HTTP. If a single parquet shard download is interrupted or throttled by Hugging Face unauthenticated rate limits, the generator stalls indefinitely.

### Investigation 2: Whether Parquet Shards are Downloaded Unnecessarily
* **Finding:** Yes, unnecessary column data is downloaded.
* **Mechanism:** In Line 156, `load_dataset(repo_id, split="test", streaming=True)` requests all 8 schema columns (`sha256`, `url`, `label`, `target`, `date`, `lang`, `lang_score`, `html`).
* **Impact:** The `html` column comprises **>99.8%** of the byte volume of each row group (~54 MB out of 55 MB for shard 0). Streaming all columns means tens of megabytes of raw HTML are transferred across the socket before deciding whether a row is a benchmark hit or not.

### Investigation 3: Whether Network Requests Have Connection and Read Timeouts
* **Finding:** **No explicit timeouts are configured.**
* **Lines of Concern:**
  - Line 92: `files = huggingface_hub.list_repo_files(repo_id, repo_type="dataset")` — uses default HTTP client timeout (often infinite or 60+ seconds per attempt).
  - Line 101: `test_shard_info = huggingface_hub.get_paths_info(repo_id, paths=test_shards, repo_type="dataset")` — uses default API timeout.
  - Line 156: `ds = load_dataset(repo_id, split="test", streaming=True)` — no `storage_options={"timeout": ...}` or socket timeout is supplied.
* **Impact:** Any dropped TCP packet or server-side hold (HTTP 429/503 rate limiting or TLS renegotiation stall) hangs the thread indefinitely in native socket `recv()`.

### Investigation 4: Whether Retry Loops Can Run Indefinitely
* **Finding:** Yes, underlying Hugging Face Hub requests use internal default exponential backoff retries (e.g., 5 retries with increasing backoff delays of 1s, 2s, 4s, 8s, 16s per request). When rate-limited or unauthenticated on Windows, requests trigger cascaded socket retries that can extend wall-clock time by tens of minutes without raising an unhandled exception.

### Investigation 5: Whether 10-Record and 100 MB Limits are Enforced Correctly
* **Finding:** The logic inside the loop (Lines 178–181 and Lines 202–205) is syntactically correct, but structurally flawed:
  - **Flaw A (Post-Transfer Check):** `row_bytes = len(html_val.encode("utf-8"))` (Line 177) is measured **after** the row has already traversed the network and entered memory. The byte limit only prevents *subsequent* rows from being accumulated into `streamed_candidates`, but does not stop data already in transit.
  - **Flaw B (Blocking Iteration):** The checks only trigger **after** `next(iterator)` successfully returns a row. If `next(iterator)` is blocked in network I/O, the condition is never evaluated.

### Investigation 6: Why the Five-Minute Timeout Failed
* **Lines of Concern:** Lines 168–174:
  ```python
  for row in ds:
      scanned_records += 1
      elapsed = time.time() - t_start

      # Check bounds
      if elapsed >= MAX_TIME_SECONDS:
          stop_reason = "time_limit_exceeded"
          ...
          break
  ```
* **Failure Analysis:**
  The timeout check is **synchronous and passive**. It only executes *between* iterations of `for row in ds:`.
  - If the socket blocks on network read, the Python GIL is blocked or waiting in C-level socket calls. Control never reaches Line 168.
  - If the network stalls at iteration $N$, or during generator startup / parquet chunk fetch, Python will wait indefinitely (30+ minutes) until OS socket TCP keepalive timeout occurs.
  - Furthermore, Phase 1 (metadata API calls) and Phase 2 (77,677 record SimHash indexing) have **zero timeout enforcement**. If Phase 2 takes 3 minutes and network initialization takes 3 minutes, the 5-minute budget is exceeded before the loop even starts.

---

## 3. Line-by-Line Bottleneck Identification

| Line(s) | Code Block / Construct | Identified Defect | Severity |
|---|---|---|---|
| **Lines 92, 101** | `huggingface_hub.list_repo_files(...)`, `get_paths_info(...)` | Unbounded network calls without socket timeout or error handling. | High |
| **Lines 118–150** | `Phase 2: Project Baseline Inventory Loading` | Heavy CPU/memory computation (building 77k-record 5-gram SimHash table) runs synchronously before any sample validation or timeout checks. | Medium |
| **Line 156** | `ds = load_dataset(repo_id, split="test", streaming=True)` | Initializes unprojected, unauthenticated streaming dataset without passing socket timeouts, storage options, or column projection. | High |
| **Line 166** | `for row in ds:` | **Primary Hang Point:** Blocking synchronous iterator call. If network socket hangs or rate limits trigger retry delays, execution stalls forever. | **Critical** |
| **Lines 171–174** | `if elapsed >= MAX_TIME_SECONDS: break` | Timeout is passive inside the loop body; cannot interrupt a blocked network read. | **Critical** |
| **Throughout** | `print(...)` statements | No `flush=True` or unbuffered mode, masking execution status from logs. | Medium |

---

## 4. Recommended Architectural Corrections

To guarantee an absolute wall-clock ceiling and eliminate the 30-minute freeze, the following changes are required:

1. **Active Preemptive Timeout Enforcement (Signal / Thread Worker):**
   Instead of checking `time.time() - t_start` inside a passive loop, wrap the acquisition phase in a dedicated daemon worker thread and use `worker.join(timeout=300)`. If the worker does not finish within 300 seconds, the main thread logs a timeout blocker and exits cleanly without hanging.
2. **Column Projection on Parquet / Selective Streaming:**
   Avoid loading full HTML strings over the streaming wire for records that are not in the benchmark index. Or, query the lightweight parquet files directly via `pyarrow.parquet` reading only metadata columns (`['sha256', 'url', 'label']`), identify the exact row indices matching the benchmark, and fetch only those specific rows.
3. **Explicit HTTP Timeout Configuration:**
   Pass explicit connection and read timeouts (e.g. `timeout=15`) to all Hugging Face and HTTP requests. Set `HF_HUB_ENABLE_HF_TRANSFER=0` and configure retries to a maximum of 2 with short backoffs.
4. **Deferred Project Indexing:**
   Do not pre-index 77,677 records before verifying candidate retrieval. Retrieve the candidate records first (taking seconds). Only screen the captured 10 candidates against the project corpus afterward. Screening 10 records against 77k takes milliseconds, whereas pre-indexing 77k records upfront takes minutes.
5. **Enforce Unbuffered Output:**
   Use `print(..., flush=True)` on all progress outputs to provide immediate real-time feedback in log streams.

---

## 5. Review Conclusion

The script `run_bounded_pilot.py` stalled because of a synchronous blocking network generator coupled with passive, inside-the-loop timeout checking and heavy upfront corpus indexing. All findings, line references, and remediation steps have been recorded in this review without executing Python or modifying runtime environments.
