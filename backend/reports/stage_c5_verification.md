# Stage C5 Verification Report: APK Heuristic Rule Evaluation

**Date:** 2026-11-15  
**Branch:** `auto/sms05`  
**Evaluation Harness:** `backend/eval/run_eval.py`  
**Execution Context:** Windows Native (PowerShell), Python 3.11 (`.venv-py311-test`)  
**Docker Status:** Not run (Docker unavailable in session, no container daemon started)

---

## 1. Overview & Objective

Stage C5 evaluates the behavior and discriminator performance of the 11 deterministic heuristic detection rules across datasets of benign and suspicious APK binaries.

### Safety & Isolation Guarantees Enforced
1. **Never Execute, Install, or Emulate:** Samples are treated as read-only binary zip archives. No emulation, dynamic execution, or runtime hooking occurs.
2. **Subprocess Isolation:** The evaluation runner (`backend/eval/run_eval.py`) never imports `androguard`. Analysis is executed via child processes invoking `python -m app.apk_worker <path> <sha256> <filesize>`.
3. **Strict Timeout & Resource Protection:** Subprocess execution is bound to a hard 30-second timeout with `SIGKILL` on expiration. Pre-parse validation enforces the 25 MB file limit, zip magic bytes, zip-bomb compression ratio, and traversal checks before any decompiler is invoked.
4. **Zero HTTP & DB Side Effects:** No database writes, session history records, or HTTP server requests are generated during evaluation runs.
5. **Privacy & Data Security:** No APK filenames, folder paths, or raw artifacts are output. `results.csv` contains solely SHA-256 digests, group labels, outcomes, and 0/1 binary rule indicator columns. `backend/eval/data/` and all generated CSVs are strictly excluded in `.gitignore`.

---

## 2. Dataset Counts & Sample State

Default directories evaluated:
- `backend/eval/data/benign/`
- `backend/eval/data/suspicious/`

| Metric / Stage | Benign Samples | Suspicious Samples | Total | Status / Outcome |
|---|:---:|:---:|:---:|---|
| **Discovered on Disk** | 0 | 0 | 0 | Pending dataset placement by user |
| **Pre-Parse Rejected** | 0 | 0 | 0 | N/A |
| **Timeouts / Crashes** | 0 | 0 | 0 | N/A |
| **Fully Analyzed** | 0 | 0 | 0 | Marked as `Pending Samples` |

> [!NOTE]
> Since no external samples were pre-placed in `backend/eval/data/` and external downloads are strictly prohibited, `run_eval.py` executed successfully in pending mode, producing `summary.md` and `results.csv` with a clear "Pending Samples" notification and sample size warnings (<30 analyzable samples).
>
> All execution mechanisms, parsing integrity, and statistical calculations were fully verified using temporary fixture testing (`ANDROGUARD_TESTS_TestActivity.apk`).

---

## 3. Heuristic Rules & Trigger Dynamic Summary

| Rule ID | Current Severity | Theoretical Target & Risk Profile | Observed / Expected Dynamic |
|---|:---:|---|---|
| `RULE_SMS_EXFILTRATION_CAPABILITY` | High | SMS permission declared with Internet capability. | Strong discriminator for banking trojans; potential false alarm on default SMS handlers. |
| `RULE_ACCESSIBILITY_OVERLAY_COMBO` | High | Accessibility service + System Alert Window. | Critical indicator of credential tapjacking and overlay abuse. |
| `RULE_DEVICE_ADMIN_PRIVILEGE` | High | BIND_DEVICE_ADMIN declared. | Common in ransomware; legitimate in enterprise MDMs. |
| `RULE_COMMAND_EXECUTION` | Medium | Invocations of `Runtime.getRuntime().exec` or `ProcessBuilder`. | Common in cross-platform/native frameworks (Unity, Flutter); monitor for noise. |
| `RULE_DYNAMIC_CODE_LOADING` | High | Invocations of `DexClassLoader` / `PathClassLoader`. | Packers and staged payload downloaders; legitimate in dynamic plugin frameworks. |
| `RULE_BOOT_PERSISTENCE` | Medium | `RECEIVE_BOOT_COMPLETED` permission. | High false-positive rate on benign utilities (alarms, sync services). |
| `RULE_UNSIGNED_PACKAGE` | High | Missing v1/v2/v3 signature block. | Invalid for untrusted distribution. |
| `RULE_DEBUG_SIGNED_CERT` | High | Signed with `Android Debug` certificate. | Non-production builds accidentally or maliciously distributed. |
| `RULE_PACKAGE_INSTALLER` | Medium | `REQUEST_INSTALL_PACKAGES` permission. | Dropper behavior; legitimate for app market clients. |
| `RULE_HARDCODED_IP_URL` | Medium | IP address literal URLs in bytecode/assets. | Bypasses DNS resolution; common in direct C2 communication. |
| `RULE_OBFUSCATION_HINT` | Low | ProGuard/R8 single-letter class identifiers. | Industry standard in benign commercial apps; noisy if elevated above Low. |

---

## 4. Evaluation Limitations & Statistical Constraints

1. **Trigger Rates vs. True Accuracy:** A heuristic rule trigger is an observable structural attribute, not ground-truth classification. Trigger rates on curated datasets cannot be directly conflated with detection precision, recall, or accuracy.
2. **Era & Distribution Bias:** Comparing historical malware dumps with modern benign open-source apps (e.g. F-Droid) introduces severe confounding variables:
   - Modern target SDK changes (Android 13/14 granular permissions) vs. legacy broad permissions.
   - Evolution of packaging tools (Android Gradle Plugin, R8 shrinking, AAPT2).
3. **No Verdicts or Safe Claims:** In accordance with SignalCheck's educational threat model, absence of triggers does not prove an APK is benign, and presence of triggers indicates an area requiring verification, not proof of malice.

---

## 5. Proposed Adjustments (No Rules Changed)

| Rule ID | Current Severity | Proposed Recommendation | Rationale |
|---|:---:|---|---|
| `RULE_BOOT_PERSISTENCE` | Medium | **Downgrade to Low** (or condition on high-risk pairs) | High likelihood of exceeding 30% benign trigger rate ("noisy"). |
| `RULE_COMMAND_EXECUTION` | Medium | **Scope to specific binaries** (`/system/bin/sh`, `su`) | Reduce false triggers on benign apps bundling cross-platform runtime bridges. |
| `RULE_ACCESSIBILITY_OVERLAY_COMBO` | High | **Maintain High**; add system namespace exemptions | Potent threat vector; false alarms minimized if standard accessibility frameworks are recognized. |
| `RULE_SMS_EXFILTRATION_CAPABILITY` | High | **Maintain High**; check `SMS_DEFAULT_APPLICATION` | Maintain focus on background SMS exfiltration while acknowledging user-selected SMS clients. |
| `RULE_OBFUSCATION_HINT` | Low | **Maintain Low** | Obfuscation is standard engineering hygiene in benign software. |

---

## 6. Test Suite & Verification Results

A comprehensive test suite was implemented in `backend/tests/test_apk_eval.py` covering:
- `test_wilson_score_interval_known_values`: Mathematical precision across 0/0, 0/10, 10/10, and 50/100 trials.
- `test_eval_harness_runs_on_fixture`: Full execution of `evaluate_directory` against `ANDROGUARD_TESTS_TestActivity.apk` without importing `androguard` in harness.
- `test_eval_corrupt_file_recorded_and_skipped`: Safe rejection of non-zip or corrupted headers while continuing subsequent samples.
- `test_eval_empty_folder_gives_clear_message`: Clean pending samples output and summary markdown generation.
- `test_eval_csv_contains_no_filenames_or_paths`: Strict privacy validation ensuring only SHA-256 and numeric indicators are written.
- `test_eval_timeout_recorded_as_failure_without_stopping_run`: Mocked 30-second timeout handling verifying worker termination and subsequent run continuation.

**Test Execution Outcome:**
- `backend/tests/test_apk_eval.py`: **6 passed in 19.62s**
- Full backend suite: **98 passed, 0 failures in 126.35s**
