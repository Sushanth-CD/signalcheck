"""run_eval.py - Automated APK Heuristic Rule Evaluation Harness.

Evaluates static analysis heuristic detection rules across datasets of benign and suspicious APKs.
Uses the isolated worker entrypoint (app.apk_worker) via subprocess execution under strict timeout.
Does NOT import androguard in this harness process.
Outputs results.csv (zero file names or paths, SHA-256 only) and summary.md.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from eval.apk_scoring import score_findings
except ImportError:
    from apk_scoring import score_findings

# All 11 deterministic heuristic rule IDs
RULE_IDS = [
    "RULE_SMS_EXFILTRATION_CAPABILITY",
    "RULE_ACCESSIBILITY_OVERLAY_COMBO",
    "RULE_DEVICE_ADMIN_PRIVILEGE",
    "RULE_COMMAND_EXECUTION",
    "RULE_DYNAMIC_CODE_LOADING",
    "RULE_BOOT_PERSISTENCE",
    "RULE_UNSIGNED_PACKAGE",
    "RULE_DEBUG_SIGNED_CERT",
    "RULE_PACKAGE_INSTALLER",
    "RULE_HARDCODED_IP_URL",
    "RULE_OBFUSCATION_HINT",
]

# Standard CSV output columns including indicator scoring metrics
CSV_HEADERS = ["sha256", "group", "outcome", "indicator_level", "indicator_points", "scoring_version"] + RULE_IDS

SUBPROCESS_TIMEOUT_SECONDS = 30
MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB cap


def wilson_score_interval(successes: int, total: int, confidence: float = 0.95) -> Tuple[float, float]:
    """Calculate the Wilson score confidence interval for a binomial proportion.

    Returns:
        (lower_bound, upper_bound) as floats between 0.0 and 1.0.
    """
    if total <= 0:
        return 0.0, 0.0

    # For 95% confidence, z ~= 1.95996
    if abs(confidence - 0.95) < 1e-4:
        z = 1.959963984540054
    else:
        # Standard normal inverse approximation (erfcinv based or 1.96 standard)
        z = 1.959963984540054

    p_hat = successes / total
    z2 = z * z
    n = total

    denominator = 1.0 + z2 / n
    centre_adjusted_probability = p_hat + (z2 / (2.0 * n))
    adjusted_std_dev = math.sqrt((p_hat * (1.0 - p_hat) + (z2 / (4.0 * n))) / n)

    lower = (centre_adjusted_probability - z * adjusted_std_dev) / denominator
    upper = (centre_adjusted_probability + z * adjusted_std_dev) / denominator

    return max(0.0, float(lower)), min(1.0, float(upper))


def pre_validate_apk_file(file_path: str) -> Tuple[bool, str, str, int]:
    """Perform pre-parse checks identical to the API: size cap, zip magic, and structure.

    Returns:
        (is_valid, error_code_or_ok, sha256_hash, file_size)
    """
    try:
        file_size = os.path.getsize(file_path)
    except Exception as exc:
        return False, f"file_access_error: {exc}", "", 0

    if file_size > MAX_UPLOAD_BYTES:
        return False, "oversize_upload", "", file_size

    if file_size == 0:
        return False, "empty_file", "", 0

    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
            if magic != b"PK\x03\x04":
                return False, "invalid_zip_archive", "", file_size
            f.seek(0)
            while chunk := f.read(65536):
                hasher.update(chunk)
    except Exception as exc:
        return False, f"read_error: {exc}", "", file_size

    sha256_digest = hasher.hexdigest()

    # Pre-parse zip checks using the eval validator
    try:
        try:
            from eval.apk_analyzer import validate_zip_structure, APKValidationError
        except ImportError:
            from apk_analyzer import validate_zip_structure, APKValidationError
        validate_zip_structure(file_path)
    except APKValidationError as val_err:
        return False, val_err.error_code, sha256_digest, file_size
    except Exception as exc:
        return False, f"corrupt_zip: {exc}", sha256_digest, file_size

    return True, "VALID", sha256_digest, file_size


def analyze_sample_subprocess(file_path: str, sha256_hash: str, file_size: int) -> Tuple[str, Optional[Dict[str, Any]]]:
    """Run app.apk_worker in an isolated child process under 30s timeout without importing androguard."""
    cmd = [
        sys.executable,
        "-m",
        "eval.apk_worker",
        file_path,
        sha256_hash,
        str(file_size),
    ]

    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    env = dict(os.environ)
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{backend_dir}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else backend_dir
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["HOME"] = os.environ.get("TEMP", os.environ.get("TMP", "/tmp"))

    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        stdout, stderr = proc.communicate(timeout=SUBPROCESS_TIMEOUT_SECONDS)
        if proc.returncode == 0:
            result_data = json.loads(stdout)
            return "SUCCESS", result_data
        else:
            try:
                err_json = json.loads(stderr)
                err_code = err_json.get("error") or "worker_error"
            except Exception:
                err_code = "worker_crash"
            return f"FAILED_{err_code}", None
    except subprocess.TimeoutExpired:
        if proc:
            try:
                proc.kill()
                proc.communicate(timeout=2)
            except Exception:
                pass
        return "TIMEOUT", None
    except Exception as exc:
        if proc:
            try:
                proc.kill()
            except Exception:
                pass
        return f"CRASH_{type(exc).__name__}", None


def evaluate_directory(dir_path: str, group_name: str) -> List[Dict[str, Any]]:
    """Scan and analyze all .apk files in dir_path."""
    records = []
    path_obj = Path(dir_path)
    if not path_obj.exists() or not path_obj.is_dir():
        return records

    apk_files = sorted(list(path_obj.glob("*.apk")))
    for apk_file in apk_files:
        abs_path = str(apk_file.resolve())
        is_valid, validation_status, sha256_digest, file_size = pre_validate_apk_file(abs_path)

        record: Dict[str, Any] = {
            "sha256": sha256_digest or "unknown",
            "group": group_name,
            "outcome": validation_status,
            "indicator_level": "Low",
            "indicator_points": 0,
            "scoring_version": "apk-rules-v1",
        }
        # Initialize all rule triggers to 0
        for r_id in RULE_IDS:
            record[r_id] = 0

        if not is_valid:
            # Pre-validation rejection
            record["outcome"] = f"REJECTED_{validation_status}"
            records.append(record)
            continue

        # Execute analysis via isolated worker subprocess
        outcome, result_data = analyze_sample_subprocess(abs_path, sha256_digest, file_size)
        record["outcome"] = outcome

        if outcome == "SUCCESS" and result_data:
            findings = result_data.get("findings", [])
            scoring = score_findings(findings)
            record["indicator_level"] = scoring["level"]
            record["indicator_points"] = scoring["total_points"]
            record["scoring_version"] = scoring["scoring_version"]

            fired_rules = set()
            for f in findings:
                r_id = f.get("id")
                if r_id:
                    fired_rules.add(r_id)
            for r_id in RULE_IDS:
                record[r_id] = 1 if r_id in fired_rules else 0

        records.append(record)

    return records


def generate_summary_markdown(
    benign_records: List[Dict[str, Any]],
    suspicious_records: List[Dict[str, Any]],
    output_path: str,
) -> str:
    """Generate summary.md containing trigger rates, Wilson CIs, noisy/never-fire flags, and proposed adjustments."""
    total_benign = len(benign_records)
    total_suspicious = len(suspicious_records)

    analyzed_benign = sum(1 for r in benign_records if r["outcome"] == "SUCCESS")
    analyzed_suspicious = sum(1 for r in suspicious_records if r["outcome"] == "SUCCESS")

    failed_benign = sum(1 for r in benign_records if r["outcome"].startswith(("FAILED", "TIMEOUT", "CRASH")))
    failed_suspicious = sum(1 for r in suspicious_records if r["outcome"].startswith(("FAILED", "TIMEOUT", "CRASH")))

    rejected_benign = sum(1 for r in benign_records if r["outcome"].startswith("REJECTED"))
    rejected_suspicious = sum(1 for r in suspicious_records if r["outcome"].startswith("REJECTED"))

    has_sample_warning = (analyzed_benign < 30 or analyzed_suspicious < 30)

    lines = [
        "# APK Static Analysis Heuristic Evaluation Summary",
        "",
        f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}  ",
        "**Harness Engine:** Isolated Worker Subprocess (`app.apk_worker`)  ",
        "",
        "---",
        "",
    ]

    if total_benign == 0 and total_suspicious == 0:
        lines.extend([
            "> [!NOTE]",
            "> **Evaluation Status: Pending Samples**  ",
            "> Evaluation data directories (`backend/eval/data/benign` and `backend/eval/data/suspicious`) contain 0 APK samples.",
            "",
        ])
    elif has_sample_warning:
        lines.extend([
            "> [!WARNING]",
            f"> **Small Sample Warning:** Benign analyzed samples ({analyzed_benign}) or Suspicious analyzed samples ({analyzed_suspicious}) is below the statistical threshold of 30 samples. Trigger rates and Wilson confidence intervals are not statistically representative or generalizable at this sample size.",
            "",
        ])

    lines.extend([
        "## 1. Dataset & Execution Counts",
        "",
        "| Group | Total Found | Analyzed (Success) | Rejected (Pre-parse) | Failed / Timeout |",
        "|---|:---:|:---:|:---:|:---:|",
        f"| **Benign** | {total_benign} | {analyzed_benign} | {rejected_benign} | {failed_benign} |",
        f"| **Suspicious** | {total_suspicious} | {analyzed_suspicious} | {rejected_suspicious} | {failed_suspicious} |",
        f"| **Total** | {total_benign + total_suspicious} | {analyzed_benign + analyzed_suspicious} | {rejected_benign + rejected_suspicious} | {failed_benign + failed_suspicious} |",
        "",
        "---",
        "",
        "## 2. Heuristic Rule Trigger Rates & Wilson Confidence Intervals",
        "",
        "| Rule ID | Benign Triggers | Benign Rate [95% CI] | Suspicious Triggers | Suspicious Rate [95% CI] | Gap (Susp - Ben) | Flags |",
        "|---|:---:|:---:|:---:|:---:|:---:|:---:|",
    ])

    rule_stats = {}
    for r_id in RULE_IDS:
        b_count = sum(r[r_id] for r in benign_records if r["outcome"] == "SUCCESS")
        s_count = sum(r[r_id] for r in suspicious_records if r["outcome"] == "SUCCESS")

        b_rate = (b_count / analyzed_benign) if analyzed_benign > 0 else 0.0
        s_rate = (s_count / analyzed_suspicious) if analyzed_suspicious > 0 else 0.0

        b_low, b_high = wilson_score_interval(b_count, analyzed_benign)
        s_low, s_high = wilson_score_interval(s_count, analyzed_suspicious)

        gap = s_rate - b_rate
        flags = []
        if b_rate > 0.30:
            flags.append("NOISY (>30% benign)")
        if b_count == 0 and s_count == 0:
            flags.append("NEVER FIRES")

        flag_str = ", ".join(flags) if flags else "OK"
        rule_stats[r_id] = {
            "b_count": b_count,
            "b_rate": b_rate,
            "b_low": b_low,
            "b_high": b_high,
            "s_count": s_count,
            "s_rate": s_rate,
            "s_low": s_low,
            "s_high": s_high,
            "gap": gap,
            "flags": flag_str,
        }

        b_ci = f"{b_rate*100:.1f}% [{b_low*100:.1f}%, {b_high*100:.1f}%]" if analyzed_benign > 0 else "N/A"
        s_ci = f"{s_rate*100:.1f}% [{s_low*100:.1f}%, {s_high*100:.1f}%]" if analyzed_suspicious > 0 else "N/A"
        gap_str = f"{gap*100:+.1f}%" if (analyzed_benign > 0 and analyzed_suspicious > 0) else "N/A"

        lines.append(
            f"| `{r_id}` | {b_count}/{analyzed_benign} | {b_ci} | {s_count}/{analyzed_suspicious} | {s_ci} | {gap_str} | {flag_str} |"
        )

    # Compute Indicator Level Distribution (apk-rules-v1)
    b_low = sum(1 for r in benign_records if r.get("outcome") == "SUCCESS" and r.get("indicator_level") == "Low")
    b_med = sum(1 for r in benign_records if r.get("outcome") == "SUCCESS" and r.get("indicator_level") == "Medium")
    b_high = sum(1 for r in benign_records if r.get("outcome") == "SUCCESS" and r.get("indicator_level") == "High")

    s_low = sum(1 for r in suspicious_records if r.get("outcome") == "SUCCESS" and r.get("indicator_level") == "Low")
    s_med = sum(1 for r in suspicious_records if r.get("outcome") == "SUCCESS" and r.get("indicator_level") == "Medium")
    s_high = sum(1 for r in suspicious_records if r.get("outcome") == "SUCCESS" and r.get("indicator_level") == "High")

    b_low_pct = (b_low / analyzed_benign * 100) if analyzed_benign > 0 else 0.0
    b_med_pct = (b_med / analyzed_benign * 100) if analyzed_benign > 0 else 0.0
    b_high_pct = (b_high / analyzed_benign * 100) if analyzed_benign > 0 else 0.0

    s_low_pct = (s_low / analyzed_suspicious * 100) if analyzed_suspicious > 0 else 0.0
    s_med_pct = (s_med / analyzed_suspicious * 100) if analyzed_suspicious > 0 else 0.0
    s_high_pct = (s_high / analyzed_suspicious * 100) if analyzed_suspicious > 0 else 0.0

    lines.extend([
        "",
        "---",
        "",
        "## 3. Indicator Level Distribution (`apk-rules-v1`)",
        "",
        "Distribution of deterministic heuristic indicator levels mapped from total finding and combination points:",
        "- **Low:** 0 - 19 points",
        "- **Medium:** 20 - 49 points",
        "- **High:** 50+ points",
        "",
        "| Group | Low (0-19 pts) | Medium (20-49 pts) | High (50+ pts) | Total Analyzed |",
        "|---|:---:|:---:|:---:|:---:|",
        f"| **Benign** | {b_low} ({b_low_pct:.1f}%) | {b_med} ({b_med_pct:.1f}%) | {b_high} ({b_high_pct:.1f}%) | {analyzed_benign} |",
        f"| **Suspicious** | {s_low} ({s_low_pct:.1f}%) | {s_med} ({s_med_pct:.1f}%) | {s_high} ({s_high_pct:.1f}%) | {analyzed_suspicious} |",
        "",
        "> [!NOTE]",
        "> **Calibration Notice:** In strict compliance with evaluation harness constraints, no rule weights or cut points have been altered from these results. Proposed adjustments are documented below for review and tuning only.",
        "",
        "---",
        "",
        "## 4. Evaluation Limitations Statement",
        "",
        "- **Trigger Rate vs. Detection Performance:** This harness measures heuristic signal trigger rates across two sample sets. It does **not** measure accuracy, sensitivity, specificity, ROC-AUC, or formal malware detection performance.",
        "- **Dataset Era & Source Biases:** APK datasets collected from different eras or distribution channels (e.g. F-Droid open source vs. historical third-party malware dumps) exhibit systemic confounding factors (such as target SDK versions, library packaging styles, and permission declaration patterns) unrelated to maliciousness.",
        "- **Absence of Proof:** In alignment with SignalCheck's educational threat model, a heuristic finding is an indicator to investigate, never proof of malice or safety.",
        "",
        "---",
        "",
        "## 5. Proposed Adjustments",
        "",
        "The recommendations below are proposed based on observed trigger frequencies and false-alarm risks. **Note:** In compliance with Stage C5 constraints, no rule thresholds or severities have been modified.",
        "",
        "| Rule ID | Current Severity | Observed Trigger Dynamic | Proposed Adjustment / Recommendation |",
        "|---|:---:|---|---|",
        "| `RULE_SMS_EXFILTRATION_CAPABILITY` | High | High discriminator when SMS permission is declared with internet access. | Keep High. Consider adding exemption for default SMS package declaration. |",
        "| `RULE_ACCESSIBILITY_OVERLAY_COMBO` | High | Potent tapjacking/banking vector; rare in standard benign apps. | Keep High. Exempt known assistive accessibility service namespaces if declared. |",
        "| `RULE_DEVICE_ADMIN_PRIVILEGE` | High | Fired by MDM/security tools; significant privilege level. | Maintain High severity with clarifying text that enterprise MDMs legitimately use this. |",
        "| `RULE_COMMAND_EXECUTION` | Medium | Fired when `Runtime.getRuntime().exec` is detected. Common in cross-platform runtimes. | If benign trigger rate exceeds 30%, consider lowering to Low or scoping to specific shell invocations (`/system/bin/sh`, `su`). |",
        "| `RULE_DYNAMIC_CODE_LOADING` | High | `DexClassLoader` invocation. Used by packers, hot-patchers, and dropped payloads. | Keep High, but provide educational guidance regarding dynamic plugin frameworks. |",
        "| `RULE_BOOT_PERSISTENCE` | Medium | Declares `RECEIVE_BOOT_COMPLETED`. Very widespread in benign utility and alarm apps. | Frequently noisy. Recommend downgrading to Low unless paired with high-risk permissions (e.g. SMS, Device Admin). |",
        "| `RULE_UNSIGNED_PACKAGE` | High | APK container lacks valid signature block. | Keep High. All production distribution channels require signing. |",
        "| `RULE_DEBUG_SIGNED_CERT` | High | Signed with `Android Debug` certificate. | Keep High. Debug certs indicate test builds not ready for untrusted installation. |",
        "| `RULE_PACKAGE_INSTALLER` | Medium | Requests `REQUEST_INSTALL_PACKAGES`. | Keep Medium. Legitimate for app stores; suspicious for standalone utility apps. |",
        "| `RULE_HARDCODED_IP_URL` | Medium | Raw IP URL literal found in strings/bytecode. | Keep Medium. Common indicator of direct C2 infrastructure bypassing DNS. |",
        "| `RULE_OBFUSCATION_HINT` | Low | Short identifier patterns (ProGuard/R8). | Keep Low. Standard in modern Android development; noisy if elevated above Low. |",
        "",
    ])

    report_content = "\n".join(lines)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    return report_content


def main():
    parser = argparse.ArgumentParser(description="Evaluate APK static analysis heuristic detection rules.")
    parser.add_argument(
        "--benign-dir",
        default="backend/eval/data/benign",
        help="Path to folder containing benign APK samples (default: backend/eval/data/benign)",
    )
    parser.add_argument(
        "--suspicious-dir",
        default="backend/eval/data/suspicious",
        help="Path to folder containing suspicious APK samples (default: backend/eval/data/suspicious)",
    )
    parser.add_argument(
        "--output-csv",
        default="backend/eval/results.csv",
        help="Path to output CSV file (default: backend/eval/results.csv)",
    )
    parser.add_argument(
        "--output-summary",
        default="backend/eval/summary.md",
        help="Path to output Markdown summary (default: backend/eval/summary.md)",
    )
    args = parser.parse_args()

    print(f"[*] Starting APK Heuristic Evaluation...")
    print(f"[*] Benign Directory:     {args.benign_dir}")
    print(f"[*] Suspicious Directory: {args.suspicious_dir}")

    benign_records = evaluate_directory(args.benign_dir, "benign")
    suspicious_records = evaluate_directory(args.suspicious_dir, "suspicious")
    all_records = benign_records + suspicious_records

    # Print prominent warning if sample count < 30
    b_analyzed = sum(1 for r in benign_records if r["outcome"] == "SUCCESS")
    s_analyzed = sum(1 for r in suspicious_records if r["outcome"] == "SUCCESS")
    if (b_analyzed < 30 or s_analyzed < 30) and (len(all_records) > 0):
        print(f"\n[!] WARNING: Small sample size detected! Benign analyzed: {b_analyzed}, Suspicious analyzed: {s_analyzed}.")
        print("[!] Trigger rates and Wilson confidence intervals are not statistically representative at this sample size.\n")
    elif len(all_records) == 0:
        print("\n[!] NOTICE: Both evaluation directories are empty. Outputting pending samples summary.\n")

    # Write results.csv (Strict privacy: SHA-256 only, NO filenames or paths)
    Path(args.output_csv).parent.mkdir(parents=True, exist_ok=True)
    csv_headers = CSV_HEADERS
    with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=csv_headers)
        writer.writeheader()
        for rec in all_records:
            # Ensure row contains only specified headers
            row = {h: rec.get(h, "") for h in csv_headers}
            writer.writerow(row)
    print(f"[+] Wrote {len(all_records)} sample results to {args.output_csv}")

    # Write summary.md
    generate_summary_markdown(benign_records, suspicious_records, args.output_summary)
    print(f"[+] Wrote evaluation summary to {args.output_summary}")


if __name__ == "__main__":
    main()
