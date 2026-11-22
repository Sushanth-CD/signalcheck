# APK Static Analysis Heuristic Evaluation Summary

**Date:** 2026-11-17 16:13:41 UTC  
**Harness Engine:** Isolated Worker Subprocess (`app.apk_worker`)  

---

> [!NOTE]
> **Evaluation Status: Pending Samples**  
> Evaluation data directories (`backend/eval/data/benign` and `backend/eval/data/suspicious`) contain 0 APK samples.

## 1. Dataset & Execution Counts

| Group | Total Found | Analyzed (Success) | Rejected (Pre-parse) | Failed / Timeout |
|---|:---:|:---:|:---:|:---:|
| **Benign** | 0 | 0 | 0 | 0 |
| **Suspicious** | 0 | 0 | 0 | 0 |
| **Total** | 0 | 0 | 0 | 0 |

---

## 2. Heuristic Rule Trigger Rates & Wilson Confidence Intervals

| Rule ID | Benign Triggers | Benign Rate [95% CI] | Suspicious Triggers | Suspicious Rate [95% CI] | Gap (Susp - Ben) | Flags |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `RULE_SMS_EXFILTRATION_CAPABILITY` | 0/0 | N/A | 0/0 | N/A | N/A | NEVER FIRES |
| `RULE_ACCESSIBILITY_OVERLAY_COMBO` | 0/0 | N/A | 0/0 | N/A | N/A | NEVER FIRES |
| `RULE_DEVICE_ADMIN_PRIVILEGE` | 0/0 | N/A | 0/0 | N/A | N/A | NEVER FIRES |
| `RULE_COMMAND_EXECUTION` | 0/0 | N/A | 0/0 | N/A | N/A | NEVER FIRES |
| `RULE_DYNAMIC_CODE_LOADING` | 0/0 | N/A | 0/0 | N/A | N/A | NEVER FIRES |
| `RULE_BOOT_PERSISTENCE` | 0/0 | N/A | 0/0 | N/A | N/A | NEVER FIRES |
| `RULE_UNSIGNED_PACKAGE` | 0/0 | N/A | 0/0 | N/A | N/A | NEVER FIRES |
| `RULE_DEBUG_SIGNED_CERT` | 0/0 | N/A | 0/0 | N/A | N/A | NEVER FIRES |
| `RULE_PACKAGE_INSTALLER` | 0/0 | N/A | 0/0 | N/A | N/A | NEVER FIRES |
| `RULE_HARDCODED_IP_URL` | 0/0 | N/A | 0/0 | N/A | N/A | NEVER FIRES |
| `RULE_OBFUSCATION_HINT` | 0/0 | N/A | 0/0 | N/A | N/A | NEVER FIRES |

---

## 3. Indicator Level Distribution (`apk-rules-v1`)

Distribution of deterministic heuristic indicator levels mapped from total finding and combination points:
- **Low:** 0 - 19 points
- **Medium:** 20 - 49 points
- **High:** 50+ points

| Group | Low (0-19 pts) | Medium (20-49 pts) | High (50+ pts) | Total Analyzed |
|---|:---:|:---:|:---:|:---:|
| **Benign** | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 |
| **Suspicious** | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 |

> [!NOTE]
> **Calibration Notice:** In strict compliance with evaluation harness constraints, no rule weights or cut points have been altered from these results. Proposed adjustments are documented below for review and tuning only.

---

## 4. Evaluation Limitations Statement

- **Trigger Rate vs. Detection Performance:** This harness measures heuristic signal trigger rates across two sample sets. It does **not** measure accuracy, sensitivity, specificity, ROC-AUC, or formal malware detection performance.
- **Dataset Era & Source Biases:** APK datasets collected from different eras or distribution channels (e.g. F-Droid open source vs. historical third-party malware dumps) exhibit systemic confounding factors (such as target SDK versions, library packaging styles, and permission declaration patterns) unrelated to maliciousness.
- **Absence of Proof:** In alignment with SignalCheck's educational threat model, a heuristic finding is an indicator to investigate, never proof of malice or safety.

---

## 5. Proposed Adjustments

The recommendations below are proposed based on observed trigger frequencies and false-alarm risks. **Note:** In compliance with Stage C5 constraints, no rule thresholds or severities have been modified.

| Rule ID | Current Severity | Observed Trigger Dynamic | Proposed Adjustment / Recommendation |
|---|:---:|---|---|
| `RULE_SMS_EXFILTRATION_CAPABILITY` | High | High discriminator when SMS permission is declared with internet access. | Keep High. Consider adding exemption for default SMS package declaration. |
| `RULE_ACCESSIBILITY_OVERLAY_COMBO` | High | Potent tapjacking/banking vector; rare in standard benign apps. | Keep High. Exempt known assistive accessibility service namespaces if declared. |
| `RULE_DEVICE_ADMIN_PRIVILEGE` | High | Fired by MDM/security tools; significant privilege level. | Maintain High severity with clarifying text that enterprise MDMs legitimately use this. |
| `RULE_COMMAND_EXECUTION` | Medium | Fired when `Runtime.getRuntime().exec` is detected. Common in cross-platform runtimes. | If benign trigger rate exceeds 30%, consider lowering to Low or scoping to specific shell invocations (`/system/bin/sh`, `su`). |
| `RULE_DYNAMIC_CODE_LOADING` | High | `DexClassLoader` invocation. Used by packers, hot-patchers, and dropped payloads. | Keep High, but provide educational guidance regarding dynamic plugin frameworks. |
| `RULE_BOOT_PERSISTENCE` | Medium | Declares `RECEIVE_BOOT_COMPLETED`. Very widespread in benign utility and alarm apps. | Frequently noisy. Recommend downgrading to Low unless paired with high-risk permissions (e.g. SMS, Device Admin). |
| `RULE_UNSIGNED_PACKAGE` | High | APK container lacks valid signature block. | Keep High. All production distribution channels require signing. |
| `RULE_DEBUG_SIGNED_CERT` | High | Signed with `Android Debug` certificate. | Keep High. Debug certs indicate test builds not ready for untrusted installation. |
| `RULE_PACKAGE_INSTALLER` | Medium | Requests `REQUEST_INSTALL_PACKAGES`. | Keep Medium. Legitimate for app stores; suspicious for standalone utility apps. |
| `RULE_HARDCODED_IP_URL` | Medium | Raw IP URL literal found in strings/bytecode. | Keep Medium. Common indicator of direct C2 infrastructure bypassing DNS. |
| `RULE_OBFUSCATION_HINT` | Low | Short identifier patterns (ProGuard/R8). | Keep Low. Standard in modern Android development; noisy if elevated above Low. |
