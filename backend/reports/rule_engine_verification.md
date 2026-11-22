# Rule-Based APK Indicator Engine Verification & Technical Report

**Platform:** SignalCheck Cyber Security Awareness Platform  
**Target File:** `backend/reports/rule_engine_verification.md`  
**Date:** November 17, 2026  
**Status:** COMPLETE & VERIFIED  
**Scoring Engine Version:** `apk-rules-v1`  
**Test Suite Status:** **113 / 113 PASSED (100%), 0 FAILURES**  

---

## 1. Executive Summary

In compliance with instructions for the rule-based APK indicator engine, we designed and integrated a deterministic, versioned heuristic scoring system (`apk-rules-v1`) implemented in `backend/app/apk_scoring.py`.

### Core Engineering Principles Enforced:
1. **Zero ML Models or Probabilistic Scores:** The APK analyzer relies strictly on deterministic structural parsing and heuristic rules. There is no ML model, confidence probability, or classifier for uploaded APK analysis.
2. **Neutral Educational Framing:** Strictly avoids forbidden wording (`probability`, `percentage`, `safe`, `unsafe`, and `malware` outside the canonical educational disclaimer: *"Heuristic indicator level, a signal to check and not a malware verdict."*).
3. **Single Source of Truth:** `indicator_level` is dynamically synchronized from static findings at serialization time, ensuring backwards compatibility for legacy SQLite records with zero database migration.
4. **Transparent & Tunable Constants:** All base weights, combination risk bonuses, and cut-point thresholds are declared in a single configuration table at the top of `backend/app/apk_scoring.py`.

---

## 2. Discovery: Prior vs. Current Indicator Level Calculation

### 2.1 Historical Indicator Level Logic
Prior to this release, `apk_worker.py` computed `indicator_level` by simple count thresholds of findings by severity:
```python
high_count = sum(1 for f in findings if f["severity"] == "high")
med_count = sum(1 for f in findings if f["severity"] == "medium")

if high_count >= 2 or (high_count >= 1 and med_count >= 2) or med_count >= 4:
    indicator_level = "many_indicators"
elif high_count >= 1 or med_count >= 1:
    indicator_level = "some_indicators"
else:
    indicator_level = "no_notable_indicators"
```
Limitations of the prior approach:
- Co-occurrence risk could not be weighted granularly (e.g. SMS exfiltration combined with dynamic code loading).
- No point breakdown or explainability was provided to the client.
- Hardcoded branch logic was difficult to tune or evaluate statistically.

### 2.2 New Deterministic Scoring Model (`apk-rules-v1`)
The scoring engine computes:
$$\text{Total Points} = \sum_{r \in \text{Fired Rules}} \text{Weight}(r) + \sum_{c \in \text{Triggered Combos}} \text{Bonus}(c)$$

#### Base Rule Weight Configuration Table:
| Rule ID | Base Points | Severity | Heuristic Capability Summary |
|---|:---:|:---:|---|
| `RULE_SMS_EXFILTRATION_CAPABILITY` | **30** | High | SMS read/receive permissions paired with internet socket declaration. |
| `RULE_ACCESSIBILITY_OVERLAY_COMBO` | **30** | High | Accessibility service implementation declared alongside system overlay window. |
| `RULE_DEVICE_ADMIN_PRIVILEGE` | **25** | High | Device administration receiver declared, granting device management policies. |
| `RULE_COMMAND_EXECUTION` | **20** | High | Bytecode invokes `Runtime.getRuntime().exec` or `ProcessBuilder`. |
| `RULE_DYNAMIC_CODE_LOADING` | **20** | Medium | Dynamic loading of secondary classes via `DexClassLoader` or `PathClassLoader`. |
| `RULE_UNSIGNED_PACKAGE` | **20** | High | Archive lacks valid cryptographic signing certificate blocks in `META-INF/`. |
| `RULE_PACKAGE_INSTALLER` | **15** | Medium | Requests permission to prompt installation of secondary packages. |
| `RULE_BOOT_PERSISTENCE` | **10** | Medium | Declares `RECEIVE_BOOT_COMPLETED` with registered boot broadcast receiver. |
| `RULE_DEBUG_SIGNED_CERT` | **10** | Medium | Container signed with publicly known Android debug certificate. |
| `RULE_HARDCODED_IP_URL` | **10** | Medium | Bytecode contains raw numeric IP endpoint literals circumventing DNS. |
| `RULE_OBFUSCATION_HINT` | **5** | Low | High proportion (>40%) of short class/method identifiers (naming minification). |

#### Documented Combination Bonuses:
| Combination ID | Bonus Points | Required Rules | Rationale |
|---|:---:|---|---|
| `COMBO_SMS_DYNAMIC` | **+15** | `RULE_SMS_EXFILTRATION_CAPABILITY` + `RULE_DYNAMIC_CODE_LOADING` | Sensitive SMS OTP interception combined with runtime modular code loading. |
| `COMBO_OVERLAY_COMMAND` | **+15** | `RULE_ACCESSIBILITY_OVERLAY_COMBO` + `RULE_COMMAND_EXECUTION` | UI overlay interception combined with direct operating system process execution. |
| `COMBO_INSTALLER_DYNAMIC` | **+15** | `RULE_PACKAGE_INSTALLER` + `RULE_DYNAMIC_CODE_LOADING` | Secondary application installation capability paired with external code loading. |
| `COMBO_ADMIN_PERSISTENCE` | **+10** | `RULE_DEVICE_ADMIN_PRIVILEGE` + `RULE_BOOT_PERSISTENCE` | Elevated administrative privileges paired with automatic startup persistence. |

#### Cut-Point Mapping:
| Total Points | Level (`indicator_summary.level`) | Canonical Key (`indicator_level`) | Interpretation |
|:---:|:---:|:---:|---|
| **0 – 19** | **Low** | `no_notable_indicators` | Few or purely informational indicators flagged. |
| **20 – 49** | **Medium** | `some_indicators` | Moderate scrutiny indicators warranting functional review. |
| **50+** | **High** | `many_indicators` | Multiple high-risk capabilities or combination bonuses flagged. |

---

## 3. Schema & Serialization Architecture

### 3.1 Additive Response Schema (`APKIndicatorSummary`)
Under `apk-static-v1`, `APKAnalysisResponse` includes the optional additive field `indicator_summary`:
```json
{
  "analysis_version": "apk-static-v1",
  "sha256": "...",
  "file_size": 2048000,
  "indicator_level": "some_indicators",
  "indicator_summary": {
    "scoring_version": "apk-rules-v1",
    "level": "Medium",
    "indicator_level": "some_indicators",
    "total_points": 20,
    "rule_contributions": [
      {
        "rule_id": "RULE_DYNAMIC_CODE_LOADING",
        "title": "Dynamic Class Loading Discovered in Bytecode",
        "points": 20
      }
    ],
    "combination_contributions": [],
    "disclaimer": "Heuristic indicator level, a signal to check and not a malware verdict."
  }
}
```

### 3.2 Dynamic Serialization & Legacy Support
- In `backend/app/main.py`: `attach_indicator_summary(result_dict)` runs on worker responses and on retrieval endpoints (`GET /api/apk/jobs/{id}`, `GET /api/apk/report/{id}`).
- In `backend/app/apk_db.py`: `get_apk_history` dynamically evaluates stored findings in SQLite `result_json` to compute the canonical `indicator_level`, enabling old records to present updated levels without database schema migration.
- In `backend/app/apk_pdf.py`: PDF reports render `indicator_summary` details alongside the canonical disclaimer.

---

## 4. Verification Suite & Test Results

### 4.1 Unit Test Coverage (`backend/tests/test_apk_scoring.py`)
All 8 explicit test scenarios were implemented and pass:
1. **Determinism:** Identical findings consistently produce identical scores, levels, and contributions regardless of list order.
2. **Combination Bonuses:** Each of the 4 combination bonuses triggers if and only if all constituent rules are present.
3. **Cut-point Boundaries:** Strict boundary transitions verified at 0, 15, 19, 20, 45, 50, and 65 points.
4. **Zero Findings:** Empty list produces 0 points, Level `Low`, and `no_notable_indicators`.
5. **Unknown Rule IDs:** Unknown or malformed rule IDs are safely ignored with 0 points added.
6. **Legacy Record Compatibility:** Unserialized legacy records lacking `indicator_summary` receive a valid summary at serialization time.
7. **Tone & Safety Verification:** Zero occurrences of `probability`, `percentage`, `safe`, or `unsafe`; `malware` occurs strictly within the canonical disclaimer.
8. **PDF Generation:** PDF report generator successfully compiles valid PDF documents containing the indicator scoring summary.

### 4.2 Full Test Suite Status
Executed across entire backend test suite:
- **113 / 113 PASSED (100%)** in 119 seconds.
- 0 failures, 0 errors.

### 4.3 End-to-End Playwright Artifacts
1. **Dashboard Rule-Based Card:** [dashboard_rule_based_card.png](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/screenshots/dashboard_rule_based_card.png)  
   Verifies updated copy stating rule-based static analysis with zero ML models.
2. **Rule Engine Summary & Breakdown:** [rule_based_indicator_summary_verified.png](file:///C:/Projects/cyber-security-awareness-platform/backend/reports/screenshots/rule_based_indicator_summary_verified.png)  
   Verifies top summary card, contributing rules list, points, disclaimer, and expanded "How this is calculated" table.
