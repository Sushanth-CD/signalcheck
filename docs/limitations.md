# SignalCheck Technical Limitations & Security Scope

This document details the intentional technical limitations, threat boundaries, and operating parameters of SignalCheck's static APK analysis engine and machine learning models.

---

## 1. Static Analysis Scope (No Dynamic Execution)
- **Static Inspection Only:** SignalCheck parses Android package manifests (`AndroidManifest.xml`), certificate signatures (`META-INF/`), resource tables, and Dalvik bytecode (`classes*.dex`) statically.
- **Never Executed, Emulated, or Installed:** The platform does not boot Android runtimes, hook APIs, instrument ART/Dalvik environments, or observe network traffic during execution.
- **Packers & Encryption Evasion:** Advanced malware employing native C/C++ libraries (JNI), dynamic code decryption, or commercial packers (e.g. Bangcle, Qihoo, SecNeo) may conceal malicious behavior from Dalvik bytecode inspection.

---

## 2. Heuristic Rules (Signals, Not Proof)
- **Rule-Based Engine with Zero ML Models:** The APK analyzer operates strictly via a deterministic, versioned rule-based scoring engine (`apk-rules-v1`). There is **no machine learning model, statistical probability, or classifier** scoring uploaded APK files. Findings and indicator levels are derived entirely from discrete structural checks and documented combination bonuses.
- **Deterministic Structural Rules:** Detection rules fire based on discrete indicators (e.g., combining SMS permissions with internet socket declarations, or detecting calls to `Runtime.getRuntime().exec`).
- **No Absolute Verdicts or Safety Guarantees:** 
  - Absence of findings does **not** prove an application is benign.
  - Presence of findings is an indicator for investigation, **not** proof of malware.
  - Many legitimate utility, accessibility, and enterprise management apps legitimately request elevated permissions (e.g., `RECEIVE_BOOT_COMPLETED`, MDM admin, accessibility overlays).
- **Educational Framing:** All findings present plain-language explanations detailing why attackers use a technique alongside legitimate business use cases to reduce panic and false alarm fatigue.

---

## 3. Subprocess Fallback vs. Container Hardening
- **Local Development Subprocess Fallback:**
  - Used when running natively on developer workstations without Docker (`REDIS_URL` unset).
  - Provides **process and timeout isolation only** (spawns child process under a hard 30-second kill timeout).
  - Does **not** provide filesystem isolation, network sandboxing, or memory cgroups; the child process executes under the host user's local operating system privileges.
- **Container Sandbox Mode:**
  - Required for staging and production environments (`REDIS_URL` configured).
  - Enforces non-root execution (`UID 10001`), an immutable read-only root filesystem, 64 MB tmpfs scratch space at `/tmp` (`noexec,nosuid,nodev`), zero external network egress (`internal: true`), and dropped Linux capabilities (`cap_drop: ALL`).

---

## 4. Evaluation Dataset & Sample Limitations
- **Curated Dataset Constraints:** Heuristic rule trigger evaluations are conducted across sample sets of benign and suspicious APKs.
- **Era & Source Bias:** Datasets collected from different eras (e.g. legacy malware dumps vs. modern F-Droid repositories) introduce systemic confounding variables such as changing Android target SDK versions and modernized packaging tools.
- **Trigger Frequency vs. Accuracy:** Evaluation metrics reflect indicator trigger rates, not calibrated statistical accuracy, precision, or recall.

---

## 5. Session-Private History & Retention
- **Anonymous Cookie Partitioning:** History records are partitioned by a cryptographic hash of an anonymous, random HTTP-only session token (`SameSite=Strict`).
- **Anti-Probing Controls:** Fetching a report ID belonging to a different session returns HTTP 404 (Not Found), preventing attackers from enumerating or probing report IDs.
- **Dual Retention Enforcement:**
  1. **Record Cap:** Enforces a maximum cap of 200 records per session hash; older records beyond this limit are automatically pruned.
  2. **Age-Based Purge:** Records older than 30 days (`SIGNALCHECK_APK_HISTORY_MAX_AGE_DAYS`) are automatically deleted on application startup and on each new analysis insertion.
- **Zero Binary Persistence:** Only parsed `apk-static-v1` JSON metadata and SHA-256 digests are stored in SQLite; raw APK files and bytecode slices are never persisted to disk or database.

---

## 6. Legacy 226-Feature ML Benchmark Limitations (44/226 Extraction Gap)
- **Offline Benchmark Only:** The 226-feature Random Forest model evaluated in the Research Lab operates strictly on precomputed numeric feature vectors and cannot score uploaded APK files.
- **44/226 Feature Reproduction Limit:**
  - Independent lineage auditing and extraction verification confirmed that **only 44 of the 226 features** can be extracted or reproduced directly from an APK container alone.
  - **165 Permission-Description Features (0 Resolved Mappings):** The training dataset utilized natural-language description labels (e.g., `"Default : Access DRM content. (S)"`) rather than canonical Android manifest permission identifiers (`android.permission.*`). Lineage auditing confirmed that 0 of the 165 permission-description features have a resolved, authoritative AOSP mapping (all 165 remain unverified/inferred).
  - **17 Taint-Engine Flow Features:** 17 features represent dataflow or taint-analysis pairs generated by an offline taint engine that exist only in the historical precomputed dataset.
- **Operating Boundary:** Because over 80% (182 of 226) of the required features cannot be reproduced from an APK alone, the tool does not score uploaded APKs with this model, avoiding synthetic imputation or misleading predictions.
