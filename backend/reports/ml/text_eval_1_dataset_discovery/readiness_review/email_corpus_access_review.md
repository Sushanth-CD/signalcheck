# Email Corpus Access & Independence Review: IWSPA-AP, DIFrauD, and CEAS 2008

**Milestone:** TEXT-EVAL-1 Readiness Review  
**Scope:** Dataset Access Verification, Provenance Tracing, and Training Collision Audit for Candidate Email Corpora  
**Status:** Read-Only Technical Review  
**Date:** November 2026  

---

## 1. IWSPA-AP Access & Availability Audit

- **Official Context:** International Workshop on Security and Privacy Analytics – Anti-Phishing Shared Task (IWSPA-AP 2018 / 2020), organized by the ReDAS Lab at the University of Houston (in conjunction with ACM CODASPY).
- **Access Status Verification:**
  - **IWSPA-AP V1.0 (2018 Task):** The no-header, body-only text dataset was released publicly for the shared task. Multiple participant repositories on GitHub maintain mirror archives of the body-only text splits (`train` and `test` text files). It **does not require formal registration or institutional NDA** for basic research benchmarking.
  - **IWSPA-AP V2.0 (2020 Task):** Features raw full-header emails and live institutional threat intelligence. **Requires formal registration, institutional verification, and signing a Non-Disclosure Agreement (NDA)** with the ReDAS Lab.
- **Composition & Labeling:**
  - V1.0 contains approximately 10,000 email bodies.
  - Class distribution: Heavily imbalanced (~90% legitimate ham, ~10% confirmed phishing).
  - Text fields: Pre-extracted body text with HTML markup stripped or retained.
- **Independence Feasibility:**
  - High independence from `ealvaradob/phishing-dataset`.
  - **Readiness Decision:** **CONDITIONAL GO.** Accessible via open V1.0 mirrors; V2.0 is blocked by NDA requirements.

---

## 2. DIFrauD Email Phishing Ingestion & Overlap Analysis

- **Repository:** `redasers/difraud` on Hugging Face (Dainis Boumber & Rakesh Verma, 2023).
- **Phishing Domain Configuration Audit:**
  - We investigated the upstream composition of the `phishing` configuration in `redasers/difraud`.
  - **Origin:** The DIFrauD phishing domain was assembled by compiling the **Jose Nazario Phishing Corpus** and the **Enron Email Corpus**, alongside SpamAssassin.
  - **Contamination Finding:**
    > [!WARNING]
    > **DIFRAUD IS NOT INDEPENDENT FROM OUR TRAINING DATA:**
    > Because `combined_reduced.json` (our training data) was derived from `ealvaradob/phishing-dataset`, which utilized Enron and Nazario as its primary email sources, the phishing configuration of DIFrauD shares identical underlying email corpora.
    > 
    > Using DIFrauD's email subset would directly re-evaluate hundreds of Enron and Nazario emails that our models were trained on.
- **Readiness Decision:** **NO-GO.** The DIFrauD email phishing subset is disqualified due to upstream training corpus collision.

---

## 3. CEAS 2008 Conference Sub-Corpus Readiness

- **Source:** Collaboration Against Spam 2008 (CEAS 2008) conference evaluation benchmark (available as `CEAS_08.csv` in the curated Zenodo collection `10.5281/zenodo.8339691` by Champa et al., 2024).
- **Investigation of Independence:**
  - Does `combined_reduced.json` include CEAS 2008?
  - **Audit Finding:** The metadata for `ealvaradob/phishing-dataset` confirms that its email component was restricted to Enron (legitimate) and Nazario (phishing). CEAS 2008 was **NOT** part of the `ealvaradob` ingestion.
- **File Structure & Availability:**
  - Standardized CSV schema: `sender`, `receiver`, `date`, `subject`, `body`, `label`.
  - Approximately 12,000 email records.
  - Contains genuine phishing lures from the 2008 era alongside legitimate academic and personal email traffic.
- **Exclusion Enforcement:**
  - While `CEAS_08.csv` is accepted, the accompanying `Enron.csv` and `Nazario.csv` files from the same Zenodo release remain **strictly quarantined and forbidden**.
- **Readiness Decision:** **GO (High Priority for Email Pilot)**.
