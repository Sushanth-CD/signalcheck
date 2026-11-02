# Dataset Provenance: ACM IMC 2025 `reportsmishing`

**Milestone:** SMS-05 Pilot Acquisition & Forensic Inspection  
**Dataset Identifier:** `reportsmishing/Smishing-Dataset-IMC25`  
**Associated Paper:** *Fishing for Smishing: Understanding SMS Phishing Infrastructure and Strategies by Mining Public User Reports*  
**Authors:** Sharad Agarwal, Antonis Papasavva, Guillermo Suarez-Tangil, Marie Vasek  
**Conference:** ACM Internet Measurement Conference (IMC 2025)  
**Permanent Repository:** [`https://github.com/reportsmishing/Smishing-Dataset-IMC25`](https://github.com/reportsmishing/Smishing-Dataset-IMC25)  
**Date:** November 2026  

---

## 1. Bibliographic & Provenance Details

- **Origin Institution:** IMDEA Networks Institute, University College London, University College Dublin.
- **Publication Venue:** Proceedings of the 2025 ACM Internet Measurement Conference (IMC '25), Madison, WI, USA.
- **Repository Commit SHA:** `a6175560b57387199871e51fbef6bc523d2516b4` (Committed September 12, 2025).
- **Target File:** `dataset/final_dataset_output.csv` (Size: 9,462,365 bytes).
- **Cryptographic SHA-256 Digest:** `1bbd1e9e82c3ea023112207b80da268a5c4a07d2353c2b0898360ab037fa9a64`.

---

## 2. Collection Methodology and Ground Truth Generation

According to the publication metadata and companion scripts:
1. **Source Data Aggregation:** The authors programmatically mined public user reports, forum discussions, and dedicated mobile fraud warning channels (Reddit, Twitter/X, and specialized consumer complaint forums) spanning 2023 to 2025.
2. **Multi-Modal Ingestion (Text & OCR):** Public reports included both copy-pasted SMS text and thousands of image attachments (screenshots of mobile text threads). The authors executed an automated Optical Character Recognition (OCR) pipeline using Tesseract and vision heuristics to extract text from screenshots.
3. **Anonymization and Sanitization:** Personally identifiable information was automatically masked with structured semantic tags (e.g., `<PHONE_NUMBER>`, `<URL>`, `<NAMED_ENTITY>`, `<LOCATION>`, `<DATE_TIME>`, `<US_BANK_NUMBER>`).
4. **Scam Taxonomy Annotation:** Every message was classified into fine-grained scam taxonomies (`banking`, `delivery`, `government`, `telecom`, `wrong number`, `hey mum/dad`, `others`) and psychological lure principles (`urgency`, `authority`, `scarcity`, `distraction`).

---

## 3. Licensing and Usage Rights

- **License:** **Creative Commons Attribution 4.0 International License (CC BY 4.0)**.
- **Verification:** Explicitly documented in `LICENSE.txt` and the repository `README.md` badge (`https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg`).
- **Research Rights:** Fully permits academic and commercial reuse, modification, and model training, provided proper attribution is maintained.
