# CompPhish V4 Mapping File & Schema Audit

**Audit Timestamp:** 2026-11-01 09:30:30 UTC  
**File Name:** `Mapping_File.xlsx` (SHA-256: `e6dda6a21d925f8aba36090f295b08e9808a5dfe8dd3276bf8cd82022855f14a`)  
**File Size:** 635,936 bytes (621 KB)  

---

## 1. Population & Schema Summary

- **Total Rows:** 15,358 records
- **Columns:** 3 columns
  1. `serial_number`: Integer / numeric identifier mapping 1:1 to the HTML file in `All_HTML/{serial_number}.txt`.
  2. `url`: Target URL string.
  3. `label`: Binary classification (0 = legitimate, 1 = phishing).
- **Null Value Count:** 0 across all columns (100% complete).
- **Unique Serial Numbers:** 15,358 (100% unique primary key).

---

## 2. Label Distribution

| Class | Label Value | Record Count | Percentage |
|---|---|---|---|
| **Legitimate** | `0` | **8,154** | **53.09%** |
| **Phishing** | `1` | **7,204** | **46.91%** |
| **Total** | - | **15,358** | **100.00%** |

*Verification:* The record count and label distribution exactly match the publisher's stated statistics.

---

## 3. URL Quality & Uniqueness

- **Unique URLs:** 15,351 (7 duplicate URL strings spanning 14 records).
- **Duplicate Analysis:**
  - Duplicate URLs share identical labels (no label conflicts).
  - Minor URL duplication represents distinct crawls of the same landing page at different collection times.

---

## 4. HTML Filename Mapping Convention

- Every serial number maps directly to `All_HTML/{serial_number}.txt`.
- The central directory of `All_HTML.zip` contains **15,359 entries** (1 directory entry `All_HTML/` + 15,358 `.txt` files), confirming **100% alignment** between `Mapping_File.xlsx` and the contents of `All_HTML.zip`.
