# Dataset Acquisition Feasibility & Source-Level Review

**Document Version:** 1.0.0  
**Review Date (UTC):** 2026-10-31  
**Project:** Cyber Security Awareness Platform  
**Target Candidates:** Phishing V2, Phishing V3 Dual-Channel, Hybrid Policy 3, Hybrid Policy 4  
**Status:** Pre-acquisition Feasibility Review (Zero Downloads Executed)

---

## 1. Executive Summary & Review Scope

To definitively evaluate the frozen Phishing Classifier models on genuinely out-of-sample data, we conducted an in-depth source-level investigation of four external candidate datasets:
1. **PhreshPhish** (`phreshphish/phreshphish` on Hugging Face)
2. **CompPhish V4** (Mendeley Data `10.17632/fmbs4kp9wz.4`)
3. **LNU-Phish** (`https://lnu-phish.github.io/`)
4. **IWSPA-AP** (International Workshop on Security and Privacy Analytics – Anti-Phishing)
5. **Historical Email Archives** (Nazario, Enron Clean, SpamAssassin)

---

## 2. In-Depth Candidate Investigation

### Candidate 1: PhreshPhish (Hugging Face)
* **Hosting & Schema:** Hosted on Hugging Face as a partitioned dataset with official splits (`train`, `validation`, `test`). Each record contains:
  - `sha256`: Unique cryptographic fingerprint of the page content.
  - `url`: The explicit target webpage URL.
  - `html`: The raw, unparsed HTML DOM of the page.
  - `label`: Binary classification string (`'phish'` or `'benign'`).
  - `target`: Impersonated brand/institution (e.g., Chase, Microsoft).
  - `date`: Verified collection timestamp (2023–2025).
  - `lang` / `lang_score`: Language detection metadata.
* **Label Quality & Provenance:** Built specifically to remediate label leakage and historical dataset corruption. Ground truth is established via multi-vendor threat intelligence consensus for phishing, and verified live enterprise domains for benign controls.
* **Licensing & Access:** Open research access under standard academic terms (accompanied by arXiv preprint `2507.10854`).
* **Download & Storage Feasibility:** The full repository spans hundreds of thousands of samples ($>50\text{ GB}$). However, Hugging Face `datasets` supports streaming mode (`streaming=True`), enabling slice-by-slice evaluation and downloading only the official held-out test split without local disk bloat.
* **Format Compatibility:** **Direct 1:1 match.** The `html` field provides raw document text to evaluate V3 Dual-Channel and HTML routing; the `url` field provides raw URL strings to evaluate V2 and URL-only routing.

### Candidate 2: CompPhish V4 (Mendeley Data)
* **Hosting & Schema:** Hosted under Mendeley Data DOI `10.17632/fmbs4kp9wz.4` (Richa Goenka). Contains approximately 70 tabular features along with raw HTML files and URL records.
  - Binary label: `0` (legitimate) and `1` (phishing).
* **Label Provenance:** Phishing URLs sourced from PhishTank and OpenPhish; legitimate URLs sourced from DataForSEO Top-1000 websites list.
* **Licensing:** CC BY 4.0 Open Access (freely downloadable without NDAs).
* **Download Feasibility:** Archive size is moderate (approx. 2–5 GB), readily downloadable as a static ZIP.
* **Critical Source Strategy Limitation:** Benign URLs are established purely by presence in the DataForSEO Top-1000. **As required by our project rules, ranking alone must never establish a benign label without confirming page integrity.** Furthermore, OpenPhish data collection restrictions must be confirmed. Thus, CompPhish V4 is suitable only as a secondary check after rigorous domain filtering.

### Candidate 3: LNU-Phish (Apruzzese & Subrahmanian)
* **Hosting & Schema:** Research site `https://lnu-phish.github.io/` describing 20,000 websites (Alexa Top 1M benign + PhishTank/OpenPhish phishing) with HTML, URLs, DNS records, and screenshots.
* **Licensing & Access Barrier:** **The dataset is gated and non-public.** Access requires submitting a formal email request to the authors with an academic justification. There is no open automated download link or permissive open license.
* **Feasibility Verdict:** **Unsuitable for immediate acquisition.** Bypassing or attempting unofficial scraping is prohibited.

### Candidate 4: IWSPA-AP (Anti-Phishing Shared Tasks)
* **Hosting & Schema:** Academic benchmark email collections (2018 / 2020) containing MIME email headers, plain text, and HTML body parts.
* **Licensing & Access Barrier:** Official IWSPA-AP 2.0 requires a signed Non-Disclosure Agreement (NDA) and institutional verification via the University of Houston. Several derivative versions (e.g. 2018 challenge forks) exist on GitHub, but their licensing is fragmented.
* **Feasibility Verdict:** **Conditional.** Acquiring raw emails requires either formal institutional NDA execution or using verified open email corpora like Apache SpamAssassin public corpus.

---

## 3. Strict Source Strategy & Safety Correctives

1. **Tranco / Ranking Invalidation:**
   - Popularity rankings (Alexa, Tranco, DataForSEO, CrUX) reflect traffic, not benign intent. Compromised sites, redirectors, and free hosting platforms appear regularly in top rankings.
   - **Enforced Rule:** A high rank is a screening filter, never proof of benign status. Benign samples must be verified against active phishing blocklists and validated for absence of credential harvesting patterns.
2. **Inert Data Handling for PhishTank & OpenPhish:**
   - All URLs extracted from threat feeds must remain purely inert text strings.
   - **Enforced Rule:** Never issue HTTP GET/HEAD requests, ping sockets, or trigger automated crawlers against candidate URLs.
3. **OpenPhish Licensing Restrictions:**
   - OpenPhish free community feeds allow research and internal testing, but commercial redistribution or automated production scraping requires enterprise licensing. For this evaluation, we only review pre-compiled static research snapshots.

---

## 4. Multi-Layer Independence Screening Framework

Before any external record enters the final evaluation test matrix, it must be verified against all **77,677 project records** (including the 9,481 training reps, 2,005 validation reps, and the quarantined/held-out test cohorts):

```
       Candidate External Record (Text T, URL U)
                         │
                         ▼
        [1. Cryptographic Exact Match Check]
        - Normalize: NFKC, lowercase, collapse whitespace
        - Hash: SHA-256
        - Compare against all 77,568 unique project text hashes
        - Match -> IMMEDIATE REJECTION (Exact Collision)
                         │
                         ▼
        [2. Lexical Near-Duplicate Check]
        - 5-shingle MinHash / 64-bit SimHash
        - Compare against training & validation corpus
        - Jaccard similarity >= 0.85 -> REJECTION (Template Leakage)
                         │
                         ▼
        [3. Destination Domain Holdout Check]
        - Extract destination host via extract_candidates()
        - Resolve canonical registrable domain via pinned Oracle JDK PSL
        - Compare against 38,764 training registrable domains & 208 IP keys
        - Match -> EXCLUDE FROM PRIMARY (Contaminated Domain)
                         │
                         ▼
          Record Approved for Evaluation
```

---

## 5. Input Format Representation (Zero New Preprocessing)

Our models take raw text strings. Each external record will be represented without introducing custom feature adapters:
* **HTML Webpage Input:** The exact UTF-8 raw HTML string is passed directly to `pipeline.predict_proba([raw_html])`.
  - V2 sees the raw HTML (suffering its known token dilution).
  - V3 Dual routes it through `ContentHTMLParser` (stripping tags) and `URLChannelExtractor`.
* **Short URL Input:** The exact raw URL string (e.g. `https://secure.example.com/login`) is passed directly.
  - V2 tokenizes character n-grams.
  - V3 Dual tokenizes host/path tokens.
* **Email Message Input:** The raw message body (including MIME HTML if present) is passed directly.
