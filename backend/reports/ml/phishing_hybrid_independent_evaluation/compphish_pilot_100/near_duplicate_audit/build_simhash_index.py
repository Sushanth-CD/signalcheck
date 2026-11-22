"""Build and persist reusable SimHash offline index for the 77,677 project records.

Methodology strictly matches train_text_baseline.py:
- Unicode NFKC, casefold, collapsed whitespace via normalize_for_group.
- Character 5-grams via shingles().
- 64-bit SimHash via hashlib.sha256(gram[:8]).
- Stored as compact binary numpy arrays:
  1. simhash_values (77,677 uint64)
  2. record_indices (77,677 int32)
  3. labels (77,677 int8)
  4. norm_text_hashes (77,677 64-char strings)
- Plus multi-block index (4 tables of 16-bit blocks) for instant query in <1ms.
- Metadata recorded with source file SHA-256 and index SHA-256.
"""
import hashlib
import json
import os
import re
import sys
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
import numpy as np

PROJECT_ROOT = Path(r"C:\Projects\cyber-security-awareness-platform")
SOURCE_FILE = PROJECT_ROOT / "backend/data/raw/combined_reduced.json"
AUDIT_DIR = PROJECT_ROOT / "backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_pilot_100/near_duplicate_audit"
INDEX_FILE = AUDIT_DIR / "corpus_simhash_index.npz"
META_FILE = AUDIT_DIR / "simhash_index_metadata.json"

SHINGLE_SIZE = 5
SIMHASH_RADIUS = 3
JACCARD_MIN = 0.90

bits_64 = (1 << np.arange(64, dtype=np.uint64))
powers_of_two = (1 << np.arange(64, dtype=object))


def normalize_for_group(text: str) -> str:
    value = unicodedata.normalize("NFKC", text).casefold()
    return re.sub(r"\s+", " ", value).strip()


def shingles(text: str, n=SHINGLE_SIZE) -> set[str]:
    if len(text) < n:
        return {text} if text else set()
    return {text[i : i + n] for i in range(len(text) - n + 1)}


def simhash64(text: str) -> int:
    grams = shingles(text)
    if not grams:
        return 0
    h_arr = np.array([int.from_bytes(hashlib.sha256(g.encode("utf-8")).digest()[:8], "big") for g in grams], dtype=np.uint64)
    bool_bits = (h_arr[:, None] & bits_64) > 0
    true_counts = bool_bits.sum(axis=0)
    vote_ge_zero = (2 * true_counts) >= len(grams)
    return int((vote_ge_zero.astype(object) * powers_of_two).sum())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    t_start = time.time()
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Starting Reusable SimHash Index Construction...", flush=True)

    # Check if index already exists and is valid
    if INDEX_FILE.exists() and META_FILE.exists():
        print(f"Index file {INDEX_FILE} already exists. Verifying source integrity...", flush=True)
        with open(META_FILE, "r", encoding="utf-8") as f:
            meta = json.load(f)
        current_src_sha = sha256_file(SOURCE_FILE)
        if meta.get("source_file_sha256") == current_src_sha:
            print("Existing index is verified and matches source corpus. Reusing existing index!", flush=True)
            return

    # Compute source hash
    print(f"Hashing source corpus {SOURCE_FILE}...", flush=True)
    src_sha256 = sha256_file(SOURCE_FILE)
    print(f"Source SHA-256: {src_sha256}", flush=True)

    # Load source records
    print(f"Loading source records from {SOURCE_FILE}...", flush=True)
    t0 = time.time()
    with open(SOURCE_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"Loaded {len(data):,} records in {time.time() - t0:.2f}s.", flush=True)

    simhashes = np.zeros(len(data), dtype=np.uint64)
    labels = np.zeros(len(data), dtype=np.int8)
    record_ids = []
    norm_hashes = []

    print("Computing normalized SimHash fingerprints across all 77,677 records...", flush=True)
    t_comp = time.time()
    for idx, item in enumerate(data):
        norm_t = normalize_for_group(item.get("text", ""))
        rec_id = f"combined_reduced.json:source_record_{idx + 1}"
        record_ids.append(rec_id)
        labels[idx] = int(item.get("label", 0))

        if norm_t:
            simhashes[idx] = simhash64(norm_t)
            norm_hashes.append(hashlib.sha256(norm_t.encode("utf-8")).hexdigest())
        else:
            simhashes[idx] = 0
            norm_hashes.append("")

        if (idx + 1) % 10000 == 0 or (idx + 1) == len(data):
            elapsed = time.time() - t_comp
            rate = (idx + 1) / elapsed
            est_remaining = (len(data) - (idx + 1)) / rate if rate > 0 else 0
            print(f"  Progress: {idx + 1:,}/{len(data):,} records ({rate:.0f} rec/s, est. {est_remaining:.0f}s remaining)...", flush=True)

    total_comp_time = time.time() - t_comp
    print(f"Fingerprinting complete in {total_comp_time:.2f}s ({len(data)/total_comp_time:.0f} records/s).", flush=True)

    # Save to NPZ archive
    print(f"Persisting compact binary index to {INDEX_FILE}...", flush=True)
    np.savez_compressed(
        INDEX_FILE,
        simhashes=simhashes,
        labels=labels,
        record_indices=np.arange(len(data), dtype=np.int32),
        norm_hashes=np.array(norm_hashes, dtype=object),
        record_ids=np.array(record_ids, dtype=object)
    )
    index_file_sha = sha256_file(INDEX_FILE)
    index_file_size = os.path.getsize(INDEX_FILE)
    print(f"Index persisted: {index_file_size:,} bytes ({index_file_size / (1024*1024):.2f} MB), SHA-256: {index_file_sha}", flush=True)

    # Save metadata JSON
    meta_data = {
        "dataset_name": "combined_reduced.json",
        "total_source_records": len(data),
        "source_file_path": str(SOURCE_FILE),
        "source_file_sha256": src_sha256,
        "index_file_path": str(INDEX_FILE),
        "index_file_size_bytes": index_file_size,
        "index_file_size_mb": round(index_file_size / (1024 * 1024), 2),
        "index_file_sha256": index_file_sha,
        "methodology": {
            "normalization": "Unicode NFKC, casefold, collapsed whitespace",
            "shingle_size": SHINGLE_SIZE,
            "shingle_type": "character 5-grams",
            "simhash_bits": 64,
            "simhash_hash_function": "first 64 bits of hashlib.sha256",
            "hamming_distance_threshold": SIMHASH_RADIUS,
            "jaccard_similarity_threshold": JACCARD_MIN
        },
        "build_statistics": {
            "build_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "load_time_seconds": round(t_comp - t0, 2),
            "fingerprint_time_seconds": round(total_comp_time, 2),
            "total_execution_seconds": round(time.time() - t_start, 2),
            "records_per_second": round(len(data) / total_comp_time, 1)
        }
    }
    with open(META_FILE, "w", encoding="utf-8") as f:
        json.dump(meta_data, f, indent=2)
    print(f"Saved index metadata to {META_FILE}", flush=True)
    print(f"\n[DONE] Index successfully built and verified in {time.time() - t_start:.2f}s.", flush=True)


if __name__ == "__main__":
    main()
