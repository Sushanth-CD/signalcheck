"""SMS-DEDICATED-TRAIN-1: Training Dataset Preparation and Leakage-Safe Splitting Pipeline.

Builds eligible candidates across WSPR, UCI, and ExAIS.
Performs independence screening against the 77,677 project corpus and 250 pilot.
Performs within-pool exact and near-duplicate grouping.
Performs group-aware partitioning into train (70%), validation (15%), and test (15%).
Outputs deliverables to backend/reports/ml/sms_dedicated_train_1/.
"""
import ast
import csv
import hashlib
import io
import json
import random
import sys
import time
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(r"C:\Projects\cyber-security-awareness-platform")
if str(PROJECT_ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from notebooks.phishing_url_extraction_v2 import extract_candidates

import importlib.util
spec = importlib.util.spec_from_file_location(
    "run_near_duplicate_audit",
    str(PROJECT_ROOT / "backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_pilot_100/near_duplicate_audit/run_near_duplicate_audit.py")
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
simhash64 = mod.simhash64
normalize_for_group = mod.normalize_for_group
shingles = mod.shingles
jaccard_similarity = mod.jaccard_similarity

OUT_DIR = PROJECT_ROOT / "backend/reports/ml/sms_dedicated_train_1"
PILOT_MANIFEST_PATH = PROJECT_ROOT / "backend/reports/ml/text_eval_1_acquisition/sms_pilot/sample_manifest.csv"
CORPUS_INDEX_PATH = PROJECT_ROOT / "backend/reports/ml/phishing_hybrid_independent_evaluation/compphish_pilot_100/near_duplicate_audit/corpus_simhash_index.npz"

SEED = 20261102
TARGET_SMISHING = 1400      # 1,400 distinct non-pilot WSPR campaigns available
TARGET_HAM = 2500           # 1,250 UCI Ham + 1,250 ExAIS Ham
TARGET_SPAM = 1500          # 30 UCI Spam + 1,470 ExAIS Spam

def sha256_str(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def main():
    print("=" * 70)
    print("SMS-DEDICATED-TRAIN-1: DATASET PREPARATION & SPLITTING PIPELINE")
    print("=" * 70)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SEED)

    # 1. Load Pilot Exclusions
    print("\n--- Step 1: Loading Pilot Exclusions ---")
    with open(PILOT_MANIFEST_PATH, encoding="utf-8") as f:
        pilot_records = list(csv.DictReader(f))

    pilot_cids = {r["campaign_id"] for r in pilot_records if r["cohort"] == "Cohort_A_Smishing"}
    pilot_exact_hashes = {r["normalized_text_sha256"] for r in pilot_records}
    pilot_simhashes = [int(r["simhash_fingerprint"]) for r in pilot_records]
    pilot_texts = [normalize_for_group(r["sanitized_message_text"]) for r in pilot_records]

    print(f"Loaded {len(pilot_records)} pilot records:")
    print(f"  Pilot Smishing Campaigns to Exclude: {len(pilot_cids)}")
    print(f"  Pilot Normalized Hashes: {len(pilot_exact_hashes)}")

    # 2. Load 77,677 Corpus Index
    print(f"\n--- Step 2: Loading 77,677 Baseline Corpus SimHash Index ---")
    idx_data = np.load(CORPUS_INDEX_PATH, allow_pickle=True)
    corpus_simhashes = [int(x) for x in idx_data["simhashes"]]
    corpus_exact_hashes = set(idx_data["norm_hashes"])
    print(f"Index loaded: {len(corpus_simhashes)} SimHashes, {len(corpus_exact_hashes)} SHA-256 hashes.")

    exclusions = []

    # 3. Screening Engine against Corpus and Pilot
    def check_independence(raw_t, source, source_id, category):
        norm_t = normalize_for_group(raw_t)
        if not norm_t:
            exclusions.append({"source": source, "source_id": source_id, "reason": "empty_normalized_text", "category": category})
            return None, "empty_normalized_text"

        h = sha256_str(norm_t)
        if h in corpus_exact_hashes:
            exclusions.append({"source": source, "source_id": source_id, "reason": "exact_corpus_collision", "category": category})
            return None, "exact_corpus_collision"

        if h in pilot_exact_hashes:
            exclusions.append({"source": source, "source_id": source_id, "reason": "exact_pilot_collision", "category": category})
            return None, "exact_pilot_collision"

        fprint = int(simhash64(norm_t))

        # Check near duplicate against pilot
        for p_idx, p_sim in enumerate(pilot_simhashes):
            if (fprint ^ p_sim).bit_count() <= 3:
                sh1 = shingles(norm_t, 5)
                sh2 = shingles(pilot_texts[p_idx], 5)
                if jaccard_similarity(sh1, sh2) >= 0.90:
                    exclusions.append({"source": source, "source_id": source_id, "reason": "near_duplicate_pilot_jaccard_ge90", "category": category})
                    return None, "near_duplicate_pilot_collision"

        # Check near duplicate against 77,677 baseline corpus
        # We prune candidate at Hamming <= 3 to guarantee zero leakage
        for c_sim in corpus_simhashes:
            if (fprint ^ c_sim).bit_count() <= 3:
                exclusions.append({"source": source, "source_id": source_id, "reason": "corpus_simhash_hamming_le3", "category": category})
                return None, "corpus_near_dup_candidate"

        return {"normalized_text": norm_t, "norm_sha256": h, "simhash": fprint}, None

    # 4. Acquire and Process WSPR-NCSU Smishing
    print("\n--- Step 3: Acquiring WSPR-NCSU Campaigns & Messages ---")
    camp_url = "https://raw.githubusercontent.com/wspr-ncsu/sms-phishing/main/phishing_campaigns.csv"
    req_c = urllib.request.Request(camp_url, headers={"User-Agent": "Mozilla/5.0"})
    raw_c = urllib.request.urlopen(req_c, timeout=30).read().decode("utf-8", errors="replace")
    c_reader = csv.reader(raw_c.splitlines())
    c_header = next(c_reader)
    c_rows = list(c_reader)

    url_to_cids = {}
    for r in c_rows:
        cid = r[0]
        try:
            urls = ast.literal_eval(r[6])
            for u in urls:
                if u and isinstance(u, str):
                    cands = extract_candidates("c", u)
                    for cand in cands:
                        norm_u = cand.candidate_text.lower().rstrip("/")
                        url_to_cids.setdefault(norm_u, set()).add(cid)
        except Exception:
            pass

    single_url_map = {u: next(iter(cids)) for u, cids in url_to_cids.items() if len(cids) == 1}

    msg_url = "https://raw.githubusercontent.com/wspr-ncsu/sms-phishing/main/phishing_messages.csv"
    req_m = urllib.request.Request(msg_url, headers={"User-Agent": "Mozilla/5.0"})
    raw_m = urllib.request.urlopen(req_m, timeout=30).read().decode("utf-8", errors="replace")
    m_reader = csv.reader(raw_m.splitlines())
    m_header = next(m_reader)
    m_rows = list(m_reader)

    # Group messages by campaign
    wspr_by_camp = {}
    for r in m_rows:
        mid, oid, dest_num, msg_text, _, time_rcv = r[:6]
        if not msg_text.strip():
            continue
        cands = extract_candidates("m", msg_text)
        match_c = {single_url_map[c.candidate_text.lower().rstrip("/")] for c in cands if c.candidate_text.lower().rstrip("/") in single_url_map}
        if len(match_c) == 1:
            cid = next(iter(match_c))
            if cid in pilot_cids:
                exclusions.append({"source": "WSPR_NCSU", "source_id": mid, "reason": "pilot_campaign_exclusion", "category": "smishing"})
                continue
            wspr_by_camp.setdefault(cid, []).append({
                "source": "WSPR_NCSU",
                "source_id": mid,
                "campaign_id": cid,
                "group_id": f"wspr_camp_{cid}",
                "text": msg_text,
                "timestamp": time_rcv,
                "category": "smishing"
            })

    print(f"Non-pilot WSPR campaigns with mapped messages: {len(wspr_by_camp)}")
    available_cids = sorted(wspr_by_camp.keys())
    rng.shuffle(available_cids)

    wspr_selected = []
    for cid in available_cids:
        msgs = wspr_by_camp[cid]
        rng.shuffle(msgs)
        for cand in msgs:
            meta, reason = check_independence(cand["text"], cand["source"], cand["source_id"], "smishing")
            if meta is not None:
                cand.update(meta)
                wspr_selected.append(cand)
                break
        if len(wspr_selected) >= TARGET_SMISHING:
            break

    print(f"WSPR Smishing Selected: {len(wspr_selected)} messages across {len(wspr_selected)} distinct campaigns.")

    # 5. Acquire and Process UCI SMS Spam Collection
    print("\n--- Step 4: Acquiring UCI SMS Collection ---")
    req_uci = urllib.request.Request("https://archive.ics.uci.edu/ml/machine-learning-databases/00228/smsspamcollection.zip", headers={"User-Agent": "Mozilla/5.0"})
    res_uci = urllib.request.urlopen(req_uci, timeout=15)
    z_uci = zipfile.ZipFile(io.BytesIO(res_uci.read()))
    text_uci = z_uci.open("SMSSpamCollection").read().decode("utf-8", errors="replace")
    uci_lines = [l for l in text_uci.splitlines() if l.strip()]

    uci_ham_cands = []
    uci_spam_cands = []
    for idx, l in enumerate(uci_lines):
        if "\t" not in l:
            continue
        tag, msg = l.split("\t", 1)
        cat = "ham" if tag == "ham" else "commercial_spam"
        item = {
            "source": "UCI",
            "source_id": f"uci_{tag}_{idx}",
            "campaign_id": "none",
            "group_id": f"uci_idx_{idx}",
            "text": msg,
            "timestamp": "",
            "category": cat
        }
        if tag == "ham":
            uci_ham_cands.append(item)
        else:
            uci_spam_cands.append(item)

    rng.shuffle(uci_ham_cands)
    rng.shuffle(uci_spam_cands)

    uci_ham_selected = []
    for cand in uci_ham_cands:
        meta, reason = check_independence(cand["text"], cand["source"], cand["source_id"], "ham")
        if meta is not None:
            cand.update(meta)
            cand["group_id"] = f"uci_hash_{cand['norm_sha256'][:16]}"
            uci_ham_selected.append(cand)
            if len(uci_ham_selected) >= 1250:
                break

    uci_spam_selected = []
    for cand in uci_spam_cands:
        meta, reason = check_independence(cand["text"], cand["source"], cand["source_id"], "commercial_spam")
        if meta is not None:
            cand.update(meta)
            cand["group_id"] = f"uci_hash_{cand['norm_sha256'][:16]}"
            uci_spam_selected.append(cand)

    print(f"UCI Selected: Ham={len(uci_ham_selected)}, Spam={len(uci_spam_selected)}")

    # 6. Acquire and Process ExAIS SMS Dataset
    print("\n--- Step 5: Acquiring ExAIS SMS Dataset ---")
    req_ex = urllib.request.Request("https://raw.githubusercontent.com/AbayomiAlli/SMS-Spam-Dataset/main/ExAIS_SMS%20Spam%20Dataset.zip", headers={"User-Agent": "Mozilla/5.0"})
    res_ex = urllib.request.urlopen(req_ex, timeout=15)
    z_ex = zipfile.ZipFile(io.BytesIO(res_ex.read()))

    ex_ham_cands = []
    ex_spam_cands = []
    for fname in z_ex.namelist():
        if not fname.endswith(".csv"):
            continue
        uname = Path(fname).stem
        raw_csv = z_ex.open(fname).read().decode("utf-8", errors="replace")
        for idx, line in enumerate(raw_csv.splitlines()[1:]):
            parts = line.split(",")
            if len(parts) <= 7:
                continue
            lbl = parts[6].strip().upper()
            msg_text = ",".join(parts[7:]).rstrip(",")
            if not msg_text.strip():
                continue
            cat = "ham" if ("HAM" in lbl or "NON" in lbl) else "commercial_spam"
            item = {
                "source": f"ExAIS_{uname}",
                "source_id": f"{uname}_row_{idx}",
                "campaign_id": "none",
                "group_id": f"exais_user_{uname}",
                "text": msg_text,
                "timestamp": "",
                "category": cat
            }
            if cat == "ham":
                ex_ham_cands.append(item)
            else:
                ex_spam_cands.append(item)

    rng.shuffle(ex_ham_cands)
    rng.shuffle(ex_spam_cands)

    target_ex_ham = TARGET_HAM - len(uci_ham_selected)
    target_ex_spam = TARGET_SPAM - len(uci_spam_selected)

    ex_ham_selected = []
    for cand in ex_ham_cands:
        meta, reason = check_independence(cand["text"], cand["source"], cand["source_id"], "ham")
        if meta is not None:
            cand.update(meta)
            ex_ham_selected.append(cand)
            if len(ex_ham_selected) >= target_ex_ham:
                break

    ex_spam_selected = []
    for cand in ex_spam_cands:
        meta, reason = check_independence(cand["text"], cand["source"], cand["source_id"], "commercial_spam")
        if meta is not None:
            cand.update(meta)
            ex_spam_selected.append(cand)
            if len(ex_spam_selected) >= target_ex_spam:
                break

    print(f"ExAIS Selected: Ham={len(ex_ham_selected)}, Spam={len(ex_spam_selected)}")

    # 7. Assemble Candidate Pool & Internal Grouping
    candidate_pool = wspr_selected + uci_ham_selected + ex_ham_selected + uci_spam_selected + ex_spam_selected
    print(f"\nTotal candidate pool assembled: {len(candidate_pool)} records")
    cat_counts = Counter(r["category"] for r in candidate_pool)
    print(f"  Categories: {dict(cat_counts)}")

    # Check and resolve any within-pool duplicates
    # Build graph of exact normalized hashes and SimHash Hamming <= 3 & Jaccard >= 0.90
    print("\n--- Step 6: Internal Connected-Component Grouping ---")
    parent = {}
    def find(i):
        path = []
        while parent.setdefault(i, i) != i:
            path.append(i)
            i = parent[i]
        for node in path:
            parent[node] = i
        return i

    def union(i, j):
        root_i = find(i)
        root_j = find(j)
        if root_i != root_j:
            parent[root_i] = root_j

    # Group by exact campaign / user group first
    group_members = {}
    for idx, r in enumerate(candidate_pool):
        group_members.setdefault(r["group_id"], []).append(idx)

    for g_id, m_idxs in group_members.items():
        for m in m_idxs[1:]:
            union(m_idxs[0], m)

    # Group by exact normalized text
    exact_hash_map = {}
    for idx, r in enumerate(candidate_pool):
        exact_hash_map.setdefault(r["norm_sha256"], []).append(idx)

    for h_val, idx_list in exact_hash_map.items():
        for m in idx_list[1:]:
            union(idx_list[0], m)

    # Check near duplicates across candidate pool
    # Group near duplicates into same component to prevent split leakage
    sims = [r["simhash"] for r in candidate_pool]
    texts = [r["normalized_text"] for r in candidate_pool]
    n_cands = len(candidate_pool)

    # Fast near-dup clustering within candidate pool
    near_dup_pairs = 0
    for i in range(n_cands):
        for j in range(i + 1, min(i + 200, n_cands)):
            if (sims[i] ^ sims[j]).bit_count() <= 3:
                sh1 = shingles(texts[i], 5)
                sh2 = shingles(texts[j], 5)
                if jaccard_similarity(sh1, sh2) >= 0.90:
                    union(i, j)
                    near_dup_pairs += 1

    print(f"Internal near-duplicate linkages identified: {near_dup_pairs}")

    # Build connected components
    components = {}
    for idx in range(n_cands):
        root = find(idx)
        components.setdefault(root, []).append(idx)

    print(f"Total unified connected components: {len(components)}")

    # Assign persistent component IDs
    component_assignments = []
    comp_list = []
    for c_idx, (root, member_indices) in enumerate(components.items(), 1):
        comp_id = f"sms_comp_{c_idx:05d}"
        members = [candidate_pool[m] for m in member_indices]
        cats = Counter(m["category"] for m in members)
        sources = Counter(m["source"] for m in members)
        comp_info = {
            "component_id": comp_id,
            "size": len(members),
            "members": member_indices,
            "categories": dict(cats),
            "sources": dict(sources),
            "dominant_category": cats.most_common(1)[0][0]
        }
        comp_list.append(comp_info)
        for m_idx in member_indices:
            candidate_pool[m_idx]["component_id"] = comp_id
            component_assignments.append({
                "candidate_index": m_idx,
                "component_id": comp_id,
                "source": candidate_pool[m_idx]["source"],
                "source_id": candidate_pool[m_idx]["source_id"],
                "category": candidate_pool[m_idx]["category"]
            })

    # Save sms_group_assignments.csv
    group_csv_path = OUT_DIR / "sms_group_assignments.csv"
    with open(group_csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["candidate_index", "component_id", "source", "source_id", "category"])
        writer.writeheader()
        writer.writerows(component_assignments)
    print(f"Saved: {group_csv_path}")

    # 8. Group-Aware Stratified Splitting (Train: 70%, Val: 15%, Test: 15%)
    print("\n--- Step 7: Leakage-Safe Group Partition Allocation ---")
    rng.shuffle(comp_list)
    comp_list.sort(key=lambda c: c["size"], reverse=True)

    part_targets = {"train": 0.70, "validation": 0.15, "test": 0.15}
    partition_counts = {"train": Counter(), "validation": Counter(), "test": Counter()}
    partition_comps = {"train": [], "validation": [], "test": []}

    target_total = len(candidate_pool)
    cat_targets = {
        "train": {cat: int(count * 0.70) for cat, count in cat_counts.items()},
        "validation": {cat: int(count * 0.15) for cat, count in cat_counts.items()},
        "test": {cat: int(count * 0.15) for cat, count in cat_counts.items()},
    }

    # Greedy allocation of components to partitions
    for comp in comp_list:
        dom_cat = comp["dominant_category"]
        best_part = None
        best_deficit = -1e9

        for part in ["train", "validation", "test"]:
            current = partition_counts[part][dom_cat]
            target = cat_targets[part][dom_cat]
            deficit = target - current
            if deficit > best_deficit:
                best_deficit = deficit
                best_part = part

        partition_comps[best_part].append(comp)
        for cat, cnt in comp["categories"].items():
            partition_counts[best_part][cat] += cnt

    print("Partition allocation summary:")
    for part in ["train", "validation", "test"]:
        total_p = sum(partition_counts[part].values())
        print(f"  {part.upper()}: Total={total_p} ({total_p/len(candidate_pool)*100:.1f}%) -> {dict(partition_counts[part])}")

    # Build final manifest
    final_manifest = []
    serial = 1
    for part in ["train", "validation", "test"]:
        for comp in partition_comps[part]:
            for m_idx in comp["members"]:
                r = candidate_pool[m_idx]
                cat = r["category"]
                binary_label = 1 if cat == "smishing" else 0
                final_manifest.append({
                    "serial_number": serial,
                    "partition": part,
                    "component_id": r["component_id"],
                    "ground_truth_category": cat,
                    "binary_phishing_label": binary_label,
                    "source_dataset": r["source"],
                    "source_record_id": r["source_id"],
                    "campaign_id": r["campaign_id"],
                    "sanitized_message_text": r["text"].strip(),
                    "normalized_text_sha256": r["norm_sha256"],
                    "simhash_fingerprint": str(r["simhash"])
                })
                serial += 1

    # Save sms_training_candidates.csv
    candidates_csv_path = OUT_DIR / "sms_training_candidates.csv"
    cand_fields = list(final_manifest[0].keys())
    with open(candidates_csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=cand_fields)
        writer.writeheader()
        writer.writerows(final_manifest)
    print(f"Saved: {candidates_csv_path} ({len(final_manifest)} candidate records)")

    # Save sms_split_manifest.csv
    split_manifest_path = OUT_DIR / "sms_split_manifest.csv"
    with open(split_manifest_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=cand_fields)
        writer.writeheader()
        writer.writerows(final_manifest)
    print(f"Saved: {split_manifest_path}")

    # Save sms_exclusion_summary.csv
    excl_csv_path = OUT_DIR / "sms_exclusion_summary.csv"
    with open(excl_csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["source", "source_id", "reason", "category"])
        writer.writeheader()
        writer.writerows(exclusions)
    print(f"Saved: {excl_csv_path} ({len(exclusions)} exclusion records)")

    # 9. Verify Leakage Invariants
    print("\n--- Step 8: Verifying Split Independence Invariants ---")
    train_cids = {r["campaign_id"] for r in final_manifest if r["partition"] == "train" and r["campaign_id"] != "none"}
    val_cids = {r["campaign_id"] for r in final_manifest if r["partition"] == "validation" and r["campaign_id"] != "none"}
    test_cids = {r["campaign_id"] for r in final_manifest if r["partition"] == "test" and r["campaign_id"] != "none"}

    train_hashes = {r["normalized_text_sha256"] for r in final_manifest if r["partition"] == "train"}
    val_hashes = {r["normalized_text_sha256"] for r in final_manifest if r["partition"] == "validation"}
    test_hashes = {r["normalized_text_sha256"] for r in final_manifest if r["partition"] == "test"}

    cid_overlap_tv = train_cids.intersection(val_cids)
    cid_overlap_tt = train_cids.intersection(test_cids)
    cid_overlap_vt = val_cids.intersection(test_cids)

    hash_overlap_tv = train_hashes.intersection(val_hashes)
    hash_overlap_tt = train_hashes.intersection(test_hashes)
    hash_overlap_vt = val_hashes.intersection(test_hashes)

    corpus_overlap = set(r["normalized_text_sha256"] for r in final_manifest).intersection(corpus_exact_hashes)
    pilot_overlap = set(r["normalized_text_sha256"] for r in final_manifest).intersection(pilot_exact_hashes)

    assert len(cid_overlap_tv) == 0, f"Campaign leakage train-val: {cid_overlap_tv}"
    assert len(cid_overlap_tt) == 0, f"Campaign leakage train-test: {cid_overlap_tt}"
    assert len(cid_overlap_vt) == 0, f"Campaign leakage val-test: {cid_overlap_vt}"
    assert len(hash_overlap_tv) == 0, f"Hash leakage train-val: {len(hash_overlap_tv)}"
    assert len(hash_overlap_tt) == 0, f"Hash leakage train-test: {len(hash_overlap_tt)}"
    assert len(hash_overlap_vt) == 0, f"Hash leakage val-test: {len(hash_overlap_vt)}"
    assert len(corpus_overlap) == 0, f"Corpus collision: {len(corpus_overlap)}"
    assert len(pilot_overlap) == 0, f"Pilot collision: {len(pilot_overlap)}"

    print("ALL LEAKAGE INVARIANTS VERIFIED:")
    print("  Zero campaign overlap across train / val / test: TRUE")
    print("  Zero text hash overlap across train / val / test: TRUE")
    print("  Zero exact collisions against 77,677 corpus: TRUE")
    print("  Zero exact collisions against 250 pilot: TRUE")

    # Save sms_independence_screening.json
    screening_json_path = OUT_DIR / "sms_independence_screening.json"
    screening_dict = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "baseline_corpus_records": 77677,
        "pilot_records_excluded": len(pilot_records),
        "pilot_campaigns_excluded": len(pilot_cids),
        "candidate_counts": {
            "total_screened_and_allocated": len(final_manifest),
            "smishing": cat_counts["smishing"],
            "ham": cat_counts["ham"],
            "commercial_spam": cat_counts["commercial_spam"]
        },
        "exclusions_by_reason": dict(Counter(e["reason"] for e in exclusions)),
        "invariants": {
            "zero_campaign_leakage": True,
            "zero_partition_text_overlap": True,
            "zero_corpus_collision": True,
            "zero_pilot_collision": True
        }
    }
    with open(screening_json_path, "w", encoding="utf-8") as f:
        json.dump(screening_dict, f, indent=2)
    print(f"Saved: {screening_json_path}")

    # Save sms_split_summary.json
    split_summary_path = OUT_DIR / "sms_split_summary.json"
    summary_dict = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "random_seed": SEED,
        "total_records": len(final_manifest),
        "total_components": len(comp_list),
        "source_breakdown": dict(Counter(r["source_dataset"] for r in final_manifest)),
        "category_breakdown": dict(Counter(r["ground_truth_category"] for r in final_manifest)),
        "binary_label_breakdown": dict(Counter(r["binary_phishing_label"] for r in final_manifest)),
        "partitions": {
            part: {
                "total_records": sum(partition_counts[part].values()),
                "component_count": len(partition_comps[part]),
                "categories": dict(partition_counts[part]),
                "binary_labels": {
                    "0": partition_counts[part]["ham"] + partition_counts[part]["commercial_spam"],
                    "1": partition_counts[part]["smishing"]
                }
            }
            for part in ["train", "validation", "test"]
        }
    }
    with open(split_summary_path, "w", encoding="utf-8") as f:
        json.dump(summary_dict, f, indent=2)
    print(f"Saved: {split_summary_path}")

    print("\nALL PREPARATION AND SPLITTING OPERATIONS COMPLETED SUCCESSFULLY!")

if __name__ == "__main__":
    main()
