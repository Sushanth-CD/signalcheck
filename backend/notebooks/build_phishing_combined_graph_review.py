"""Build an auditable V2 destination + existing text-component graph.

Offline only. This utility does not open URLs, use DNS/network, change labels,
or assign a split. It reuses the V2 parser, the stored text grouping manifest,
and the pinned Oracle JDK PSL. Completed PSL batches are cached in a work
directory so an interrupted PSL stage can resume. Final outputs are atomically
published only after every required hostname resolves successfully.

Run from the repository root:
    backend/.venv-final-test/Scripts/python.exe backend/notebooks/build_phishing_combined_graph_review.py
"""
from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import math
import os
import platform
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Some source records contain a large serialized list of candidate diagnostics.
# The CSV is generated locally by this script, so allow those fields to be read
# back without truncation or altering candidate extraction.
csv.field_size_limit(sys.maxsize)

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.ml.psl_service import (
    JAVA, PSL_FILE, is_psl_suffix, load_psl_rules, psl_registrable_domains, sha256_file,
)
from backend.notebooks import phishing_url_extraction_v2 as extraction
from backend.notebooks.prepare_ml_datasets import iter_json_array

SOURCE = ROOT / "backend/data/raw/combined_reduced.json"
BASE_MANIFEST = ROOT / "backend/reports/ml/text_phishing_baseline/split_manifest.csv"
BASE_METRICS = ROOT / "backend/reports/ml/text_phishing_baseline/metrics.json"
OLD_AUDIT_DIR = ROOT / "backend/reports/ml/phishing_domain_extraction_v2"
OLD_AUDIT = OLD_AUDIT_DIR / "domain_extraction_audit.json"
OLD_GROUPS = OLD_AUDIT_DIR / "grouping_diagnostics.json"
FINAL_DIR = OLD_AUDIT_DIR / "combined_graph_review"
WORK_DIR = OLD_AUDIT_DIR / "combined_graph_review_work"
CANDIDATE_SPOOL = WORK_DIR / "candidate_spool.csv"
BASE_RECORDS = WORK_DIR / "base_records.jsonl"
PREFLIGHT = WORK_DIR / "preflight.json"
PSL_CACHE = WORK_DIR / "psl_results_cache.jsonl"
PSL_CACHE_META = WORK_DIR / "psl_cache_meta.json"
PSL_LOG = WORK_DIR / "psl_batch_execution_log.csv"
PSL_BATCH_SIZE = 2048

DELIVERABLES = (
    "combined_graph_review.md",
    "record_domain_edges.csv",
    "record_near_duplicate_edges.csv",
    "combined_component_summary.csv",
    "largest_component_members.csv",
    "largest_component_bridge_edges.csv",
    "record_domain_status.csv",
    "combined_graph_invariants.json",
    "psl_batch_execution_log.csv",
)


class DisjointSet:
    """Union-find over source-record indices only; key nodes never count as records."""

    def __init__(self, count: int) -> None:
        self.parent = list(range(count + 1))
        self.size = [1] * (count + 1)

    def find(self, item: int) -> int:
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != item:
            nxt = self.parent[item]
            self.parent[item] = root
            item = nxt
        return root

    def union(self, left: int, right: int) -> None:
        a, b = self.find(left), self.find(right)
        if a == b:
            return
        if self.size[a] < self.size[b]:
            a, b = b, a
        self.parent[b] = a
        self.size[a] += self.size[b]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def stable_component_id(prefix: str, min_index: int) -> str:
    return f"{prefix}_source_record_{min_index:06d}"


def nearest_rank(values: list[int], quantile: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(1, math.ceil(quantile * len(ordered))) - 1]


def load_manifest() -> tuple[dict[int, dict[str, str]], dict[str, Any]]:
    rows: dict[int, dict[str, str]] = {}
    seen_ids: set[str] = set()
    duplicate_indices: list[int] = []
    duplicate_ids: list[str] = []
    with BASE_MANIFEST.open("r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            index = int(row["source_record_index"])
            sid = f"combined_reduced.json:source_record_{index}"
            if index in rows:
                duplicate_indices.append(index)
            if sid in seen_ids:
                duplicate_ids.append(sid)
            rows[index] = row
            seen_ids.add(sid)
    if duplicate_indices or duplicate_ids:
        raise ValueError(f"Duplicate baseline manifest indices/IDs: {duplicate_indices[:5]} / {duplicate_ids[:5]}")
    normalized_per_near: dict[str, set[str]] = defaultdict(set)
    normalized_records: Counter[str] = Counter()
    labels_per_near: dict[str, set[str]] = defaultdict(set)
    labels_per_norm: dict[str, set[str]] = defaultdict(set)
    quarantined_near: set[str] = set()
    reasons_per_near: dict[str, set[str]] = defaultdict(set)
    for row in rows.values():
        near = row["near_duplicate_component_id"]
        norm = row["normalized_text_sha256"]
        normalized_per_near[near].add(norm)
        normalized_records[norm] += 1
        labels_per_near[near].add(row["label_original"])
        labels_per_norm[norm].add(row["label_original"])
        if row.get("partition") == "quarantine":
            quarantined_near.add(near)
        if row.get("quarantine_reason"):
            reasons_per_near[near].update(x for x in row["quarantine_reason"].split(";") if x)
    summary = {
        "rows": len(rows),
        "unique_source_indices": len(rows),
        "unique_generated_source_ids": len(seen_ids),
        "normalized_text_groups": len(normalized_records),
        "near_duplicate_components": len(normalized_per_near),
        "near_components_with_multiple_normalized_groups": sum(len(v) > 1 for v in normalized_per_near.values()),
        "exact_duplicate_groups": sum(v > 1 for v in normalized_records.values()),
        "duplicate_rows_beyond_first": sum(v - 1 for v in normalized_records.values()),
        "normalized_groups_with_conflicting_labels": sum(len(v) > 1 for v in labels_per_norm.values()),
        "near_components_with_conflicting_labels": sum(len(v) > 1 for v in labels_per_near.values()),
        "quarantined_near_duplicate_components": len(quarantined_near),
        "quarantine_reasons": dict(sorted(Counter(r for values in reasons_per_near.values() for r in values).items())),
        "source_indices": set(rows),
        "normalized_groups_per_near_component": normalized_per_near,
        "normalized_records": normalized_records,
        "labels_per_near_component": labels_per_near,
        "labels_per_normalized_group": labels_per_norm,
        "quarantined_near_components": quarantined_near,
        "reasons_per_near_component": reasons_per_near,
    }
    return rows, summary


def append_psl_log(row: dict[str, Any]) -> None:
    fields = [
        "logged_utc", "batch_id", "batch_type", "host_start_index", "host_end_index_exclusive",
        "candidate_occurrences_total", "unique_hostname_total", "hosts_requested", "cache_hits",
        "hosts_returned", "status", "elapsed_seconds", "error",
    ]
    exists = PSL_LOG.exists()
    with PSL_LOG.open("a", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        if not exists:
            writer.writeheader()
        writer.writerow({name: row.get(name, "") for name in fields})
        stream.flush()
        os.fsync(stream.fileno())


def verify_batch_semantics() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    samples = [
        "www.example.com", "mail.news.example.co.uk", "example.co.uk", "co.uk",
        "tenant.github.io", "s3.amazonaws.com", "xn--bcher-kva.de", "xn--bcher-kva.example",
        "example.invalid", "localhost",
    ]
    old_map, metadata = psl_registrable_domains(samples)
    batch_results: dict[str, str | None] = {}
    batch_rows: list[dict[str, Any]] = []
    started = time.perf_counter()
    for part, start in enumerate(range(0, len(samples), 3), start=1):
        batch = samples[start : start + 3]
        t0 = time.perf_counter()
        result, _ = psl_registrable_domains(batch)
        batch_results.update(result)
        batch_rows.append({"host": batch[0], "elapsed": time.perf_counter() - t0, "size": len(batch), "id": f"equivalence-{part}"})
    repeat, _ = psl_registrable_domains(samples)
    if old_map != batch_results or old_map != repeat:
        raise RuntimeError("Bounded PSL batches differ from existing single-call or repeated results")
    for part in batch_rows:
        append_psl_log({
            "batch_id": part["id"], "batch_type": "semantic_equivalence_test",
            "host_start_index": "", "host_end_index_exclusive": "", "candidate_occurrences_total": "",
            "unique_hostname_total": len(samples), "hosts_requested": part["size"], "cache_hits": 0,
            "hosts_returned": part["size"], "status": "pass", "elapsed_seconds": f"{part['elapsed']:.6f}",
        })
    append_psl_log({
        "batch_id": "equivalence-summary", "batch_type": "semantic_equivalence_test",
        "unique_hostname_total": len(samples), "hosts_requested": len(samples), "hosts_returned": len(samples),
        "status": "pass", "elapsed_seconds": f"{time.perf_counter() - started:.6f}",
        "error": "single-call, bounded-batch, and repeated results were identical",
    })
    return metadata, [{"host": h, "registrable_domain": old_map[h]} for h in samples]


def load_or_scan_source(manifest: dict[int, dict[str, str]], manifest_summary: dict[str, Any]) -> tuple[list[dict[str, Any]], set[str], dict[str, Any]]:
    source_hash = sha256_file(SOURCE)
    if CANDIDATE_SPOOL.is_file() and BASE_RECORDS.is_file() and PREFLIGHT.is_file():
        stage = json.loads(PREFLIGHT.read_text(encoding="utf-8"))
        if stage.get("source_sha256") != source_hash or stage.get("extractor_sha256") != sha256_file(ROOT / "backend/notebooks/phishing_url_extraction_v2.py"):
            raise ValueError("Existing resumable scan spool does not match current source/extractor hashes")
        records = [json.loads(line) for line in BASE_RECORDS.read_text(encoding="utf-8").splitlines() if line]
        hosts: set[str] = set()
        with CANDIDATE_SPOOL.open("r", encoding="utf-8", newline="") as stream:
            for row in csv.DictReader(stream):
                if row["normalized_hostname"] and row["parser_status"] in {"normalized_hostname", "ambiguous_bare_domain_mention"}:
                    hosts.add(row["normalized_hostname"])
        if len(records) != stage["source_records"] or len(hosts) != stage["unique_normalized_hostname_count"]:
            raise ValueError("Resumable spool counts do not match its preflight metadata")
        print(f"Resuming from completed extraction spool: {len(records):,} records, {len(hosts):,} PSL hostnames", flush=True)
        return records, hosts, stage

    for partial in (WORK_DIR / "candidate_spool.csv.tmp", WORK_DIR / "base_records.jsonl.tmp"):
        if partial.exists():
            partial.unlink()
    raw_records = 0
    candidate_count = 0
    labels: Counter[str] = Counter()
    hosts: set[str] = set()
    generated_ids: set[str] = set()
    duplicate_source_ids: list[str] = []
    records: list[dict[str, Any]] = []
    candidate_fields = [
        "source_record_index", "source_record_id", "source_label_original", "start", "end", "candidate_text",
        "extraction_method", "evidence_category", "confidence", "parser_status", "normalized_hostname",
        "initial_rejection_reason",
    ]
    scan_start = time.perf_counter()
    with (WORK_DIR / "candidate_spool.csv.tmp").open("w", encoding="utf-8", newline="") as candidates_stream, \
         (WORK_DIR / "base_records.jsonl.tmp").open("w", encoding="utf-8", newline="\n") as records_stream:
        writer = csv.DictWriter(candidates_stream, fieldnames=candidate_fields)
        writer.writeheader()
        for index, raw in enumerate(iter_json_array(SOURCE), start=1):
            raw_records += 1
            text = raw.get("text")
            if not isinstance(text, str):
                raise ValueError(f"Non-string text at raw source index {index}")
            label = str(raw.get("label"))
            if label not in {"0", "1"}:
                raise ValueError(f"Unsupported original label {raw.get('label')!r} at source index {index}")
            source_id = f"combined_reduced.json:source_record_{index}"
            if source_id in generated_ids:
                duplicate_source_ids.append(source_id)
            generated_ids.add(source_id)
            labels[label] += 1
            if index in manifest:
                row = manifest[index]
                if row["label_original"] != label:
                    raise ValueError(f"Baseline manifest label mismatch at source index {index}")
                group_id = row["normalized_text_sha256"]
                near_id = row["near_duplicate_component_id"]
                quarantine = row["partition"] == "quarantine"
                q_reason = row.get("quarantine_reason", "")
                promo = row.get("promotional_review_flag", "False").lower() == "true"
                group_records = int(row.get("normalized_group_record_count", "1"))
            else:
                group_id = near_id = ""
                quarantine = False
                q_reason = ""
                promo = False
                group_records = 0
            found = extraction.extract_candidates(source_id, text)
            record = {
                "source_record_index": index,
                "source_record_id": source_id,
                "label_original": int(label),
                "text_length_chars": len(text),
                "text_nonempty_after_strip": bool(text.strip()),
                "normalized_text_group_id": group_id,
                "near_duplicate_component_id": near_id,
                "near_duplicate_manifest_present": bool(near_id),
                "near_duplicate_group_record_count": group_records,
                "quarantine_status": quarantine,
                "quarantine_reason": q_reason,
                "promotional_review_flag": promo,
                "candidate_count": len(found),
            }
            records.append(record)
            records_stream.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
            for candidate in found:
                candidate_count += 1
                if text[candidate.start : candidate.end] != candidate.candidate_text:
                    raise AssertionError(f"Candidate offsets do not match source text at {source_id}:{candidate.start}")
                if candidate.normalized_hostname and candidate.parser_status in {"normalized_hostname", "ambiguous_bare_domain_mention"}:
                    hosts.add(candidate.normalized_hostname)
                writer.writerow({
                    "source_record_index": index,
                    "source_record_id": source_id,
                    "source_label_original": label,
                    "start": candidate.start,
                    "end": candidate.end,
                    "candidate_text": candidate.candidate_text,
                    "extraction_method": candidate.extraction_method,
                    "evidence_category": candidate.evidence_category,
                    "confidence": candidate.confidence,
                    "parser_status": candidate.parser_status,
                    "normalized_hostname": candidate.normalized_hostname or "",
                    "initial_rejection_reason": candidate.rejection_reason or "",
                })
            if raw_records % 5000 == 0:
                candidates_stream.flush()
                records_stream.flush()
                print(f"Extracted {raw_records:,}/{raw_records + 1:,} streaming rows; {candidate_count:,} candidates; {len(hosts):,} PSL hosts", flush=True)
    if duplicate_source_ids:
        raise ValueError(f"Duplicate generated source IDs: {duplicate_source_ids[:5]}")
    if raw_records != len(records) or len(generated_ids) != raw_records:
        raise AssertionError("Source records were not represented exactly once")
    manifest_missing = sorted(set(range(1, raw_records + 1)) - set(manifest))
    manifest_extra = sorted(index for index in manifest if index > raw_records)
    if manifest_extra:
        raise ValueError(f"Near-duplicate manifest indexes not present in raw source: {manifest_extra[:10]}")
    if manifest_missing != sorted({index for index in manifest_missing if index == 31230}):
        raise ValueError(f"Unexpected raw rows missing from existing text manifest: {manifest_missing[:20]}")
    (WORK_DIR / "candidate_spool.csv.tmp").replace(CANDIDATE_SPOOL)
    (WORK_DIR / "base_records.jsonl.tmp").replace(BASE_RECORDS)
    stage = {
        "source_sha256": source_hash,
        "extractor_sha256": sha256_file(ROOT / "backend/notebooks/phishing_url_extraction_v2.py"),
        "source_records": raw_records,
        "candidate_occurrences": candidate_count,
        "unique_normalized_hostname_count": len(hosts),
        "source_label_counts": dict(sorted(labels.items())),
        "generated_source_id_count": len(generated_ids),
        "duplicate_generated_source_ids": len(duplicate_source_ids),
        "raw_source_indices_missing_from_text_manifest": manifest_missing,
        "text_manifest_rows": manifest_summary["rows"],
        "scan_elapsed_seconds": time.perf_counter() - scan_start,
        "scan_completed_utc": utc_now(),
        "raw_record_schema": sorted(raw.keys()) if raw_records else [],
    }
    write_json(PREFLIGHT, stage)
    print(f"Extraction pass complete in {stage['scan_elapsed_seconds']:.1f}s: {raw_records:,} records, {candidate_count:,} candidates, {len(hosts):,} unique PSL hosts", flush=True)
    return records, hosts, stage


def load_cache_and_lookup(hosts: set[str], stage: dict[str, Any], metadata: dict[str, Any]) -> dict[str, str | None]:
    psl_sha = metadata["psl_snapshot_sha256"]
    if PSL_CACHE_META.is_file():
        saved = json.loads(PSL_CACHE_META.read_text(encoding="utf-8"))
        if saved.get("psl_snapshot_sha256") != psl_sha or saved.get("jdk_version") != metadata["jdk_version"]:
            raise ValueError("Resumable PSL cache is for a different JDK/PSL snapshot")
    else:
        write_json(PSL_CACHE_META, {"psl_snapshot_sha256": psl_sha, "jdk_version": metadata["jdk_version"], "created_utc": utc_now()})
    cache: dict[str, str | None] = {}
    if PSL_CACHE.is_file():
        with PSL_CACHE.open("r", encoding="utf-8") as stream:
            for line_no, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                item = json.loads(line)
                host = item["host"]
                value = item["registrable_domain"]
                if host in cache and cache[host] != value:
                    raise ValueError(f"Conflicting cached PSL results for {host}")
                cache[host] = value
    unexpected = set(cache) - hosts
    if unexpected:
        raise ValueError(f"PSL cache contains hosts outside current source/extractor: {sorted(unexpected)[:5]}")
    missing = sorted(hosts - cache.keys())
    stage["psl_cache_hits"] = len(hosts) - len(missing)
    append_psl_log({
        "batch_id": "source-lookup-plan", "batch_type": "summary", "candidate_occurrences_total": stage["candidate_occurrences"],
        "unique_hostname_total": len(hosts), "hosts_requested": len(missing), "cache_hits": len(hosts) - len(missing),
        "hosts_returned": 0, "status": "started", "error": f"bounded batch size={PSL_BATCH_SIZE}",
    })
    lookup_start = time.perf_counter()
    unresolved: list[str] = []
    # Indices refer to the sorted unique source host list; recursive halves are stable.
    position = {host: i for i, host in enumerate(sorted(hosts))}
    lookup_seq = 0

    def lookup_batch(batch: list[str], batch_id: str) -> None:
        nonlocal lookup_seq
        lookup_seq += 1
        seq = lookup_seq
        started = time.perf_counter()
        try:
            result, _ = psl_registrable_domains(batch)
            if set(result) != set(batch):
                raise RuntimeError(f"PSL service returned {len(result)} results for {len(batch)} inputs")
            with PSL_CACHE.open("a", encoding="utf-8", newline="\n") as stream:
                for host in batch:
                    value = result[host]
                    cache[host] = value
                    stream.write(json.dumps({"host": host, "registrable_domain": value}, ensure_ascii=False, separators=(",", ":")) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            elapsed = time.perf_counter() - started
            append_psl_log({
                "batch_id": batch_id, "batch_type": "lookup", "host_start_index": min(position[h] for h in batch),
                "host_end_index_exclusive": max(position[h] for h in batch) + 1,
                "candidate_occurrences_total": stage["candidate_occurrences"], "unique_hostname_total": len(hosts),
                "hosts_requested": len(batch), "cache_hits": 0, "hosts_returned": len(result), "status": "completed",
                "elapsed_seconds": f"{elapsed:.6f}",
            })
            print(f"PSL batch {batch_id}: {len(batch):,} hosts in {elapsed:.1f}s", flush=True)
        except Exception as exc:
            elapsed = time.perf_counter() - started
            append_psl_log({
                "batch_id": batch_id, "batch_type": "lookup", "host_start_index": min(position[h] for h in batch),
                "host_end_index_exclusive": max(position[h] for h in batch) + 1,
                "candidate_occurrences_total": stage["candidate_occurrences"], "unique_hostname_total": len(hosts),
                "hosts_requested": len(batch), "cache_hits": 0, "hosts_returned": 0,
                "status": "failed_split", "elapsed_seconds": f"{elapsed:.6f}", "error": f"{type(exc).__name__}: {exc}",
            })
            if len(batch) == 1:
                unresolved.append(batch[0])
                return
            middle = len(batch) // 2
            lookup_batch(batch[:middle], f"{batch_id}a")
            lookup_batch(batch[middle:], f"{batch_id}b")

    for batch_number, start in enumerate(range(0, len(missing), PSL_BATCH_SIZE), start=1):
        batch = missing[start : start + PSL_BATCH_SIZE]
        lookup_batch(batch, f"batch-{batch_number:04d}")
    elapsed = time.perf_counter() - lookup_start
    missing_after = sorted(hosts - cache.keys())
    status = "complete" if not unresolved and not missing_after else "incomplete"
    append_psl_log({
        "batch_id": "source-lookup-summary", "batch_type": "summary", "candidate_occurrences_total": stage["candidate_occurrences"],
        "unique_hostname_total": len(hosts), "hosts_requested": len(missing), "cache_hits": len(hosts) - len(missing),
        "hosts_returned": len(hosts) - len(missing_after), "status": status, "elapsed_seconds": f"{elapsed:.6f}",
        "error": f"unresolved={len(set(unresolved) | set(missing_after))}",
    })
    if unresolved or missing_after:
        raise RuntimeError(
            f"PSL lookup incomplete: {len(set(unresolved) | set(missing_after))} hostnames unresolved; "
            f"completed results cached in {PSL_CACHE}. No final graph will be written."
        )
    return cache


def candidate_from_row(row: dict[str, str]) -> extraction.Candidate:
    return extraction.Candidate(
        source_record_id=row["source_record_id"], original_text="", start=int(row["start"]), end=int(row["end"]),
        candidate_text=row["candidate_text"], extraction_method=row["extraction_method"],
        evidence_category=row["evidence_category"], confidence=row["confidence"], parser_status=row["parser_status"],
        normalized_hostname=row["normalized_hostname"] or None,
        rejection_reason=row["initial_rejection_reason"] or None,
    )


def primary_classification(flags: dict[str, bool], candidate_count: int) -> str:
    if flags["has_confident_domain_key"] and flags["has_confident_ip_key"]:
        return "confident_domain_and_ip"
    if flags["has_confident_domain_key"]:
        return "confident_domain_key"
    if flags["has_confident_ip_key"]:
        return "confident_ip_key"
    if candidate_count == 0:
        return "no_destination_candidate"
    if flags["has_malformed_url_candidate"]:
        return "malformed_or_invalid_candidate"
    if flags["has_public_suffix_only_candidate"]:
        return "public_suffix_only_candidate"
    if flags["has_unknown_suffix_candidate"]:
        return "unknown_suffix_candidate"
    if flags["has_ambiguous_bare_domain_mention"]:
        return "ambiguous_bare_domain_or_ip_mention"
    return "other_unresolved_candidate"


def write_candidate_outputs(records: list[dict[str, Any]], psl_map: dict[str, str | None], psl_rules: tuple[set[str], set[str], set[str]],
                            domain_dsu: DisjointSet, combined_dsu: DisjointSet) -> tuple[dict[str, Any], list[set[str]], dict[str, set[int]]]:
    for name in ("record_domain_edges.csv", "record_near_duplicate_edges.csv", "record_domain_status.csv"):
        target = WORK_DIR / name
        if target.exists():
            target.unlink()
    key_cache: dict[str, str | None] = {}
    for host, value in psl_map.items():
        key_cache[host] = value
    public_suffix_cache = {host: is_psl_suffix(host, psl_rules) if not registrable else False for host, registrable in psl_map.items()}
    for record in records:
        domain_dsu.parent[record["source_record_index"]] = record["source_record_index"]
        domain_dsu.size[record["source_record_index"]] = 1
        combined_dsu.parent[record["source_record_index"]] = record["source_record_index"]
        combined_dsu.size[record["source_record_index"]] = 1
    domain_key_owner: dict[str, int] = {}
    near_owner: dict[str, int] = {}
    for record in records:
        index = record["source_record_index"]
        near_id = record["near_duplicate_component_id"]
        if near_id:
            prior = near_owner.setdefault(near_id, index)
            if prior != index:
                combined_dsu.union(prior, index)

    record_key_sets: list[set[str]] = [set() for _ in range(len(records) + 1)]
    record_host_sets: list[set[str]] = [set() for _ in range(len(records) + 1)]
    has_key = [False] * (len(records) + 1)
    flags_per_record: list[dict[str, bool]] = [
        {"has_confident_domain_key": False, "has_confident_ip_key": False,
         "has_ambiguous_bare_domain_mention": False, "has_malformed_url_candidate": False,
         "has_public_suffix_only_candidate": False, "has_unknown_suffix_candidate": False,
         "has_other_unresolved_candidate": False}
        for _ in range(len(records) + 1)
    ]
    evidence_all: Counter[str] = Counter()
    status_all: Counter[str] = Counter()
    method_all: Counter[str] = Counter()
    rejection_all: Counter[str] = Counter()
    candidate_count = 0
    valid_reg_occurrences = 0
    resolved_domains: set[str] = set()
    all_keys: set[str] = set()
    reg_keys: set[str] = set()
    ip_keys: set[str] = set()
    valid_ip_records: set[int] = set()
    ambiguous_records: set[int] = set()
    reg_owner_records: set[int] = set()
    record_candidates_without_key = 0
    multi_hosts = 0
    multi_keys = 0
    edge_fields = [
        "source_record_id", "source_record_index", "label_original", "normalized_text_group_id",
        "near_duplicate_component_id", "quarantine_status", "start", "end", "candidate_text",
        "extraction_method", "evidence_category", "confidence", "normalized_hostname",
        "registrable_domain", "domain_grouping_key",
    ]
    status_fields = [
        "source_record_id", "source_record_index", "label_original", "normalized_text_group_id",
        "near_duplicate_component_id", "near_duplicate_manifest_present", "quarantine_status",
        "quarantine_reason", "promotional_review_flag", "has_confident_domain_key", "has_confident_ip_key",
        "has_ambiguous_bare_domain_mention", "has_malformed_url_candidate", "has_public_suffix_only_candidate",
        "has_unknown_suffix_candidate", "has_other_unresolved_candidate", "has_no_detected_candidate",
        "candidate_count", "primary_classification", "candidate_status_json",
    ]
    edge_tmp = WORK_DIR / "record_domain_edges.csv"
    near_tmp = WORK_DIR / "record_near_duplicate_edges.csv"
    status_tmp = WORK_DIR / "record_domain_status.csv"
    candidate_stream = CANDIDATE_SPOOL.open("r", encoding="utf-8", newline="")
    candidate_reader = iter(csv.DictReader(candidate_stream))
    pending = next(candidate_reader, None)
    next_candidate_index = int(pending["source_record_index"]) if pending else None
    start_time = time.perf_counter()
    try:
        with edge_tmp.open("w", encoding="utf-8", newline="") as edge_stream, \
             near_tmp.open("w", encoding="utf-8", newline="") as near_stream, \
             status_tmp.open("w", encoding="utf-8", newline="") as status_stream:
            edge_writer = csv.DictWriter(edge_stream, fieldnames=edge_fields)
            near_writer = csv.DictWriter(near_stream, fieldnames=[
                "source_record_id", "source_record_index", "label_original", "normalized_text_group_id",
                "near_duplicate_component_id", "edge_type", "normalized_group_record_count",
                "normalized_groups_in_near_component", "near_component_quarantined", "quarantine_reason",
            ])
            status_writer = csv.DictWriter(status_stream, fieldnames=status_fields)
            edge_writer.writeheader()
            near_writer.writeheader()
            status_writer.writeheader()
            for record in records:
                index = record["source_record_index"]
                near_id = record["near_duplicate_component_id"]
                if near_id:
                    group_count = len(manifest_norms_per_near[near_id])
                    group_records = record["near_duplicate_group_record_count"]
                    edge_type = "near_duplicate_component_membership" if group_count > 1 else (
                        "exact_duplicate_group_membership" if group_records > 1 else "singleton_text_group"
                    )
                else:
                    group_count = 0
                    group_records = 0
                    edge_type = "no_nonempty_text_manifest_entry"
                near_writer.writerow({
                    "source_record_id": record["source_record_id"], "source_record_index": index,
                    "label_original": record["label_original"], "normalized_text_group_id": record["normalized_text_group_id"],
                    "near_duplicate_component_id": near_id, "edge_type": edge_type,
                    "normalized_group_record_count": group_records, "normalized_groups_in_near_component": group_count,
                    "near_component_quarantined": record["quarantine_status"], "quarantine_reason": record["quarantine_reason"],
                })
                details: list[dict[str, Any]] = []
                row_keys: set[str] = set()
                row_hosts: set[str] = set()
                while pending and next_candidate_index == index:
                    candidate_count += 1
                    candidate = candidate_from_row(pending)
                    host = candidate.normalized_hostname
                    if host:
                        row_hosts.add(host)
                    if candidate.parser_status in {"normalized_hostname", "ambiguous_bare_domain_mention"}:
                        if host not in psl_map:
                            raise RuntimeError(f"Hostname absent from completed PSL cache: {host}")
                        candidate = extraction.apply_psl(
                            candidate,
                            psl_map.get(host),
                            is_public_suffix=bool(public_suffix_cache.get(host, False)),
                        )
                    else:
                        candidate = extraction.apply_psl(candidate, None)
                    evidence_all[candidate.evidence_category] += 1
                    status_all[candidate.parser_status] += 1
                    method_all[candidate.extraction_method] += 1
                    if candidate.rejection_reason:
                        rejection_all[candidate.rejection_reason] += 1
                    if candidate.registrable_domain:
                        valid_reg_occurrences += 1
                        resolved_domains.add(candidate.registrable_domain)
                    if candidate.domain_grouping_key:
                        key = candidate.domain_grouping_key
                        if candidate.confidence != "high":
                            raise AssertionError(f"Non-high-confidence candidate received key: {candidate}")
                        if key.startswith("registrable:"):
                            if candidate.parser_status != "normalized_hostname" or not candidate.registrable_domain or key != f"registrable:{candidate.registrable_domain}":
                                raise AssertionError(f"Invalid registrable-domain key lineage: {candidate}")
                            reg_keys.add(key)
                            reg_owner_records.add(index)
                        elif key.startswith("ip:"):
                            ip = ipaddress.ip_address(candidate.normalized_hostname or "").compressed.lower()
                            if candidate.parser_status != "ip_literal" or key != f"ip:{ip}":
                                raise AssertionError(f"Invalid IP key lineage: {candidate}")
                            ip_keys.add(key)
                            valid_ip_records.add(index)
                        else:
                            raise AssertionError(f"Unexpected grouping-key prefix: {key}")
                        all_keys.add(key)
                        row_keys.add(key)
                        has_key[index] = True
                        record_key_sets[index].add(key)
                        owner = domain_key_owner.setdefault(key, index)
                        if owner != index:
                            domain_dsu.union(owner, index)
                            combined_dsu.union(owner, index)
                        edge_writer.writerow({
                            "source_record_id": record["source_record_id"], "source_record_index": index,
                            "label_original": record["label_original"], "normalized_text_group_id": record["normalized_text_group_id"],
                            "near_duplicate_component_id": record["near_duplicate_component_id"],
                            "quarantine_status": record["quarantine_status"], "start": candidate.start, "end": candidate.end,
                            "candidate_text": candidate.candidate_text, "extraction_method": candidate.extraction_method,
                            "evidence_category": candidate.evidence_category, "confidence": candidate.confidence,
                            "normalized_hostname": candidate.normalized_hostname, "registrable_domain": candidate.registrable_domain,
                            "domain_grouping_key": key,
                        })
                    elif candidate.confidence == "high":
                        # High-confidence host candidates without keys must have an explicit rejection state.
                        if candidate.parser_status not in {"unknown_suffix", "public_suffix_only", "invalid_hostname", "invalid_port", "malformed_url"}:
                            raise AssertionError(f"High-confidence destination without key has unexpected status: {candidate}")
                    if candidate.parser_status == "ambiguous_bare_domain_mention":
                        flags_per_record[index]["has_ambiguous_bare_domain_mention"] = True
                    if candidate.parser_status in {"malformed_url", "invalid_hostname", "invalid_port", "html_parse_error"}:
                        flags_per_record[index]["has_malformed_url_candidate"] = True
                    if candidate.parser_status == "public_suffix_only":
                        flags_per_record[index]["has_public_suffix_only_candidate"] = True
                    if candidate.parser_status == "unknown_suffix":
                        flags_per_record[index]["has_unknown_suffix_candidate"] = True
                    if candidate.domain_grouping_key and candidate.domain_grouping_key.startswith("registrable:"):
                        flags_per_record[index]["has_confident_domain_key"] = True
                    elif candidate.domain_grouping_key and candidate.domain_grouping_key.startswith("ip:"):
                        flags_per_record[index]["has_confident_ip_key"] = True
                    elif candidate.evidence_category == "bare_ip_mention" or candidate.parser_status in {"relative_without_base", "unsupported_scheme", "empty_attribute", "ambiguous_ip_mention"}:
                        flags_per_record[index]["has_other_unresolved_candidate"] = True
                    details.append({
                        "start": candidate.start, "end": candidate.end, "candidate_text": candidate.candidate_text,
                        "extraction_method": candidate.extraction_method, "evidence_category": candidate.evidence_category,
                        "confidence": candidate.confidence, "parser_status": candidate.parser_status,
                        "normalized_hostname": candidate.normalized_hostname, "registrable_domain": candidate.registrable_domain,
                        "domain_grouping_key": candidate.domain_grouping_key, "rejection_reason": candidate.rejection_reason,
                    })
                    pending = next(candidate_reader, None)
                    next_candidate_index = int(pending["source_record_index"]) if pending else None
                record_host_sets[index] = row_hosts
                if len(row_hosts) > 1:
                    multi_hosts += 1
                if len(row_keys) > 1:
                    multi_keys += 1
                flags = flags_per_record[index]
                if not has_key[index]:
                    record_candidates_without_key += 1
                    ambiguous_records.add(index) if any(flags.values()) else None
                record["candidate_count_recomputed"] = len(details)
                status_writer.writerow({
                    "source_record_id": record["source_record_id"], "source_record_index": index,
                    "label_original": record["label_original"], "normalized_text_group_id": record["normalized_text_group_id"],
                    "near_duplicate_component_id": record["near_duplicate_component_id"],
                    "near_duplicate_manifest_present": record["near_duplicate_manifest_present"],
                    "quarantine_status": record["quarantine_status"], "quarantine_reason": record["quarantine_reason"],
                    "promotional_review_flag": record["promotional_review_flag"],
                    **flags, "has_no_detected_candidate": len(details) == 0,
                    "candidate_count": len(details),
                    "primary_classification": primary_classification(flags, len(details)),
                    "candidate_status_json": json.dumps(details, ensure_ascii=False, separators=(",", ":")),
                })
                if index % 5000 == 0:
                    print(f"Mapped candidates through source record {index:,}/{len(records):,}; {candidate_count:,} candidates; {len(all_keys):,} distinct keys", flush=True)
            if pending:
                raise AssertionError(f"Candidate spool contains out-of-range row at source record {next_candidate_index}")
    finally:
        candidate_stream.close()

    expected_candidate_count = json.loads(PREFLIGHT.read_text(encoding="utf-8"))["candidate_occurrences"]
    if candidate_count != expected_candidate_count:
        raise AssertionError(f"Candidate spool row count mismatch: {candidate_count} != {expected_candidate_count}")
    # The exact source-level counters below are compared with the completed V2 audit.
    old_audit = json.loads(OLD_AUDIT.read_text(encoding="utf-8"))
    checks = {
        "source_records": len(records) == old_audit["source_records"],
        "candidate_occurrences": candidate_count == old_audit["candidate_count_second_pass"],
        "candidate_evidence_counts": dict(sorted(evidence_all.items())) == old_audit["candidate_evidence_counts"],
        "candidate_parser_status_counts": dict(sorted(status_all.items())) == old_audit["candidate_parser_status_counts"],
        "valid_registrable_occurrences": valid_reg_occurrences == old_audit["valid_registrable_domain_candidate_count"],
        "distinct_valid_registrable_values": len(resolved_domains) == old_audit["distinct_valid_registrable_domains"],
        "registrable_keys": len(reg_keys) == old_audit["distinct_registrable_domain_grouping_keys"],
        "ip_keys": len(ip_keys) == old_audit["distinct_ip_grouping_keys"],
        "records_with_multiple_hosts": multi_hosts == old_audit["records_with_multiple_distinct_destination_hosts"],
        "records_with_multiple_grouping_keys": multi_keys == old_audit["records_with_multiple_destination_grouping_keys"],
        "records_without_confident_keys": record_candidates_without_key == old_audit["records_without_confident_destination_keys"],
        "records_with_valid_ip_keys": len(valid_ip_records) == old_audit["records_with_valid_ip_destinations"],
    }
    failed_checks = [key for key, ok in checks.items() if not ok]
    if failed_checks:
        raise RuntimeError(f"Recomputed V2 results differ from saved audit: {failed_checks}; no final graph will be published")
    # record -> near-component membership edges are written above; separate DSU now receives their unions.
    duplicate_dsu = DisjointSet(len(records))
    for index, record in enumerate(records, start=1):
        near_id = record["near_duplicate_component_id"]
        if near_id:
            prior = near_owner.setdefault(near_id, index)
            if prior != index:
                duplicate_dsu.union(prior, index)
    run_info = {
        "candidate_count": candidate_count, "candidate_evidence_counts": dict(sorted(evidence_all.items())),
        "candidate_parser_status_counts": dict(sorted(status_all.items())), "candidate_extraction_method_counts": dict(sorted(method_all.items())),
        "candidate_rejection_reason_counts": dict(sorted(rejection_all.items())),
        "valid_registrable_domain_candidate_occurrences": valid_reg_occurrences,
        "distinct_valid_registrable_domains": len(resolved_domains),
        "registrable_domain_keys": len(reg_keys), "ip_keys": len(ip_keys), "domain_keys_total": len(all_keys),
        "record_multiple_hosts": multi_hosts, "record_multiple_keys": multi_keys,
        "records_without_confident_keys": record_candidates_without_key,
        "records_with_confident_ip_key": len(valid_ip_records),
        "audit_aggregate_comparison": checks,
        "record_key_sets": record_key_sets,
        "domain_key_owner": domain_key_owner,
        "record_host_sets": record_host_sets,
        "flags_per_record": flags_per_record,
        "domain_keys": all_keys,
        "registrable_keys": reg_keys,
        "ip_keys": ip_keys,
        "valid_ip_records": valid_ip_records,
    }
    return run_info, record_key_sets, {key: set(value) for key, value in defaultdict(set).items()}


def aggregate_components(dsu: DisjointSet, records: list[dict[str, Any]], record_key_sets: list[set[str]],
                         graph_name: str, write_summary: bool = False) -> tuple[dict[str, Any], dict[int, dict[str, Any]], dict[int, int]]:
    by_root: dict[int, dict[str, Any]] = {}
    roots_by_record: dict[int, int] = {}
    for record in records:
        index = record["source_record_index"]
        root = dsu.find(index)
        roots_by_record[index] = root
        agg = by_root.setdefault(root, {
            "records": [], "labels": Counter(), "norms": set(), "near": set(), "keys": set(),
            "quarantined_records": 0, "no_confident_records": 0, "promo_records": 0,
        })
        agg["records"].append(index)
        agg["labels"][str(record["label_original"])] += 1
        if record["normalized_text_group_id"]:
            agg["norms"].add(record["normalized_text_group_id"])
        if record["near_duplicate_component_id"]:
            agg["near"].add(record["near_duplicate_component_id"])
        agg["keys"].update(record_key_sets[index])
        agg["quarantined_records"] += int(record["quarantine_status"])
        agg["promo_records"] += int(record["promotional_review_flag"])
        agg["no_confident_records"] += int(not record_key_sets[index])
    rows: list[dict[str, Any]] = []
    for root, agg in by_root.items():
        indexes = agg["records"]
        norm_groups = len(agg["norms"])
        near_count = len(agg["near"])
        regs = {key for key in agg["keys"] if key.startswith("registrable:")}
        ips = {key for key in agg["keys"] if key.startswith("ip:")}
        rows.append({
            "root": root,
            "component_id": stable_component_id(graph_name, min(indexes)),
            "records": len(indexes),
            "unique_normalized_text_groups": norm_groups,
            "near_duplicate_components": near_count,
            "registrable_domain_keys": len(regs),
            "ip_keys": len(ips),
            "distinct_destination_grouping_keys": len(agg["keys"]),
            "label_0_records": agg["labels"].get("0", 0),
            "label_1_records": agg["labels"].get("1", 0),
            "contains_multiple_labels": len(agg["labels"]) > 1,
            "quarantined_records": agg["quarantined_records"],
            "has_quarantined_group": agg["quarantined_records"] > 0,
            "promotional_review_records": agg["promo_records"],
            "records_without_confident_destination_key": agg["no_confident_records"],
            "member_indices": indexes,
            "key_set": agg["keys"],
        })
    rows.sort(key=lambda row: (-row["records"], row["component_id"]))
    sizes = [row["records"] for row in rows]
    stats = {
        "graph": graph_name,
        "components": len(rows),
        "source_records": sum(sizes),
        "singleton_components": sum(size == 1 for size in sizes),
        "largest_20_sizes": sizes[:20],
        "median_nearest_rank": nearest_rank(sizes, .5),
        "p90_nearest_rank": nearest_rank(sizes, .90),
        "p95_nearest_rank": nearest_rank(sizes, .95),
        "p99_nearest_rank": nearest_rank(sizes, .99),
        "components_with_multiple_registrable_domains": sum(row["registrable_domain_keys"] > 1 for row in rows),
        "components_with_multiple_labels": sum(row["contains_multiple_labels"] for row in rows),
        "label_distribution_across_records": {
            "0": sum(row["label_0_records"] for row in rows), "1": sum(row["label_1_records"] for row in rows),
        },
        "components_larger_than_dataset_fraction": {
            f"{fraction:.0%}": sum(row["records"] > len(records) * fraction for row in rows)
            for fraction in (.01, .05, .10, .15)
        },
        "quarantined_components": sum(row["has_quarantined_group"] for row in rows),
        "records_in_quarantined_components": sum(row["records"] for row in rows if row["has_quarantined_group"]),
        "largest_component": {k: v for k, v in rows[0].items() if k not in {"member_indices", "key_set"}} if rows else None,
    }
    if write_summary:
        path = WORK_DIR / "combined_component_summary.csv"
        fields = [
            "component_id", "records", "unique_normalized_text_groups", "near_duplicate_components",
            "registrable_domain_keys", "ip_keys", "distinct_destination_grouping_keys", "label_0_records",
            "label_1_records", "contains_multiple_labels", "quarantined_records", "has_quarantined_group",
            "promotional_review_records", "records_without_confident_destination_key",
        ]
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows({key: row[key] for key in fields} for row in rows)
    return stats, {row["root"]: row for row in rows}, roots_by_record


def build_large_component_outputs(records: list[dict[str, Any]], largest: dict[str, Any],
                                  record_key_sets: list[set[str]], combined_roots: dict[int, int],
                                  combined_rows: dict[int, dict[str, Any]]) -> dict[str, Any]:
    members = set(largest["member_indices"])
    member_out = WORK_DIR / "largest_component_members.csv"
    combined_component_id = combined_rows[combined_roots[min(members)]] ["component_id"]
    base_by_index = {r["source_record_index"]: r for r in records}
    fields = [
        "source_record_id", "source_record_index", "label_original", "normalized_text_group_id",
        "near_duplicate_component_id", "quarantine_status", "quarantine_reason", "promotional_review_flag",
        "domain_only_component_id", "combined_component_id", "distinct_record_domain_keys", "has_confident_destination_key",
    ]
    with member_out.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for index in sorted(members):
            record = base_by_index[index]
            writer.writerow({
                "source_record_id": record["source_record_id"], "source_record_index": index,
                "label_original": record["label_original"], "normalized_text_group_id": record["normalized_text_group_id"],
                "near_duplicate_component_id": record["near_duplicate_component_id"],
                "quarantine_status": record["quarantine_status"], "quarantine_reason": record["quarantine_reason"],
                "promotional_review_flag": record["promotional_review_flag"],
                "domain_only_component_id": largest["component_id"], "combined_component_id": combined_component_id,
                "distinct_record_domain_keys": len(record_key_sets[index]),
                "has_confident_destination_key": bool(record_key_sets[index]),
            })
    # Re-read candidate-to-key edges to compute direct key participation and provenance.
    by_key: dict[str, dict[str, Any]] = {}
    whole_evidence: Counter[str] = Counter()
    whole_methods: Counter[str] = Counter()
    whole_candidate_edges = 0
    with (WORK_DIR / "record_domain_edges.csv").open("r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            index = int(row["source_record_index"])
            if index not in members:
                continue
            whole_candidate_edges += 1
            whole_evidence[row["evidence_category"]] += 1
            whole_methods[row["extraction_method"]] += 1
            key = row["domain_grouping_key"]
            data = by_key.setdefault(key, {"records": set(), "norms": set(), "evidence": Counter(), "methods": Counter(), "samples": []})
            data["records"].add(index)
            if row["normalized_text_group_id"]:
                data["norms"].add(row["normalized_text_group_id"])
            data["evidence"][row["evidence_category"]] += 1
            data["methods"][row["extraction_method"]] += 1
            if len(data["samples"]) < 10 and index not in data["samples"]:
                data["samples"].append(index)
    ranked = sorted(by_key.items(), key=lambda item: (-len(item[1]["records"]), item[0]))[:50]
    bridge_path = WORK_DIR / "largest_component_bridge_edges.csv"
    bridge_fields = [
        "rank", "key_type", "domain_or_ip", "domain_grouping_key", "direct_source_record_count",
        "connected_normalized_text_group_count", "candidate_edge_occurrence_count", "evidence_category_counts_json",
        "extraction_method_counts_json", "representative_source_record_ids_json",
    ]
    with bridge_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=bridge_fields)
        writer.writeheader()
        for rank, (key, data) in enumerate(ranked, start=1):
            kind, value = key.split(":", 1)
            writer.writerow({
                "rank": rank, "key_type": kind, "domain_or_ip": value, "domain_grouping_key": key,
                "direct_source_record_count": len(data["records"]),
                "connected_normalized_text_group_count": len(data["norms"]),
                "candidate_edge_occurrence_count": sum(data["evidence"].values()),
                "evidence_category_counts_json": json.dumps(dict(sorted(data["evidence"].items())), ensure_ascii=False),
                "extraction_method_counts_json": json.dumps(dict(sorted(data["methods"].items())), ensure_ascii=False),
                "representative_source_record_ids_json": json.dumps([
                    f"combined_reduced.json:source_record_{i}" for i in sorted(data["samples"])
                ], ensure_ascii=False),
            })
    return {
        "member_count": len(members),
        "source_record_ids_unique": len(members) == largest["records"],
        "unique_normalized_text_groups": largest["unique_normalized_text_groups"],
        "near_duplicate_components": largest["near_duplicate_components"],
        "distinct_destination_keys": largest["distinct_destination_grouping_keys"],
        "distinct_registrable_domains": largest["registrable_domain_keys"],
        "distinct_ip_keys": largest["ip_keys"],
        "label_distribution": {"0": largest["label_0_records"], "1": largest["label_1_records"]},
        "records_with_quarantine": largest["quarantined_records"],
        "exact_duplicate_record_excess_over_normalized_groups": largest["records"] - largest["unique_normalized_text_groups"],
        "near_component_group_merges_lower_bound": max(0, largest["unique_normalized_text_groups"] - largest["near_duplicate_components"]),
        "direct_near_duplicate_pair_edges_within_component": None,
        "direct_near_duplicate_pair_edge_limitation": "The saved near-duplicate manifest preserves transitive component membership but not the individual pair edges from the original BK-tree/Jaccard pass.",
        "candidate_domain_edge_occurrences": whole_candidate_edges,
        "edge_counts_by_evidence_category": dict(sorted(whole_evidence.items())),
        "edge_counts_by_extraction_method": dict(sorted(whole_methods.items())),
        "top_50_key_count": len(ranked),
        "top_50_bridge_keys_file": bridge_path.name,
        "largest_component_member_file": member_out.name,
        "largest_component_seed_source_record_id": largest["component_id"],
    }


def write_final_report(path: Path, facts: dict[str, Any]) -> None:
    d = facts["domain_only_graph"]
    u = facts["duplicate_only_graph"]
    c = facts["combined_graph"]
    giant = facts["largest_domain_only_component"]
    stat = facts["source_audit"]
    psl = facts["psl"]
    share = giant["records"] / stat["source_records"]
    text = f"""# Combined V2 domain and text-component graph review

## Decision

**{facts['decision']}** -- {facts['decision_reason']}

No train/validation/test split or model training was performed. All graph vertices counted as records are original source rows; domain keys and text-component identifiers are edge labels, not extra records.

## Source-count reconciliation and identity

- The raw JSON array contains **{stat['source_records']:,}** objects, labels 0={stat['label_counts']['0']:,}, 1={stat['label_counts']['1']:,}. Its observed schema is `{stat['raw_schema']}` and contains no native record ID field.
- The original text-baseline manifest contains **{facts['text_manifest']['rows']:,}** nonempty records, **{facts['text_manifest']['missing_count']}** fewer than the raw array. It omits source index {facts['text_manifest']['missing_indices']}; that raw row is label 1 with a one-character newline-only text value. The earlier figure of 77,676 corresponds to prepared nonempty text rows; the V2 raw-source audit correctly counted 77,677 objects.
- Source IDs use the established deterministic convention `combined_reduced.json:source_record_<one-based raw index>`. All {stat['source_records']:,} indexes 1..N occurred exactly once; duplicate generated IDs={stat['duplicate_source_ids']}, duplicate indexes={stat['duplicate_source_indexes']}. The one whitespace-only row remains a source-record singleton with no normalized-text/near-duplicate manifest membership; no record was silently removed or assigned a fabricated raw identifier.
- The completed domain-only recount matches the prior V2 source/candidate aggregates: candidates={stat['candidate_occurrences']:,}, domain components={d['components']:,}, record total={d['source_records']:,}, original domain-only largest size={d['largest_20_sizes'][0]:,}.

## Reused grouping definitions

- Text normalization: Unicode NFKC, `casefold`, collapsed whitespace, then strip.
- Exact duplicate grouping: SHA-256 of normalized text; identical normalized groups stay together.
- Near duplicate rule (unchanged): unique character 5-grams; SimHash uses first 64 bits of SHA-256 per shingle; candidate pairs are checked within Hamming distance 3; shingle Jaccard must be at least 0.90; connected components are transitive. The saved baseline manifest provides the normalized-text and near-duplicate component IDs; no similarity threshold was recomputed or changed.
- Existing baseline quarantine is carried on every source-record edge. It includes prior promotional-review and label-conflict grouping decisions. Combined components inherit a quarantined state if any member text component was quarantined; no records were removed.
- Domain edges use only V2 `domain_grouping_key` values from the unchanged extractor and the pinned local JDK PSL. Ambiguous bare mentions and all rejected/unresolved candidates remain in the status lineage and never create graph edges.

## PSL batch execution and reproducibility

- PSL provider: {psl['implementation']}; JDK `{psl['jdk_version']}`; snapshot SHA-256 `{psl['psl_snapshot_sha256']}`. Python `{facts['python_version']}`.
- Candidate occurrences scanned: {stat['candidate_occurrences']:,}; unique normalized non-IP hostnames requiring PSL: {stat['unique_psl_hostnames']:,}. Duplicate hostnames were deduplicated before lookup. The previous one-shot lookup exceeded its 300-second subprocess limit; it spent the call on one CPU-bound batch over this host set. The earlier implementation already deduplicated hosts, so repetition was not the timeout cause.
- The equivalent batch implementation was compared with the existing `psl_registrable_domains()` behavior for common domains, `co.uk`, `github.io`, `s3.amazonaws.com`, public-suffix-only values, IDN ASCII labels, an unknown suffix, and an unqualified hostname. One-call, bounded-batch, and repeated outputs were identical. The production JDK implementation and PSL snapshot were unchanged.
- Batch size was {facts['psl_batch_size']:,}; successful lookup batches={facts['psl_batches_completed']:,}; failed/split-retry attempts={facts['psl_failed_batches']:,}; summed successful-batch elapsed time={facts['psl_batch_elapsed_seconds']:.2f}s; finalization-run PSL cache read time={facts['psl_cache_read_elapsed_seconds']:.2f}s with {facts['psl_cache_hits']:,} cache hits; final unresolved hostnames=0. Successful results are retained in `psl_results_cache.jsonl`; per-batch timing and host ranges are in `psl_batch_execution_log.csv`.
- Full source scan/extraction time={facts['scan_elapsed_seconds']:.2f}s; initial PSL lookup batch subprocess elapsed time={facts['psl_batch_elapsed_seconds']:.2f}s summed across successful batches; final cached graph-construction run time={facts['total_elapsed_seconds']:.2f}s (graph construction/output={facts['graph_elapsed_seconds']:.2f}s). These stage timings may span the initial cache-fill attempt and a resumed run; the final run duration is not necessarily an end-to-end cold-run duration. Reproduction is offline with the same raw file, extractor, text manifest, Python behavior, JDK 27 and PSL snapshot hash.

## Reconciliation of V2 grouping keys

- V2 eligible candidate edges: {stat['eligible_domain_candidate_occurrences']:,} candidate occurrences; {stat['unique_domain_keys']:,} total destination keys ({stat['unique_registrable_keys']:,} registrable-domain keys and {stat['unique_ip_keys']:,} IP keys).
- Valid registrable-domain candidate occurrences: {stat['valid_registrable_domain_candidate_occurrences']:,}; distinct PSL-resolved registrable values={stat['distinct_resolved_registrable_values']:,}; distinct registrable grouping keys={stat['unique_registrable_keys']:,}. The extra {stat['distinct_resolved_registrable_values'] - stat['unique_registrable_keys']:,} values are resolved ambiguous bare-domain mentions excluded by policy; the earlier audit showed this domain-count difference is expected.
- Candidate evidence/status counts and key invariants were rechecked against the saved full audit. `combined_graph_invariants.json` records each comparison. Candidate edge rows preserve source ID/index, label, normalized-text group, near component, exact candidate text and offsets, extraction method, evidence, confidence, normalized host, PSL registrable value/canonical IP, and key.
- `record_domain_status.csv` contains exactly one row per source record and all candidate statuses/rejection reasons. `record_domain_edges.csv` contains every successful high-confidence candidate-to-key edge. `record_near_duplicate_edges.csv` contains one row per raw record; the newline-only record has an explicit no-manifest-membership state.

## Graph comparison

| Graph | Components | Source records | Singletons | Median | P90 | P95 | P99 | Largest 20 sizes | Multiple registrable domains | Mixed-label components |
|---|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|
| V2 domain/IP only | {d['components']:,} | {d['source_records']:,} | {d['singleton_components']:,} | {d['median_nearest_rank']} | {d['p90_nearest_rank']} | {d['p95_nearest_rank']} | {d['p99_nearest_rank']} | `{d['largest_20_sizes']}` | {d['components_with_multiple_registrable_domains']:,} | {d['components_with_multiple_labels']:,} |
| Existing exact/near-text only | {u['components']:,} | {u['source_records']:,} | {u['singleton_components']:,} | {u['median_nearest_rank']} | {u['p90_nearest_rank']} | {u['p95_nearest_rank']} | {u['p99_nearest_rank']} | `{u['largest_20_sizes']}` | {u['components_with_multiple_registrable_domains']:,} | {u['components_with_multiple_labels']:,} |
| Combined | {c['components']:,} | {c['source_records']:,} | {c['singleton_components']:,} | {c['median_nearest_rank']} | {c['p90_nearest_rank']} | {c['p95_nearest_rank']} | {c['p99_nearest_rank']} | `{c['largest_20_sizes']}` | {c['components_with_multiple_registrable_domains']:,} | {c['components_with_multiple_labels']:,} |

The combined graph connects {facts['combined_component_merges_from_domain_graph']:,} previously separate domain-only components into shared combined components, affecting {facts['records_in_text_joined_combined_components']:,} source records. The overall component count changes from {d['components']:,} to {c['components']:,}. All connected components remain indivisible; no partition was assigned.

Class distribution by source records: domain-only 0={d['label_distribution_across_records']['0']:,}, 1={d['label_distribution_across_records']['1']:,}; duplicate-only 0={u['label_distribution_across_records']['0']:,}, 1={u['label_distribution_across_records']['1']:,}; combined 0={c['label_distribution_across_records']['0']:,}, 1={c['label_distribution_across_records']['1']:,}. Components containing both labels: {c['components_with_multiple_labels']:,}. Baseline label-conflict/quarantine counts and combined propagation are in the component summary and invariants.

Components exceeding 1%, 5%, 10%, 15% of all source records (combined): `{json.dumps(c['components_larger_than_dataset_fraction'], sort_keys=True)}`. A component greater than 15% cannot fit in a nominal 15% test partition without violating indivisibility.

## Existing oversized domain-only component

The prior 15,442-record component was reconstructed. It has {giant['records']:,} source records ({share:.2%}), {giant['unique_normalized_text_groups']:,} normalized-text groups, {giant['near_duplicate_components']:,} near-duplicate components, {giant['distinct_destination_grouping_keys']:,} destination keys ({giant['registrable_domain_keys']:,} registrable domains and {giant['ip_keys']:,} IP keys), labels 0={giant['label_0_records']:,}/1={giant['label_1_records']:,}, and {facts['largest_domain_component_edge_summary']['candidate_domain_edge_occurrences']:,} candidate-to-key edge occurrences.

Edge occurrences by evidence category: `{json.dumps(facts['largest_domain_component_edge_summary']['edge_counts_by_evidence_category'], sort_keys=True)}`. By extraction method: `{json.dumps(facts['largest_domain_component_edge_summary']['edge_counts_by_extraction_method'], sort_keys=True)}`. Direct duplicate counts within the component: {facts['largest_domain_component_edge_summary']['exact_duplicate_record_excess_over_normalized_groups']:,} extra rows beyond normalized groups; at least {facts['largest_domain_component_edge_summary']['near_component_group_merges_lower_bound']:,} normalized-group merges into near components. The baseline manifest stores transitive near-component IDs, not original pairwise BK-tree edges, so exact pair-edge counts within this component are not available.

Source record 41 is a confirmed seed bridge: its HTML contains 66 anchor candidates, four form-action attributes (three absolute/form destinations and one relative reference), a canonical URL and Open Graph URL, spanning eight hosts including Facebook, LinkedIn, Twitter, Pinterest, Mailchimp and Seatmaestro hosts. This verifies common navigation/platform destinations at the seed. Whether these or other common hosts account for most transitive connectivity is evidenced by the top-50 key table, not inferred from the seed alone. No platform/CDN/social key was excluded.

Shared navigation/platform destinations are clearly present among the largest component bridges: Facebook directly occurs in 4,435 source records, Twitter in 4,296, YouTube in 2,192, LinkedIn in 1,910, and Instagram in 1,839. These shared keys contribute to graph connectivity, although their exclusive transitive contribution cannot be separated because components overlap. The unchanged V2 policy also turns HTML canonical and Open Graph document-identity metadata into grouping edges; this is a policy risk because these URLs are not necessarily user-clickable destinations. The largest component includes 4,612 canonical and 3,627 Open Graph candidate edges. This audit preserves them and recommends policy review before any future split; it does not remove them.

Shared navigation/platform destinations are clearly present among the largest component's bridges: Facebook directly occurs in 4,435 source records, Twitter in 4,296, YouTube in 2,192, LinkedIn in 1,910, and Instagram in 1,839. These shared keys contribute to graph connectivity, although their exclusive transitive contribution cannot be separated because components overlap. The unchanged V2 policy also turns HTML canonical and Open Graph document-identity metadata into grouping edges; this is a policy risk because these URLs are not necessarily user-clickable destinations. The largest component includes 4,612 canonical and 3,627 Open Graph candidate edges. This audit preserves them and recommends policy review before any future split; it does not remove them.

The 50 highest-degree keys in this domain-only component are in `largest_component_bridge_edges.csv`, with direct source-record counts, connected text groups, occurrence counts, evidence/method distributions, and representative source IDs. `largest_component_members.csv` lists every source record and its text/near-duplicate/quarantine/combined-component associations.

## Records with no confident destination key

Record-level status flags can overlap and are counted independently. The exclusive primary classification uses this order: confident domain+IP; confident domain; confident IP; no candidate; malformed/invalid; public-suffix-only; unknown-suffix; ambiguous bare domain/IP; other unresolved. Counts reconcile exactly to {stat['source_records']:,} records.

No confident key: {stat['records_without_confident_keys']:,}; with at least one unresolved/ambiguous candidate: {stat['no_key_records_with_candidates']:,}; no candidate at all: {stat['no_key_records_without_candidates']:,}; with a confident key and additional unresolved candidates: {stat['keyed_records_with_unresolved_candidates']:,}. Exclusive primary classes: `{json.dumps(stat['record_primary_classification_counts'], sort_keys=True)}`. Overlapping flags: ambiguous bare-domain mention={stat['records_with_ambiguous_bare_domain']:,}; malformed/invalid={stat['records_with_malformed_candidates']:,}; public-suffix-only={stat['records_with_public_suffix_only']:,}; unknown-suffix={stat['records_with_unknown_suffix']:,}; other unresolved={stat['records_with_other_unresolved']:,}; no candidate={stat['records_with_no_candidate']:,}.

No-key rows may be retained for separate, clearly labeled evaluation slices, but they must not be represented as unseen-domain examples. A record with a confident key plus unresolved candidates remains in the domain graph by its confident key and has all unresolved candidate diagnostics preserved.

## Split-feasibility assessment

The combined graph is complete and leakage edges were kept intact, but 70/15/15 is only an approximate target. The largest combined component is {c['largest_component']['records']:,} records; the largest component cannot be broken up to meet the test percentage. Component-level class balance, mixed-label components, quarantine propagation, 48,092 no-confident-key records, and the many multi-domain records should be handled explicitly in any later split. Keep no-key rows separate from the unseen-domain claim. If components prevent balanced allocations, report the achieved proportions or design a separately justified evaluation; do not remove high-degree domains or split large components.

## Validation checks

All requested invariants and reconciliation checks are in `combined_graph_invariants.json`. Graph nodes counted as records equal the raw array count; source indices and generated IDs are unique; there are no duplicate source rows; domain-only counts match the old V2 audit; every PSL hostname has a cached, completed result; no incomplete lookup was used; all final edge records have source offsets; and no network/DNS operation occurred.
"""
    path.write_text(text, encoding="utf-8")


def main() -> int:
    started = time.perf_counter()
    if FINAL_DIR.exists():
        raise FileExistsError(f"Refusing to overwrite existing output directory: {FINAL_DIR}")
    for path in (SOURCE, BASE_MANIFEST, BASE_METRICS, OLD_AUDIT, OLD_GROUPS, PSL_FILE, JAVA):
        if not path.is_file():
            raise FileNotFoundError(path)
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    manifest, manifest_summary = load_manifest()
    metrics = json.loads(BASE_METRICS.read_text(encoding="utf-8"))
    if manifest_summary["normalized_text_groups"] != metrics["grouping"]["normalized_text_groups"]:
        raise ValueError("Existing manifest normalized-text count differs from baseline metrics")
    if manifest_summary["near_duplicate_components"] != metrics["grouping"]["near_duplicate_components"]:
        raise ValueError("Existing manifest near-duplicate count differs from baseline metrics")

    psl_meta, psl_semantics_test = verify_batch_semantics()
    records, hostnames, stage = load_or_scan_source(manifest, manifest_summary)
    if len(records) != stage["source_records"]:
        raise ValueError("Source row count disagrees with resumable extraction stage")
    if stage["raw_source_indices_missing_from_text_manifest"] != [31230]:
        raise ValueError(f"Unexpected manifest/source discrepancy: {stage['raw_source_indices_missing_from_text_manifest']}")

    # Validate manifest-to-record uniqueness and label consistency without counting graph IDs as records.
    expected_indices = set(range(1, len(records) + 1))
    if {r["source_record_index"] for r in records} != expected_indices:
        raise AssertionError("Source record index coverage is not exactly 1..N")
    if len({r["source_record_id"] for r in records}) != len(records):
        raise AssertionError("Generated source record IDs are not unique")
    for record in records:
        idx = record["source_record_index"]
        if idx in manifest and manifest[idx]["label_original"] != str(record["label_original"]):
            raise ValueError(f"Label mismatch for source index {idx}")

    psl_start = time.perf_counter()
    psl_map = load_cache_and_lookup(hostnames, stage, psl_meta)
    psl_elapsed = time.perf_counter() - psl_start
    if set(psl_map) != hostnames:
        raise AssertionError("PSL cache is incomplete; refusing to build graph")

    all_host_rules = load_psl_rules()
    # Expose component-level manifest group counts to the streaming edge builder.
    global manifest_norms_per_near
    manifest_norms_per_near = manifest_summary["normalized_groups_per_near_component"]
    domain_dsu = DisjointSet(len(records))
    combined_dsu = DisjointSet(len(records))
    # Set for all raw rows before unions (one array slot per record index).
    for i in range(1, len(records) + 1):
        domain_dsu.parent[i] = i
        domain_dsu.size[i] = 1
        combined_dsu.parent[i] = i
        combined_dsu.size[i] = 1

    graph_start = time.perf_counter()
    run_info, record_key_sets, _ = write_candidate_outputs(
        records, psl_map, all_host_rules, domain_dsu, combined_dsu,
    )
    # Domain-only, duplicate-only and combined graphs all use source-row vertices.
    duplicate_dsu = DisjointSet(len(records))
    near_owner: dict[str, int] = {}
    for record in records:
        index = record["source_record_index"]
        near_id = record["near_duplicate_component_id"]
        if near_id:
            prior = near_owner.setdefault(near_id, index)
            if prior != index:
                duplicate_dsu.union(prior, index)
    domain_stats, domain_rows, domain_roots = aggregate_components(domain_dsu, records, record_key_sets, "domain_component")
    duplicate_stats, duplicate_rows, duplicate_roots = aggregate_components(duplicate_dsu, records, record_key_sets, "text_component")
    combined_stats, combined_rows, combined_roots = aggregate_components(
        combined_dsu, records, record_key_sets, "combined_component", write_summary=True,
    )

    old_audit = json.loads(OLD_AUDIT.read_text(encoding="utf-8"))
    old_groups = json.loads(OLD_GROUPS.read_text(encoding="utf-8"))
    old_domain_sizes = Counter()
    for row in old_groups["component_size_distribution"]:
        old_domain_sizes[int(row["records"])] = int(row["component_count"])
    new_domain_sizes = Counter(row["records"] for row in domain_rows.values())
    if domain_stats["components"] != old_groups["connected_components_including_no-key_singletons"]:
        raise RuntimeError("Reconstructed domain-only component count differs from saved V2 diagnostics")
    if old_domain_sizes != new_domain_sizes:
        raise RuntimeError("Reconstructed domain-only component size distribution differs from saved V2 diagnostics")
    if domain_stats["largest_component"]["records"] != 15442:
        raise RuntimeError("Reconstructed prior largest domain-only component does not match the saved size 15,442")
    largest_domain = max(domain_rows.values(), key=lambda row: (row["records"], -min(row["member_indices"])))
    large_detail = build_large_component_outputs(records, largest_domain, record_key_sets, combined_roots, combined_rows)

    no_key_class_counts: Counter[str] = Counter()
    record_primary_counts: Counter[str] = Counter()
    no_key_with_candidate = 0
    no_key_without_candidate = 0
    keyed_with_unresolved = 0
    flags_counts: Counter[str] = Counter()
    status_path = WORK_DIR / "record_domain_status.csv"
    with status_path.open("r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            record_primary_counts[row["primary_classification"]] += 1
            if row["has_confident_domain_key"] == "True" or row["has_confident_ip_key"] == "True":
                if any(row[k] == "True" for k in ("has_ambiguous_bare_domain_mention", "has_malformed_url_candidate", "has_public_suffix_only_candidate", "has_unknown_suffix_candidate", "has_other_unresolved_candidate")):
                    keyed_with_unresolved += 1
            else:
                no_key_class_counts[row["primary_classification"]] += 1
                if int(row["candidate_count"]):
                    no_key_with_candidate += 1
                else:
                    no_key_without_candidate += 1
            for key in ("has_confident_domain_key", "has_confident_ip_key", "has_ambiguous_bare_domain_mention", "has_malformed_url_candidate", "has_public_suffix_only_candidate", "has_unknown_suffix_candidate", "has_other_unresolved_candidate", "has_no_detected_candidate"):
                flags_counts[key] += row[key] == "True"
    if sum(record_primary_counts.values()) != len(records):
        raise AssertionError("Record-level primary classifications do not reconcile to source count")
    if no_key_with_candidate + no_key_without_candidate != run_info["records_without_confident_keys"]:
        raise AssertionError("No-key record classification does not reconcile")
    if record_primary_counts["no_destination_candidate"] != flags_counts["has_no_detected_candidate"]:
        raise AssertionError("No-candidate classification and flag disagree")

    combined_component_merges = sum(max(0, len({domain_roots[i] for i in row["member_indices"]}) - 1) for row in combined_rows.values())
    records_in_joined_comps = sum(row["records"] for row in combined_rows.values() if len({domain_roots[i] for i in row["member_indices"]}) > 1)
    # Baseline text quarantine follows its stored component decision through all domain merges.
    graph_elapsed = time.perf_counter() - graph_start
    output_names = set(DELIVERABLES) - {"psl_batch_execution_log.csv"}
    for name in sorted(output_names):
        if name == "combined_component_summary.csv":
            source = WORK_DIR / name
        else:
            continue
        if not source.is_file():
            raise FileNotFoundError(source)

    source_hash = stage["source_sha256"]
    extractor_hash = stage["extractor_sha256"]
    baseline_hash = sha256_file(BASE_MANIFEST)
    with (WORK_DIR / "psl_batch_execution_log.csv").open("r", encoding="utf-8", newline="") as log_stream:
        psl_log_rows = list(csv.DictReader(log_stream))
    successful_psl_batches = [row for row in psl_log_rows if row["batch_type"] == "lookup" and row["status"] == "completed"]
    graph_facts = {
        "raw_source_file": str(SOURCE.relative_to(ROOT)), "raw_source_sha256": source_hash,
        "raw_schema": stage["raw_record_schema"], "source_records": len(records),
        "source_label_counts": stage["source_label_counts"], "source_ids_are_generated_from_index": True,
        "native_record_id_fields": [], "unique_source_record_ids": len({r["source_record_id"] for r in records}),
        "duplicate_source_record_ids": 0, "unique_source_indices": len({r["source_record_index"] for r in records}),
        "duplicate_source_indices": 0, "raw_indices_missing_from_text_manifest": stage["raw_source_indices_missing_from_text_manifest"],
        "text_manifest_rows": len(manifest), "text_manifest_sha256": baseline_hash,
        "whitespace_only_text_rows_missing_from_manifest": [31230],
        "candidate_occurrences": run_info["candidate_count"],
        "candidate_evidence_counts": run_info["candidate_evidence_counts"],
        "candidate_parser_status_counts": run_info["candidate_parser_status_counts"],
        "candidate_extraction_method_counts": run_info["candidate_extraction_method_counts"],
        "candidate_rejection_reason_counts": run_info["candidate_rejection_reason_counts"],
        "eligible_domain_candidate_occurrences": run_info["candidate_count"] - sum(1 for _ in []),
        "unique_psl_hostnames": len(hostnames), "unique_registrable_domain_candidate_occurrences": run_info["valid_registrable_domain_candidate_occurrences"],
        "distinct_resolved_registrable_values": run_info["distinct_valid_registrable_domains"],
        "unique_registrable_keys": run_info["registrable_domain_keys"], "unique_ip_keys": len(run_info["ip_keys"]),
        "unique_domain_keys": run_info["domain_keys_total"],
        "records_with_multiple_hosts": run_info["record_multiple_hosts"],
        "records_with_multiple_destination_keys": run_info["record_multiple_keys"],
        "records_without_confident_keys": run_info["records_without_confident_keys"],
        "records_with_valid_ip_key": run_info["records_with_confident_ip_key"],
        "records_with_ambiguous_bare_domain": flags_counts["has_ambiguous_bare_domain_mention"],
        "records_with_malformed_candidates": flags_counts["has_malformed_url_candidate"],
        "records_with_public_suffix_only": flags_counts["has_public_suffix_only_candidate"],
        "records_with_unknown_suffix": flags_counts["has_unknown_suffix_candidate"],
        "records_with_other_unresolved": flags_counts["has_other_unresolved_candidate"],
        "records_with_no_candidate": flags_counts["has_no_detected_candidate"],
        "no_key_records_with_candidates": no_key_with_candidate,
        "no_key_records_without_candidates": no_key_without_candidate,
        "keyed_records_with_unresolved_candidates": keyed_with_unresolved,
        "record_primary_classification_counts": dict(sorted(record_primary_counts.items())),
        "no_key_primary_classification_counts": dict(sorted(no_key_class_counts.items())),
        "domain_only_graph": domain_stats,
        "duplicate_only_graph": duplicate_stats,
        "combined_graph": combined_stats,
        "combined_component_merges_from_domain_graph": combined_component_merges,
        "records_in_text_joined_combined_components": records_in_joined_comps,
        "largest_domain_only_component": {k: v for k, v in largest_domain.items() if k not in {"member_indices", "key_set"}},
        "largest_domain_component_edge_summary": large_detail,
        "near_duplicate_manifest_summary": {k: v for k, v in manifest_summary.items() if not isinstance(v, (set, dict))},
        "baseline_near_duplicate_method": metrics["grouping"]["near_duplicate_method"],
        "baseline_near_duplicate_pairs_joined_global": metrics["grouping"]["near_duplicate_pairs_joined"],
        "baseline_quarantined_components": metrics["grouping"]["quarantined_components"],
        "quarantine_propagation": {
            "domain_only_quarantined_components": domain_stats["quarantined_components"],
            "combined_quarantined_components": combined_stats["quarantined_components"],
            "combined_quarantined_records": combined_stats["records_in_quarantined_components"],
            "policy": "A combined component is treated as quarantined when any member record's existing near-duplicate component was quarantined; no record is dropped.",
        },
        "psl": psl_meta,
        "psl_batch_semantic_equivalence_test": {"passed": True, "samples": psl_semantics_test},
        "psl_batch_size": PSL_BATCH_SIZE,
        "psl_batches_completed": len({row["batch_id"] for row in successful_psl_batches}),
        "psl_failed_batches": sum(1 for row in psl_log_rows if row["batch_type"] == "lookup" and row["status"] == "failed_split"),
        "psl_cache_hits": stage.get("psl_cache_hits", 0),
        "psl_batch_elapsed_seconds": sum(float(row["elapsed_seconds"]) for row in successful_psl_batches),
        "psl_cache_read_elapsed_seconds": psl_elapsed,
        "scan_elapsed_seconds": stage["scan_elapsed_seconds"], "graph_elapsed_seconds": graph_elapsed,
        "total_elapsed_seconds": time.perf_counter() - started,
        "python_version": platform.python_version(), "extractor_sha256": extractor_hash,
        "batch_log_path": "psl_batch_execution_log.csv", "cache_path": "psl_results_cache.jsonl",
        "cache_complete_host_count": len(psl_map), "cache_unresolved_host_count": len(set(hostnames) - psl_map.keys()),
        "audit_aggregate_comparison": run_info["audit_aggregate_comparison"],
        "network_or_dns_used": False,
    }
    # Distinct high-confidence candidate occurrences are key-bearing; all such edges are serialized.
    with (WORK_DIR / "record_domain_edges.csv").open("r", encoding="utf-8", newline="") as stream:
        edge_rows_count = sum(1 for _ in csv.DictReader(stream))
    graph_facts["eligible_domain_candidate_occurrences"] = edge_rows_count
    graph_facts["record_domain_edge_rows"] = edge_rows_count
    graph_facts["record_near_duplicate_edge_rows"] = len(records)
    graph_facts["record_domain_status_rows"] = len(records)
    graph_facts["decision"] = "CONDITIONAL GO"
    graph_facts["decision_reason"] = (
        "The complete source-record graph was reconstructed and reconciled, but component indivisibility, "
        "mixed-label groups, the oversized domain component, and records without confident destination keys "
        "require an explicit evaluation design before any held-out split is assigned."
    )
    graph_facts["text_manifest"] = {
        "rows": len(manifest),
        "missing_count": len(stage["raw_source_indices_missing_from_text_manifest"]),
        "missing_indices": stage["raw_source_indices_missing_from_text_manifest"],
    }
    graph_facts["source_audit"] = {
        "source_records": len(records),
        "label_counts": stage["source_label_counts"],
        "raw_schema": stage["raw_record_schema"],
        "duplicate_source_ids": 0,
        "duplicate_source_indexes": 0,
        "candidate_occurrences": run_info["candidate_count"],
        "eligible_domain_candidate_occurrences": edge_rows_count,
        "unique_domain_keys": run_info["domain_keys_total"],
        "unique_registrable_keys": run_info["registrable_domain_keys"],
        "unique_ip_keys": len(run_info["ip_keys"]),
        "valid_registrable_domain_candidate_occurrences": run_info["valid_registrable_domain_candidate_occurrences"],
        "distinct_resolved_registrable_values": run_info["distinct_valid_registrable_domains"],
        "records_without_confident_keys": run_info["records_without_confident_keys"],
        "unique_psl_hostnames": len(hostnames),
        "no_key_records_with_candidates": no_key_with_candidate,
        "no_key_records_without_candidates": no_key_without_candidate,
        "keyed_records_with_unresolved_candidates": keyed_with_unresolved,
        "record_primary_classification_counts": dict(sorted(record_primary_counts.items())),
        "records_with_ambiguous_bare_domain": flags_counts["has_ambiguous_bare_domain_mention"],
        "records_with_malformed_candidates": flags_counts["has_malformed_url_candidate"],
        "records_with_public_suffix_only": flags_counts["has_public_suffix_only_candidate"],
        "records_with_unknown_suffix": flags_counts["has_unknown_suffix_candidate"],
        "records_with_other_unresolved": flags_counts["has_other_unresolved_candidate"],
        "records_with_no_candidate": flags_counts["has_no_detected_candidate"],
    }
    giant = graph_facts["largest_domain_only_component"]
    graph_facts["graph_node_accounting"] = {
        "source_record_nodes": len(records),
        "domain_key_nodes": run_info["domain_keys_total"],
        "text_component_nodes": manifest_summary["near_duplicate_components"],
        "auxiliary_nodes_counted_as_records": 0,
        "source_record_nodes_exactly_once": len(records) == len(set(r["source_record_index"] for r in records)),
    }
    graph_facts["delivery_files"] = list(DELIVERABLES) + ["psl_results_cache.jsonl", "psl_cache_meta.json"]

    write_final_report(WORK_DIR / "combined_graph_review.md", graph_facts)
    write_json(WORK_DIR / "combined_graph_invariants.json", graph_facts)
    # Rename the durable cache with an explicit, final-artifact name.
    (WORK_DIR / "psl_results_cache.jsonl").write_text(PSL_CACHE.read_text(encoding="utf-8"), encoding="utf-8")
    # Temp extraction artifacts are no longer needed; retain cache + per-batch log.
    CANDIDATE_SPOOL.unlink()
    BASE_RECORDS.unlink()
    PREFLIGHT.unlink()
    if FINAL_DIR.exists():
        raise FileExistsError(f"Refusing to overwrite existing output directory: {FINAL_DIR}")
    WORK_DIR.rename(FINAL_DIR)
    print(json.dumps({
        "output_directory": str(FINAL_DIR.relative_to(ROOT)),
        "domain_graph_components": domain_stats["components"],
        "duplicate_only_components": duplicate_stats["components"],
        "combined_components": combined_stats["components"],
        "largest_domain_only_component": giant["records"],
        "largest_combined_component": combined_stats["largest_component"]["records"],
        "source_records": len(records), "psl_hostnames": len(hostnames), "eligible_edges": edge_rows_count,
        "elapsed_seconds": graph_facts["total_elapsed_seconds"],
    }, ensure_ascii=False, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
