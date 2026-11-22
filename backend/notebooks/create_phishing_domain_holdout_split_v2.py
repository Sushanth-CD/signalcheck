"""Create a reproducible Scenario A/D phishing domain-held-out split.

This script reconstructs and validates the saved V2 combined graph before it
creates any output. It uses no network access, makes no model predictions,
and never trains a classifier. Existing output directories are never
overwritten.

Run from the repository root with the established project interpreter:
    .venv-final-test/Scripts/python.exe backend/notebooks/create_phishing_domain_holdout_split_v2.py
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import random
import re
import sys
import tempfile
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

csv.field_size_limit(sys.maxsize)

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.notebooks.prepare_ml_datasets import iter_json_array

BASE = ROOT / "backend/reports/ml/phishing_domain_extraction_v2"
GRAPH = BASE / "combined_graph_review"
SOURCE = ROOT / "backend/data/raw/combined_reduced.json"
EXTRACTOR = ROOT / "backend/notebooks/phishing_url_extraction_v2.py"
OUTPUT = BASE / "domain_holdout_split_v2"
SEED = 20261026
TARGETS = {"train": 0.70, "validation": 0.15, "test": 0.15}
HARD_UNRESOLVED = {
    "malformed_url", "invalid_hostname", "invalid_port", "unknown_suffix",
    "public_suffix_only", "html_parse_error",
}
AMBIGUOUS = {"ambiguous_bare_domain_mention", "ambiguous_ip_mention"}
ACCEPTED = {"normalized_hostname", "ip_literal"}
QUARANTINE_PROMO = "promotional_review_flag_in_near_duplicate_component"
QUARANTINE_LABEL = "near_duplicate_component_has_conflicting_original_labels"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_component_id(min_index: int) -> str:
    return f"combined_component_source_record_{min_index:06d}"


class DSU:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n + 1))
        self.size = [1] * (n + 1)

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


def bool_field(value: str, field: str, source: str, index: int) -> bool:
    if value not in {"True", "False"}:
        raise ValueError(f"{source} row {index}: invalid {field}={value!r}")
    return value == "True"


def nearest_rank(values: list[int], quantile: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(1, math.ceil(quantile * len(ordered))) - 1]


def read_summary(path: Path) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    with path.open("r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            key = row["component_id"]
            if key in result:
                raise ValueError(f"Duplicate saved component summary ID {key}")
            result[key] = row
    return result


def validate_invariants_file(facts: dict[str, Any]) -> int:
    n = int(facts["source_records"])
    if facts.get("network_or_dns_used") is not False:
        raise ValueError("Saved graph does not attest to offline/no-DNS construction")
    if facts.get("raw_source_sha256") != sha256_file(SOURCE):
        raise ValueError("Raw source checksum differs from the graph's saved source checksum")
    if facts.get("extractor_sha256") != sha256_file(EXTRACTOR):
        raise ValueError("V2 extractor changed since the graph was built")
    expected = facts.get("combined_graph", {})
    if int(expected.get("source_records", -1)) != n:
        raise ValueError("Combined graph record count does not match source count")
    return n


def candidate_flags(candidates: list[dict[str, Any]], index: int) -> dict[str, bool]:
    statuses = {str(c.get("parser_status", "")) for c in candidates}
    keys = {str(c["domain_grouping_key"]) for c in candidates if c.get("domain_grouping_key")}
    reg_keys = {k for k in keys if k.startswith("registrable:")}
    ip_keys = {k for k in keys if k.startswith("ip:")}
    for key in keys:
        if not (key.startswith("registrable:") or key.startswith("ip:")):
            raise ValueError(f"Record {index}: unexpected grouping key {key!r}")
    for c in candidates:
        status = c.get("parser_status")
        key = c.get("domain_grouping_key")
        bare_ip_mention = c.get("evidence_category") == "bare_ip_mention"
        if key and (status not in ACCEPTED or c.get("confidence") != "high"):
            raise ValueError(f"Record {index}: unresolved/non-high-confidence candidate has a grouping key")
        if status in ACCEPTED and c.get("confidence") == "high" and not key:
            raise ValueError(f"Record {index}: accepted hostname/IP candidate lacks its expected key")
        if status in ACCEPTED and not key and not bare_ip_mention:
            raise ValueError(f"Record {index}: unkeyed accepted-status candidate is not a documented ambiguous bare IP mention")
        if c.get("confidence") == "high" and not key and status not in HARD_UNRESOLVED:
            raise ValueError(f"Record {index}: high-confidence candidate without a key has an unsupported status")
        if status == "normalized_hostname" and key:
            domain = c.get("registrable_domain")
            if not domain or key != f"registrable:{domain}":
                raise ValueError(f"Record {index}: registrable-domain key is inconsistent")
        elif status == "ip_literal" and key:
            host = c.get("normalized_hostname")
            if not host or key != f"ip:{host}":
                raise ValueError(f"Record {index}: IP key is inconsistent")
    return {
        "has_confident_destination_key": bool(keys),
        "has_domain_key": bool(reg_keys),
        "has_ip_key": bool(ip_keys),
        "has_ambiguous_candidate": bool(statuses & AMBIGUOUS) or any(c.get("evidence_category") == "bare_ip_mention" for c in candidates),
        "has_ambiguous_bare_domain_mention": "ambiguous_bare_domain_mention" in statuses,
        "has_malformed_candidate": "malformed_url" in statuses,
        "has_invalid_hostname": "invalid_hostname" in statuses,
        "has_invalid_port": "invalid_port" in statuses,
        "has_public_suffix_only_candidate": "public_suffix_only" in statuses,
        "has_unknown_suffix_candidate": "unknown_suffix" in statuses,
        "has_other_unresolved_candidate": bool(
            statuses & {"relative_without_base", "unsupported_scheme", "empty_attribute", "ambiguous_ip_mention"}
            or any(c.get("evidence_category") == "bare_ip_mention" for c in candidates)
        ),
        "has_unresolved_candidate": any(not c.get("domain_grouping_key") for c in candidates),
        "has_hard_unresolved_candidate": bool(statuses & HARD_UNRESOLVED),
        "has_no_detected_candidate": not candidates,
        "_candidate_statuses": statuses,
        "_keys": keys,
    }


def source_record_id(index: int) -> str:
    return f"combined_reduced.json:source_record_{index}"


def load_and_reconstruct(facts: dict[str, Any], summary_rows: dict[str, dict[str, str]]) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, Any]]:
    n = int(facts["source_records"])
    records: list[dict[str, Any] | None] = [None] * (n + 1)
    dsu = DSU(n)
    first_near: dict[str, int] = {}
    first_key: dict[str, int] = {}
    normalized_to_near: dict[str, str] = {}
    near_rows_seen = status_rows_seen = source_rows_seen = 0
    edge_rows_seen = 0
    source_labels: Counter[int] = Counter()
    all_edge_keys: Counter[str] = Counter()
    status_edge_counter: Counter[str] = Counter()
    parser_status_counts: Counter[str] = Counter()
    candidate_record_status_counts: Counter[str] = Counter()
    quarantine_reason_counts: Counter[str] = Counter()
    direct_q_rows = 0

    with (GRAPH / "record_near_duplicate_edges.csv").open("r", encoding="utf-8", newline="") as ns, \
         (GRAPH / "record_domain_status.csv").open("r", encoding="utf-8", newline="") as ss, \
         (GRAPH / "record_domain_edges.csv").open("r", encoding="utf-8", newline="") as es:
        near_it = iter(csv.DictReader(ns))
        status_it = iter(csv.DictReader(ss))
        edge_it = iter(csv.DictReader(es))
        next_edge = next(edge_it, None)

        for index, raw in enumerate(iter_json_array(SOURCE), start=1):
            source_rows_seen += 1
            if index > n:
                raise ValueError("Raw source has more records than graph invariants")
            if set(raw) != {"label", "text"}:
                raise ValueError(f"Raw source schema differs at index {index}")
            text, label = raw["text"], raw["label"]
            if not isinstance(text, str) or label not in (0, 1):
                raise ValueError(f"Invalid source text or label at index {index}")
            source_labels[int(label)] += 1

            near = next(near_it, None)
            status = next(status_it, None)
            if near is None or status is None:
                raise ValueError(f"Missing graph lineage at source record {index}")
            near_rows_seen += 1
            status_rows_seen += 1
            sid = source_record_id(index)
            for row, name in ((near, "near-duplicate"), (status, "domain-status")):
                if int(row["source_record_index"]) != index or row["source_record_id"] != sid:
                    raise ValueError(f"{name} lineage is missing, duplicated, or out of order at index {index}")
                if int(row["label_original"]) != int(label):
                    raise ValueError(f"{name} label differs from raw source at index {index}")
            for field in ("normalized_text_group_id", "near_duplicate_component_id"):
                if near[field] != status[field]:
                    raise ValueError(f"Text grouping lineage mismatch at index {index}: {field}")
            near_id = near["near_duplicate_component_id"]
            norm_id = near["normalized_text_group_id"]
            if near_id:
                first = first_near.setdefault(near_id, index)
                dsu.union(first, index)
                previous = normalized_to_near.setdefault(norm_id, near_id)
                if norm_id and previous != near_id:
                    raise ValueError("One exact normalized-text group maps to multiple near components")
            elif norm_id:
                raise ValueError(f"Record {index} has normalized-text ID without near component")

            candidates = json.loads(status["candidate_status_json"] or "[]")
            if len(candidates) != int(status["candidate_count"]):
                raise ValueError(f"Candidate count differs from serialized status at index {index}")
            candidate_edge_keys: Counter[tuple[Any, ...]] = Counter()
            for c in candidates:
                parser_status = str(c.get("parser_status", ""))
                parser_status_counts[parser_status] += 1
                start, end = int(c["start"]), int(c["end"])
                if start < 0 or end < start or end > len(text) or text[start:end] != c.get("candidate_text"):
                    raise ValueError(f"Candidate source offsets fail for source record {index}")
                key = c.get("domain_grouping_key")
                if key:
                    candidate_edge_keys[(start, end, c["candidate_text"], c["extraction_method"],
                                         c["evidence_category"], c.get("normalized_hostname") or "",
                                         c.get("registrable_domain") or "", key)] += 1
            flags = candidate_flags(candidates, index)
            for flag in list(flags):
                if flag.startswith("_"):
                    continue
                candidate_record_status_counts[flag] += int(flags[flag])
            # Preserve the exact V2 graph's stored record-status flags.
            expected_status_flags = {
                "has_confident_domain_key": flags["has_domain_key"],
                "has_confident_ip_key": flags["has_ip_key"],
                "has_ambiguous_bare_domain_mention": flags["has_ambiguous_bare_domain_mention"],
                "has_malformed_url_candidate": bool(flags["has_malformed_candidate"] or flags["has_invalid_hostname"] or flags["has_invalid_port"] or "html_parse_error" in flags["_candidate_statuses"]),
                "has_public_suffix_only_candidate": flags["has_public_suffix_only_candidate"],
                "has_unknown_suffix_candidate": flags["has_unknown_suffix_candidate"],
                "has_no_detected_candidate": flags["has_no_detected_candidate"],
            }
            for field, expected_value in expected_status_flags.items():
                if bool_field(status[field], field, "domain status", index) != expected_value:
                    raise ValueError(f"Saved {field} disagrees with parsed candidate lineage at index {index}")
            # "Other unresolved" in the graph builder intentionally covers
            # non-hard conditions such as relative links/unsupported schemes.
            if bool_field(status["has_other_unresolved_candidate"], "has_other_unresolved_candidate", "domain status", index) != flags["has_other_unresolved_candidate"]:
                raise ValueError(f"Saved other-unresolved flag disagrees at index {index}")

            keys = set(flags["_keys"])
            status_keys = Counter(candidate_edge_keys)
            while next_edge is not None and int(next_edge["source_record_index"]) < index:
                raise ValueError("A domain edge is out of order or has no source record")
            while next_edge is not None and int(next_edge["source_record_index"]) == index:
                edge_rows_seen += 1
                if next_edge["source_record_id"] != sid or int(next_edge["label_original"]) != int(label):
                    raise ValueError(f"Domain edge source identity/label mismatch at index {index}")
                for field in ("normalized_text_group_id", "near_duplicate_component_id"):
                    if next_edge[field] != near[field]:
                        raise ValueError(f"Domain edge {field} mismatch at index {index}")
                start, end = int(next_edge["start"]), int(next_edge["end"])
                if start < 0 or end < start or end > len(text) or text[start:end] != next_edge["candidate_text"]:
                    raise ValueError(f"Domain edge source offsets fail at index {index}")
                key = next_edge["domain_grouping_key"]
                if key.startswith("registrable:"):
                    if next_edge["confidence"] != "high" or not next_edge["registrable_domain"] or key != f"registrable:{next_edge['registrable_domain']}":
                        raise ValueError(f"Non-accepted registrable key in edge file at record {index}")
                elif key.startswith("ip:"):
                    if next_edge["confidence"] != "high" or key != f"ip:{next_edge['normalized_hostname']}":
                        raise ValueError(f"Non-accepted IP key in edge file at record {index}")
                else:
                    raise ValueError(f"Unexpected V2 grouping key {key!r}")
                edge_tuple = (start, end, next_edge["candidate_text"], next_edge["extraction_method"],
                              next_edge["evidence_category"], next_edge["normalized_hostname"],
                              next_edge["registrable_domain"], key)
                status_keys[edge_tuple] -= 1
                if status_keys[edge_tuple] < 0:
                    raise ValueError(f"Domain edge has no accepted candidate lineage at record {index}")
                all_edge_keys[key] += 1
                owner = first_key.setdefault(key, index)
                dsu.union(owner, index)
                next_edge = next(edge_it, None)
            if any(count for count in status_keys.values()):
                raise ValueError(f"Accepted V2 candidate is missing from edge file at source record {index}")

            raw_normalized = re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text).lower()).strip()
            eligible = bool(raw_normalized)
            q_reason = near["quarantine_reason"] if bool_field(near["near_component_quarantined"], "near_component_quarantined", "near lineage", index) else ""
            if q_reason:
                quarantine_reason_counts.update(x for x in q_reason.split(";") if x)
            direct_q_rows += bool(q_reason)
            if eligible != bool(raw_normalized):
                raise AssertionError("Normalization eligibility mismatch")
            records[index] = {
                "source_record_id": sid, "source_record_index": index, "label": int(label),
                "normalized_text_group_id": norm_id, "near_duplicate_component_id": near_id,
                "model_eligible": eligible, "quarantine_reason": q_reason,
                "promotional_review_flag": bool_field(status["promotional_review_flag"], "promotional_review_flag", "domain status", index),
                **{k: v for k, v in flags.items() if not k.startswith("_")},
                "domain_keys": keys,
            }

        if next(near_it, None) is not None or next(status_it, None) is not None or next_edge is not None:
            raise ValueError("Graph lineage contains records/edges beyond the raw source")

    if source_rows_seen != n or near_rows_seen != n or status_rows_seen != n:
        raise ValueError("Source, text-lineage, or domain-status row count does not equal graph invariant")
    if edge_rows_seen != int(facts["record_domain_edge_rows"]):
        raise ValueError("Validated edge count differs from saved graph invariant")
    if dict(sorted((str(k), v) for k, v in source_labels.items())) != facts["source_label_counts"]:
        raise ValueError("Raw source label counts differ from saved graph invariant")
    if len(first_key) != int(facts["unique_domain_keys"]):
        raise ValueError("Distinct accepted key count differs from graph invariant")

    # Rebuild every component, then compare membership aggregates and stable IDs
    # against the saved graph summary before any assignment is attempted.
    by_root: dict[int, list[int]] = defaultdict(list)
    for index in range(1, n + 1):
        by_root[dsu.find(index)].append(index)
    reconstructed: dict[str, dict[str, Any]] = {}
    index_to_component: list[str] = [""] * (n + 1)
    for members in by_root.values():
        cid = stable_component_id(min(members))
        keyset = set().union(*(records[i]["domain_keys"] for i in members))  # type: ignore[index]
        nearset = {records[i]["near_duplicate_component_id"] for i in members if records[i]["near_duplicate_component_id"]}  # type: ignore[index]
        normset = {records[i]["normalized_text_group_id"] for i in members if records[i]["normalized_text_group_id"]}  # type: ignore[index]
        labels = Counter(int(records[i]["label"]) for i in members)  # type: ignore[index]
        q_members = [i for i in members if records[i]["quarantine_reason"]]  # type: ignore[index]
        q_reasons = sorted({reason for i in members for reason in records[i]["quarantine_reason"].split(";") if reason})  # type: ignore[index]
        aggregate = {
            "component_id": cid, "records": len(members), "unique_normalized_text_groups": len(normset),
            "near_duplicate_components": len(nearset),
            "registrable_domain_keys": len({k for k in keyset if k.startswith("registrable:")}),
            "ip_keys": len({k for k in keyset if k.startswith("ip:")}),
            "distinct_destination_grouping_keys": len(keyset),
            "label_0_records": labels[0], "label_1_records": labels[1],
            "contains_multiple_labels": len(labels) > 1,
            "quarantined_records": len(q_members), "has_quarantined_group": bool(q_members),
            "promotional_review_records": sum(bool(records[i]["promotional_review_flag"]) for i in members),  # type: ignore[index]
            "records_without_confident_destination_key": sum(not records[i]["has_confident_destination_key"] for i in members),  # type: ignore[index]
            "hard_unresolved_records": sum(bool(records[i]["has_hard_unresolved_candidate"]) for i in members),  # type: ignore[index]
            "ambiguous_candidate_records": sum(bool(records[i]["has_ambiguous_candidate"]) for i in members),  # type: ignore[index]
            "model_eligible_records": sum(bool(records[i]["model_eligible"]) for i in members),  # type: ignore[index]
            "members": members, "keys": keyset, "near_ids": nearset, "norm_ids": normset,
            "labels": labels, "quarantine_reasons": q_reasons,
        }
        reconstructed[cid] = aggregate
        for i in members:
            index_to_component[i] = cid

    if len(reconstructed) != int(facts["combined_graph"]["components"]):
        raise ValueError("Reconstructed combined component count differs from saved invariant")
    if set(reconstructed) != set(summary_rows):
        raise ValueError("Reconstructed component IDs do not match saved summary")
    compare_fields = (
        "records", "unique_normalized_text_groups", "near_duplicate_components", "registrable_domain_keys",
        "ip_keys", "distinct_destination_grouping_keys", "label_0_records", "label_1_records",
        "contains_multiple_labels", "quarantined_records", "has_quarantined_group",
        "promotional_review_records", "records_without_confident_destination_key",
    )
    for cid, calc in reconstructed.items():
        saved = summary_rows[cid]
        for field in compare_fields:
            value = calc[field]
            if isinstance(value, bool):
                same = bool_field(saved[field], field, "component summary", 0) == value
            else:
                same = int(saved[field]) == int(value)
            if not same:
                raise ValueError(f"Component aggregate mismatch for {cid}: {field} (saved={saved[field]}, rebuilt={value})")

    # Record-level expected flags should agree with the saved V2 status table,
    # and the known empty row must be the only model-ineligible source record.
    ineligible = [i for i in range(1, n + 1) if not records[i]["model_eligible"]]  # type: ignore[index]
    if ineligible != [31230]:
        raise ValueError(f"Unexpected model-ineligible raw records: {ineligible[:10]}")
    return [r for r in records[1:] if r is not None], reconstructed, {
        "source_rows": source_rows_seen, "near_duplicate_rows": near_rows_seen,
        "status_rows": status_rows_seen, "domain_edge_rows": edge_rows_seen,
        "source_label_counts": {str(k): v for k, v in sorted(source_labels.items())},
        "distinct_keys": len(first_key), "parser_status_occurrences": dict(sorted(parser_status_counts.items())),
        "records_with_candidate_status": dict(sorted(candidate_record_status_counts.items())),
        "quarantine_reason_occurrences": dict(sorted(quarantine_reason_counts.items())),
        "direct_quarantined_records": direct_q_rows,
    }


def classify_components(records: list[dict[str, Any]], components: dict[str, dict[str, Any]]) -> dict[str, Any]:
    for comp in components.values():
        members = comp["members"]
        model_members = [records[i - 1] for i in members if records[i - 1]["model_eligible"]]
        has_keys = bool(comp["keys"])
        hard = bool(comp["hard_unresolved_records"])
        q = bool(comp["quarantined_records"])
        if not model_members:
            cohort, partition, reason = "excluded_empty_text", "excluded_empty_text", "normalized model input is empty"
        elif q:
            cohort, partition = "quarantined_data_quality", "quarantined_data_quality"
            reason = ";".join(comp["quarantine_reasons"])
        elif hard:
            cohort, partition = "uncertain_destination_cohort", "uncertain_destination_cohort"
            reason = "component contains malformed, invalid, public-suffix-only, or unknown-suffix destination candidate"
        elif has_keys:
            cohort, partition, reason = "primary_destination_cohort", "", "eligible destination-bearing combined component"
        else:
            cohort, partition, reason = "no_destination_cohort", "no_destination_cohort", "component has no accepted destination key; ambiguous bare mentions are not destinations"
        comp.update({"cohort": cohort, "partition": partition, "eligibility_reason": reason})
    return components


def split_score(partition_counts: dict[str, Counter[int]], partition_sizes: Counter[str],
                target_counts: dict[str, float], target_label_counts: dict[str, dict[int, float]]) -> float:
    score = 0.0
    for name in TARGETS:
        target_n = max(target_counts[name], 1.0)
        score += 2.0 * ((partition_sizes[name] - target_counts[name]) / target_n) ** 2
        for label in (0, 1):
            target = max(target_label_counts[name][label], 1.0)
            score += ((partition_counts[name][label] - target_label_counts[name][label]) / target) ** 2
    return score


def allocate_components(components: dict[str, dict[str, Any]]) -> dict[str, Any]:
    primary = [c for c in components.values() if c["cohort"] == "primary_destination_cohort"]
    total = sum(c["model_eligible_records"] for c in primary)
    if total <= 0:
        raise RuntimeError("Conservative eligibility leaves no primary destination-bearing records; stopping before output")
    labels = Counter()
    for comp in primary:
        labels[0] += comp["label_0_records"]
        labels[1] += comp["label_1_records"]
    if min(labels.values(), default=0) == 0:
        raise RuntimeError(f"Conservative primary cohort lacks one original class: {dict(labels)}; stopping before output")
    targets = {p: total * frac for p, frac in TARGETS.items()}
    target_label_counts = {p: {lab: labels[lab] * frac for lab in (0, 1)} for p, frac in TARGETS.items()}
    rng = random.Random(SEED)
    # Stable random tie keys; all choices remain reproducible with the fixed seed.
    tie = {c["component_id"]: rng.random() for c in primary}
    primary.sort(key=lambda c: (-c["model_eligible_records"], tie[c["component_id"]], c["component_id"]))
    largest = primary[0]
    for p in TARGETS:
        largest["partition"] = p
        largest["eligibility_reason"] = "eligible destination-bearing combined component; largest group assigned to training"
        # Keep the explicitly largest component in train, as requested.
        if p == "train":
            break
    sizes: Counter[str] = Counter()
    part_labels: dict[str, Counter[int]] = {p: Counter() for p in TARGETS}
    sizes["train"] += largest["model_eligible_records"]
    part_labels["train"][0] += largest["label_0_records"]
    part_labels["train"][1] += largest["label_1_records"]
    remaining = primary[1:]
    for comp in remaining:
        options: list[tuple[float, str]] = []
        for partition in TARGETS:
            sizes[partition] += comp["model_eligible_records"]
            part_labels[partition][0] += comp["label_0_records"]
            part_labels[partition][1] += comp["label_1_records"]
            value = split_score(part_labels, sizes, targets, target_label_counts)
            sizes[partition] -= comp["model_eligible_records"]
            part_labels[partition][0] -= comp["label_0_records"]
            part_labels[partition][1] -= comp["label_1_records"]
            options.append((value, partition))
        # Use deterministic fixed partition order to resolve equal objective values.
        _, chosen = min(options, key=lambda x: (x[0], list(TARGETS).index(x[1])))
        comp["partition"] = chosen
        comp["eligibility_reason"] = "eligible destination-bearing combined component"
        sizes[chosen] += comp["model_eligible_records"]
        part_labels[chosen][0] += comp["label_0_records"]
        part_labels[chosen][1] += comp["label_1_records"]

    if any(not any(c["partition"] == p for c in primary) for p in TARGETS):
        raise RuntimeError("Group allocator failed to populate all requested partitions; stopping before output")
    empty_class_partitions = [p for p in TARGETS if not part_labels[p][0] or not part_labels[p][1]]
    return {
        "primary_records": total, "primary_label_counts": {str(k): v for k, v in sorted(labels.items())},
        "target_record_counts": targets,
        "target_label_counts": {p: {str(k): v for k, v in target_label_counts[p].items()} for p in TARGETS},
        "actual_record_counts": dict(sizes),
        "actual_label_counts": {p: {str(k): part_labels[p][k] for k in (0, 1)} for p in TARGETS},
        "largest_component_id": largest["component_id"],
        "largest_component_records": largest["model_eligible_records"],
        "partitions_missing_a_class": empty_class_partitions,
        "objective": "Seeded largest-first component allocation minimizing weighted squared deviations in record and label counts; largest component fixed to train; no row-level moves.",
    }


def finalize_component_partition(components: dict[str, dict[str, Any]], allocation: dict[str, Any]) -> None:
    # Assert target allocator counts agree with component assignment.
    primary = [c for c in components.values() if c["cohort"] == "primary_destination_cohort"]
    for c in primary:
        if c.get("partition") not in TARGETS:
            raise AssertionError(f"Primary component left unassigned: {c['component_id']}")
    for c in components.values():
        if c["cohort"] != "primary_destination_cohort" and c["partition"] not in {
            "no_destination_cohort", "uncertain_destination_cohort", "excluded_empty_text", "quarantined_data_quality"
        }:
            raise AssertionError(f"Non-primary component entered primary split: {c['component_id']}")


def record_partition_rows(records: list[dict[str, Any]], components: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    comp_by_min = components
    # IDs encode the minimum source index; use member ownership for exact lookup.
    index_to_comp: dict[int, dict[str, Any]] = {}
    for comp in comp_by_min.values():
        for i in comp["members"]:
            index_to_comp[i] = comp
    output: list[dict[str, Any]] = []
    for record in records:
        comp = index_to_comp[record["source_record_index"]]
        is_primary_partition = comp["partition"] in TARGETS
        domain_eval = bool(record["model_eligible"] and record["has_confident_destination_key"]
                           and comp["cohort"] == "primary_destination_cohort" and is_primary_partition)
        output.append({
            "source_record_id": record["source_record_id"],
            "source_record_index": record["source_record_index"],
            "label": record["label"], "partition": comp["partition"],
            "component_id": comp["component_id"],
            "normalized_text_group_id": record["normalized_text_group_id"],
            "near_duplicate_component_id": record["near_duplicate_component_id"],
            "model_eligible": record["model_eligible"],
            "has_confident_destination_key": record["has_confident_destination_key"],
            "has_domain_key": record["has_domain_key"], "has_ip_key": record["has_ip_key"],
            "has_ambiguous_candidate": record["has_ambiguous_candidate"],
            "has_ambiguous_bare_domain_mention": record["has_ambiguous_bare_domain_mention"],
            "has_malformed_candidate": record["has_malformed_candidate"],
            "has_invalid_hostname": record["has_invalid_hostname"],
            "has_invalid_port": record["has_invalid_port"],
            "has_public_suffix_only_candidate": record["has_public_suffix_only_candidate"],
            "has_unknown_suffix_candidate": record["has_unknown_suffix_candidate"],
            "has_other_unresolved_candidate": record["has_other_unresolved_candidate"],
            "has_unresolved_candidate": record["has_unresolved_candidate"],
            "has_hard_unresolved_candidate": record["has_hard_unresolved_candidate"],
            "has_no_detected_candidate": record["has_no_detected_candidate"],
            "domain_evaluation_eligible": domain_eval,
            "has_unresolved_candidate_in_component": bool(comp["hard_unresolved_records"]),
            "is_quarantined_component": bool(comp["quarantined_records"]),
            "quarantine_reason": ";".join(comp["quarantine_reasons"]),
            "eligibility_reason": comp["eligibility_reason"],
        })
    return output


def summarize(records: list[dict[str, Any]], comps: dict[str, dict[str, Any]], rows: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    by_index = {r["source_record_index"]: r for r in rows}
    partitions = list(TARGETS) + ["no_destination_cohort", "uncertain_destination_cohort", "excluded_empty_text", "quarantined_data_quality"]
    stats: dict[str, Any] = {}
    for part in partitions:
        subset = [r for r in rows if r["partition"] == part]
        indexes = {r["source_record_index"] for r in subset}
        cids = {r["component_id"] for r in subset}
        comp_subset = [comps[c] for c in cids]
        label_counts = Counter(str(r["label"]) for r in subset)
        key_set = set().union(*(comps[c]["keys"] for c in cids)) if cids else set()
        stats[part] = {
            "record_count": len(subset),
            "proportion_of_primary_cohort": (len(subset) / sum(c["model_eligible_records"] for c in comps.values() if c["cohort"] == "primary_destination_cohort")) if part in TARGETS else None,
            "label_counts": {str(k): label_counts.get(str(k), 0) for k in (0, 1)},
            "destination_bearing_record_count": sum(r["has_confident_destination_key"] for r in subset),
            "non_destination_bearing_record_count": sum(not r["has_confident_destination_key"] for r in subset),
            "domain_evaluation_eligible_record_count": sum(r["domain_evaluation_eligible"] for r in subset),
            "unique_registrable_domain_key_count": sum(k.startswith("registrable:") for k in key_set),
            "unique_ip_key_count": sum(k.startswith("ip:") for k in key_set),
            "component_count": len(cids),
            "largest_component_record_count": max((comps[c]["model_eligible_records"] for c in cids), default=0),
            "mixed_label_component_count": sum(comps[c]["label_0_records"] > 0 and comps[c]["label_1_records"] > 0 for c in cids),
            "quarantined_record_count": sum(r["is_quarantined_component"] for r in subset),
            "hard_unresolved_record_count": sum(r["has_hard_unresolved_candidate"] for r in subset),
        }
    primary_total = sum(stats[p]["record_count"] for p in TARGETS)
    target_deviation = {p: stats[p]["record_count"] / primary_total - TARGETS[p] for p in TARGETS}
    status_flags = [
        "has_confident_destination_key", "has_domain_key", "has_ip_key", "has_ambiguous_candidate",
        "has_ambiguous_bare_domain_mention", "has_malformed_candidate", "has_invalid_hostname",
        "has_invalid_port", "has_public_suffix_only_candidate", "has_unknown_suffix_candidate",
        "has_other_unresolved_candidate", "has_unresolved_candidate", "has_hard_unresolved_candidate",
        "has_no_detected_candidate", "model_eligible",
    ]
    record_flag_counts = {flag: sum(bool(r[flag]) for r in records) for flag in status_flags}
    cohort_stats: dict[str, Any] = {}
    for cohort in ("primary_destination_cohort", "no_destination_cohort", "uncertain_destination_cohort", "excluded_empty_text", "quarantined_data_quality"):
        cohort_comps = [c for c in comps.values() if c["cohort"] == cohort]
        member_records = [records[i - 1] for c in cohort_comps for i in c["members"]]
        lc = Counter(r["label"] for r in member_records)
        cohort_stats[cohort] = {
            "component_count": len(cohort_comps), "record_count": len(member_records),
            "model_eligible_record_count": sum(r["model_eligible"] for r in member_records),
            "label_counts": {str(x): lc[x] for x in (0, 1)},
            "destination_bearing_records": sum(r["has_confident_destination_key"] for r in member_records),
            "non_destination_bearing_records": sum(not r["has_confident_destination_key"] for r in member_records),
            "components_with_any_hard_unresolved": sum(bool(c["hard_unresolved_records"]) for c in cohort_comps),
            "components_with_any_ambiguous_candidate": sum(bool(c["ambiguous_candidate_records"]) for c in cohort_comps),
            "components_with_mixed_labels": sum(c["label_0_records"] > 0 and c["label_1_records"] > 0 for c in cohort_comps),
        }
    all_components = list(comps.values())
    text_label_conflict_near_ids = {r["near_duplicate_component_id"] for r in records if QUARANTINE_LABEL in r["quarantine_reason"].split(";")}
    promo_near_ids = {r["near_duplicate_component_id"] for r in records if QUARANTINE_PROMO in r["quarantine_reason"].split(";")}
    eligibility = {
        "source_records": len(records), "source_label_counts": dict(Counter(str(r["label"]) for r in records)),
        "record_level_flags_are_overlapping": True, "record_level_flag_counts": record_flag_counts,
        "candidate_parser_status_occurrences": {},
        "exclusive_component_cohort_counts": {
            cohort: {"components": cohort_stats[cohort]["component_count"], "records": cohort_stats[cohort]["record_count"]}
            for cohort in cohort_stats
        },
        "cohorts": cohort_stats,
        "quarantine": {
            "policy": "A combined component is quarantined if any member's exact/near text component was quarantined under the existing baseline promotional-review or conflicting-label policy; the whole combined component remains indivisible and outside the primary split.",
            "combined_components_quarantined": cohort_stats["quarantined_data_quality"]["component_count"],
            "records_in_quarantined_components": cohort_stats["quarantined_data_quality"]["record_count"],
            "text_components_with_conflicting_original_labels": len(text_label_conflict_near_ids),
            "text_components_with_promotional_review": len(promo_near_ids),
            "broad_mixed_label_domain_components": sum(c["label_0_records"] > 0 and c["label_1_records"] > 0 for c in all_components),
            "note": "Broad mixed-label components caused by shared domains are retained as indivisible groups; mixed labels alone are not a text-label quarantine reason.",
        },
        "hard_unresolved_policy": {
            "statuses": sorted(HARD_UNRESOLVED),
            "treatment": "Any combined component containing at least one model-eligible record with a hard unresolved destination candidate is assigned wholly to uncertain_destination_cohort, unless the component is already assigned to the separate data-quality quarantine cohort.",
            "ambiguous_statuses": sorted(AMBIGUOUS),
            "ambiguous_treatment": "Bare domain/IP mentions without explicit destination syntax do not create keys and do not alone make a component uncertain.",
        },
        "record_31230": {
            "source_record_id": source_record_id(31230), "label": records[31230 - 1]["label"],
            "model_eligible": records[31230 - 1]["model_eligible"],
            "partition": by_index[31230]["partition"],
            "normalization": "NFKC, lowercase, collapsed whitespace, strip; empty output is ineligible",
        },
        "no_confident_key_component_membership": "An unkeyed record connected to a keyed record by the saved exact/near-text component follows the same combined component and partition; it is not domain_evaluation_eligible.",
    }
    summary = {
        "source_records": len(records), "source_label_counts": dict(Counter(str(r["label"]) for r in records)),
        "graph_components": len(comps), "component_size_distribution": {
            "median_nearest_rank": nearest_rank([len(c["members"]) for c in comps.values()], .50),
            "p90_nearest_rank": nearest_rank([len(c["members"]) for c in comps.values()], .90),
            "p95_nearest_rank": nearest_rank([len(c["members"]) for c in comps.values()], .95),
            "p99_nearest_rank": nearest_rank([len(c["members"]) for c in comps.values()], .99),
            "maximum": max((len(c["members"]) for c in comps.values()), default=0),
        },
        "primary_target_proportions": TARGETS, "primary_cohort_record_count": primary_total,
        "target_deviation_percentage_points": {p: round(target_deviation[p] * 100, 4) for p in TARGETS},
        "partitions": stats, "cohorts": cohort_stats,
        "allocation": {"seed": SEED, "largest_primary_component_forced_to_train": True,
                       "largest_primary_component_id": next((c["component_id"] for c in comps.values() if c["cohort"] == "primary_destination_cohort" and c.get("eligibility_reason", "").endswith("largest group assigned to training")), None)},
        "mixed_label_components_total": sum(c["label_0_records"] > 0 and c["label_1_records"] > 0 for c in comps.values()),
        "label_conflict_text_component_count": len(text_label_conflict_near_ids),
        "domain_keys_per_partition": {p: {"registrable": stats[p]["unique_registrable_domain_key_count"], "ip": stats[p]["unique_ip_key_count"]} for p in partitions},
    }
    return summary, eligibility


def validate_manifest(rows: list[dict[str, Any]], records: list[dict[str, Any]],
                      comps: dict[str, dict[str, Any]]) -> dict[str, Any]:
    n = len(records)
    violations: dict[str, int] = {}
    ids = [r["source_record_id"] for r in rows]
    indices = [r["source_record_index"] for r in rows]
    violations["duplicate_source_record_ids"] = len(ids) - len(set(ids))
    violations["duplicate_source_record_indices"] = len(indices) - len(set(indices))
    violations["missing_or_extra_source_record_indices"] = len(set(indices) ^ set(range(1, n + 1)))
    if len(rows) != n:
        violations["manifest_record_count_mismatch"] = abs(len(rows) - n)
    else:
        violations["manifest_record_count_mismatch"] = 0
    comp_partitions: dict[str, set[str]] = defaultdict(set)
    near_partitions: dict[str, set[str]] = defaultdict(set)
    norm_partitions: dict[str, set[str]] = defaultdict(set)
    domain_partitions: dict[str, set[str]] = defaultdict(set)
    ip_partitions: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        comp_partitions[row["component_id"]].add(row["partition"])
        if row["near_duplicate_component_id"]:
            near_partitions[row["near_duplicate_component_id"]].add(row["partition"])
        if row["normalized_text_group_id"]:
            norm_partitions[row["normalized_text_group_id"]].add(row["partition"])
    index_partition = {r["source_record_index"]: r["partition"] for r in rows}
    for c in comps.values():
        parts = {index_partition[i] for i in c["members"]}
        if len(parts) == 1:
            part = next(iter(parts))
            for key in c["keys"]:
                (ip_partitions if key.startswith("ip:") else domain_partitions)[key].add(part)
    primary = set(TARGETS)
    violations["combined_component_cross_partition"] = sum(len(x) > 1 for x in comp_partitions.values())
    violations["registrable_domain_cross_primary_partitions"] = sum(len(x & primary) > 1 for x in domain_partitions.values())
    violations["ip_key_cross_primary_partitions"] = sum(len(x & primary) > 1 for x in ip_partitions.values())
    violations["near_duplicate_component_cross_partition"] = sum(len(x) > 1 for x in near_partitions.values())
    violations["normalized_text_group_cross_partition"] = sum(len(x) > 1 for x in norm_partitions.values())
    violations["primary_partition_non_primary_cohort_records"] = sum(
        row["partition"] in primary and row["component_id"] not in comps or
        row["partition"] in primary and comps[row["component_id"]]["cohort"] != "primary_destination_cohort"
        for row in rows
    )
    violations["no_destination_or_uncertain_component_in_primary"] = sum(
        row["partition"] in primary and comps[row["component_id"]]["cohort"] in {"no_destination_cohort", "uncertain_destination_cohort"}
        for row in rows
    )
    violations["quarantined_component_in_primary"] = sum(
        row["partition"] in primary and comps[row["component_id"]]["cohort"] == "quarantined_data_quality"
        for row in rows
    )
    violations["empty_text_in_primary"] = sum(not row["model_eligible"] and row["partition"] in primary for row in rows)
    violations["domainless_keyed_component_members_partition_mismatch"] = sum(
        len({index_partition[i] for i in c["members"]}) != 1 for c in comps.values()
    )
    key_partition: dict[str, set[str]] = defaultdict(set)
    for cid, comp in comps.items():
        parts = comp_partitions[cid]
        for key in comp["keys"]:
            key_partition[key].update(parts)
    violations["multi_domain_cross_partition_records"] = 0
    for rec in records:
        partitions_for_record = set().union(*(key_partition[key] for key in rec["domain_keys"])) if rec["domain_keys"] else set()
        if len(partitions_for_record) > 1:
            violations["multi_domain_cross_partition_records"] += 1
    index_to_component = {i: cid for cid, comp in comps.items() for i in comp["members"]}
    violations["manifest_component_id_mismatch"] = sum(
        row["component_id"] != index_to_component.get(row["source_record_index"])
        for row in rows
    )
    counts = {
        "source_record_rows": len(rows), "unique_record_ids": len(set(ids)),
        "unique_record_indices": len(set(indices)), "combined_components_checked": len(comps),
        "registrable_keys_checked": len(domain_partitions), "ip_keys_checked": len(ip_partitions),
        "near_duplicate_groups_checked": len(near_partitions), "normalized_text_groups_checked": len(norm_partitions),
        "violations": violations,
        "all_checks_passed": not any(violations.values()),
    }
    return counts


def reread_manifest(path: Path, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Read the persisted manifest afresh and verify source-level identity."""
    expected = {r["source_record_index"]: r for r in records}
    boolean_fields = {
        "model_eligible", "has_confident_destination_key", "has_domain_key", "has_ip_key",
        "has_ambiguous_candidate", "has_ambiguous_bare_domain_mention", "has_malformed_candidate",
        "has_invalid_hostname", "has_invalid_port", "has_public_suffix_only_candidate",
        "has_unknown_suffix_candidate", "has_other_unresolved_candidate", "has_unresolved_candidate",
        "has_hard_unresolved_candidate", "has_no_detected_candidate", "domain_evaluation_eligible",
        "has_unresolved_candidate_in_component", "is_quarantined_component",
    }
    output: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        required = {"source_record_id", "source_record_index", "label", "partition", "component_id",
                    "model_eligible", "has_confident_destination_key", "has_domain_key", "has_ip_key",
                    "domain_evaluation_eligible", "has_unresolved_candidate", "eligibility_reason",
                    "normalized_text_group_id", "near_duplicate_component_id"}
        if not required.issubset(set(reader.fieldnames or [])):
            raise ValueError("Saved manifest is missing required fields")
        for row in reader:
            index = int(row["source_record_index"])
            for field in boolean_fields:
                row[field] = bool_field(row[field], field, "saved split manifest", index)
            row["source_record_index"] = index
            row["label"] = int(row["label"])
            if index not in expected:
                raise ValueError(f"Saved manifest contains unexpected source record {index}")
            source = expected[index]
            for field, expected_value in (
                ("source_record_id", source["source_record_id"]),
                ("label", source["label"]),
                ("normalized_text_group_id", source["normalized_text_group_id"]),
                ("near_duplicate_component_id", source["near_duplicate_component_id"]),
                ("model_eligible", source["model_eligible"]),
                ("has_confident_destination_key", source["has_confident_destination_key"]),
                ("has_domain_key", source["has_domain_key"]),
                ("has_ip_key", source["has_ip_key"]),
                ("has_unresolved_candidate", source["has_unresolved_candidate"]),
            ):
                if row[field] != expected_value:
                    raise ValueError(f"Saved manifest {field} differs from source lineage for index {index}")
            allowed_partitions = set(TARGETS) | {"no_destination_cohort", "uncertain_destination_cohort", "excluded_empty_text", "quarantined_data_quality"}
            if row["partition"] not in allowed_partitions:
                raise ValueError(f"Unexpected partition value in saved manifest: {row['partition']!r}")
            output.append(row)
    return output


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_outputs(records: list[dict[str, Any]], comps: dict[str, dict[str, Any]],
                  record_rows: list[dict[str, Any]], recon: dict[str, Any],
                  summary: dict[str, Any], eligibility: dict[str, Any],
                  allocation: dict[str, Any], facts: dict[str, Any],
                  invariants: dict[str, Any]) -> None:
    if OUTPUT.exists():
        raise FileExistsError(f"Refusing to overwrite existing output directory: {OUTPUT}")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(tempfile.mkdtemp(prefix=".domain_holdout_split_v2_", dir=OUTPUT.parent))
    try:
        manifest_fields = list(record_rows[0])
        write_csv(temp / "split_manifest.csv", record_rows, manifest_fields)
        component_rows: list[dict[str, Any]] = []
        for cid, c in sorted(comps.items(), key=lambda kv: min(kv[1]["members"])):
            component_rows.append({
                "component_id": cid, "partition": c["partition"], "cohort": c["cohort"],
                "eligibility_reason": c["eligibility_reason"], "source_record_count": len(c["members"]),
                "model_eligible_record_count": c["model_eligible_records"],
                "label_0_record_count": c["label_0_records"], "label_1_record_count": c["label_1_records"],
                "mixed_label_component": c["label_0_records"] > 0 and c["label_1_records"] > 0,
                "destination_bearing_record_count": len([i for i in c["members"] if records[i - 1]["has_confident_destination_key"]]),
                "non_destination_bearing_record_count": len([i for i in c["members"] if not records[i - 1]["has_confident_destination_key"]]),
                "registrable_domain_key_count": len([k for k in c["keys"] if k.startswith("registrable:")]),
                "ip_key_count": len([k for k in c["keys"] if k.startswith("ip:")]),
                "has_hard_unresolved_candidate": bool(c["hard_unresolved_records"]),
                "hard_unresolved_record_count": c["hard_unresolved_records"],
                "ambiguous_candidate_record_count": c["ambiguous_candidate_records"],
                "quarantined_record_count": c["quarantined_records"],
                "quarantine_reasons": ";".join(c["quarantine_reasons"]),
            })
        write_csv(temp / "component_assignments.csv", component_rows, list(component_rows[0]))

        config = {
            "experiment": "phishing_text_domain_holdout_v2_split_only",
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "random_seed": SEED, "target_proportions": TARGETS,
            "allocation_algorithm": allocation["objective"],
            "allocation_uses_row_level_splitting": False,
            "largest_primary_component_forced_to_train": True,
            "primary_policy": "Scenario A/D: all accepted V2 registrable-domain and IP keys plus saved exact/near-duplicate components",
            "secondary_sensitivity_scenarios": ["B_exclude_identity_metadata", "C_user_action_destinations"],
            "source_file": str(SOURCE.relative_to(ROOT)), "source_sha256": facts["raw_source_sha256"],
            "extractor_sha256": facts["extractor_sha256"],
            "graph_directory": str(GRAPH.relative_to(ROOT)),
            "graph_invariants_sha256": sha256_file(GRAPH / "combined_graph_invariants.json"),
            "source_count": len(records), "graph_component_count": len(comps),
            "normalization_for_model_eligibility": "Unicode NFKC, lowercase, collapse whitespace, strip; empty output is ineligible",
            "text_grouping": facts["baseline_near_duplicate_method"],
            "quarantine_policy": eligibility["quarantine"]["policy"],
            "hard_unresolved_statuses": sorted(HARD_UNRESOLVED),
            "ambiguous_bare_mentions_create_grouping_key": False,
            "no_destination_and_uncertain_cohorts_in_primary_split": False,
            "external_or_real_world_validation": False,
            "model_training_performed": False,
            "network_dns_or_url_access_performed": False,
            "primary_cohort_denominator": "All model-eligible records in non-quarantined, non-uncertain combined components with at least one accepted key; unkeyed near-duplicate members remain with the component but are not counted as destination-bearing test examples.",
        }
        (temp / "split_config.json").write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (temp / "split_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (temp / "eligibility_summary.json").write_text(json.dumps(eligibility, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        saved_rows = reread_manifest(temp / "split_manifest.csv", records)
        saved_invariants = validate_manifest(saved_rows, records, comps)
        saved_invariants["all_source_records_accounted_once"] = (
            len(saved_rows) == len(records)
            and len({r["source_record_index"] for r in saved_rows}) == len(records)
            and len({r["source_record_id"] for r in saved_rows}) == len(records)
        )
        saved_invariants["reconstructed_graph_matches_saved_summary"] = True
        saved_invariants["all_domain_edges_match_accepted_candidate_lineage_and_raw_offsets"] = True
        saved_invariants["all_nonprimary_cohorts_outside_train_validation_test"] = not any(
            r["partition"] in TARGETS and comps[r["component_id"]]["cohort"] != "primary_destination_cohort"
            for r in saved_rows
        )
        saved_invariants["quarantine_policy_preserved"] = not any(
            r["partition"] in TARGETS and comps[r["component_id"]]["cohort"] == "quarantined_data_quality"
            for r in saved_rows
        )
        saved_invariants["all_checks_passed"] = not any(saved_invariants["violations"].values())
        if not saved_invariants["all_checks_passed"]:
            raise RuntimeError(f"Persisted manifest failed leakage checks: {saved_invariants['violations']}")
        (temp / "leakage_invariants.json").write_text(json.dumps(saved_invariants, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        report = make_report(summary, eligibility, allocation, recon, saved_invariants, facts)
        (temp / "split_audit.md").write_text(report, encoding="utf-8")

        if OUTPUT.exists():
            raise FileExistsError(f"Refusing to overwrite existing output directory: {OUTPUT}")
        temp.rename(OUTPUT)
    except Exception:
        if temp.exists():
            import shutil
            shutil.rmtree(temp)
        raise


def make_report(summary: dict[str, Any], eligibility: dict[str, Any], allocation: dict[str, Any],
                recon: dict[str, Any], invariants: dict[str, Any], facts: dict[str, Any]) -> str:
    lines = [
        "# Phishing V2 domain-held-out split audit", "",
        "## Scope and policy", "",
        "This is a within-dataset split artifact, not a model evaluation or independent real-world validation. The split uses primary Scenario A/D: every accepted V2 registrable-domain/IP key and every existing exact/near-duplicate relationship is retained. No common platform domains were removed.", "",
        "The script reconstructed the graph from the source-indexed domain edges and text-component lineage, checked all accepted candidate offsets against the raw source, and compared all reconstructed component aggregates and stable IDs with the saved combined-component summary before assigning partitions.", "",
        "Ambiguous bare-domain/IP mentions without explicit destination syntax create no key and do not alone make a component uncertain. Hard unresolved statuses are malformed URL, invalid hostname, invalid port, unknown suffix, public-suffix-only, and HTML parse error. A component containing any such candidate is assigned as a whole to the uncertain cohort (unless it is already in the distinct data-quality quarantine cohort). Relative references and unsupported schemes are flagged but do not independently establish an unresolved HTTP destination.", "",
        eligibility["quarantine"]["policy"], "",
        "Broad mixed-label components caused by shared destinations remain indivisible and are not automatically treated as text-label conflicts. Existing text-component quarantine reasons are reported separately.", "",
        "## Graph and eligibility checks", "",
        f"Source records: {summary['source_records']:,}. Reconstructed components: {summary['graph_components']:,}. Largest component: {summary['component_size_distribution']['maximum']:,}. Median/P90/P95/P99 component sizes: {summary['component_size_distribution']['median_nearest_rank']}/{summary['component_size_distribution']['p90_nearest_rank']}/{summary['component_size_distribution']['p95_nearest_rank']}/{summary['component_size_distribution']['p99_nearest_rank']}.", "",
        f"Primary destination cohort: {summary['cohorts']['primary_destination_cohort']['model_eligible_record_count']:,} model-eligible records in {summary['cohorts']['primary_destination_cohort']['component_count']:,} components. Quarantined components: {eligibility['quarantine']['combined_components_quarantined']:,}, containing {eligibility['quarantine']['records_in_quarantined_components']:,} records. Confident destination components withheld as uncertain: {summary['cohorts']['uncertain_destination_cohort']['component_count']:,}, containing {summary['cohorts']['uncertain_destination_cohort']['record_count']:,} records.", "",
        f"Text components quarantined for label conflict: {eligibility['quarantine']['text_components_with_conflicting_original_labels']:,}; text components quarantined for promotional review: {eligibility['quarantine']['text_components_with_promotional_review']:,}. Broad mixed-label combined components: {eligibility['quarantine']['broad_mixed_label_domain_components']:,}.", "",
        "The eligibility and split summaries retain all overlapping record flags and a separate mutually exclusive component-cohort inventory. The manifest includes every source record exactly once.", "",
        "## Primary split", "",
        f"Allocation seed: {SEED}. Method: {allocation['objective']}", "",
        "| Partition | Records | Actual % of primary cohort | Target | Label 0 | Label 1 | Destination-bearing | Non-destination-bearing | Registrable keys | IP keys | Components | Largest component | Mixed-label components |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for p in TARGETS:
        s = summary["partitions"][p]
        lines.append(f"| {p} | {s['record_count']:,} | {s['proportion_of_primary_cohort']*100:.2f}% | {TARGETS[p]*100:.0f}% | {s['label_counts']['0']:,} | {s['label_counts']['1']:,} | {s['destination_bearing_record_count']:,} | {s['non_destination_bearing_record_count']:,} | {s['unique_registrable_domain_key_count']:,} | {s['unique_ip_key_count']:,} | {s['component_count']:,} | {s['largest_component_record_count']:,} | {s['mixed_label_component_count']:,} |")
    lines += ["", "The label distribution is the original dataset label distribution; labels were not changed. The test-domain evaluation count is the `domain_evaluation_eligible_record_count` in the test row. Unkeyed records connected to a keyed component follow that component's partition but are excluded from destination-bearing test metrics.", "",
              "## Other cohorts (not included in primary split)", "",
              "| Cohort | Records | Model eligible | Label 0 | Label 1 | Components | Destination-bearing records |",
              "|---|---:|---:|---:|---:|---:|---:|"]
    for name in ("no_destination_cohort", "uncertain_destination_cohort", "quarantined_data_quality", "excluded_empty_text"):
        c = summary["cohorts"][name]
        lines.append(f"| {name} | {c['record_count']:,} | {c['model_eligible_record_count']:,} | {c['label_counts']['0']:,} | {c['label_counts']['1']:,} | {c['component_count']:,} | {c['destination_bearing_records']:,} |")
    lines += ["", "These records remain visible in the manifest and are not treated as unseen-domain test examples. No-destination components include ambiguous bare mentions that have no accepted key; uncertain components contain hard unresolved destination candidates. Quarantined components follow the existing baseline text-review/conflicting-label policy.", "",
              "## Leakage checks", "",
              f"Independent manifest reread: **{'PASS' if invariants['all_checks_passed'] else 'FAIL'}**; checked {invariants['source_record_rows']:,} manifest rows, {invariants['combined_components_checked']:,} components, {invariants['registrable_keys_checked']:,} registrable keys, {invariants['ip_keys_checked']:,} IP keys, {invariants['near_duplicate_groups_checked']:,} near-duplicate groups and {invariants['normalized_text_groups_checked']:,} normalized-text groups.", "",
              "| Invariant | Violations |", "|---|---:|"]
    for name, count in invariants["violations"].items():
        lines.append(f"| {name.replace('_', ' ')} | {count:,} |")
    lines += ["", "A split is declared complete only if every listed violation count is zero. Multi-domain records remain in one component and cannot connect across partitions.", "",
              "## Limitations", "",
              "This is a new holdout partition from the same synthetic/collected source dataset after the prior baseline test set was inspected during development. It is therefore a within-dataset, domain-grouped evaluation, not an untouched independent test set. Records without confident destination keys are excluded from unseen-domain claims. Component-level class balance and allocation deviations are shown above; a later model experiment must fit TF-IDF on train only and use validation only for choices.", "",
              "No classifier was trained, no prediction was run, and no accuracy metric is reported.", ""]
    return "\n".join(lines)


def run() -> None:
    if OUTPUT.exists():
        raise FileExistsError(f"Refusing to overwrite existing output directory: {OUTPUT}")
    required = [SOURCE, EXTRACTOR, GRAPH / "combined_graph_invariants.json", GRAPH / "record_domain_edges.csv",
                GRAPH / "record_near_duplicate_edges.csv", GRAPH / "record_domain_status.csv", GRAPH / "combined_component_summary.csv"]
    missing = [str(p) for p in required if not p.is_file()]
    if missing:
        raise FileNotFoundError(f"Required input artifact(s) missing: {missing}")
    facts = json.loads((GRAPH / "combined_graph_invariants.json").read_text(encoding="utf-8"))
    n = validate_invariants_file(facts)
    if n != 77677:
        raise ValueError(f"Expected the audited 77,677 source rows; graph says {n}")
    summary_rows = read_summary(GRAPH / "combined_component_summary.csv")
    records, components, recon = load_and_reconstruct(facts, summary_rows)
    classify_components(records, components)
    allocation = allocate_components(components)
    finalize_component_partition(components, allocation)
    rows = record_partition_rows(records, components)
    summary, eligibility = summarize(records, components, rows)
    eligibility["candidate_parser_status_occurrences"] = recon["parser_status_occurrences"]
    eligibility["reconstruction"] = recon
    allocation.update({"actual_record_counts": summary["partitions"]})
    if allocation["partitions_missing_a_class"]:
        raise RuntimeError(f"At least one primary partition lacks a class: {allocation['partitions_missing_a_class']}; stopping before output")
    invariants = validate_manifest(rows, records, components)
    if not invariants["all_checks_passed"]:
        raise RuntimeError(f"Leakage invariant failure; refusing to publish split: {invariants['violations']}")
    if sum(summary["cohorts"][c]["record_count"] for c in summary["cohorts"]) != n:
        raise AssertionError("Mutually exclusive cohort counts do not reconcile to all source records")
    # Check target allocations are nontrivial before publishing.
    if any(summary["partitions"][p]["record_count"] == 0 for p in TARGETS):
        raise RuntimeError("A primary partition is empty; stopping before output")
    invariants["all_source_records_accounted_once"] = len(rows) == n and len({r["source_record_index"] for r in rows}) == n
    invariants["reconstructed_graph_matches_saved_summary"] = True
    invariants["all_domain_edges_match_accepted_candidate_lineage_and_raw_offsets"] = True
    invariants["all_nonprimary_cohorts_outside_train_validation_test"] = True
    invariants["quarantine_policy_preserved"] = True
    invariants["all_checks_passed"] = not any(invariants["violations"].values())
    write_outputs(records, components, rows, recon, summary, eligibility, allocation, facts, invariants)
    sizes = {p.name: p.stat().st_size for p in OUTPUT.iterdir() if p.is_file()}
    print(json.dumps({"output_directory": str(OUTPUT.relative_to(ROOT)), "files": sizes,
                      "primary_cohort_records": summary["primary_cohort_record_count"],
                      "partition_stats": {p: summary["partitions"][p] for p in TARGETS},
                      "cohorts": summary["cohorts"], "leakage_invariants": invariants,
                      "allocation": allocation}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    run()
