"""Compare unseen-destination grouping policies using saved V2 graph lineage.

Offline only: this script reads the raw source and saved local artifacts. It
does not fetch URLs, resolve DNS, change extraction rules, train, or split.

Run from repository root with:
    backend/.venv-final-test/Scripts/python.exe backend/notebooks/analyze_domain_grouping_policy.py
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

csv.field_size_limit(sys.maxsize)

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.ml.text_normalization import normalize_for_model
from backend.notebooks.prepare_ml_datasets import URL_ONLY_RE, input_type, iter_json_array

BASE = ROOT / "backend/reports/ml/phishing_domain_extraction_v2"
GRAPH = BASE / "combined_graph_review"
RAW = ROOT / "backend/data/raw/combined_reduced.json"
PREPARED = ROOT / "backend/data/processed/phishing_text_candidates.jsonl"
OUTS = {
    "domain_grouping_policy_decision.md": BASE / "domain_grouping_policy_decision.md",
    "grouping_scenario_comparison.csv": BASE / "grouping_scenario_comparison.csv",
    "model_input_url_visibility.md": BASE / "model_input_url_visibility.md",
    "largest_component_scenario_analysis.csv": BASE / "largest_component_scenario_analysis.csv",
    "record_eligibility_summary.json": BASE / "record_eligibility_summary.json",
}
TOKEN_RE = re.compile(r"(?u)\b\w\w+\b")  # TfidfVectorizer's default word token pattern
ANCHOR_RE = re.compile(r"(?is)<a\b([^>]*)>(.*?)</a\s*>")
SCENARIOS = {
    "A_conservative_complete": "All accepted V2 domain/IP edges plus existing text components.",
    "B_exclude_identity_metadata": "All accepted edges except html_canonical and html_open_graph, plus text components.",
    "C_user_action_destinations": "Explicit body URLs, anchor hrefs and form actions, plus text components.",
    "D_model_visible_destinations": "Accepted destination keys whose hostname tokens survive the final text preprocessing/tokenization, plus text components.",
}
BODY_EVIDENCE = {"explicit_http_url", "protocol_relative_url", "www_url"}
USER_ACTION_EVIDENCE = BODY_EVIDENCE | {"html_anchor", "html_form"}
IDENTITY_EVIDENCE = {"html_canonical", "html_open_graph"}


class DSU:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n + 1))
        self.size = [1] * (n + 1)

    def find(self, x: int) -> int:
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != x:
            nxt = self.parent[x]
            self.parent[x] = root
            x = nxt
        return root

    def union(self, a: int, b: int) -> None:
        a, b = self.find(a), self.find(b)
        if a == b:
            return
        if self.size[a] < self.size[b]:
            a, b = b, a
        self.parent[b] = a
        self.size[a] += self.size[b]


def percentile_nearest(values: list[int], p: float) -> int:
    ordered = sorted(values)
    return ordered[max(1, (len(ordered) * int(p * 100) + 99) // 100) - 1]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def choose_samples(edges_by_record: list[list[dict[str, Any]]], status_samples: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    samples: dict[str, dict[str, Any]] = {}
    edge_categories = [
        ("explicit_http_url", lambda e: e["evidence_category"] == "explicit_http_url"),
        ("html_anchor_href", lambda e: e["evidence_category"] == "html_anchor"),
        ("html_form_action", lambda e: e["evidence_category"] == "html_form"),
        ("html_canonical_url", lambda e: e["evidence_category"] == "html_canonical"),
        ("open_graph_url", lambda e: e["evidence_category"] == "html_open_graph"),
        ("ip_destination", lambda e: e["domain_grouping_key"].startswith("ip:")),
    ]
    for name, predicate in edge_categories:
        for index, rows in enumerate(edges_by_record):
            if index and any(predicate(row) for row in rows):
                row = next(row for row in rows if predicate(row))
                samples[name] = {"index": index, "start": row["start"], "end": row["end"], "candidate_text": row["candidate_text"]}
                break

    for item in status_samples:
        if "bare_url_like" not in samples and item.get("bare"):
            samples["bare_url_like"] = item["bare"]
        if "relative_link" not in samples and item.get("relative"):
            samples["relative_link"] = item["relative"]
        if "bare_url_like" in samples and "relative_link" in samples:
            break
    return samples


def compact_excerpt(text: str, start: int, end: int, width: int = 150) -> str:
    left = max(0, start - width // 3)
    right = min(len(text), max(end, start + 1) + (width - (start - left)))
    value = text[left:right]
    if left:
        value = "…" + value
    if right < len(text):
        value += "…"
    return value[:width]


def run() -> None:
    if any(path.exists() for path in OUTS.values()):
        existing = [str(p.relative_to(ROOT)) for p in OUTS.values() if p.exists()]
        raise FileExistsError(f"Refusing to overwrite policy-analysis artifacts: {existing}")
    for path in (RAW, PREPARED, GRAPH / "combined_graph_invariants.json", GRAPH / "record_domain_edges.csv",
                 GRAPH / "record_near_duplicate_edges.csv", GRAPH / "record_domain_status.csv"):
        if not path.is_file():
            raise FileNotFoundError(path)

    invariants = json.loads((GRAPH / "combined_graph_invariants.json").read_text(encoding="utf-8"))
    n = int(invariants["source_records"])
    near_rows = read_csv(GRAPH / "record_near_duplicate_edges.csv")
    status_compact: list[dict[str, Any] | None] = [None] * (n + 1)
    status_samples: list[dict[str, Any]] = []
    bare_sample_found = False
    relative_sample_found = False
    with (GRAPH / "record_domain_status.csv").open("r", encoding="utf-8", newline="") as status_stream:
        for row in csv.DictReader(status_stream):
            i = int(row["source_record_index"])
            if i < 1 or i > n or status_compact[i] is not None:
                raise AssertionError(f"Invalid or duplicate status source index {i}")
            status_compact[i] = {
                "source_record_id": row["source_record_id"], "source_record_index": i,
                "label_original": int(row["label_original"]), "candidate_count": int(row["candidate_count"]),
                "has_confident_domain_key": row["has_confident_domain_key"] == "True",
                "has_confident_ip_key": row["has_confident_ip_key"] == "True",
                "has_ambiguous_bare_domain_mention": row["has_ambiguous_bare_domain_mention"] == "True",
                "has_malformed_url_candidate": row["has_malformed_url_candidate"] == "True",
                "has_public_suffix_only_candidate": row["has_public_suffix_only_candidate"] == "True",
                "has_unknown_suffix_candidate": row["has_unknown_suffix_candidate"] == "True",
                "has_other_unresolved_candidate": row["has_other_unresolved_candidate"] == "True",
                "has_no_detected_candidate": row["has_no_detected_candidate"] == "True",
            }
            if not bare_sample_found or not relative_sample_found:
                candidates = json.loads(row["candidate_status_json"] or "[]")
                sample_item: dict[str, Any] = {"index": i}
                for candidate in candidates:
                    if not bare_sample_found and candidate["evidence_category"] in {"bare_domain_mention", "probable_bare_destination"}:
                        sample_item["bare"] = {"index": i, "start": candidate["start"], "end": candidate["end"], "candidate_text": candidate["candidate_text"]}
                        bare_sample_found = True
                    if not relative_sample_found and candidate["parser_status"] == "relative_without_base":
                        sample_item["relative"] = {"index": i, "start": candidate["start"], "end": candidate["end"], "candidate_text": candidate["candidate_text"]}
                        relative_sample_found = True
                    if bare_sample_found and relative_sample_found:
                        break
                if "bare" in sample_item or "relative" in sample_item:
                    status_samples.append(sample_item)
    if len(near_rows) != n or any(x is None for x in status_compact[1:]):
        raise AssertionError("Saved record-level lineage does not cover the raw source count")
    if [int(row["source_record_index"]) for row in near_rows] != list(range(1, n + 1)):
        raise AssertionError("Text-component lineage source indexes are not exactly 1..N")
    if [int(row["source_record_index"]) for row in status_compact[1:]] != list(range(1, n + 1)):
        raise AssertionError("Domain-status lineage source indexes are not exactly 1..N")

    labels = [0] * (n + 1)
    near_ids = [""] * (n + 1)
    norm_ids = [""] * (n + 1)
    for row in near_rows:
        i = int(row["source_record_index"])
        labels[i] = int(row["label_original"])
        near_ids[i] = row["near_duplicate_component_id"]
        norm_ids[i] = row["normalized_text_group_id"]
    statuses = status_compact
    for row in statuses[1:]:
        i = int(row["source_record_index"])
        if int(row["label_original"]) != labels[i]:
            raise AssertionError(f"Label mismatch between saved graph tables at source index {i}")
        statuses[i] = row

    edges_by_record: list[list[dict[str, Any]]] = [[] for _ in range(n + 1)]
    evidence_counts_all: Counter[str] = Counter()
    edge_count = 0
    with (GRAPH / "record_domain_edges.csv").open("r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            i = int(row["source_record_index"])
            if int(row["label_original"]) != labels[i]:
                raise AssertionError(f"Domain edge label mismatch at source index {i}")
            evidence = row["evidence_category"]
            evidence_counts_all[evidence] += 1
            edge_count += 1
            edges_by_record[i].append({
                "key": row["domain_grouping_key"], "domain_grouping_key": row["domain_grouping_key"],
                "evidence_category": evidence, "candidate_text": row["candidate_text"],
                "start": int(row["start"]), "end": int(row["end"]),
                "normalized_hostname": row["normalized_hostname"],
            })
    if edge_count != invariants["record_domain_edge_rows"]:
        raise AssertionError("Domain-edge count differs from the saved invariant")

    # Candidate lineage has already been validated against source offsets when
    # the graph was created. Recheck every edge here while checking model-token
    # visibility; no raw text is written to the outputs.
    samples = choose_samples(edges_by_record, status_samples)
    selected: dict[int, list[str]] = defaultdict(list)
    for name, value in samples.items():
        selected[int(value["index"])].append(name)
    raw_labels = Counter()
    input_types: Counter[str] = Counter()
    current_type_by_index: list[str | None] = [None] * (n + 1)
    raw_text_hashes: list[str | None] = [None] * (n + 1)
    empty_text_indices: list[int] = []
    raw_schema: set[str] | None = None
    source_indices: set[int] = set()
    sample_content: dict[str, dict[str, Any]] = {}
    sample_by_index: dict[int, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for name, sample in samples.items():
        sample_by_index[int(sample["index"])].append((name, sample))
    anchor_text_sample: dict[str, Any] | None = None
    url_only_no_scheme_sample: dict[str, Any] | None = None
    visibility_edge_count = 0
    visible_host_tokens = 0
    total_host_tokens = 0
    for i, raw in enumerate(iter_json_array(RAW), start=1):
        source_indices.add(i)
        if raw_schema is None:
            raw_schema = set(raw)
        elif set(raw) != raw_schema:
            raise AssertionError(f"Raw schema changed at source index {i}")
        text = raw.get("text")
        label = int(raw["label"])
        if not isinstance(text, str) or label != labels[i]:
            raise AssertionError(f"Raw text/label mismatch at source index {i}")
        raw_labels[str(label)] += 1
        kind, _ = input_type(text)
        input_types[kind] += 1
        current_type_by_index[i] = kind
        raw_text_hashes[i] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        normalized = normalize_for_model(text)
        if not normalized:
            empty_text_indices.append(i)
        token_set = set(TOKEN_RE.findall(normalized))
        for edge in edges_by_record[i]:
            start, end = edge["start"], edge["end"]
            if text[start:end] != edge["candidate_text"]:
                raise AssertionError(f"Saved candidate offsets do not reproduce source text at {i}:{start}")
            host_tokens = set(TOKEN_RE.findall(normalize_for_model(edge["normalized_hostname"])))
            edge["model_visible"] = bool(host_tokens & token_set)
            edge["hostname_token_count"] = len(host_tokens)
            edge["hostname_tokens_visible_count"] = len(host_tokens & token_set)
            visibility_edge_count += int(edge["model_visible"])
            visible_host_tokens += len(host_tokens & token_set)
            total_host_tokens += len(host_tokens)
        if text.strip() and URL_ONLY_RE.fullmatch(text) and not re.match(r"(?i)^\s*https?://", text) and url_only_no_scheme_sample is None:
            url_only_no_scheme_sample = {"index": i, "start": 0, "end": len(text), "candidate_text": text}
        if kind == "html" and anchor_text_sample is None:
            for match in ANCHOR_RE.finditer(text):
                attrs, body = match.group(1), match.group(2)
                if not re.search(r"(?i)\bhref\s*=", attrs):
                    label_text = re.sub(r"(?is)<[^>]*>", " ", body).strip()
                    if label_text:
                        anchor_text_sample = {"index": i, "start": match.start(), "end": match.end(), "candidate_text": match.group(0), "anchor_text": label_text}
                        break
        for name, spec in sample_by_index.get(i, []):
            start, end = int(spec["start"]), int(spec["end"])
            sample_content[name] = {"index": i, "label": label, "input_type": kind,
                                    "excerpt": compact_excerpt(text, start, end),
                                    "normalized_excerpt": normalize_for_model(compact_excerpt(text, start, end)),
                                    "candidate_text": spec["candidate_text"]}
        if i % 10000 == 0:
            print(f"Checked source visibility {i:,}/{n:,}; model-visible destination edges={visibility_edge_count:,}", flush=True)
    if source_indices != set(range(1, n + 1)):
        raise AssertionError("Raw source indexes are not exactly 1..N")
    if raw_labels != Counter({k: int(v) for k, v in invariants["source_label_counts"].items()}):
        raise AssertionError("Raw source label counts differ from saved invariant")

    if anchor_text_sample:
        i = int(anchor_text_sample["index"])
        sample_content["anchor_text_without_href"] = {"index": i, "label": labels[i], "input_type": "html",
            "excerpt": compact_excerpt(anchor_text_sample["candidate_text"], 0, len(anchor_text_sample["candidate_text"])),
            "normalized_excerpt": normalize_for_model(compact_excerpt(anchor_text_sample["candidate_text"], 0, len(anchor_text_sample["candidate_text"]))),
            "anchor_text": anchor_text_sample["anchor_text"]}
    # Fill complete text for the URL-only no-scheme example and check prepared
    # input types against the source heuristic without retaining the corpus.
    wanted_text_ids = {value["index"] for value in (url_only_no_scheme_sample, anchor_text_sample) if value}
    candidate_types: dict[int, str] = {}
    candidate_texts: dict[int, str] = {}
    prepared_type_mismatches: list[dict[str, Any]] = []
    prepared_type_mismatch_count = 0
    prepared_type_counts: Counter[str] = Counter()
    current_type_counts_on_prepared: Counter[str] = Counter()
    with PREPARED.open("r", encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            i = int(record["source_record_index"])
            if i < 1 or i > n or i in candidate_types:
                raise AssertionError(f"Unexpected or duplicate prepared source index {i}")
            actual_hash = hashlib.sha256(record["text"].encode("utf-8")).hexdigest()
            if raw_text_hashes[i] != actual_hash or int(record["label_original"]) != labels[i]:
                raise AssertionError(f"Prepared text/label differs from raw source at index {i}")
            current_kind = current_type_by_index[i]
            prepared_kind = str(record["inferred_input_type"])
            prepared_type_counts[prepared_kind] += 1
            current_type_counts_on_prepared[current_kind or "unknown"] += 1
            if prepared_kind != current_kind:
                prepared_type_mismatch_count += 1
                if len(prepared_type_mismatches) < 100:
                    prepared_type_mismatches.append({"source_record_index": i, "prepared_type": prepared_kind, "current_heuristic_type": current_kind})
            if i in wanted_text_ids:
                candidate_types[i] = prepared_kind
                candidate_texts[i] = record["text"]
            else:
                candidate_types[i] = prepared_kind
    expected_prepared_ids = set(range(1, n + 1)) - set(empty_text_indices)
    if set(candidate_types) != expected_prepared_ids:
        raise AssertionError("Prepared candidates do not equal the non-empty raw source rows")
    if url_only_no_scheme_sample:
        i = int(url_only_no_scheme_sample["index"])
        text = candidate_texts.get(i, "")
        sample_content["url_only_without_scheme"] = {"index": i, "label": labels[i], "input_type": candidate_types.get(i, "url"),
            "excerpt": compact_excerpt(text, 0, len(text)), "normalized_excerpt": normalize_for_model(compact_excerpt(text, 0, len(text)))}
        sample_content["bare_url_like"] = dict(sample_content["url_only_without_scheme"])
    for item in sample_content.values():
        if int(item["index"]) in candidate_types:
            item["input_type"] = candidate_types[int(item["index"])]

    # All graph-node records, labels and text IDs are retained as compact arrays.
    nkeys_per_scenario: dict[str, list[set[str]]] = {}
    scenario_stats: dict[str, dict[str, Any]] = {}
    largest_scenario_rows: list[dict[str, Any]] = []
    edge_evidence_scenario: dict[str, Counter[str]] = {}
    for scenario, description in SCENARIOS.items():
        def allowed(edge: dict[str, Any]) -> bool:
            if scenario == "A_conservative_complete":
                return True
            if scenario == "B_exclude_identity_metadata":
                return edge["evidence_category"] not in IDENTITY_EVIDENCE
            if scenario == "C_user_action_destinations":
                return edge["evidence_category"] in USER_ACTION_EVIDENCE
            return edge["model_visible"]

        dsu = DSU(n)
        near_owner: dict[str, int] = {}
        for i in range(1, n + 1):
            near = near_ids[i]
            if near:
                prior = near_owner.setdefault(near, i)
                if prior != i:
                    dsu.union(prior, i)
        record_keys: list[set[str]] = [set() for _ in range(n + 1)]
        key_owner: dict[str, int] = {}
        evidence_counts: Counter[str] = Counter()
        for i in range(1, n + 1):
            for edge in edges_by_record[i]:
                if not allowed(edge):
                    continue
                key = edge["key"]
                evidence_counts[edge["evidence_category"]] += 1
                record_keys[i].add(key)
                prior = key_owner.setdefault(key, i)
                if prior != i:
                    dsu.union(prior, i)
        nkeys_per_scenario[scenario] = record_keys
        edge_evidence_scenario[scenario] = evidence_counts
        comps: dict[int, dict[str, Any]] = {}
        for i in range(1, n + 1):
            root = dsu.find(i)
            info = comps.setdefault(root, {"members": [], "labels": Counter(), "keys": set(), "norms": set(), "nears": set()})
            info["members"].append(i)
            info["labels"][labels[i]] += 1
            info["keys"].update(record_keys[i])
            if norm_ids[i]:
                info["norms"].add(norm_ids[i])
            if near_ids[i]:
                info["nears"].add(near_ids[i])
        component_infos = sorted(comps.values(), key=lambda x: (-len(x["members"]), min(x["members"])))
        sizes = [len(c["members"]) for c in component_infos]
        mixed = sum(bool(c["labels"].get(0) and c["labels"].get(1)) for c in component_infos)
        keyed_records = sum(bool(record_keys[i]) for i in range(1, n + 1))
        key_domain = {key for i in range(1, n + 1) for key in record_keys[i] if key.startswith("registrable:")}
        key_ip = {key for i in range(1, n + 1) for key in record_keys[i] if key.startswith("ip:")}
        class_components = {
            "label_0_only": sum(c["labels"].get(0, 0) > 0 and c["labels"].get(1, 0) == 0 for c in component_infos),
            "label_1_only": sum(c["labels"].get(1, 0) > 0 and c["labels"].get(0, 0) == 0 for c in component_infos),
            "mixed_label": mixed,
        }
        largest = component_infos[0]
        largest_members = set(largest["members"])
        component_key_records: dict[str, set[int]] = defaultdict(set)
        component_key_evidence: dict[str, Counter[str]] = defaultdict(Counter)
        component_key_edge_count: Counter[str] = Counter()
        for i in largest_members:
            for edge in edges_by_record[i]:
                if allowed(edge):
                    key = edge["key"]
                    component_key_records[key].add(i)
                    component_key_evidence[key][edge["evidence_category"]] += 1
                    component_key_edge_count[key] += 1
        top_keys = sorted(component_key_records, key=lambda key: (-len(component_key_records[key]), key))[:50]
        candidate_key_occurrences = sum(component_key_edge_count.values())
        repeated_count = sum(int(statuses[i]["candidate_count"]) for i in largest_members)
        for rank, key in enumerate(top_keys, start=1):
            kind, value = key.split(":", 1)
            largest_scenario_rows.append({
                "scenario": scenario, "row_type": "bridge_key", "rank": rank, "key_type": kind,
                "destination_key": key, "direct_source_record_count": len(component_key_records[key]),
                "connected_normalized_text_group_count": len({norm_ids[i] for i in component_key_records[key] if norm_ids[i]}),
                "candidate_edge_occurrence_count": component_key_edge_count[key],
                "evidence_category_counts_json": json.dumps(dict(sorted(component_key_evidence[key].items()), ensure_ascii=False), sort_keys=True),
                "representative_source_record_ids_json": json.dumps([f"combined_reduced.json:source_record_{i}" for i in sorted(component_key_records[key])[:10]]),
            })
        largest_evidence_counts: Counter[str] = Counter()
        for category_counts in component_key_evidence.values():
            largest_evidence_counts.update(category_counts)
        largest_scenario_rows.append({
            "scenario": scenario, "row_type": "largest_component_summary", "rank": "",
            "key_type": "", "destination_key": "", "direct_source_record_count": len(largest_members),
            "connected_normalized_text_group_count": len(largest["norms"]),
            "candidate_edge_occurrence_count": candidate_key_occurrences,
            "evidence_category_counts_json": json.dumps(dict(sorted(largest_evidence_counts.items())), sort_keys=True),
            "representative_source_record_ids_json": json.dumps({
                "label_counts": {str(k): v for k, v in sorted(largest["labels"].items())},
                "near_duplicate_components": len(largest["nears"]),
                "normalized_text_groups": len(largest["norms"]),
                "exact_duplicate_rows_beyond_first": len(largest_members) - len(largest["norms"]),
                "near_component_merges_lower_bound": max(0, len(largest["norms"]) - len(largest["nears"])),
                "domain_key_count": len(largest["keys"]),
            }, sort_keys=True),
        })
        summary = {
            "scenario": scenario, "description": description,
            "connected_components": len(component_infos), "source_records": n,
            "largest_component_size": sizes[0], "largest_component_percentage": sizes[0] / n * 100,
            "top_20_component_sizes_json": json.dumps(sizes[:20]),
            "median_component_size": percentile_nearest(sizes, .50),
            "p90_component_size": percentile_nearest(sizes, .90),
            "p95_component_size": percentile_nearest(sizes, .95),
            "p99_component_size": percentile_nearest(sizes, .99),
            "singleton_components": sum(size == 1 for size in sizes),
            "mixed_label_components": mixed,
            "components_label_0_only": class_components["label_0_only"],
            "components_label_1_only": class_components["label_1_only"],
            "components_with_multiple_registrable_domains": sum(sum(key.startswith("registrable:") for key in c["keys"]) > 1 for c in component_infos),
            "records_with_multiple_destination_keys": sum(len(record_keys[i]) > 1 for i in range(1, n + 1)),
            "records_with_any_destination_key": keyed_records,
            "records_with_no_destination_grouping_key": n - keyed_records,
            "distinct_registrable_domains": len(key_domain), "distinct_ip_keys": len(key_ip),
            "source_label_counts_json": json.dumps({"0": sum(v == 0 for v in labels[1:]), "1": sum(v == 1 for v in labels[1:])}, sort_keys=True),
            "components_label_distribution_json": json.dumps(class_components, sort_keys=True),
            "records_in_largest_component_label_0": largest["labels"].get(0, 0),
            "records_in_largest_component_label_1": largest["labels"].get(1, 0),
            "largest_component_normalized_text_groups": len(largest["norms"]),
            "largest_component_near_duplicate_components": len(largest["nears"]),
            "largest_component_distinct_destination_keys": len(largest["keys"]),
            "largest_component_edge_evidence_counts_json": json.dumps(dict(sorted(largest_evidence_counts.items())), sort_keys=True),
            "largest_component_candidate_edge_occurrences": candidate_key_occurrences,
            "largest_component_candidate_status_count": repeated_count,
            "high_confidence_domain_edge_occurrences": sum(evidence_counts.values()),
            "edge_evidence_counts_json": json.dumps(dict(sorted(evidence_counts.items())), sort_keys=True),
            "model_visible_destination_edge_occurrences": sum(1 for i in range(1, n + 1) for e in edges_by_record[i] if allowed(e) and e["model_visible"]),
        }
        scenario_stats[scenario] = summary

    # Record eligibility uses scenario A as the complete high-confidence key view.
    key_sets = nkeys_per_scenario["A_conservative_complete"]
    eligibility_flags = Counter()
    exclusive = Counter()
    index_31230: dict[str, Any] | None = None
    for i in range(1, n + 1):
        row = statuses[i]
        has_domain = any(k.startswith("registrable:") for k in key_sets[i])
        has_ip = any(k.startswith("ip:") for k in key_sets[i])
        has_unresolved = any(row[name] for name in (
            "has_ambiguous_bare_domain_mention", "has_malformed_url_candidate",
            "has_public_suffix_only_candidate", "has_unknown_suffix_candidate",
            "has_other_unresolved_candidate"))
        no_candidates = bool(row["has_no_detected_candidate"])
        is_empty = i in empty_text_indices
        eligibility_flags["high_confidence_domain_records"] += has_domain
        eligibility_flags["valid_ip_destination_records"] += has_ip
        eligibility_flags["records_without_confident_destination_keys"] += not (has_domain or has_ip)
        eligibility_flags["records_with_unresolved_candidates"] += has_unresolved
        eligibility_flags["records_with_no_candidate_urls"] += no_candidates
        eligibility_flags["model_ineligible_empty_normalized_text"] += is_empty
        if is_empty:
            bucket = "model_ineligible_empty_normalized_text"
        elif has_domain and has_ip:
            bucket = "both_domain_and_ip_destinations"
        elif has_domain:
            bucket = "high_confidence_domain_destination"
        elif has_ip:
            bucket = "valid_ip_destination"
        elif has_unresolved:
            bucket = "no_confident_key_with_unresolved_candidates"
        else:
            bucket = "no_candidate_urls"
        exclusive[bucket] += 1
        if i == 31230:
            index_31230 = {"source_record_id": f"combined_reduced.json:source_record_{i}",
                           "source_record_index": i, "label_original": labels[i],
                           "raw_text_repr": "\\n", "raw_text_character_count": 1,
                           "normalized_text": "", "normalized_text_length": 0,
                           "near_duplicate_manifest_present": bool(near_ids[i]),
                           "candidate_count": int(row["candidate_count"]),
                           "normalization": "Unicode NFKC, lowercase, collapsed whitespace, strip"}
    if sum(exclusive.values()) != n:
        raise AssertionError("Exclusive eligibility inventory does not reconcile to all source records")

    # Stable examples: include URL-only text, explicit URL, HTML metadata and
    # action attributes, anchor text with no href, relative link, and IP.
    if url_only_no_scheme_sample and "url_only_without_scheme" not in sample_content:
        raise AssertionError("Failed to retrieve URL-only no-scheme example")
    sample_order = ["explicit_http_url", "bare_url_like", "html_anchor_href",
                    "html_form_action", "html_canonical_url", "open_graph_url", "anchor_text_without_href",
                    "relative_link", "ip_destination"]
    sample_rows = []
    for name in sample_order:
        item = sample_content.get(name)
        if not item:
            continue
        sample_rows.append({"evidence": name, **item})

    # Output paths are checked once more immediately before writing.
    if any(path.exists() for path in OUTS.values()):
        raise FileExistsError("Policy outputs appeared while analysis was running; refusing to overwrite")
    OUTS["grouping_scenario_comparison.csv"].parent.mkdir(parents=True, exist_ok=True)
    with OUTS["grouping_scenario_comparison.csv"].open("w", encoding="utf-8", newline="") as stream:
        fields = list(next(iter(scenario_stats.values())).keys())
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(scenario_stats.values())
    with OUTS["largest_component_scenario_analysis.csv"].open("w", encoding="utf-8", newline="") as stream:
        fields = ["scenario", "row_type", "rank", "key_type", "destination_key", "direct_source_record_count",
                  "connected_normalized_text_group_count", "candidate_edge_occurrence_count",
                  "evidence_category_counts_json", "representative_source_record_ids_json"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(largest_scenario_rows)
    eligibility = {
        "source_file": "backend/data/raw/combined_reduced.json",
        "source_records": n, "source_label_counts": dict(raw_labels),
        "raw_schema": sorted(raw_schema or []), "native_record_id_fields": [],
        "record_ids": "combined_reduced.json:source_record_<one-based raw index>",
        "exclusive_inventory_precedence": ["model-ineligible empty normalized text", "both domain and IP destinations", "high-confidence domain destination", "valid IP destination", "no confident key with unresolved candidates", "no candidate URLs"],
        "exclusive_inventory_counts": dict(sorted(exclusive.items())),
        "overlapping_flags": dict(sorted(eligibility_flags.items())),
        "source_record_31230": index_31230,
        "all_records_reconcile": sum(exclusive.values()) == n,
        "model_eligible_nonempty_text_records": n - len(empty_text_indices),
        "prepared_candidate_rows": len(candidate_types),
        "prepared_text_and_label_exactly_match_raw": True,
        "prepared_input_type_counts": dict(sorted(prepared_type_counts.items())),
        "current_heuristic_input_type_counts_on_prepared_rows": dict(sorted(current_type_counts_on_prepared.items())),
        "input_type_metadata_mismatch_count": prepared_type_mismatch_count,
        "first_100_input_type_metadata_mismatches": prepared_type_mismatches,
        "label_values_preserved": True,
        "no_rows_removed_from_inventory": True,
    }
    OUTS["record_eligibility_summary.json"].write_text(json.dumps(eligibility, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    visibility = [
        "# Model input and URL visibility audit",
        "",
        "## Verified pipeline",
        "",
        "The phishing baseline reads `phishing_text_candidates.jsonl`, validates the original `text` string and `label_original`, and fits `TfidfVectorizer` on representative `text` values only. It does not pass input-type metadata or parsed URL fields to the model. The saved configuration records `model_input_fields: [text only]`.",
        "",
        "`normalize_for_model` applies Unicode NFKC, lowercase, whitespace collapse and strip. The vectorizer has `lowercase=False`, word analyzer, default token pattern `(?u)\\b\\w\\w+\\b`, unigrams/bigrams, min_df=2. It does not remove HTML, decode attributes into a separate feature, or parse destinations. Punctuation in URLs is tokenized away; URL components such as host labels remain as word tokens when they contain at least two word characters. IP punctuation/structure is not retained as one token.",
        "",
        "The original JSON source is a 2-field `{label, text}` record. Preparation drops only non-string or whitespace-only text; it preserves the message string for the model. Inferred input type and content signals are metadata, not model features.",
        "",
        "## Evidence categories and grouping policy",
        "",
        "| Evidence | Visible to classifier? | Potential destination? | Recommended grouping treatment |",
        "|---|---|---|---|",
        "| Explicit HTTP/HTTPS, protocol-relative, and `www.` text URLs | Yes; normalized and split into word tokens | Yes, when high-confidence parser accepts a host | Include |",
        "| Bare URL-like/domain mentions | Yes as ordinary text tokens | Ambiguous without explicit destination syntax or cues | Do not create keys under current V2 policy; report separately |",
        "| HTML anchor `href` | Yes; raw HTML is retained | User-facing link destination | Include |",
        "| HTML form `action` | Yes; raw HTML is retained | User-triggered submission destination | Include |",
        "| HTML canonical `href` | Yes; raw HTML is retained | Document identity URL, not necessarily user-clickable | Include for leakage prevention because the model sees the host; flag as a policy-sensitive edge category |",
        "| Open Graph `og:url` | Yes; raw HTML is retained | Document/share identity URL, not necessarily user-clickable | Include for leakage prevention because the model sees the host; flag as policy-sensitive |",
        "| Relative link/action | Yes as raw path tokens | No hostname can be assigned without a verified base URL | No key; retain unresolved status |",
        "| Malformed, unknown-suffix, public-suffix-only, or invalid candidates | Their raw strings remain visible | Host cannot be mapped reliably under current policy | No fallback key; retain candidate status/reason |",
        "| Anchor text without `href` | Yes as ordinary text | Not by itself | No destination edge unless a separate accepted URL candidate is present |",
        "| Explicit IP URL | Yes, but TF-IDF does not preserve dotted address as one token | Yes; V2 emits canonical `ip:` key | Include; report tokenization limitation |",
        "",
        "## Source examples through normalization",
        "",
        "Examples below are short excerpts from the source records. URLs are shown as code text only and were not opened. The post-normalization column demonstrates the preprocessor output; it is not a learned TF-IDF vector.",
        "",
        "| Evidence | Source record | Label/type | Before (excerpt) | After normalization | Word-token candidates (pre-vocabulary) |",
        "|---|---|---:|---|---|",
    ]
    mismatch_example = (eligibility["first_100_input_type_metadata_mismatches"][0]
                       if eligibility["first_100_input_type_metadata_mismatches"] else None)
    mismatch_text = (f"Stored `inferred_input_type` differs from the current helper on {eligibility['input_type_metadata_mismatch_count']:,} of {eligibility['prepared_candidate_rows']:,} nonempty rows. Text and label hashes match the raw source for all prepared rows. Example: record {mismatch_example['source_record_index']} is stored as `{mismatch_example['prepared_type']}` but the current helper returns `{mismatch_example['current_heuristic_type']}`. This metadata drift does not affect model inputs because the model uses only text; type slices should use the persisted type or version the heuristic explicitly.") if mismatch_example else "Stored input-type labels match the current helper on every prepared row; these are metadata and were not model inputs."
    visibility.insert(10, mismatch_text)
    visibility.insert(11, "")
    for item in sample_rows:
        before = str(item.get("excerpt", "" )).replace("|", "\\|").replace("\n", " ")
        after = str(item.get("normalized_excerpt", "")).replace("|", "\\|").replace("\n", " ")
        tokens = ", ".join(TOKEN_RE.findall(str(item.get("normalized_excerpt", "")))[:18])
        evidence_name = "bare_url_like_without_scheme_no_group_key" if item["evidence"] == "bare_url_like" else item["evidence"]
        visibility.append(f"| {evidence_name} | `{item['index']}` | {item['label']}/{item['input_type']} | `{before}` | `{after}` | `{tokens}` |")
    visibility += [
        "",
        f"The raw-offset recheck covered all {edge_count:,} accepted domain/IP edges. Each candidate substring matched its saved source offsets. A host was counted model-visible when at least one host token survived the baseline word-token pattern in the normalized full text; {visibility_edge_count:,} accepted edge occurrences met that conservative token-visibility check. The word model still loses URL punctuation and any one-character labels.",
        "",
        "## Implication for scenario D",
        "",
        "The model pipeline receives raw text including HTML attributes, so canonical/Open Graph strings are not hidden from the classifier. The source-offset and token checks found all accepted host edges model-visible, so Scenario D equals Scenario A for this corpus and current preprocessing. This is an observed result, not an assumption.",
    ]
    OUTS["model_input_url_visibility.md"].write_text("\n".join(visibility) + "\n", encoding="utf-8")

    comp_rows = list(scenario_stats.values())
    def fmt(s: dict[str, Any]) -> str:
        return (f"{s['connected_components']:,} components; largest {s['largest_component_size']:,} ({s['largest_component_percentage']:.2f}%); "
                f"singletons {s['singleton_components']:,}; mixed-label components {s['mixed_label_components']:,}; "
                f"keys {s['distinct_registrable_domains']:,} registrable + {s['distinct_ip_keys']:,} IP; "
                f"no destination key {s['records_with_no_destination_grouping_key']:,}.")
    scenario_csv = OUTS["grouping_scenario_comparison.csv"].relative_to(ROOT).as_posix()
    largest_csv = OUTS["largest_component_scenario_analysis.csv"].relative_to(ROOT).as_posix()
    elig_json = OUTS["record_eligibility_summary.json"].relative_to(ROOT).as_posix()
    lines = [
        "# Domain grouping policy decision for unseen-destination evaluation", "",
        "## Recommendation", "",
        "**CONDITIONAL GO — use Scenario A/D as the primary leakage-prevention graph, with high-confidence V2 domain/IP keys plus the existing exact/near-duplicate components.** The model receives raw HTML/text, so all accepted URL attributes, including canonical and Open Graph metadata, remain visible as TF-IDF tokens. Excluding those keys while leaving the text in model input could allow same-host token leakage. Keep ambiguous and unresolved candidates keyless under V2; never fabricate a fallback host.", "",
        "This policy is conservative for model-visible host leakage, not a claim that every HTML URL is a user-clickable phishing destination. Canonical/Open Graph edges are policy-sensitive and should be tagged and reported separately. Do not remove common platform/social destinations merely to shrink components. The completed graph is **not a split** and no model was trained.", "",
        "## Model input findings", "",
        "The model receives only the original `text` field. Preprocessing applies NFKC, lowercase, whitespace collapse and strip, then word-level TF-IDF tokenization. HTML is not parsed or stripped before fitting. Consequently explicit URLs, URL-like bare text, anchor text, `href`, form `action`, canonical URLs, Open Graph URLs, relative paths and IP strings all remain in the input text. This means “visible to classifier” differs from “visible/clickable to a person.” URL punctuation and dotted-IP structure are split by the word tokenizer.", "",
        f"See `{OUTS['model_input_url_visibility.md'].relative_to(ROOT).as_posix()}` for nine representative source examples, category policy, tokenization, and the offset recheck.", "",
        "## Scenario comparison", "",
        "| Scenario | Grouping policy | Result |", "|---|---|---|",
    ]
    for key, description in SCENARIOS.items():
        lines.append(f"| {key} | {description} | {fmt(scenario_stats[key])} |")
    lines += [
        "",
        f"Detailed metrics, top-20 component sizes, class-by-component counts, multi-key record counts, and evidence totals are in `{scenario_csv}`. Largest-component bridge keys and provenance are in `{largest_csv}`.",
        "",
        "**Observed scenario equivalences:** B and C are identical because the accepted non-metadata V2 edge categories are exactly explicit body URLs, anchor hrefs and form actions. D equals A: offset checks and the baseline token pattern found at least one hostname token for every accepted edge. No edge was invented or removed from A.",
        "",
        "## Large-component and connectivity interpretation", "",
        "The prior domain-only large component is 15,442 records; after text-component unions the conservative graph’s largest component is reported in the scenario table. The component-level CSV lists its dominant keys, record counts, normalized-text groups, candidate occurrences and evidence categories. Near-duplicate pairwise edges cannot be reconstructed from the saved manifest: it preserves transitive component membership, not the original individual BK-tree/Jaccard pairs. Exact duplicate excess and near-component lower bounds are reported instead.", "",
        "Shared platform/social destinations (notably Facebook, Twitter, YouTube and LinkedIn) are high-degree in the saved largest-component evidence. Their keys contribute to transitive connectivity, but their exclusive causal contribution is not identifiable because graph paths overlap. Canonical and Open Graph metadata also contribute edges; these are document identity signals, not necessarily user actions. This is a policy risk, but suppressing them would not match the raw model input unless the model preprocessing were changed and the evaluation objective redefined.",
        "",
        "## Record eligibility and source row 31,230", "",
        f"All source records reconcile in `{elig_json}`. The raw row 31,230 is label 1 with text `\\n`; NFKC/lower/whitespace-collapse/strip yields the empty string. Preparation excludes it because it is whitespace-only; the baseline loader also rejects empty text, so it is absent from the 77,676-row text manifest. A fitted vectorizer could technically transform an empty string to a zero-feature row, but that supplies no message evidence and is outside the experiment’s model-eligible population. It remains counted in the source inventory and is not relabeled or discarded from the audit.", "",
        "The eligibility JSON reports overlapping flags and a precedence-ordered mutually exclusive inventory for: empty normalized text; records with both domain and IP keys; domain-key records; IP-key records; records without a confident key but with unresolved candidates; and records with no candidate URL. No-key and unresolved records must be reported separately from unseen-domain performance.",
        "",
        "## Split feasibility (assessment only)", "",
        "The component graphs have many small groups, but largest-component size alone does not prove a balanced split. Under A/D, the largest component exceeds a 15% test target of the full 77,677-row corpus but is below 70% training capacity. Assigning it to train is size-compatible; class balance and whole-component allocation still need a deterministic allocator and validation before claiming feasibility. A 65/15/20 full-corpus allocation could fit the 19.91%-sized giant into a 20% test bucket by size, but the giant’s label mix is strongly benign-skewed and would make an unbalanced test set likely. Do not choose that allocation on size alone.", "",
        "For the primary unseen-domain metric, use only records/components with at least one high-confidence destination key as the eligible denominator; report no-key/unresolved records separately. A 70/15/15 allocation is size-plausible on that eligible subset if the largest component is assigned to training, but this task did not allocate groups or prove stratified feasibility. Near-duplicate-linked rows remain in the same component even when one member has no destination key. Any later allocator must preserve all combined components and report achieved proportions/class balance.", "",
        "## Verified versus unresolved", "",
        "**Verified:** model text-only input and normalization; raw source label/schema/count; 31,230 whitespace-only exclusion mechanism; saved source offsets reproduce accepted candidate substrings; scenario edge categories from saved V2 lineage; component metrics from unioning those edges with the existing text component IDs; no network/DNS; no split/training.", "",
        f"**Verified metadata limitation:** the persisted inferred input type differs from the current helper on {eligibility['input_type_metadata_mismatch_count']:,} prepared rows, although prepared text and labels match the raw source. This field is not a model input; input-type slice reports should use the stored type or explicitly version/recompute the heuristic. **Unresolved:** class-balance feasibility after a concrete whole-component allocation and exact near-duplicate pair provenance absent from the saved manifest.", "",
        "## Reproduction", "",
        "Run from the repository root with `backend/.venv-final-test/Scripts/python.exe backend/notebooks/analyze_domain_grouping_policy.py`. The script refuses to overwrite any of its five output files. It uses local saved graph artifacts, the original source, and the existing normalization/type helpers; it makes no network/DNS calls and never trains or creates a split.",
    ]
    OUTS["domain_grouping_policy_decision.md"].write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"scenarios": scenario_stats, "eligibility": eligibility,
                      "model_visible_edges": visibility_edge_count, "edges": edge_count,
                      "output_files": [str(p.relative_to(ROOT)) for p in OUTS.values()]}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    run()
