"""Create a hostname, normalized-text, and near-duplicate grouped split.

Run from the repository root with the ML environment:
    backend/.venv-ml/Scripts/python.exe backend/notebooks/create_domain_grouped_split.py

This script uses the existing training module's normalization, near-duplicate,
and component-quarantine implementation. It does not load, train, or score a
model, and it never opens URLs or performs network requests. Existing outputs
are never overwritten; if either output already exists the script stops.
"""

from __future__ import annotations

import hashlib
import json
import math
import platform
import re
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Reuse the baseline implementation as the source of truth for normalized
# text, near-duplicate components, labels, and conservative quarantine.
from backend.ml import train_text_baseline as baseline
from backend.notebooks.prepare_ml_datasets import URL_ONLY_RE, URL_RE

import sklearn
from sklearn.model_selection import StratifiedGroupKFold


INPUT = ROOT / "backend" / "data" / "processed" / "phishing_text_candidates.jsonl"
OUTPUT_DIR = ROOT / "backend" / "data" / "processed"
MANIFEST_PATH = OUTPUT_DIR / "domain_grouped_split_manifest.jsonl"
REPORT_PATH = OUTPUT_DIR / "domain_grouped_split_report.md"
SEED = 20261026
N_SPLITS = 20
EXPLICIT_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
TRAILING_URL_PUNCTUATION = ".,;:!?)]}>'\""


class DisjointSet:
    """Union-find keyed by the existing near-duplicate component IDs."""

    def __init__(self, values: list[str]) -> None:
        self.parent = {value: value for value in values}
        self.rank = {value: 0 for value in values}

    def find(self, value: str) -> str:
        parent = self.parent[value]
        if parent != value:
            self.parent[value] = self.find(parent)
        return self.parent[value]

    def union(self, left: str, right: str) -> None:
        a, b = self.find(left), self.find(right)
        if a == b:
            return
        if self.rank[a] < self.rank[b]:
            a, b = b, a
        self.parent[b] = a
        if self.rank[a] == self.rank[b]:
            self.rank[a] += 1


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_id(prefix: str, values: list[str]) -> str:
    payload = "\n".join(sorted(values))
    return hashlib.sha256(f"{prefix}\0{payload}".encode("utf-8")).hexdigest()


def normalize_hostname(value: str, *, allow_bare: bool = False) -> str | None:
    """Parse and normalize one already-extracted URL/hostname offline."""
    candidate = value.strip().rstrip(TRAILING_URL_PUNCTUATION)
    if not candidate:
        return None

    if candidate.startswith("//"):
        candidate = "http:" + candidate
    elif candidate.lower().startswith(("http://", "https://")):
        pass
    elif candidate.lower().startswith("www."):
        candidate = "http://" + candidate
    elif allow_bare:
        candidate = "http://" + candidate
    else:
        # Relative paths and unqualified HTML attributes have no reliable
        # page origin, so they must not be mistaken for hostnames.
        return None

    try:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        # Python's built-in IDNA codec is used locally; no suffix database,
        # DNS lookup, or URL request is involved.
        hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except (UnicodeError, ValueError):
        return None
    return hostname or None


def explicit_url_hosts(text: str) -> set[str]:
    hosts: set[str] = set()
    for match in EXPLICIT_URL_RE.finditer(text):
        hostname = normalize_hostname(match.group(0))
        if hostname:
            hosts.add(hostname)
    return hosts


def url_only_hosts(text: str) -> set[str]:
    """Use the preparation script's URL-only rule, then extract candidates."""
    if URL_ONLY_RE.fullmatch(text) is None:
        return set()
    hosts: set[str] = set()
    for match in URL_RE.finditer(text):
        hostname = normalize_hostname(match.group(0), allow_bare=True)
        if hostname:
            hosts.add(hostname)
    return hosts


class HTMLDestinationParser(HTMLParser):
    """Collect only canonical, form-action, and anchor destination hosts."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.canonical_hosts: set[str] = set()
        self.form_action_hosts: set[str] = set()
        self.anchor_hosts: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle_tag(tag, attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle_tag(tag, attrs)

    def _handle_tag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs if key}
        if tag.lower() == "link":
            rel = set(values.get("rel", "").lower().split())
            if "canonical" in rel:
                host = normalize_hostname(values.get("href", ""))
                if host:
                    self.canonical_hosts.add(host)
        elif tag.lower() == "form":
            host = normalize_hostname(values.get("action", ""))
            if host:
                self.form_action_hosts.add(host)
        elif tag.lower() == "a":
            host = normalize_hostname(values.get("href", ""))
            if host:
                self.anchor_hosts.add(host)


def destination_hosts(record: dict[str, Any]) -> tuple[set[str], str]:
    kind = str(record.get("inferred_input_type", ""))
    text = str(record["text"])
    if kind == "url":
        hosts = url_only_hosts(text)
        if len(hosts) == 1:
            return hosts, "url_only_single_hostname"
        return set(), "url_only_ambiguous_or_unparseable"
    if kind in {"plain_text", "email"}:
        hosts = explicit_url_hosts(text)
        if len(hosts) == 1:
            return hosts, "single_explicit_url_hostname"
        if len(hosts) > 1:
            return set(), "ambiguous_multiple_explicit_hostnames"
        return set(), "no_explicit_destination_hostname"
    if kind == "html":
        parser = HTMLDestinationParser()
        try:
            parser.feed(text)
            parser.close()
        except Exception:
            return set(), "html_parse_error"
        if len(parser.canonical_hosts) == 1:
            return parser.canonical_hosts, "html_canonical"
        if len(parser.canonical_hosts) > 1:
            return set(), "html_ambiguous_canonical"
        if len(parser.form_action_hosts) == 1:
            return parser.form_action_hosts, "html_form_action"
        if len(parser.form_action_hosts) > 1:
            return set(), "html_ambiguous_form_action"
        if len(parser.anchor_hosts) == 1:
            return parser.anchor_hosts, "html_single_anchor_hostname"
        if len(parser.anchor_hosts) > 1:
            return set(), "html_ambiguous_anchor_hostnames"
        return set(), "html_no_identifiable_destination"
    return set(), "unsupported_input_type"


def percentile(values: list[int], q: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    # Nearest-rank percentile, documented to make the report reproducible.
    return ordered[max(0, math.ceil(q * len(ordered)) - 1)]


def markdown_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend("| " + " | ".join(str(value) for value in row) + " |" for row in rows)
    return lines


def main() -> int:
    for output in (MANIFEST_PATH, REPORT_PATH):
        if output.exists():
            raise FileExistsError(f"Refusing to overwrite existing output: {output}")
    if not INPUT.is_file():
        raise FileNotFoundError(f"Candidate input does not exist: {INPUT}")

    records, source_summary = baseline.load_records(INPUT)
    text_groups, near_duplicate_summary = baseline.create_groups(records)

    base_components: dict[str, list[dict[str, Any]]] = defaultdict(list)
    base_quarantine_reasons: dict[str, set[str]] = defaultdict(set)
    host_to_base_components: dict[str, set[str]] = defaultdict(set)
    group_destination_info: dict[str, tuple[list[str], str, str]] = {}

    for group in text_groups:
        base_id = str(group["component_id"])
        base_components[base_id].append(group)
        base_quarantine_reasons[base_id].update(group["quarantine_reasons"])

        hosts: set[str] = set()
        methods: set[str] = set()
        # Examine every source row in this normalized-text group, not only
        # the representative, so casing/encoding variants cannot lose a host.
        for record in group["records"]:
            row_hosts, method = destination_hosts(record)
            hosts.update(row_hosts)
            methods.add(method)

        if len(hosts) == 1:
            status = "single_exact_hostname"
            method_name = ";".join(sorted(methods))
            for host in hosts:
                host_to_base_components[host].add(base_id)
        elif len(hosts) > 1:
            # A normalized group that yields inconsistent destinations is
            # still kept together by text/near-duplicate components, but it
            # does not impose ambiguous domain edges.
            status = "ambiguous_multiple_hostnames"
            method_name = ";".join(sorted(methods))
            hosts = set()
        else:
            status = "no_usable_destination_hostname"
            method_name = ";".join(sorted(methods))

        group_destination_info[str(group["normalized_hash"])] = (
            sorted(hosts), status, method_name
        )

    dsu = DisjointSet(sorted(base_components))
    for component_ids in host_to_base_components.values():
        ordered_ids = sorted(component_ids)
        if len(ordered_ids) > 1:
            first = ordered_ids[0]
            for other in ordered_ids[1:]:
                dsu.union(first, other)

    combined_members: dict[str, list[str]] = defaultdict(list)
    for base_id in base_components:
        combined_members[dsu.find(base_id)].append(base_id)
    combined_id_for_base: dict[str, str] = {}
    combined_reasons: dict[str, list[str]] = {}
    for root, member_ids in combined_members.items():
        combined_id = stable_id("domain-grouped-component-v1", member_ids)
        reasons = sorted({reason for item in member_ids for reason in base_quarantine_reasons[item]})
        combined_reasons[combined_id] = reasons
        for base_id in member_ids:
            combined_id_for_base[base_id] = combined_id

    # Any domain-connected component containing an existing quarantined
    # near-duplicate component is quarantined in full.
    unique_groups_by_combined: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for group in text_groups:
        base_id = str(group["component_id"])
        combined_id = combined_id_for_base[base_id]
        unique_groups_by_combined[combined_id].append(group)
    quarantined_combined_ids = {
        component_id for component_id, reasons in combined_reasons.items() if reasons
    }
    eligible_groups: list[dict[str, Any]] = []
    eligible_labels: list[int] = []
    eligible_group_ids: list[str] = []
    for group in text_groups:
        combined_id = combined_id_for_base[str(group["component_id"])]
        if combined_id in quarantined_combined_ids:
            continue
        if group["label"] is None:
            raise ValueError("An unquarantined normalized-text group has conflicting labels")
        eligible_groups.append(group)
        eligible_labels.append(int(group["label"]))
        eligible_group_ids.append(combined_id)
    if len(set(eligible_labels)) != 2:
        raise ValueError("Eligible groups do not contain both binary labels")

    splitter = StratifiedGroupKFold(
        n_splits=N_SPLITS,
        shuffle=True,
        random_state=SEED,
    )
    fold_for_group: dict[str, int] = {}
    for fold, (_, held_indices) in enumerate(
        splitter.split(
            X=[None] * len(eligible_groups),
            y=eligible_labels,
            groups=eligible_group_ids,
        )
    ):
        for index in held_indices:
            group_id = eligible_group_ids[int(index)]
            prior = fold_for_group.setdefault(group_id, fold)
            if prior != fold:
                raise AssertionError("A combined component was assigned to multiple folds")
    if set(fold_for_group) != set(eligible_group_ids):
        raise AssertionError("Some eligible combined components received no fold")

    def partition_for_group(component_id: str) -> str:
        if component_id in quarantined_combined_ids:
            return "quarantine"
        fold = fold_for_group[component_id]
        if fold in {0, 1, 2}:
            return "test"
        if fold in {3, 4, 5}:
            return "validation"
        return "train"

    combined_partition = {
        component_id: partition_for_group(component_id)
        for component_id in set(combined_id_for_base.values())
    }

    # Build a source-indexed manifest only after every group/component has a
    # single final partition.
    manifest_rows: list[dict[str, Any]] = []
    for group in text_groups:
        normalized_group_id = str(group["normalized_hash"])
        hosts, host_status, host_method = group_destination_info[normalized_group_id]
        base_id = str(group["component_id"])
        combined_id = combined_id_for_base[base_id]
        partition = combined_partition[combined_id]
        quarantine_status = partition == "quarantine"
        reasons = list(combined_reasons[combined_id])
        if quarantine_status and not group["quarantine_reasons"]:
            reasons.append("connected_to_quarantined_component_through_hostname_group")
        reasons = sorted(set(reasons))
        host_group_ids = [
            hashlib.sha256(f"exact-hostname-v1\0{host}".encode("utf-8")).hexdigest()
            for host in hosts
        ]
        for record in group["records"]:
            source_index = int(record.get("source_record_index", record["_line_no"]))
            manifest_rows.append(
                {
                    "record_id": f"{record['source_dataset']}:{source_index}",
                    "source_dataset": record["source_dataset"],
                    "source_record_index": source_index,
                    "label_original": str(record["label_original"]),
                    "inferred_input_type": record["inferred_input_type"],
                    "normalized_text_group_id": normalized_group_id,
                    "near_duplicate_component_id": base_id,
                    "combined_component_id": combined_id,
                    "partition": partition,
                    "destination_hostnames": hosts,
                    "hostname_group_ids": host_group_ids,
                    "hostname_grouping_status": host_status,
                    "hostname_grouping_method": host_method,
                    "review_required": bool(record["review_required"]),
                    "review_reason": list(record.get("review_reason", [])),
                    "quarantine_status": quarantine_status,
                    "quarantine_reasons": reasons,
                }
            )
    manifest_rows.sort(key=lambda row: row["source_record_index"])
    source_indices = [row["source_record_index"] for row in manifest_rows]
    if len(manifest_rows) != len(records) or len(set(source_indices)) != len(records):
        raise AssertionError("Manifest does not map one-to-one to all source records")

    # Validate all split constraints before writing anything.
    norm_parts: dict[str, set[str]] = defaultdict(set)
    near_parts: dict[str, set[str]] = defaultdict(set)
    host_parts: dict[str, set[str]] = defaultdict(set)
    combined_parts: dict[str, set[str]] = defaultdict(set)
    quarantine_primary = 0
    for row in manifest_rows:
        part = row["partition"]
        combined_parts[row["combined_component_id"]].add(part)
        if part == "quarantine":
            if row["quarantine_status"] is not True:
                raise AssertionError("Quarantine partition row is not marked quarantined")
            continue
        if row["quarantine_status"]:
            quarantine_primary += 1
        norm_parts[row["normalized_text_group_id"]].add(part)
        near_parts[row["near_duplicate_component_id"]].add(part)
        for host in row["destination_hostnames"]:
            host_parts[host].add(part)

    overlap_counts = {
        "normalized_text": sum(len(parts) > 1 for parts in norm_parts.values()),
        "near_duplicate_component": sum(len(parts) > 1 for parts in near_parts.values()),
        "eligible_exact_hostname": sum(len(parts) > 1 for parts in host_parts.values()),
        "combined_component": sum(len(parts) > 1 for parts in combined_parts.values()),
        "quarantined_rows_in_primary": quarantine_primary,
    }
    if any(overlap_counts.values()):
        raise AssertionError(f"Leakage/quarantine validation failed: {overlap_counts}")

    record_counts: dict[str, Counter[int]] = {
        name: Counter() for name in ("train", "validation", "test", "quarantine")
    }
    unique_group_labels: dict[str, dict[str, int]] = {
        name: {} for name in ("train", "validation", "test", "quarantine")
    }
    components_per_partition: dict[str, set[str]] = {
        name: set() for name in ("train", "validation", "test", "quarantine")
    }
    no_host_records: Counter[str] = Counter()
    for row in manifest_rows:
        part = row["partition"]
        label = int(row["label_original"])
        record_counts[part][label] += 1
        unique_group_labels[part][row["normalized_text_group_id"]] = label
        components_per_partition[part].add(row["combined_component_id"])
        if not row["destination_hostnames"]:
            no_host_records[part] += 1

    final_quarantine_records = sum(record_counts["quarantine"].values())
    base_quarantine_records = sum(
        len(group["records"])
        for group in text_groups
        if group["quarantine_reasons"]
    )
    explicit_promo_records = sum(bool(record["_promo"]) for record in records)
    eligible_component_sizes = [
        len(unique_groups_by_combined[component_id])
        for component_id, part in combined_partition.items()
        if part != "quarantine"
    ]
    eligible_components = [
        component_id for component_id, part in combined_partition.items() if part != "quarantine"
    ]
    class_group_counts = Counter(int(group["label"]) for group in eligible_groups)
    total_eligible = sum(record_counts[name].total() for name in ("train", "validation", "test"))
    unique_eligible = len(eligible_groups)

    partition_summary: dict[str, dict[str, Any]] = {}
    targets = {"train": 0.70, "validation": 0.15, "test": 0.15}
    for name in ("train", "validation", "test", "quarantine"):
        rows_in_partition = sum(record_counts[name].values())
        groups_in_partition = len(unique_group_labels[name])
        target = targets.get(name)
        partition_summary[name] = {
            "records": rows_in_partition,
            "unique_normalized_text_groups": groups_in_partition,
            "combined_components": len(components_per_partition[name]),
            "record_class_counts": {
                "0": int(record_counts[name].get(0, 0)),
                "1": int(record_counts[name].get(1, 0)),
            },
            "unique_text_class_counts": {
                "0": sum(value == 0 for value in unique_group_labels[name].values()),
                "1": sum(value == 1 for value in unique_group_labels[name].values()),
            },
            "records_without_usable_destination_hostname": int(no_host_records[name]),
            "target_share": target,
            "record_share": rows_in_partition / total_eligible if target is not None and total_eligible else None,
            "record_share_deviation_percentage_points": (
                100 * (rows_in_partition / total_eligible - target)
                if target is not None and total_eligible
                else None
            ),
            "unique_text_share": groups_in_partition / unique_eligible if target is not None and unique_eligible else None,
            "unique_text_share_deviation_percentage_points": (
                100 * (groups_in_partition / unique_eligible - target)
                if target is not None and unique_eligible
                else None
            ),
        }

    eligible_groups_with_hostname = sum(
        bool(group_destination_info[str(group["normalized_hash"])][0])
        for group in eligible_groups
    )

    component_mixed = sum(
        sum(int(group["label"] == 0) for group in groups_in_component)
        > 0
        and sum(int(group["label"] == 1) for group in groups_in_component)
        > 0
        for component_id, groups_in_component in unique_groups_by_combined.items()
        if combined_partition[component_id] != "quarantine"
    )
    eligible_sizes_sorted = sorted(eligible_component_sizes)
    max_component = max(eligible_component_sizes, default=0)
    target_test_or_validation = math.ceil(0.15 * max(unique_eligible, 1))
    target_train = math.ceil(0.70 * max(unique_eligible, 1))
    constraining_components = sorted(
        (
            (len(unique_groups_by_combined[component_id]), component_id)
            for component_id in eligible_components
            if len(unique_groups_by_combined[component_id]) > 0.15 * unique_eligible
        ),
        reverse=True,
    )

    report_lines = [
        "# Hostname-grouped exploratory split report",
        "",
        "This is an exploratory within-dataset split. It is not independently collected data and does not establish real-world detection performance.",
        "No model was loaded, trained, scored, or tuned. No URLs were opened and no network requests were made.",
        "",
        "## Reproducibility and inputs",
        "",
        f"- Created UTC: `{datetime.now(timezone.utc).isoformat()}`.",
        f"- Random seed: `{SEED}`; grouping allocation: `StratifiedGroupKFold(n_splits={N_SPLITS}, shuffle=True)`.",
        "- Fold mapping: folds 0-2 test, 3-5 validation, 6-19 train; components are indivisible.",
        f"- Python: `{platform.python_version()}`; scikit-learn: `{sklearn.__version__}`.",
        f"- Candidate SHA-256: `{file_sha256(INPUT)}`.",
        f"- Candidate rows: {source_summary['candidate_records']:,}; source dataset values: `{', '.join(source_summary['source_dataset_values'])}`.",
        "- The candidate source field identifies `combined_reduced.json`; no finer record-level source identifier is available, so this split cannot enforce source separation.",
        "- Text normalization, near-duplicate matching, and initial quarantine reuse `backend/ml/train_text_baseline.py` (`normalize_for_group`, `create_groups`, `DisjointSet`, `BKTree`, `simhash64`, and `jaccard_match`).",
        "- Domain grouping uses exact normalized hostnames. Casing is lowercased, a trailing dot is removed, and the Python built-in IDNA codec converts supported IDNs. No public-suffix list is used; subdomains are not merged.",
        "- URL extraction is local and syntactic. URL-only records use the preparation script's `URL_ONLY_RE`; ordinary text and email require one distinct explicit URL host. HTML uses one canonical host, else one form-action host, else one distinct absolute anchor host. Relative URLs and resource hosts are ignored.",
        "",
        "## Component audit before split",
        "",
        f"- Source records: {source_summary['candidate_records']:,}; unique normalized-text groups before quarantine: {near_duplicate_summary['normalized_text_groups']:,}; existing near-duplicate components: {near_duplicate_summary['near_duplicate_components']:,}.",
        f"- Existing near-duplicate components initially quarantined: {near_duplicate_summary['quarantined_components']:,}; base-component quarantined records: {base_quarantine_records:,}; explicitly promotional-flagged records: {explicit_promo_records:,}.",
        f"- After hostname union and quarantine propagation: {final_quarantine_records:,} quarantined records in {len(quarantined_combined_ids):,} connected components; additional records propagated through connected groups: {max(0, final_quarantine_records - base_quarantine_records):,}.",
        f"- Eligible records: {total_eligible:,}; eligible unique normalized texts: {unique_eligible:,}; eligible combined components: {len(eligible_components):,}.",
        f"- Eligible label counts by unique text: label 0 = {class_group_counts[0]:,}; label 1 = {class_group_counts[1]:,}.",
        f"- Eligible unique-text groups with one usable hostname: {eligible_groups_with_hostname:,}.",
        f"- Destination hostname coverage among eligible records: {sum(1 for row in manifest_rows if row['partition'] != 'quarantine' and row['destination_hostnames']):,}; without a usable hostname: {sum(1 for row in manifest_rows if row['partition'] != 'quarantine' and not row['destination_hostnames']):,}.",
        f"- Distinct eligible exact hostnames: {len({host for row in manifest_rows if row['partition'] != 'quarantine' for host in row['destination_hostnames']}):,}.",
        f"- Eligible component label composition: label-0-only = {sum(1 for c in eligible_components if component_has_labels(unique_groups_by_combined[c], {0})):,}; label-1-only = {sum(1 for c in eligible_components if component_has_labels(unique_groups_by_combined[c], {1})):,}; both labels = {component_mixed:,}.",
        f"- Component sizes are measured in unique normalized texts. Median = {percentile(eligible_sizes_sorted, 0.50):,}; p90 = {percentile(eligible_sizes_sorted, 0.90):,}; p95 = {percentile(eligible_sizes_sorted, 0.95):,}; maximum = {max_component:,}.",
        f"- Components larger than a nominal 15% holdout target ({target_test_or_validation:,} unique texts): {len(constraining_components):,}; larger than the nominal 70% training target ({target_train:,}): {sum(size > 0.70 * unique_eligible for size in eligible_component_sizes):,}.",
        "",
        "### Counts by input type",
        "",
    ]
    type_rows = []
    for kind in sorted({str(record.get("inferred_input_type", "unknown")) for record in records}):
        matching = [row for row in manifest_rows if row["inferred_input_type"] == kind and row["partition"] != "quarantine"]
        type_rows.append([
            kind,
            len(matching),
            sum(bool(row["destination_hostnames"]) for row in matching),
            sum(not row["destination_hostnames"] for row in matching),
        ])
    report_lines.extend(markdown_table(["Input type", "Eligible records", "With hostname", "Without hostname"], type_rows))
    report_lines.extend(["", "### Largest eligible components", ""])
    largest_components = sorted(
        (
            (len(groups_in_component), component_id, groups_in_component)
            for component_id, groups_in_component in unique_groups_by_combined.items()
            if combined_partition[component_id] != "quarantine"
        ),
        reverse=True,
    )[:10]
    largest_rows = []
    for size, component_id, groups_in_component in largest_components:
        labels = Counter(int(group["label"]) for group in groups_in_component if group["label"] is not None)
        row_total = sum(len(group["records"]) for group in groups_in_component)
        hosts = sorted({host for group in groups_in_component for host in group_destination_info[str(group["normalized_hash"])][0]})
        largest_rows.append([component_id, size, row_total, labels[0], labels[1], len(hosts)])
    report_lines.extend(markdown_table(
        ["Combined component ID", "Unique texts", "Source rows", "Label 0 texts", "Label 1 texts", "Hostnames"],
        largest_rows,
    ))
    report_lines.extend([
        "",
        "## Split sizes and class balance",
        "",
        "Source-row class counts preserve every candidate label. Unique-text counts count each normalized-text group once.",
        "",
    ])
    split_rows = []
    for name in ("train", "validation", "test"):
        item = partition_summary[name]
        split_rows.append([
            name,
            item["records"],
            f"{item['record_share'] * 100:.3f}%",
            f"{item['record_share_deviation_percentage_points']:+.3f} pp",
            item["unique_normalized_text_groups"],
            f"{item['unique_text_share'] * 100:.3f}%",
            f"{item['unique_text_share_deviation_percentage_points']:+.3f} pp",
            item["combined_components"],
            item["record_class_counts"]["0"],
            item["record_class_counts"]["1"],
            item["records_without_usable_destination_hostname"],
        ])
    report_lines.extend(markdown_table(
        ["Partition", "Records", "Record %", "Record deviation", "Unique texts", "Text %", "Text deviation", "Components", "Label 0 rows", "Label 1 rows", "No hostname rows"],
        split_rows,
    ))
    report_lines.extend(["", "Unique-text label counts by partition:", ""])
    unique_rows = []
    for name in ("train", "validation", "test"):
        item = partition_summary[name]
        unique_rows.append([name, item["unique_text_class_counts"]["0"], item["unique_text_class_counts"]["1"]])
    report_lines.extend(markdown_table(["Partition", "Label 0 unique texts", "Label 1 unique texts"], unique_rows))
    report_lines.extend([
        "",
        "## Leakage and quarantine validation",
        "",
        f"- Normalized-text group overlaps across primary partitions: {overlap_counts['normalized_text']}.",
        f"- Existing near-duplicate component overlaps across primary partitions: {overlap_counts['near_duplicate_component']}.",
        f"- Eligible exact-hostname overlaps across primary partitions: {overlap_counts['eligible_exact_hostname']}.",
        f"- Combined-component overlaps across primary partitions: {overlap_counts['combined_component']}.",
        f"- Quarantined records entering train/validation/test: {overlap_counts['quarantined_rows_in_primary']}.",
        f"- Quarantine rows in output manifest: {final_quarantine_records:,}; quarantine components: {len(quarantined_combined_ids):,}; no-host quarantine rows: {no_host_records['quarantine']:,}.",
        "- Validation is performed by the script before output files are written; any nonzero overlap or quarantine count in a primary partition stops generation.",
        "",
        "## Limitations",
        "",
        "- Exact hostnames do not merge subdomains. No suitable local public-suffix list was available, so registrable-domain grouping was not attempted.",
        "- A hostname extracted from content is not proven active, registered, or malicious. Destination selection for HTML and text remains heuristic; ambiguous records have no hostname key and rely on text/near-duplicate grouping only.",
        "- This split is drawn from the same combined dataset whose baseline test results have already been inspected. It is exploratory and within-dataset, not an independent test set or real-world validation.",
        "- The source data has no per-record original-source identifier, so source-separated leakage cannot be prevented with these files.",
        "- No model predictions or evaluation metrics are included in the manifest or this report.",
        "",
        "## Outputs",
        "",
        f"- Manifest: `{MANIFEST_PATH.relative_to(ROOT)}`.",
        f"- Report: `{REPORT_PATH.relative_to(ROOT)}`.",
        f"- Reproduce with: `backend\\.venv-ml\\Scripts\\python.exe backend/notebooks/create_domain_grouped_split.py`.",
        "",
    ])

    # Stage both outputs, and refuse replacement if another process has
    # created either target during computation.
    manifest_lines = [json.dumps(row, ensure_ascii=False, sort_keys=True) for row in manifest_rows]
    report_text = "\n".join(report_lines)
    if MANIFEST_PATH.exists() or REPORT_PATH.exists():
        raise FileExistsError("An output appeared during generation; refusing to overwrite it")
    with tempfile.TemporaryDirectory(prefix=".domain_grouped_split_", dir=OUTPUT_DIR) as temp_name:
        temp_dir = Path(temp_name)
        staged_manifest = temp_dir / MANIFEST_PATH.name
        staged_report = temp_dir / REPORT_PATH.name
        staged_manifest.write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
        staged_report.write_text(report_text, encoding="utf-8")
        if MANIFEST_PATH.exists() or REPORT_PATH.exists():
            raise FileExistsError("An output appeared before commit; refusing to overwrite it")
        staged_manifest.replace(MANIFEST_PATH)
        staged_report.replace(REPORT_PATH)

    print(json.dumps({
        "manifest": str(MANIFEST_PATH.relative_to(ROOT)),
        "report": str(REPORT_PATH.relative_to(ROOT)),
        "candidate_records": source_summary["candidate_records"],
        "eligible_records": total_eligible,
        "eligible_unique_texts": unique_eligible,
        "quarantined_records": final_quarantine_records,
        "quarantined_components": len(quarantined_combined_ids),
        "partition_counts": partition_summary,
        "overlap_validation": overlap_counts,
    }, ensure_ascii=False, indent=2))
    return 0


def component_has_labels(groups: list[dict[str, Any]], labels: set[int]) -> bool:
    return {
        int(group["label"])
        for group in groups
        if group["label"] is not None
    } == labels


if __name__ == "__main__":
    raise SystemExit(main())
