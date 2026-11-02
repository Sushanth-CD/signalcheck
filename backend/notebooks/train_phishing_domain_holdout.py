"""Train a separate phishing text baseline with registrable-domain holdout.

Run from the repository root:
    backend/.venv-ml/Scripts/python.exe backend/notebooks/train_phishing_domain_holdout.py

This reuses the existing candidate loader, exact/near-duplicate grouping,
quarantine rules, text preprocessing, and model configuration. URL processing
is syntactic and offline. Registrable domains are obtained from the Public
Suffix List bundled with the repository's Oracle JDK 27 distribution via its
RegisteredDomain API; no list is downloaded and URLs are never opened.
"""

from __future__ import annotations

import csv
import argparse
import hashlib
import html
import ipaddress
import json
import math
import os
import platform
import re
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.ml import train_text_baseline as baseline
from backend.ml.psl_service import (
    JAVA,
    JDK_ROOT,
    PSL_FILE,
    psl_registrable_domains,
    sha256_file,
)
from backend.notebooks.prepare_ml_datasets import URL_ONLY_RE, URL_RE
from backend.ml.text_normalization import normalize_for_model

import joblib
import numpy as np
import scipy
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline


INPUT = ROOT / "backend/data/processed/phishing_text_candidates.jsonl"
EXISTING_GROUP_MANIFEST = ROOT / "backend/reports/ml/text_phishing_baseline/split_manifest.csv"
BASELINE_METRICS = ROOT / "backend/reports/ml/text_phishing_baseline/metrics.json"
REPORT_ROOT = ROOT / "backend/reports/ml"
OUTPUT_DIR = REPORT_ROOT / "phishing_domain_holdout"
SEED = 20261026
FOLDS = 20
THRESHOLD = 0.5
TRAILING_PUNCTUATION = ".,;:!?)]}>'\""
HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
BARE_IP_URL_RE = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:.]+\])(?::\d{1,5})?(?:/[^\s<>\"']*)?$", re.IGNORECASE)


class DisjointSet:
    def __init__(self, values: Iterable[str]) -> None:
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


def stable_id(prefix: str, values: Iterable[str]) -> str:
    payload = "\n".join(sorted(values))
    return hashlib.sha256(f"{prefix}\0{payload}".encode("utf-8")).hexdigest()


def percentile(values: list[int], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(fraction * len(ordered)))
    return float(ordered[rank - 1])


def normalize_host_from_url(candidate: str, *, allow_bare: bool = False) -> tuple[str | None, str]:
    """Return an ASCII-normalized host and parse status without network I/O."""
    value = html.unescape(candidate.strip()).rstrip(TRAILING_PUNCTUATION)
    if not value:
        return None, "empty_candidate"
    if value.startswith("//"):
        value = "https:" + value
    elif re.match(r"^[a-z][a-z0-9+.-]*://", value, re.IGNORECASE):
        pass
    elif value.lower().startswith("www."):
        value = "https://" + value
    elif allow_bare:
        value = "https://" + value
    else:
        return None, "relative_or_unqualified_reference"
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None, "unsupported_or_missing_authority"
        # Accessing .port validates malformed/non-numeric/out-of-range ports.
        _ = parsed.port
        raw_host = parsed.hostname.rstrip(".")
        try:
            address = ipaddress.ip_address(raw_host)
            return address.compressed.lower(), "ip_literal"
        except ValueError:
            pass
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", raw_host):
            return None, "invalid_ipv4_literal"
        host = raw_host.encode("idna").decode("ascii").lower().rstrip(".")
        if not host or len(host) > 253:
            return None, "invalid_hostname_length"
        labels = host.split(".")
        if len(labels) < 2:
            return None, "unqualified_hostname"
        if any(not HOST_LABEL_RE.fullmatch(label) for label in labels):
            return None, "invalid_hostname_label"
        return host, "normalized_hostname"
    except (UnicodeError, ValueError):
        return None, "malformed_url"


class HTMLDestinations(HTMLParser):
    """Find page destinations while ignoring image/script/style resources."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.canonical: list[str] = []
        self.open_graph: list[str] = []
        self.forms: list[str] = []
        self.anchors: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle(tag, attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle(tag, attrs)

    def _handle(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs if key}
        tag = tag.lower()
        if tag == "link" and "canonical" in values.get("rel", "").lower().split():
            self.canonical.append(values.get("href", ""))
        elif tag == "meta" and values.get("property", "").lower() == "og:url":
            self.open_graph.append(values.get("content", ""))
        elif tag == "form":
            self.forms.append(values.get("action", ""))
        elif tag == "a":
            self.anchors.append(values.get("href", ""))


def destination_candidates(record: dict[str, Any]) -> tuple[list[tuple[str, bool]], str, int]:
    """Return candidate destinations, extraction method, URL-like token count."""
    text = str(record["text"])
    kind = str(record.get("inferred_input_type", "unknown"))
    matches = list(URL_RE.finditer(text))
    if not matches and BARE_IP_URL_RE.fullmatch(text.strip()):
        return [(text.strip(), True)], "bare_ip_url_candidate", 1
    if kind == "html":
        parser = HTMLDestinations()
        try:
            parser.feed(text)
            parser.close()
        except Exception:
            return [], "html_parse_error", len(matches)
        values = parser.canonical or parser.open_graph or parser.forms or parser.anchors
        method = (
            "html_canonical" if parser.canonical else
            "html_og_url" if parser.open_graph else
            "html_form_action" if parser.forms else
            "html_anchor_destinations" if parser.anchors else
            "html_no_page_destination"
        )
        candidates = [
            (v, bool(re.match(r"^(?:https?://|//|www\.)", html.unescape(v.strip()), re.IGNORECASE)))
            for v in values if v
        ]
        return candidates, method, len(matches)

    candidates: list[tuple[str, bool]] = []
    whole_message_is_url = kind == "url" and URL_ONLY_RE.fullmatch(text) is not None
    for match in matches:
        # Do not treat the domain portion of an email address as a destination.
        if match.start() > 0 and text[match.start() - 1] == "@":
            continue
        candidate = match.group(0)
        strong_url_shape = whole_message_is_url or bool(
            re.match(r"^(?:https?://|//|www\.)", candidate, re.IGNORECASE)
        )
        candidates.append((candidate, strong_url_shape))
    if kind == "url":
        return candidates, "url_only_or_url_type_tokens", len(matches)
    return candidates, "explicit_or_bare_url_tokens", len(matches)


def calculate_metrics(y_true: list[int], y_pred: list[int], scores: list[float]) -> dict[str, Any]:
    if not y_true:
        return {"records": 0, "class_counts": {"0": 0, "1": 0}, "metrics": None}
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = map(int, (matrix[0, 0], matrix[0, 1], matrix[1, 0], matrix[1, 1]))
    labels = set(y_true)
    return {
        "records": len(y_true),
        "class_counts": {"0": int(sum(y == 0 for y in y_true)), "1": int(sum(y == 1 for y in y_true))},
        "confusion_matrix_labels_0_1": [[tn, fp], [fn, tp]],
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "TP": tp,
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "specificity": float(tn / (tn + fp)) if tn + fp else None,
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else None,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else None,
        "roc_auc": float(roc_auc_score(y_true, scores)) if labels == {0, 1} else None,
        "average_precision_pr_auc": float(average_precision_score(y_true, scores)) if 1 in labels else None,
        "undefined_metric_note": None if labels == {0, 1} else "ROC-AUC requires both classes; one or more class-dependent rates may be undefined.",
    }


def write_csv(path: Path, header: list[str], rows: Iterable[list[Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(header)
        writer.writerows(rows)


def load_existing_groups(
    records: list[dict[str, Any]], baseline_metrics: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Validate and reuse persisted near-duplicate components without rebuilding them."""
    if not EXISTING_GROUP_MANIFEST.is_file():
        raise FileNotFoundError(f"Existing grouped manifest is missing: {EXISTING_GROUP_MANIFEST}")
    candidate_digest = sha256_file(INPUT)
    recorded_digest = baseline_metrics.get("input", {}).get("sha256")
    if candidate_digest != recorded_digest:
        raise ValueError("Candidate dataset hash does not match the saved grouping/baseline source")

    by_source_index = {
        int(record.get("source_record_index", record["_line_no"])): record
        for record in records
    }
    if len(by_source_index) != len(records):
        raise ValueError("Candidate source_record_index values are not unique")
    seen_source_indices: set[int] = set()
    groups_by_hash: dict[str, dict[str, Any]] = {}
    reasons_by_component: dict[str, set[str]] = defaultdict(set)
    normalized_by_component: dict[str, set[str]] = defaultdict(set)
    qstate_by_component: dict[str, set[str]] = defaultdict(set)
    row_count = 0
    with EXISTING_GROUP_MANIFEST.open("r", encoding="utf-8", newline="") as stream:
        for manifest_line, row in enumerate(csv.DictReader(stream), start=2):
            source_index = int(row["source_record_index"])
            if source_index in seen_source_indices or source_index not in by_source_index:
                raise ValueError(f"Unexpected or duplicate source_record_index {source_index} in grouping manifest")
            seen_source_indices.add(source_index)
            record = by_source_index[source_index]
            line = int(record["_line_no"])
            if int(row["label_original"]) != int(record["_label"]):
                raise ValueError(f"Label mismatch at source record line {line}")
            if row.get("normalized_text_sha256") != record["_normalized_hash"]:
                raise ValueError(f"Normalized-text hash mismatch at source record line {line}")
            component_id = str(row["near_duplicate_component_id"])
            quarantine_state = "quarantine" if row["partition"] == "quarantine" else "eligible"
            if row["promotional_review_flag"].lower() != str(bool(record["_promo"])).lower():
                raise ValueError(f"Promotional-review flag mismatch at source record line {line}")
            if quarantine_state not in {"eligible", "quarantine"}:
                raise ValueError(f"Unknown quarantine state at source record line {line}: {quarantine_state}")
            normalized_hash = str(record["_normalized_hash"])
            group = groups_by_hash.setdefault(
                normalized_hash,
                {
                    "normalized_hash": normalized_hash,
                    "normalized_text": record["_normalized"],
                    "records": [],
                    "labels": set(),
                    "has_promo": False,
                    "component_id": component_id,
                    "quarantine_reasons": [],
                },
            )
            if group["component_id"] != component_id:
                raise ValueError(f"One normalized-text group maps to multiple components at line {line}")
            group["records"].append(record)
            group["labels"].add(int(record["_label"]))
            group["has_promo"] |= bool(record["_promo"])
            normalized_by_component[component_id].add(normalized_hash)
            qstate_by_component[component_id].add(quarantine_state)
            if row.get("quarantine_reason"):
                reasons_by_component[component_id].update(row["quarantine_reason"].split(";"))
            row_count += 1

    if seen_source_indices != set(by_source_index):
        missing = sorted(set(by_source_index) - seen_source_indices)[:10]
        raise ValueError(f"Grouping manifest does not cover every source record; sample missing indices: {missing}")
    if any(len(states) != 1 for states in qstate_by_component.values()):
        raise ValueError("Existing near-duplicate component has inconsistent quarantine states")

    groups = list(groups_by_hash.values())
    for group in groups:
        component_id = str(group["component_id"])
        group["quarantine_reasons"] = sorted(reasons_by_component[component_id])
        group["component_size"] = len(normalized_by_component[component_id])
        group["source_record_count"] = len(group["records"])
        group["label"] = next(iter(group["labels"])) if len(group["labels"]) == 1 else None
        group["representative"] = min(group["records"], key=lambda record: int(record["_line_no"]))
        manifest_quarantined = next(iter(qstate_by_component[component_id])) in {"quarantined", "quarantine"}
        should_quarantine = bool(group["quarantine_reasons"]) or group["label"] is None
        if manifest_quarantined != should_quarantine:
            raise ValueError(f"Existing quarantine decision is inconsistent for component {component_id}")

    group_summary = dict(baseline_metrics["grouping"])
    if len(groups) != group_summary.get("normalized_text_groups"):
        raise ValueError("Persisted manifest normalized-text count differs from baseline metadata")
    if len({str(group["component_id"]) for group in groups}) != group_summary.get("near_duplicate_components"):
        raise ValueError("Persisted manifest near-duplicate component count differs from baseline metadata")
    if row_count != len(records):
        raise ValueError("Persisted manifest source row count differs from candidate data")
    group_summary["reused_manifest"] = str(EXISTING_GROUP_MANIFEST.relative_to(ROOT))
    group_summary["reused_manifest_sha256"] = sha256_file(EXISTING_GROUP_MANIFEST)
    group_summary["reused_and_validated_without_recomputation"] = True
    return groups, group_summary


def compact_group_stats(sizes: list[int]) -> dict[str, Any]:
    if not sizes:
        return {"groups": 0, "median": None, "p90_nearest_rank": None, "p95_nearest_rank": None, "maximum": None}
    return {
        "groups": len(sizes),
        "median": float(np.median(sizes)),
        "p90_nearest_rank": percentile(sizes, 0.90),
        "p95_nearest_rank": percentile(sizes, 0.95),
        "maximum": max(sizes),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Print pre-split domain/component feasibility statistics and exit without assigning partitions or training.",
    )
    args = parser.parse_args()
    if OUTPUT_DIR.exists() and not args.preflight:
        raise FileExistsError(f"Refusing to overwrite existing experiment directory: {OUTPUT_DIR}")
    if not INPUT.is_file() or not BASELINE_METRICS.is_file():
        raise FileNotFoundError("Required candidate data or baseline metrics are missing")

    parser_cases = {
        "HTTPS://WWW.Example.COM.:443/path": ("www.example.com", "normalized_hostname", False),
        "portal.example.co.uk/login": ("portal.example.co.uk", "normalized_hostname", True),
        "https://[2001:db8::1]:443/": ("2001:db8::1", "ip_literal", False),
        "192.0.2.1": ("192.0.2.1", "ip_literal", True),
    }
    for candidate, (expected_host, expected_status, allow_bare) in parser_cases.items():
        if normalize_host_from_url(candidate, allow_bare=allow_bare) != (expected_host, expected_status):
            raise RuntimeError(f"URL normalization smoke check failed for {candidate!r}")
    if normalize_host_from_url("https://example.com:bad/path")[0] is not None:
        raise RuntimeError("Malformed port smoke check unexpectedly produced a hostname")
    if normalize_host_from_url("999.999.999.999", allow_bare=True)[0] is not None:
        raise RuntimeError("Invalid IPv4 smoke check unexpectedly produced a hostname")

    records, source_summary = baseline.load_records(INPUT)
    baseline_metrics = json.loads(BASELINE_METRICS.read_text(encoding="utf-8"))
    groups, duplicate_summary = load_existing_groups(records, baseline_metrics)
    group_by_normalized_hash = {str(group["normalized_hash"]): group for group in groups}
    base_ids = sorted({str(group["component_id"]) for group in groups})
    base_components: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for group in groups:
        base_components[str(group["component_id"])].append(group)

    row_destinations: dict[int, dict[str, Any]] = {}
    normalized_hostnames: set[str] = set()
    malformed_candidate_count = 0
    url_containing_records = 0
    host_parse_status_counts: Counter[str] = Counter()
    host_to_base_components: dict[str, set[str]] = defaultdict(set)
    hosts_by_base_component: dict[str, set[str]] = defaultdict(set)
    domain_keys_by_base_component: dict[str, set[str]] = defaultdict(set)
    candidate_fallback_evidence: dict[str, bool] = defaultdict(bool)
    bare_candidate_count_by_host: Counter[str] = Counter()
    unrecognized_bare_candidate_count = 0

    for record in records:
        line = int(record["_line_no"])
        candidates, extraction_method, token_count = destination_candidates(record)
        if token_count:
            url_containing_records += 1
        parsed_hosts: list[tuple[str, bool]] = []
        for candidate, fallback_ok in candidates:
            host, status = normalize_host_from_url(candidate, allow_bare=True)
            host_parse_status_counts[status] += 1
            if host is None:
                malformed_candidate_count += 1
            else:
                parsed_hosts.append((host, fallback_ok))
                candidate_fallback_evidence[host] |= fallback_ok
                if not fallback_ok:
                    bare_candidate_count_by_host[host] += 1
        base_id = str(group_by_normalized_hash[record["_normalized_hash"]]["component_id"])
        row_destinations[line] = {
            "parsed_hosts": parsed_hosts,
            "hosts": [],
            "base_component_id": base_id,
            "method": extraction_method,
            "url_token_count": token_count,
        }

    candidate_hostnames = sorted(candidate_fallback_evidence)
    psl_map, psl_info = psl_registrable_domains(candidate_hostnames)
    host_group_keys: dict[str, str] = {}
    group_key_status: dict[str, str] = {}
    for host in candidate_hostnames:
        try:
            ip = ipaddress.ip_address(host)
            key = f"ip:{ip.compressed.lower()}"
            status = "exact_ip_literal"
        except ValueError:
            registrable = psl_map.get(host)
            if registrable:
                key = f"registrable:{registrable}"
                status = "registrable_domain_psl"
            elif candidate_fallback_evidence[host]:
                # Fallback only for clearly URL-shaped authorities or URL-only
                # inputs. Bare dotted text without a PSL result is ambiguous.
                key = f"exact_host_fallback:{host}"
                status = "exact_host_fallback_explicit_url_without_psl_domain"
            else:
                unrecognized_bare_candidate_count += bare_candidate_count_by_host[host]
                continue
        host_group_keys[host] = key
        group_key_status[host] = status
    normalized_hostnames = set(host_group_keys)
    for line, row in row_destinations.items():
        row["hosts"] = sorted({host for host, fallback_ok in row["parsed_hosts"]
                               if host in host_group_keys and (fallback_ok or psl_map.get(host) or group_key_status[host] == "exact_ip_literal")})
        base_id = row["base_component_id"]
        hosts_by_base_component[base_id].update(row["hosts"])
    for base_id, hosts in hosts_by_base_component.items():
        for host in hosts:
            key = host_group_keys[host]
            host_to_base_components[key].add(base_id)
            domain_keys_by_base_component[base_id].add(key)

    dsu = DisjointSet(base_ids)
    for component_ids in host_to_base_components.values():
        ordered = sorted(component_ids)
        if len(ordered) > 1:
            anchor = ordered[0]
            for other in ordered[1:]:
                dsu.union(anchor, other)

    component_members: dict[str, list[str]] = defaultdict(list)
    for base_id in base_ids:
        component_members[dsu.find(base_id)].append(base_id)
    domain_component_id_by_base: dict[str, str] = {}
    domain_component_members: dict[str, list[str]] = {}
    for root, members in component_members.items():
        component_id = stable_id("phishing-registrable-domain-component-v1", members)
        domain_component_members[component_id] = sorted(members)
        for base_id in members:
            domain_component_id_by_base[base_id] = component_id

    groups_by_domain_component: dict[str, list[dict[str, Any]]] = defaultdict(list)
    component_quarantine_reasons: dict[str, set[str]] = defaultdict(set)
    component_domain_keys: dict[str, set[str]] = defaultdict(set)
    for group in groups:
        base_id = str(group["component_id"])
        component_id = domain_component_id_by_base[base_id]
        groups_by_domain_component[component_id].append(group)
        component_quarantine_reasons[component_id].update(group["quarantine_reasons"])
        component_domain_keys[component_id].update(domain_keys_by_base_component[base_id])

    quarantined_components = {
        component_id for component_id, reasons in component_quarantine_reasons.items() if reasons
    }
    eligible_groups: list[dict[str, Any]] = []
    quarantined_groups: list[dict[str, Any]] = []
    for group in groups:
        cid = domain_component_id_by_base[str(group["component_id"])]
        if cid in quarantined_components:
            quarantined_groups.append(group)
        else:
            if group["label"] is None:
                raise ValueError("A non-quarantined text group has conflicting labels")
            eligible_groups.append(group)
    if len({int(g["label"]) for g in eligible_groups}) != 2:
        raise ValueError("Both source labels are required in the eligible primary groups")

    # Pre-split component and class audit, before calling the splitter.
    component_text_sizes: list[int] = []
    component_source_sizes: list[int] = []
    mixed_label_components = 0
    class_by_component: dict[str, dict[str, int]] = {}
    top_components: list[dict[str, Any]] = []
    for cid, member_base_ids in domain_component_members.items():
        member_groups = groups_by_domain_component[cid]
        counts = Counter(int(g["label"]) for g in member_groups if g["label"] is not None)
        source_counts = Counter(
            int(r["_label"])
            for g in member_groups
            for r in g["records"]
        )
        if len(counts) > 1:
            mixed_label_components += 1
        component_text_sizes.append(len(member_groups))
        component_source_sizes.append(sum(len(g["records"]) for g in member_groups))
        class_by_component[cid] = {str(k): int(v) for k, v in sorted(counts.items())}
        top_components.append({
            "component_id": cid,
            "unique_text_groups": len(member_groups),
            "source_records": sum(len(g["records"]) for g in member_groups),
            "unique_text_group_counts_by_label": {"0": counts.get(0, 0), "1": counts.get(1, 0)},
            "source_record_counts_by_label": {"0": source_counts.get(0, 0), "1": source_counts.get(1, 0)},
            "domain_group_count": len(component_domain_keys[cid]),
            "quarantined": cid in quarantined_components,
        })
    top_components.sort(key=lambda x: (-x["unique_text_groups"], x["component_id"]))

    eligible_component_ids = sorted({domain_component_id_by_base[str(g["component_id"])] for g in eligible_groups})
    eligible_unique_texts = len(eligible_groups)
    eligible_source_records = sum(len(g["records"]) for g in eligible_groups)
    eligible_unique_text_label_counts = Counter(int(g["label"]) for g in eligible_groups)
    eligible_source_label_counts = Counter(
        int(record["_label"]) for group in eligible_groups for record in group["records"]
    )
    quarantined_source_label_counts = Counter(
        int(record["_label"]) for group in quarantined_groups for record in group["records"]
    )
    biggest_eligible_component = max(
        (len(groups_by_domain_component[cid]) for cid in eligible_component_ids), default=0
    )
    components_over_15pct = [
        cid for cid in eligible_component_ids
        if len(groups_by_domain_component[cid]) > 0.15 * eligible_unique_texts
    ]

    if args.preflight:
        component_label_patterns = Counter()
        for cid in eligible_component_ids:
            labels_in_component = set(class_by_component[cid])
            component_label_patterns["mixed" if len(labels_in_component) == 2 else str(next(iter(labels_in_component), "none"))] += 1
        print(json.dumps({
            "phase": "preflight_before_partition_assignment",
            "records": len(records),
            "url_containing_records": url_containing_records,
            "distinct_normalized_hostnames": len(normalized_hostnames),
            "distinct_registrable_domains": len({v for v in psl_map.values() if v}),
            "hostnames_mapped_to_psl_registrable_domains": sum(bool(v) for v in psl_map.values()),
            "hostnames_using_exact_ip_or_host_fallback": len(host_group_keys) - sum(bool(v) for v in psl_map.values()),
            "normalized_text_groups": duplicate_summary["normalized_text_groups"],
            "existing_near_duplicate_components": duplicate_summary["near_duplicate_components"],
            "combined_components_total": len(domain_component_members),
            "eligible_components": len(eligible_component_ids),
            "quarantined_components_after_domain_propagation": len(quarantined_components),
            "eligible_unique_texts": eligible_unique_texts,
            "eligible_source_records": eligible_source_records,
            "eligible_unique_text_class_counts": {"0": eligible_unique_text_label_counts.get(0, 0), "1": eligible_unique_text_label_counts.get(1, 0)},
            "eligible_source_record_class_counts": {"0": eligible_source_label_counts.get(0, 0), "1": eligible_source_label_counts.get(1, 0)},
            "quarantined_source_record_class_counts": {"0": quarantined_source_label_counts.get(0, 0), "1": quarantined_source_label_counts.get(1, 0)},
            "records_without_destination_hosts": no_destination_rows if 'no_destination_rows' in locals() else len(records) - sum(bool(x["hosts"]) for x in row_destinations.values()),
            "unrecognized_bare_domain_candidates_ignored_without_psl_match": unrecognized_bare_candidate_count,
            "component_label_patterns_unique_text_groups": dict(component_label_patterns),
            "component_size_unique_text_groups": compact_group_stats([len(groups_by_domain_component[cid]) for cid in eligible_component_ids]),
            "component_size_source_records": compact_group_stats([
                sum(len(g["records"]) for g in groups_by_domain_component[cid]) for cid in eligible_component_ids
            ]),
            "components_with_both_labels_total": mixed_label_components,
            "largest_components": top_components[:20],
            "largest_eligible_component_share": biggest_eligible_component / eligible_unique_texts if eligible_unique_texts else None,
            "components_larger_than_15_percent_of_primary_texts": len(components_over_15pct),
            "psl": psl_info,
        }, ensure_ascii=False, indent=2))
        return 0

    # Whole combined components are assigned once by group-aware stratification.
    y = np.asarray([int(group["label"]) for group in eligible_groups], dtype=np.int8)
    domain_component_ids = np.asarray(
        [domain_component_id_by_base[str(group["component_id"])] for group in eligible_groups],
        dtype=object,
    )
    splitter = StratifiedGroupKFold(n_splits=FOLDS, shuffle=True, random_state=SEED)
    fold_for_component: dict[str, int] = {}
    for fold, (_, heldout) in enumerate(
        splitter.split(np.zeros((len(eligible_groups), 1), dtype=np.uint8), y, groups=domain_component_ids)
    ):
        for index in heldout:
            cid = str(domain_component_ids[int(index)])
            prior = fold_for_component.setdefault(cid, fold)
            if prior != fold:
                raise AssertionError("A connected domain component was split across folds")
    if set(fold_for_component) != set(eligible_component_ids):
        raise AssertionError("Some eligible components did not receive a fold")

    def partition_for_component(cid: str) -> str:
        if cid in quarantined_components:
            return "quarantine"
        fold = fold_for_component[cid]
        return "test" if fold < 3 else "validation" if fold < 6 else "train"

    partition_by_component = {
        cid: partition_for_component(cid) for cid in domain_component_members
    }
    partition_by_normalized_hash: dict[str, str] = {}
    partition_by_near_component: dict[str, str] = {}
    part_domain_keys: dict[str, set[str]] = {p: set() for p in ("train", "validation", "test")}
    partition_unique_texts: dict[str, list[dict[str, Any]]] = {p: [] for p in ("train", "validation", "test")}
    for group in groups:
        base_id = str(group["component_id"])
        cid = domain_component_id_by_base[base_id]
        part = partition_by_component[cid]
        prior_hash = partition_by_normalized_hash.setdefault(str(group["normalized_hash"]), part)
        prior_component = partition_by_near_component.setdefault(base_id, part)
        if prior_hash != part or prior_component != part:
            raise AssertionError("Normalized text or existing near-duplicate component split across partitions")
        if part != "quarantine":
            partition_unique_texts[part].append(group)
            part_domain_keys[part].update(domain_keys_by_base_component[base_id])

    train_validation_overlap = part_domain_keys["train"] & part_domain_keys["validation"]
    train_test_overlap = part_domain_keys["train"] & part_domain_keys["test"]
    validation_test_overlap = part_domain_keys["validation"] & part_domain_keys["test"]
    if train_validation_overlap or train_test_overlap or validation_test_overlap:
        raise AssertionError("Domain-group overlap across primary partitions")

    # Every source record must be represented exactly once in the manifest.
    row_lookup = {int(record["_line_no"]): record for record in records}
    if len(row_lookup) != len(records):
        raise AssertionError("Source record line numbers are not unique")
    rows_by_partition: dict[str, list[dict[str, Any]]] = {p: [] for p in ("train", "validation", "test", "quarantine")}
    manifest_rows: list[list[Any]] = []
    for record in records:
        line = int(record["_line_no"])
        group = group_by_normalized_hash[record["_normalized_hash"]]
        base_id = str(group["component_id"])
        cid = domain_component_id_by_base[base_id]
        part = partition_by_component[cid]
        info = row_destinations[line]
        hosts = info["hosts"]
        keys = sorted({host_group_keys[h] for h in hosts})
        registrable = sorted({key.removeprefix("registrable:") for key in keys if key.startswith("registrable:")})
        fallback = sorted({key for key in keys if not key.startswith("registrable:")})
        source_index = int(record.get("source_record_index", line))
        row = {
            "source_record_id": f"{record['source_dataset']}:source_record_{source_index}",
            "source_record_index": source_index,
            "candidate_jsonl_line": line,
            "source_dataset": record["source_dataset"],
            "label_original": int(record["_label"]),
            "inferred_input_type": str(record.get("inferred_input_type", "unknown")),
            "url_containing": bool(info["url_token_count"]),
            "normalized_text_group_id": str(group["normalized_hash"]),
            "near_duplicate_component_id": base_id,
            "domain_component_id": cid,
            "partition": part,
            "destination_hostnames": hosts,
            "registrable_domains": registrable,
            "non_registrable_domain_keys": fallback,
            "destination_extraction_method": info["method"],
            "url_like_token_count": info["url_token_count"],
            "hostname_grouping_status": (
                "registrable_domain" if registrable else
                "ip_or_exact_host_fallback" if fallback else
                "no_extractable_destination_domain"
            ),
            "review_required": bool(record["review_required"]),
            "review_reason": list(record.get("review_reason", [])),
            "quarantine_status": part == "quarantine",
            "quarantine_reasons": sorted(component_quarantine_reasons[cid]),
        }
        rows_by_partition[part].append(row)
        manifest_rows.append([
            row["source_record_id"], source_index, line, row["source_dataset"], row["label_original"],
            row["inferred_input_type"], row["url_containing"], row["normalized_text_group_id"],
            row["near_duplicate_component_id"], cid, part,
            json.dumps(hosts, ensure_ascii=False), json.dumps(registrable, ensure_ascii=False),
            json.dumps(fallback, ensure_ascii=False), info["method"], info["url_token_count"],
            row["hostname_grouping_status"], row["review_required"],
            json.dumps(row["review_reason"], ensure_ascii=False), row["quarantine_status"],
            json.dumps(row["quarantine_reasons"], ensure_ascii=False),
        ])
    if sum(map(len, rows_by_partition.values())) != len(records):
        raise AssertionError("Manifest row count does not match source record count")
    if sum(len(rows_by_partition[p]) for p in ("train", "validation", "test")) != eligible_source_records:
        raise AssertionError("Eligible source records do not reconcile with the manifest")
    if any(row["quarantine_status"] for p in ("train", "validation", "test") for row in rows_by_partition[p]):
        raise AssertionError("Quarantined record entered a primary partition")

    # Fit only on training unique-text representatives; validation/test are not
    # used for vocabulary fitting or threshold selection.
    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            preprocessor=normalize_for_model,
            lowercase=False,
            ngram_range=(1, 2),
            min_df=2,
            max_df=0.995,
            sublinear_tf=True,
            max_features=200000,
        )),
        ("classifier", LogisticRegression(
            C=1.0,
            solver="liblinear",
            class_weight=None,
            max_iter=2000,
            random_state=SEED,
        )),
    ])
    train_groups = partition_unique_texts["train"]
    model.fit(
        [g["representative"]["text"] for g in train_groups],
        [int(g["label"]) for g in train_groups],
    )

    def score_groups(part: str) -> tuple[dict[str, Any], list[int], list[float], list[int]]:
        selected = partition_unique_texts[part]
        texts = [g["representative"]["text"] for g in selected]
        actual = [int(g["label"]) for g in selected]
        scores = model.predict_proba(texts)[:, 1].astype(float).tolist() if selected else []
        pred = [int(score >= THRESHOLD) for score in scores]
        return calculate_metrics(actual, pred, scores), actual, scores, pred

    train_metrics, _, _, _ = score_groups("train")
    validation_metrics, y_validation, scores_validation, pred_validation = score_groups("validation")
    test_metrics, y_test, scores_test, pred_test = score_groups("test")

    test_groups = partition_unique_texts["test"]
    url_indices = [i for i, g in enumerate(test_groups) if URL_RE.search(str(g["representative"]["text"]))]
    url_index_set = set(url_indices)
    non_url_indices = [i for i, g in enumerate(test_groups) if i not in url_index_set]

    def slice_metrics(indices: list[int]) -> dict[str, Any]:
        return calculate_metrics(
            [y_test[i] for i in indices],
            [pred_test[i] for i in indices],
            [scores_test[i] for i in indices],
        )

    input_type_indices: dict[str, list[int]] = defaultdict(list)
    for index, group in enumerate(test_groups):
        kind = str(group["representative"].get("inferred_input_type", "unknown"))
        input_type_indices[kind].append(index)
    by_input_type = {kind: slice_metrics(indices) for kind, indices in sorted(input_type_indices.items())}

    # For URL-bearing text, distinguish URLs grouped by a PSL registrable
    # domain from IP/exact-host fallback URLs and unextractable URLs.
    url_metric_indices: dict[str, list[int]] = defaultdict(list)
    test_row_by_line = {row["candidate_jsonl_line"]: row for row in rows_by_partition["test"]}
    for index, group in enumerate(test_groups):
        if index not in url_index_set:
            continue
        line = int(group["representative"]["_line_no"])
        row = test_row_by_line[line]
        if row["registrable_domains"]:
            url_metric_indices["url_with_registrable_domain"].append(index)
        elif row["non_registrable_domain_keys"]:
            url_metric_indices["url_with_ip_or_exact_host_fallback"].append(index)
        else:
            url_metric_indices["url_without_extractable_destination"].append(index)
    by_url_domain_status = {
        status: slice_metrics(indices) for status, indices in sorted(url_metric_indices.items())
    }

    def classification_block(indices: list[int], title: str) -> str:
        if not indices:
            return f"{title}: no records\n"
        return title + "\n" + classification_report(
            [y_test[i] for i in indices],
            [pred_test[i] for i in indices],
            labels=[0, 1],
            target_names=["benign_source_label_0", "phishing_source_label_1"],
            zero_division=0,
            digits=6,
        )

    # Build split summaries at both record and unique-text levels.
    partition_summary: dict[str, Any] = {}
    eligible_partition_total = sum(len(partition_unique_texts[p]) for p in ("train", "validation", "test"))
    for part in ("train", "validation", "test"):
        part_groups = partition_unique_texts[part]
        part_labels = Counter(int(g["label"]) for g in part_groups)
        part_records = rows_by_partition[part]
        record_labels = Counter(int(row["label_original"]) for row in part_records)
        partition_summary[part] = {
            "unique_text_groups": len(part_groups),
            "source_records": len(part_records),
            "unique_text_class_counts": {"0": part_labels.get(0, 0), "1": part_labels.get(1, 0)},
            "source_record_class_counts": {"0": record_labels.get(0, 0), "1": record_labels.get(1, 0)},
            "unique_text_percentage_of_primary": len(part_groups) / eligible_partition_total if eligible_partition_total else None,
            "source_record_percentage_of_primary": len(part_records) / eligible_source_records if eligible_source_records else None,
        }

    def class_report_for(y_values: list[int], pred_values: list[int]) -> str:
        return classification_report(
            y_values, pred_values, labels=[0, 1],
            target_names=["benign_source_label_0", "phishing_source_label_1"],
            zero_division=0, digits=6,
        )

    dataset_digest = sha256_file(INPUT)
    psl_host_map = {
        host: {
            "registrable_domain": psl_map.get(host),
            "group_key": host_group_keys[host],
            "grouping_status": group_key_status[host],
        }
        for host in sorted(normalized_hostnames)
    }

    destination_host_records = sum(bool(row_destinations[line]["hosts"]) for line in row_destinations)
    no_destination_rows = len(records) - destination_host_records
    base_quarantine_records = sum(len(g["records"]) for g in groups if g["quarantine_reasons"])
    explicitly_flagged = sum(1 for r in records if r["_promo"])
    primary_domain_status_counts = Counter(
        row["hostname_grouping_status"]
        for part in ("train", "validation", "test")
        for row in rows_by_partition[part]
    )

    config = {
        "experiment": "Phishing TF-IDF + Logistic Regression: registrable-domain holdout",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "interpretation": "Exploratory within-dataset domain-held-out evaluation; not independently collected data or real-world validation.",
        "target": {
            "field": "label_original",
            "0": "benign according to the source dataset",
            "1": "phishing according to the source dataset",
            "positive_label": 1,
            "source_dataset": source_summary["source_dataset_values"],
            "source_semantics_note": "The candidate file identifies combined_reduced.json; its public source labels have not been independently adjudicated and no finer record-level source provenance is available.",
        },
        "input": {"path": str(INPUT.relative_to(ROOT)), "sha256": dataset_digest, **source_summary},
        "baseline_reference": {
            "metrics_path": str(BASELINE_METRICS.relative_to(ROOT)),
            "baseline_test_metrics": baseline_metrics["primary_test_metrics"],
            "baseline_split_method": baseline_metrics["split"]["method"],
            "baseline_test_unique_text_count": baseline_metrics["primary_test_metrics"]["records"],
            "baseline_scikit_learn": baseline_metrics["versions"]["scikit_learn"],
            "comparability": "Different test components and split objective; metrics are contextual, not directly equivalent. This experiment also uses the currently active scikit-learn version recorded below.",
        },
        "preprocessing": {
            "group_normalization": "Unicode NFKC, casefold, collapsed whitespace (existing train_text_baseline.normalize_for_group)",
            "model_preprocessing": "Unicode NFKC, lowercase, collapsed whitespace (existing text_normalization.normalize_for_model)",
            "near_duplicate": baseline_metrics["grouping"]["near_duplicate_method"],
            "quarantine_policy": "Reuse existing component-wide promotional-review and conflicting-label quarantine; quarantine propagates through all domain-connected components.",
        },
        "domain_extraction": {
            "offline_only": True,
            "urls_opened_or_resolved": False,
            "normalization": "Parse URL authority locally; lowercase, remove trailing dot, IDNA ASCII encoding, validate DNS labels; canonicalize IP literals.",
            "scheme_policy": "HTTP/HTTPS and protocol-relative URLs are parsed; candidates without a scheme receive an HTTPS parse prefix. URL_RE from preparation is reused to identify scheme-bearing, www, and bare-domain URL-like tokens.",
            "html_policy": "Prefer canonical URL, then og:url, then form actions, then all anchor destinations; do not group image, script, stylesheet, or other resource URLs.",
            "multi_url_policy": "All extracted destination domains on a record are unioned with its existing near-duplicate component, preventing their domains from crossing partitions.",
            "public_suffix_list": psl_info,
            "ip_policy": "IP literals use exact canonical IP grouping keys.",
            "unclassified_hostname_policy": "If the local PSL does not return a registrable domain, use exact normalized host grouping only and mark it as fallback; never infer registrable domains using the last two labels.",
            "no_domain_policy": "Retain records and group by normalized/near-duplicate text component only; report separately because they cannot demonstrate unseen-domain generalization.",
            "no_source_split": "Only combined_reduced.json provenance is available; no source-level holdout is feasible.",
        },
        "model": {
            "pipeline": ["TfidfVectorizer", "LogisticRegression"],
            "vectorizer": {"analyzer": "word", "ngram_range": [1, 2], "min_df": 2, "max_df": 0.995, "max_features": 200000, "sublinear_tf": True, "preprocessor": "normalize_for_model", "lowercase": False},
            "logistic_regression": {"C": 1.0, "solver": "liblinear", "class_weight": None, "max_iter": 2000, "random_state": SEED},
            "input_features": ["text only"],
            "threshold": THRESHOLD,
            "threshold_policy": "Fixed at 0.5 for comparability; no threshold selection or hyperparameter tuning was performed on validation or test data.",
        },
        "split": {
            "algorithm": "StratifiedGroupKFold",
            "n_splits": FOLDS,
            "shuffle": True,
            "random_seed": SEED,
            "fold_assignment": {"test": [0, 1, 2], "validation": [3, 4, 5], "train": list(range(6, FOLDS))},
            "target_proportions": {"train": 0.70, "validation": 0.15, "test": 0.15},
            "actual": partition_summary,
            "quarantine_source_records": len(rows_by_partition["quarantine"]),
            "quarantine_unique_text_groups": len(quarantined_groups),
            "explicit_promotional_review_records": explicitly_flagged,
            "base_near_duplicate_quarantine_records_before_domain_propagation": base_quarantine_records,
            "records_without_destination_hosts_in_primary": sum(
                not bool(row["destination_hostnames"])
                for part in ("train", "validation", "test") for row in rows_by_partition[part]
            ),
            "primary_hostname_grouping_status_counts": dict(primary_domain_status_counts),
        },
        "verification": {
            "source_records_in_manifest": len(manifest_rows),
            "source_record_id_duplicates": len(manifest_rows) - len({row[0] for row in manifest_rows}),
            "normalized_text_overlap_train_validation": 0,
            "normalized_text_overlap_train_test": 0,
            "normalized_text_overlap_validation_test": 0,
            "near_duplicate_component_overlap_train_validation": 0,
            "near_duplicate_component_overlap_train_test": 0,
            "near_duplicate_component_overlap_validation_test": 0,
            "registrable_domain_overlap_train_validation": 0,
            "registrable_domain_overlap_train_test": 0,
            "registrable_domain_overlap_validation_test": 0,
            "all_domain_group_key_overlap_train_validation": 0,
            "all_domain_group_key_overlap_train_test": 0,
            "all_domain_group_key_overlap_validation_test": 0,
            "quarantined_records_in_primary": 0,
            "validation_method": "Computed by set-intersection assertions immediately before and after partition assignment.",
        },
        "environment": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "numpy": np.__version__,
            "scipy": scipy.__version__,
            "joblib": joblib.__version__,
        },
        "outputs": {
            "experiment_config": "experiment_config.json",
            "split_manifest": "split_manifest.csv",
            "metrics": "metrics.json",
            "classification_report": "classification_report.txt",
            "audit_report": "domain_split_audit.md",
            "model": "model.joblib",
        },
    }

    metrics_output = {
        "experiment": config["experiment"],
        "interpretation": config["interpretation"],
        "threshold": THRESHOLD,
        "threshold_policy": config["model"]["threshold_policy"],
        "environment": config["environment"],
        "split_counts": partition_summary,
        "validation_at_threshold_0_5": validation_metrics,
        "test_overall": test_metrics,
        "test_url_containing": slice_metrics(url_indices),
        "test_non_url_containing": slice_metrics(non_url_indices),
        "test_url_by_domain_grouping_status": by_url_domain_status,
        "test_by_inferred_input_type": by_input_type,
        "leakage_checks": config["verification"],
        "limitations": [
            "Within-dataset evaluation on combined_reduced.json; not an independent external test.",
            "Source labels are not independently adjudicated.",
            "Rows without usable destination domains are retained but do not demonstrate unseen-domain generalization.",
            "Domain extraction is syntactic and may miss obfuscated or nonstandard URLs.",
            "Domain components can couple otherwise unrelated examples that share any extracted destination domain.",
        ],
    }

    classification_text = (
        "Domain-held-out phishing classifier; source labels: 0=benign, 1=phishing; threshold=0.5\n"
        "\nOVERALL TEST (unique normalized text groups)\n"
        + class_report_for(list(y_test), list(pred_test))
        + "\nURL-CONTAINING TEST\n"
        + classification_block(url_indices, "URL-containing test")
        + "\nNON-URL TEST\n"
        + classification_block(non_url_indices, "Non-URL test")
    )
    for kind, indices in sorted(input_type_indices.items()):
        classification_text += "\nINPUT TYPE: " + kind + "\n" + classification_block(indices, kind)

    # Detailed audit report is written only after the grouped split is fixed and
    # all required leakage assertions have succeeded.
    target_sizes = {p: t for p, t in (("train", 0.70), ("validation", 0.15), ("test", 0.15))}
    deviations = {
        p: {
            "unique_text_percentage_points": (partition_summary[p]["unique_text_percentage_of_primary"] - target_sizes[p]) * 100,
            "source_record_percentage_points": (partition_summary[p]["source_record_percentage_of_primary"] - target_sizes[p]) * 100,
        }
        for p in target_sizes
    }
    psl_hosts_count = sum(key.startswith("registrable:") for key in host_group_keys.values())
    fallback_host_count = len(host_group_keys) - psl_hosts_count
    report_lines = [
        "# Phishing registrable-domain holdout audit",
        "",
        "This is an exploratory within-dataset experiment. The test set is composed of held-out domain-connected components from the same combined source file; it is not independent real-world validation.",
        "",
        "## Data, target, and preserved workflow",
        "",
        f"- Candidate source: `{INPUT.relative_to(ROOT)}`; SHA-256: `{dataset_digest}`.",
        f"- Candidate records: {len(records):,}; unique normalized text groups: {len(groups):,}; existing near-duplicate components: {duplicate_summary['near_duplicate_components']:,}.",
        f"- Target: `label_original`, 0=benign according to source and 1=phishing according to source. All records come from `{', '.join(source_summary['source_dataset_values'])}`; finer row-level source provenance is unavailable.",
        f"- Original label counts: 0={source_summary['label_counts'].get('0',0):,}; 1={source_summary['label_counts'].get('1',0):,}.",
        f"- Eligible unique-text class counts before split: 0={eligible_unique_text_label_counts.get(0,0):,}; 1={eligible_unique_text_label_counts.get(1,0):,}. Eligible source-record class counts: 0={eligible_source_label_counts.get(0,0):,}; 1={eligible_source_label_counts.get(1,0):,}.",
        f"- Reused existing exact/near-duplicate grouping: NFKC/casefold/whitespace normalization, unique 5-character shingles, 64-bit SHA-256 SimHash radius 3, Jaccard threshold 0.90.",
        f"- Explicit promotional review flags: {explicitly_flagged:,}; all baseline quarantine groups remain quarantined, and quarantine propagates to any connected domain component.",
        "- Training records use text only. The TF-IDF vocabulary is fit by the sklearn pipeline on training groups only.",
        "",
        "## URL and domain inventory before partitioning",
        "",
        f"- URL-like records identified syntactically: {url_containing_records:,}.",
        f"- Distinct normalized destination hostnames: {len(normalized_hostnames):,}.",
        f"- Hostnames mapped by the local PSL to registrable domains: {psl_hosts_count:,}.",
        f"- Distinct registrable domains: {len({v for v in psl_map.values() if v}):,}.",
        f"- Hostnames handled as IP or exact-host fallback (not registrable-domain keys): {fallback_host_count:,}.",
        f"- Bare dotted candidates without a PSL mapping that were intentionally ignored instead of exact-host grouped: {unrecognized_bare_candidate_count:,}.",
        f"- Records with at least one selected destination hostname: {destination_host_records:,}; records without one: {no_destination_rows:,}.",
        f"- Malformed/unusable URL candidate tokens: {malformed_candidate_count:,}; URL parser status counts: `{dict(host_parse_status_counts)}`.",
        f"- Existing normalized-text groups: {duplicate_summary['normalized_text_groups']:,}; existing near-duplicate components: {duplicate_summary['near_duplicate_components']:,}.",
        f"- Combined connected components after PSL/domain linking (including quarantined): {len(domain_component_members):,}; eligible components: {len(eligible_component_ids):,}; quarantined components: {len(quarantined_components):,}.",
        f"- Connected component sizes in unique normalized text groups: `{json.dumps(compact_group_stats(component_text_sizes))}`.",
        f"- Connected component sizes in source records: `{json.dumps(compact_group_stats(component_source_sizes))}`.",
        f"- Components containing both labels among non-conflicting unique text groups: {mixed_label_components:,}.",
        f"- Largest eligible component: {biggest_eligible_component:,} unique texts ({biggest_eligible_component/eligible_unique_texts:.2%} of eligible unique texts). Components larger than 15% of the eligible unique text pool: {len(components_over_15pct)}.",
        "",
        "### Largest connected components",
        "",
        "| Component | Unique texts | Source records | Unique texts label 0 | Unique texts label 1 | Domain keys | Quarantined |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for item in top_components[:10]:
        report_lines.append(
            f"| `{item['component_id'][:12]}` | {item['unique_text_groups']:,} | {item['source_records']:,} | {item['unique_text_group_counts_by_label']['0']:,} | {item['unique_text_group_counts_by_label']['1']:,} | {item['domain_group_count']:,} | {item['quarantined']} |"
        )
    largest = top_components[0]
    largest_cid = largest["component_id"]
    report_lines.extend([
        "",
        f"Largest component detail: `{largest_cid}`; quarantine reasons: `{sorted(component_quarantine_reasons[largest_cid])}`; example domain group keys: `{sorted(component_domain_keys[largest_cid])[:20]}`.",
        f"Existing near-duplicate quarantine records before domain propagation: {base_quarantine_records:,}. Records assigned to quarantine after conservative domain-component propagation: {len(rows_by_partition['quarantine']):,} (labels 0={quarantined_source_label_counts.get(0,0):,}, 1={quarantined_source_label_counts.get(1,0):,}). These records remain in the complete split manifest but are excluded from primary fitting/evaluation under the existing review policy; this is explicitly reported and is not a metric-driven removal.",
    ])
    report_lines.extend([
        "",
        "## Split and class distribution",
        "",
        "The deterministic `StratifiedGroupKFold(n_splits=20, shuffle=True, random_state=20261026)` assignment maps folds 0–2 to test, 3–5 to validation, and 6–19 to training. Each connected component is indivisible. The percentages below are based on unique normalized text groups; source-record percentages are included as a secondary accounting measure.",
        "",
        "| Partition | Unique texts | Source records | Unique-text label 0 | Unique-text label 1 | Unique-text % | Record % | Deviation from target (unique text / records, pp) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for part in ("train", "validation", "test"):
        item = partition_summary[part]
        report_lines.append(
            f"| {part} | {item['unique_text_groups']:,} | {item['source_records']:,} | {item['unique_text_class_counts']['0']:,} | {item['unique_text_class_counts']['1']:,} | {item['unique_text_percentage_of_primary']:.2%} | {item['source_record_percentage_of_primary']:.2%} | {deviations[part]['unique_text_percentage_points']:+.2f} / {deviations[part]['source_record_percentage_points']:+.2f} |"
        )
    report_lines.extend([
        "",
        "## Leakage and quarantine verification",
        "",
        f"- Source records in manifest: {len(manifest_rows):,}; unique source record IDs: {len({row[0] for row in manifest_rows}):,}; each input line appears once.",
        "- Registrable-domain key intersections (train/validation, train/test, validation/test): 0 / 0 / 0.",
        "- All domain grouping key intersections, including exact IP and exact-host fallback (same pairs): 0 / 0 / 0.",
        "- Normalized-text group intersections (same pairs): 0 / 0 / 0.",
        "- Existing near-duplicate component intersections (same pairs): 0 / 0 / 0.",
        "- Quarantined records in primary splits: 0; all source records remain represented in the manifest.",
        "- Host extraction is local URL parsing only. No URL was opened, no DNS was queried, and no external network request was made.",
        "",
        "## Model and results",
        "",
        f"- Same baseline configuration: word TF-IDF unigrams+bigrams, min_df=2, max_df=0.995, max_features=200000, sublinear TF; LogisticRegression C=1, liblinear, max_iter=2000. Threshold={THRESHOLD:.1f}.",
        f"- Runtime: Python {platform.python_version()}, scikit-learn {sklearn.__version__}, NumPy {np.__version__}, SciPy {scipy.__version__}.",
        f"- Overall test metrics: `{json.dumps(test_metrics, sort_keys=True)}`.",
        f"- URL-containing test metrics: `{json.dumps(slice_metrics(url_indices), sort_keys=True)}`.",
        f"- Non-URL-containing test metrics: `{json.dumps(slice_metrics(non_url_indices), sort_keys=True)}`.",
        f"- URL test by host-group status: `{json.dumps(by_url_domain_status, sort_keys=True)}`.",
        "- Test class reports by overall, URL/non-URL, and inferred input type are in `classification_report.txt`; detailed metrics are in `metrics.json`.",
        "",
        "## Comparison with the existing grouped-text baseline",
        "",
        f"The saved grouped-text baseline test set contains {baseline_metrics['primary_test_metrics']['records']:,} unique normalized texts and reported F1={baseline_metrics['primary_test_metrics']['f1']:.6f}, specificity={baseline_metrics['primary_test_metrics']['specificity']:.6f}, ROC-AUC={baseline_metrics['primary_test_metrics']['roc_auc']:.6f}. This new test partition is selected by connected registrable-domain components and has a different set of examples, while the old split was grouped by text/near-duplicates. The existing test set was already inspected. The experiments are therefore not paired or directly equivalent; differences are descriptive and do not establish domain generalization beyond this source corpus.",
        "",
        "## Caveats and interpretation",
        "",
        "- URL records with registrable domains can test whether the model transfers to domains held out by this split. The no-domain and exact-host fallback slices do not establish unseen registrable-domain generalization.",
        "- Multiple HTML anchor/form destinations are all grouped; this can connect otherwise unrelated pages and enlarge components. Resource URLs (images, scripts, stylesheets) are excluded to reduce unrelated joins. Component sizes and deviations are reported rather than weakening grouping.",
        "- Exact-host fallback is used only for IP literals or clearly URL-shaped authorities (scheme, protocol-relative, `www`, or URL-only records) when the PSL has no registrable result. Bare dotted prose without a PSL result is ignored, not treated as a destination host. Such exact-host keys do not merge subdomains.",
        "- The split is within one combined source file; per-record source IDs, independently adjudicated labels, and independent modern-domain samples are unavailable.",
        "- The existing development baseline used scikit-learn "+str(baseline_metrics["versions"]["scikit_learn"])+"; this run records its active runtime version separately. The pipeline configuration is matched, but library versions and test partitions differ.",
        "- No test-set tuning was performed; threshold remained fixed at 0.5.",
        "",
        "## Artifacts",
        "",
        "- `experiment_config.json` — input hashes, environment, feature/model setup, split, and artifact paths.",
        "- `split_manifest.csv` — one row per source record with text, near-duplicate, domain component, label, domain, partition, and quarantine identifiers.",
        "- `metrics.json` — overall, URL, non-URL, input-type, and domain-status test metrics plus leakage checks.",
        "- `classification_report.txt` — classification reports by slice.",
        "- `domain_split_audit.md` — this audit and interpretation.",
        "- `model.joblib` — separately saved pipeline; existing models are untouched.",
        "",
    ])

    # Stage all new outputs, then publish the directory atomically and only if
    # it remains absent. No existing experiment artifact is overwritten.
    with tempfile.TemporaryDirectory(prefix=".phishing_domain_holdout_", dir=REPORT_ROOT) as temp_name:
        stage = Path(temp_name)
        manifest_path = stage / "split_manifest.csv"
        write_csv(
            manifest_path,
            [
                "source_record_id", "source_record_index", "candidate_jsonl_line", "source_dataset", "label_original",
                "inferred_input_type", "url_containing", "normalized_text_group_id",
                "near_duplicate_component_id", "domain_component_id", "partition",
                "destination_hostnames_json", "registrable_domains_json", "non_registrable_domain_keys_json",
                "destination_extraction_method", "url_like_token_count", "hostname_grouping_status",
                "review_required", "review_reason_json", "quarantine_status", "quarantine_reasons_json",
            ], manifest_rows,
        )
        (stage / "experiment_config.json").write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (stage / "metrics.json").write_text(json.dumps(metrics_output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (stage / "classification_report.txt").write_text(classification_text + "\n", encoding="utf-8")
        (stage / "domain_split_audit.md").write_text("\n".join(report_lines), encoding="utf-8")
        joblib.dump(model, stage / "model.joblib")
        if OUTPUT_DIR.exists():
            raise FileExistsError(f"Refusing to overwrite existing experiment directory: {OUTPUT_DIR}")
        os.rename(stage, OUTPUT_DIR)

    print(json.dumps({
        "output_dir": str(OUTPUT_DIR.relative_to(ROOT)),
        "manifest_records": len(manifest_rows),
        "eligible_unique_texts": eligible_unique_texts,
        "eligible_source_records": eligible_source_records,
        "quarantined_source_records": len(rows_by_partition["quarantine"]),
        "distinct_hostnames": len(normalized_hostnames),
        "distinct_registrable_domains": len({v for v in psl_map.values() if v}),
        "connected_components": len(domain_component_members),
        "partition_summary": partition_summary,
        "test_overall": test_metrics,
        "test_url_containing": slice_metrics(url_indices),
        "test_non_url_containing": slice_metrics(non_url_indices),
        "leakage_checks": config["verification"],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
