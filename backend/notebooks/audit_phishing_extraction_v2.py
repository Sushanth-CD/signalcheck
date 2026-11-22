"""Stream the original phishing corpus through the isolated V2 extractor.

Run from the repository root with the ML environment and bundled JDK:
    python backend/notebooks/audit_phishing_extraction_v2.py

The script is offline, read-only with respect to inputs, and refuses to
overwrite its output directory. It neither trains nor splits a model dataset.
"""
from __future__ import annotations

import csv
import json
import os
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.notebooks import phishing_url_extraction_v2 as extraction
from backend.notebooks.prepare_ml_datasets import iter_json_array
from backend.ml.psl_service import (
    is_psl_suffix,
    load_psl_rules,
    psl_registrable_domains,
    sha256_file,
)
from backend.tests.test_phishing_url_extraction_v2 import run_parser_cases

SOURCE = ROOT / "backend/data/raw/combined_reduced.json"
OUTPUT_DIR = ROOT / "backend/reports/ml/phishing_domain_extraction_v2"


class DisjointSet:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}
        self.size: dict[str, int] = {}

    def add(self, value: str) -> None:
        if value not in self.parent:
            self.parent[value] = value
            self.size[value] = 1

    def find(self, value: str) -> str:
        parent = self.parent[value]
        if parent != value:
            self.parent[value] = self.find(parent)
        return self.parent[value]

    def union(self, left: str, right: str) -> None:
        a, b = self.find(left), self.find(right)
        if a == b:
            return
        if self.size[a] < self.size[b]:
            a, b = b, a
        self.parent[b] = a
        self.size[a] += self.size[b]


def _source_id(index: int) -> str:
    return f"combined_reduced.json:source_record_{index}"


def _text(record: dict[str, Any], index: int) -> str:
    value = record.get("text")
    if not isinstance(value, str):
        raise ValueError(f"Source record {index} has non-string text; refusing to silently coerce it")
    return value


def _candidate_status(candidate: extraction.Candidate, psl_map: dict[str, str | None],
                      psl_rules: tuple[set[str], set[str], set[str]]) -> extraction.Candidate:
    host = candidate.normalized_hostname
    return extraction.apply_psl(
        candidate,
        psl_map.get(host or ""),
        is_public_suffix=bool(host and is_psl_suffix(host, psl_rules)),
    )


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_parser_csv(path: Path, rows: list[dict[str, object]]) -> None:
    fields = [
        "case", "pass", "candidate_count", "candidate_text", "hostname", "registrable_domain",
        "evidence", "confidence", "grouping_key", "status", "reason", "actual_json", "expected_json",
    ]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                **{key: row.get(key, "") for key in fields},
                "actual_json": json.dumps({k: v for k, v in row.items() if k not in {"case", "input", "expected", "pass"}}, ensure_ascii=False),
                "expected_json": json.dumps(row.get("expected", {}), ensure_ascii=False),
            })


def _policy_text(psl_metadata: dict[str, Any], parser_pass: int, parser_total: int) -> str:
    return f"""# Phishing URL Extraction V2 policy

## Scope

This is an offline candidate extraction and grouping audit. It does not open
URLs, use DNS, train a model, modify labels, or create a split. Source record
IDs are the stable one-based positions in combined_reduced.json:
combined_reduced.json:source_record_<index>. The original text and source
label remain read-only inputs.

## Candidate evidence and grouping

- Absolute HTTP/HTTPS URLs, protocol-relative URLs, and www. destinations
  are high-confidence candidates only when syntactic hostname validation and
  the pinned Public Suffix List identify a registrable domain, or the host is
  a valid IP literal.
- HTML canonical and Open Graph URLs are document metadata. Anchor href and
  form action values are clickable/form destinations. These evidence types
  remain separate. Image, script, stylesheet, and navigation resources are
  not extracted as destinations.
- Bare dotted strings are ambiguous mentions. Bare domains with path/query
  material or nearby destination language are marked probable, but remain
  medium confidence and do not generate grouping keys.
- Relative HTML references have no base URL and remain unresolved. mailto:,
  javascript:, data:, empty attributes, invalid ports, malformed hosts,
  public-suffix-only values, and hosts without a PSL registrable result are
  retained with explicit statuses and no fallback key.
- Repeated HTTP/HTTPS schemes inside a single token define deterministic
  separate URL boundaries. No arbitrary trailing letters are trimmed from a
  hostname.
- Only registrable:<domain> keys from high-confidence PSL-mapped
  destinations and ip:<address> keys from high-confidence valid IP
  destinations participate in connected components.

## Public Suffix List

Registrable domains are provided by the existing Oracle JDK
RegisteredDomain implementation and its bundled PSL. The lookup is local
only. Snapshot metadata: {json.dumps(psl_metadata, ensure_ascii=False, sort_keys=True)}.

## Parser fixtures

The parser fixture run recorded {parser_pass}/{parser_total} passing cases.
Its individual expected and observed values are in parser_test_results.csv.
"""


def main() -> int:
    if not SOURCE.is_file():
        raise FileNotFoundError(SOURCE)
    if OUTPUT_DIR.exists():
        raise FileExistsError(f"Refusing to overwrite existing V2 audit directory: {OUTPUT_DIR}")
    OUTPUT_DIR.parent.mkdir(parents=True, exist_ok=True)

    parser_rows = run_parser_cases()
    parser_pass = sum(bool(row["pass"]) for row in parser_rows)
    parser_total = len(parser_rows)
    source_hash = sha256_file(SOURCE)
    record_count = 0
    labels: Counter[str] = Counter()
    hostnames: set[str] = set()
    candidate_count = 0
    # First sequential pass collects only parseable hostname keys, not raw texts.
    for index, record in enumerate(iter_json_array(SOURCE), start=1):
        record_count += 1
        if "label" not in record:
            raise ValueError(f"Source record {index} has no original label")
        if str(record["label"]) not in {"0", "1"}:
            raise ValueError(f"Unexpected source label {record['label']!r} at record {index}")
        labels[str(record["label"])] += 1
        text = _text(record, index)
        for candidate in extraction.extract_candidates(_source_id(index), text):
            candidate_count += 1
            if candidate.normalized_hostname and candidate.parser_status in {
                "normalized_hostname", "ambiguous_bare_domain_mention", "ip_literal", "ambiguous_ip_mention"
            } and candidate.parser_status not in {"ip_literal", "ambiguous_ip_mention"}:
                hostnames.add(candidate.normalized_hostname)
    if not record_count:
        raise ValueError("Raw source dataset contains no records")
    psl_map, psl_metadata = psl_registrable_domains(sorted(hostnames))
    psl_rules = load_psl_rules()

    evidence_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    registrable_candidate_count = 0
    registrable_domains: set[str] = set()
    grouping_keys: set[str] = set()
    ip_keys: set[str] = set()
    records_without_key = 0
    records_multiple_keys = 0
    records_with_multiple_hosts = 0
    records_with_explicit_candidate: set[str] = set()
    records_with_explicit: set[str] = set()
    records_with_www: set[str] = set()
    records_with_bare: set[str] = set()
    records_with_probable_bare: set[str] = set()
    records_ambiguous: set[str] = set()
    records_html_meta: set[str] = set()
    records_html_anchor: set[str] = set()
    records_form: set[str] = set()
    records_ip: set[str] = set()
    owner_by_key: dict[str, str] = {}
    components = DisjointSet()
    component_keys: dict[str, set[str]] = defaultdict(set)

    temp_dir = Path(tempfile.mkdtemp(prefix=".phishing-url-v2-", dir=OUTPUT_DIR.parent))
    try:
        suspicious_path = temp_dir / "suspicious_candidates.csv"
        with suspicious_path.open("w", encoding="utf-8", newline="") as suspicious_stream:
            fields = [
                "source_record_id", "source_label_original", "start", "end", "candidate_text",
                "extraction_method", "evidence_category", "confidence", "parser_status",
                "normalized_hostname", "registrable_domain", "domain_grouping_key", "rejection_reason",
            ]
            writer = csv.DictWriter(suspicious_stream, fieldnames=fields)
            writer.writeheader()
            for index, record in enumerate(iter_json_array(SOURCE), start=1):
                record_id = _source_id(index)
                components.add(record_id)
                text = _text(record, index)
                label = str(record["label"])
                found = extraction.extract_candidates(record_id, text)
                record_keys: set[str] = set()
                record_hosts: set[str] = set()
                for candidate in found:
                    candidate = _candidate_status(candidate, psl_map, psl_rules)
                    evidence_counts[candidate.evidence_category] += 1
                    status_counts[candidate.parser_status] += 1
                    if candidate.evidence_category == "explicit_http_url":
                        records_with_explicit_candidate.add(record_id)
                    if candidate.normalized_hostname:
                        record_hosts.add(candidate.normalized_hostname)
                    if candidate.registrable_domain:
                        registrable_candidate_count += 1
                        registrable_domains.add(candidate.registrable_domain)
                    key = candidate.domain_grouping_key
                    if key:
                        record_keys.add(key)
                        grouping_keys.add(key)
                        if key.startswith("ip:"):
                            ip_keys.add(key)
                            records_ip.add(record_id)
                        if key in owner_by_key:
                            components.union(record_id, owner_by_key[key])
                        else:
                            owner_by_key[key] = record_id
                        component_keys[record_id].add(key)
                    if candidate.evidence_category == "explicit_http_url" and key:
                        records_with_explicit.add(record_id)
                    if candidate.evidence_category == "www_url" and key:
                        records_with_www.add(record_id)
                    if candidate.evidence_category == "bare_domain_mention":
                        records_with_bare.add(record_id)
                    if candidate.evidence_category == "probable_bare_destination":
                        records_with_probable_bare.add(record_id)
                    if candidate.confidence != "high" or not key:
                        records_ambiguous.add(record_id)
                        writer.writerow({
                            "source_record_id": candidate.source_record_id,
                            "source_label_original": label,
                            "start": candidate.start,
                            "end": candidate.end,
                            "candidate_text": candidate.candidate_text,
                            "extraction_method": candidate.extraction_method,
                            "evidence_category": candidate.evidence_category,
                            "confidence": candidate.confidence,
                            "parser_status": candidate.parser_status,
                            "normalized_hostname": candidate.normalized_hostname or "",
                            "registrable_domain": candidate.registrable_domain or "",
                            "domain_grouping_key": key or "",
                            "rejection_reason": candidate.rejection_reason or "",
                        })
                    if candidate.evidence_category in {"html_canonical", "html_open_graph"} and key:
                        records_html_meta.add(record_id)
                    if candidate.evidence_category == "html_anchor" and key:
                        records_html_anchor.add(record_id)
                    if candidate.evidence_category == "html_form" and key:
                        records_form.add(record_id)
                if len(record_hosts) > 1:
                    records_with_multiple_hosts += 1
                if len(record_keys) > 1:
                    records_multiple_keys += 1
                if not record_keys:
                    records_without_key += 1
                component_keys[record_id].update(record_keys)

        if sum(evidence_counts.values()) != candidate_count:
            raise ValueError(
                "Candidate count changed between the two streaming passes; source data or parser behavior is inconsistent"
            )

        component_sizes: Counter[int] = Counter()
        root_key_sets: dict[str, set[str]] = defaultdict(set)
        for record_id in components.parent:
            root = components.find(record_id)
            component_sizes[components.size[root]] += 1
            root_key_sets[root].update(component_keys.get(record_id, set()))
        size_distribution = sorted(
            ({"records": size, "component_count": count // size} for size, count in component_sizes.items()),
            key=lambda row: int(row["records"]),
        )
        largest_components = sorted(
            ({"component_id": root, "records": components.size[root], "distinct_destination_keys": len(keys)}
             for root, keys in root_key_sets.items()),
            key=lambda row: (-int(row["records"]), str(row["component_id"])),
        )[:25]
        multi_key_components = sum(len(keys) > 1 for keys in root_key_sets.values())
        audit = {
            "status": "completed",
            "source_file": str(SOURCE.relative_to(ROOT)),
            "source_sha256": source_hash,
            "source_records": record_count,
            "original_label_counts": dict(sorted(labels.items())),
            "source_label_meaning": {"0": "benign", "1": "phishing", "basis": "source dataset documentation; labels are not changed"},
            "candidate_count_first_pass": candidate_count,
            "candidate_count_second_pass": sum(evidence_counts.values()),
            "distinct_normalized_hostnames_queried": len(hostnames),
            "psl": psl_metadata,
            "candidate_evidence_counts": dict(sorted(evidence_counts.items())),
            "candidate_parser_status_counts": dict(sorted(status_counts.items())),
            "records_with_explicit_http_https_destinations": len(records_with_explicit),
            "records_with_explicit_http_https_candidates_including_unresolved": len(records_with_explicit_candidate),
            "records_with_www_destinations": len(records_with_www),
            "records_with_bare_domain_mentions": len(records_with_bare),
            "records_with_probable_bare_destinations": len(records_with_probable_bare),
            "records_with_ambiguous_or_unresolved_candidates": len(records_ambiguous),
            "records_with_html_metadata_destinations": len(records_html_meta),
            "records_with_html_anchor_destinations": len(records_html_anchor),
            "records_with_html_form_destinations": len(records_form),
            "records_with_valid_ip_destinations": len(records_ip),
            "records_with_multiple_distinct_destination_hosts": records_with_multiple_hosts,
            "records_with_multiple_destination_grouping_keys": records_multiple_keys,
            "records_without_confident_destination_keys": records_without_key,
            "malformed_candidate_count": sum(v for k, v in status_counts.items()
                                              if k in {"malformed_url", "invalid_port", "invalid_hostname", "html_parse_error"}),
            "public_suffix_only_candidate_count": status_counts.get("public_suffix_only", 0),
            "unknown_suffix_candidate_count": status_counts.get("unknown_suffix", 0),
            "valid_registrable_domain_candidate_count": registrable_candidate_count,
            "distinct_valid_registrable_domains": len(registrable_domains),
            "distinct_registrable_domain_grouping_keys": sum(k.startswith("registrable:") for k in grouping_keys),
            "distinct_ip_grouping_keys": len(ip_keys),
            "parser_fixture_cases": parser_total,
            "parser_fixture_passed": parser_pass,
            "parser_fixture_failed": parser_total - parser_pass,
            "v1_parser_issue_checks": {
                "public_suffix_only_rejected_without_key": next((
                    row["pass"] for row in parser_rows if row["case"] == "public suffix only"
                ), False),
                "ordinary_bare_domain_not_grouped": next((
                    row["pass"] for row in parser_rows if row["case"] == "bare domain prose"
                ), False),
                "unknown_url_shaped_host_not_grouped": next((
                    row["pass"] for row in parser_rows if row["case"] == "URL followed by prose"
                ), False),
                "concatenated_schemes_split": next((
                    row["pass"] for row in parser_rows if row["case"] == "concatenated URLs"
                ), False),
            },
        }
        grouping = {
            "distinct_registrable_domain_grouping_keys": sum(k.startswith("registrable:") for k in grouping_keys),
            "distinct_ip_grouping_keys": len(ip_keys),
            "distinct_reliable_grouping_keys_total": len(grouping_keys),
            "records_with_multiple_destination_keys": records_multiple_keys,
            "records_without_reliable_destination_key": records_without_key,
            "connected_components_including_no-key_singletons": len(root_key_sets),
            "component_size_distribution": size_distribution,
            "largest_components": largest_components,
            "components_connected_through_multiple_destination_keys": multi_key_components,
            "records_connected_through_multiple_destination_links": records_multiple_keys,
            "component_size_semantics": "all source records are included; records with no key are singleton components",
        }
        _write_parser_csv(temp_dir / "parser_test_results.csv", parser_rows)
        _write_json(temp_dir / "domain_extraction_audit.json", audit)
        _write_json(temp_dir / "grouping_diagnostics.json", grouping)
        (temp_dir / "extraction_policy.md").write_text(_policy_text(psl_metadata, parser_pass, parser_total), encoding="utf-8")
        report_lines = [
            "# Phishing URL Extraction V2 dataset audit", "",
            f"- Source records: {record_count:,}",
            f"- Original labels: {json.dumps(dict(sorted(labels.items())), sort_keys=True)}",
            "- Label interpretation: 0 = benign and 1 = phishing according to the source documentation; labels are preserved.",
            f"- Extracted candidates: {sum(evidence_counts.values()):,}",
            f"- Records with valid HTTP(S) destination URLs: {len(records_with_explicit):,}",
            f"- Records with www. destinations: {len(records_with_www):,}",
            f"- Records with bare-domain mentions / probable bare destinations: {len(records_with_bare):,} / {len(records_with_probable_bare):,}",
            f"- Records with ambiguous or unresolved candidates: {len(records_ambiguous):,}",
            f"- Records with HTML canonical/Open Graph destinations: {len(records_html_meta):,}",
            f"- Records with HTML anchor destinations: {len(records_html_anchor):,}",
            f"- Records with HTML form destinations: {len(records_form):,}",
            f"- Records with valid IP destinations: {len(records_ip):,}",
            f"- Records with multiple hostnames / grouping keys: {records_with_multiple_hosts:,} / {records_multiple_keys:,}",
            f"- Records without reliable grouping keys: {records_without_key:,}",
            f"- Malformed / public-suffix-only / unknown-suffix candidates: {audit['malformed_candidate_count']:,} / {audit['public_suffix_only_candidate_count']:,} / {audit['unknown_suffix_candidate_count']:,}",
            f"- Distinct PSL-resolved domains observed / reliable registrable keys / IP keys: "
            f"{len(registrable_domains):,} / {sum(k.startswith('registrable:') for k in grouping_keys):,} / {len(ip_keys):,}",
            f"- Parser fixtures: {parser_pass}/{parser_total} passed", "",
            "## Grouping diagnostics", "",
            f"- Reliable destination keys: {len(grouping_keys):,}",
            f"- Connected components: {len(root_key_sets):,}",
            f"- Components linking multiple destination keys: {multi_key_components:,}",
            "- Largest components (records, key count):",
        ]
        report_lines.extend(
            f"  - {row['component_id'][:16]}: {row['records']:,} records, {row['distinct_destination_keys']:,} keys"
            for row in largest_components[:10]
        )
        report_lines += [
            "", "## Interpretation and limits", "",
            "Grouping diagnostics are descriptive only. No split was created. Bare prose mentions, malformed "
            "candidates, public-suffix-only values, unknown suffixes, and relative HTML links do not create keys. "
            "The suspicious-candidate file lists ambiguous, malformed, or unresolved candidates for review; it does "
            "not imply maliciousness.", "",
            "The extractor uses the existing local JDK PSL snapshot. The dataset may contain concatenated or "
            "truncated content and does not establish that an identified host was the actual user-facing destination. "
            "Review the candidate file and grouping diagnostics before using V2 for a held-out experiment.", "",
            "Compared with the prior audit's documented parser failures, the V2 fixtures specifically check that "
            "public-suffix-only values, ordinary prose domains, and URL-shaped unknown-suffix hosts receive no key; "
            "that repeated schemes are split into separate candidates; and that trailing letters are left unresolved "
            "rather than trimmed. These fixture results are not a claim that all corpus cases are resolved.", "",
        ]
        (temp_dir / "domain_extraction_audit.md").write_text("\n".join(report_lines), encoding="utf-8")
        if OUTPUT_DIR.exists():
            raise FileExistsError(f"Refusing to overwrite V2 audit directory: {OUTPUT_DIR}")
        os.rename(temp_dir, OUTPUT_DIR)
    except Exception:
        if temp_dir.exists():
            import shutil
            shutil.rmtree(temp_dir)
        raise
    print(json.dumps({"output_dir": str(OUTPUT_DIR.relative_to(ROOT)), **audit}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
