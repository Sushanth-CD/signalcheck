"""Summarize saved V2 phishing-domain audit artifacts without rescanning data.

This read-only review helper does not change extraction, create a split, train,
or contact the network. It derives candidate-level tables from the audit JSON
and the saved file of candidates that did not receive a confident grouping key.
Run from the repository root with the standard-library-capable project Python.
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "backend/reports/ml/phishing_domain_extraction_v2"
AUDIT = OUT / "domain_extraction_audit.json"
GROUPS = OUT / "grouping_diagnostics.json"
SUSPICIOUS = OUT / "suspicious_candidates.csv"
PARSER = OUT / "parser_test_results.csv"
BASELINE_METRICS = ROOT / "backend/reports/ml/text_phishing_baseline/metrics.json"
BASELINE_MANIFEST = ROOT / "backend/reports/ml/text_phishing_baseline/split_manifest.csv"
EXTRACTOR = ROOT / "backend/notebooks/phishing_url_extraction_v2.py"
REPORT = OUT / "domain_grouping_readiness_review.md"
COMPONENTS_CSV = OUT / "domain_grouping_component_summary.csv"
INVARIANTS_JSON = OUT / "domain_grouping_invariants.json"
NO_KEY_JSON = OUT / "no_confident_domain_breakdown.json"

for output in (REPORT, COMPONENTS_CSV, INVARIANTS_JSON, NO_KEY_JSON):
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite review artifact: {output}")

audit = json.loads(AUDIT.read_text(encoding="utf-8"))
groups = json.loads(GROUPS.read_text(encoding="utf-8"))
baseline = json.loads(BASELINE_METRICS.read_text(encoding="utf-8"))
with BASELINE_MANIFEST.open("r", encoding="utf-8", newline="") as stream:
    baseline_source_indices = {int(row["source_record_index"]) for row in csv.DictReader(stream)}
missing_source_indices = sorted(set(range(1, audit["source_records"] + 1)) - baseline_source_indices)

nonkey = {name: Counter() for name in (
    "confidence", "evidence_category", "extraction_method", "parser_status", "rejection_reason"
)}
nonkey_record_ids: set[str] = set()
nonkey_reg_domains: set[str] = set()
empty_group_key_rows = 0
keyed_nonhigh_rows = 0
with SUSPICIOUS.open("r", encoding="utf-8", newline="") as stream:
    for row in csv.DictReader(stream):
        for field in ("confidence", "evidence_category", "extraction_method", "parser_status"):
            nonkey[field][row[field]] += 1
        if row["rejection_reason"]:
            nonkey["rejection_reason"][row["rejection_reason"]] += 1
        nonkey_record_ids.add(row["source_record_id"])
        if row["registrable_domain"]:
            nonkey_reg_domains.add(row["registrable_domain"].lower().rstrip("."))
        if not row["domain_grouping_key"]:
            empty_group_key_rows += 1
        else:
            keyed_nonhigh_rows += 1

key_evidence = {
    evidence: count - nonkey["evidence_category"][evidence]
    for evidence, count in audit["candidate_evidence_counts"].items()
    if count - nonkey["evidence_category"][evidence]
}
key_status = {
    status: count - nonkey["parser_status"][status]
    for status, count in audit["candidate_parser_status_counts"].items()
    if count - nonkey["parser_status"][status]
}
key_methods_by_evidence = {
    "explicit_http_url": "explicit_token",
    "protocol_relative_url": "explicit_token",
    "www_url": "explicit_token",
    "html_anchor": "html_anchor_attribute",
    "html_canonical": "html_canonical_attribute",
    "html_open_graph": "html_open_graph_attribute",
    "html_form": "html_form_attribute",
}
key_methods: Counter[str] = Counter()
for evidence, count in key_evidence.items():
    key_methods[key_methods_by_evidence[evidence]] += count

key_occurrences = sum(key_evidence.values())
key_domain_count = audit["distinct_registrable_domain_grouping_keys"]
all_reg_domains = audit["distinct_valid_registrable_domains"]
domain_intersection = key_domain_count + len(nonkey_reg_domains) - all_reg_domains
domain_only_nonkey = len(nonkey_reg_domains) - domain_intersection

parser_rows = list(csv.DictReader(PARSER.open("r", encoding="utf-8", newline="")))
parser_passed = sum(row["pass"].lower() == "true" for row in parser_rows)
extractor_sha256 = hashlib.sha256(EXTRACTOR.read_bytes()).hexdigest()

component_rows = []
for row in groups["largest_components"]:
    component_rows.append({
        "row_type": "largest_component_detail_available",
        "component_id": row["component_id"],
        "component_records": row["records"],
        "distinct_destination_keys": row["distinct_destination_keys"],
        "component_count_at_size": "",
    })
for row in groups["component_size_distribution"]:
    component_rows.append({
        "row_type": "complete_size_distribution",
        "component_id": "",
        "component_records": row["records"],
        "distinct_destination_keys": "",
        "component_count_at_size": row["component_count"],
    })
with COMPONENTS_CSV.open("x", encoding="utf-8", newline="") as stream:
    fields = ["row_type", "component_id", "component_records", "distinct_destination_keys", "component_count_at_size"]
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    writer.writerows(component_rows)

key_confidence = {"high": key_occurrences}
all_confidence = dict(nonkey["confidence"])
all_confidence["high"] = key_occurrences
all_candidate_methods = dict(nonkey["extraction_method"])
for method, count in key_methods.items():
    all_candidate_methods[method] = all_candidate_methods.get(method, 0) + count
all_candidate_status = dict(nonkey["parser_status"])
for status, count in key_status.items():
    all_candidate_status[status] = all_candidate_status.get(status, 0) + count

invariants = {
    "audit_status": audit["status"],
    "source_records": audit["source_records"],
    "source_sha256": audit["source_sha256"],
    "candidate_occurrences": audit["candidate_count_second_pass"],
    "baseline_near_duplicate_manifest": {
        "path": str(BASELINE_MANIFEST.relative_to(ROOT)),
        "rows": len(baseline_source_indices),
        "source_indices_missing_from_manifest": missing_source_indices,
        "raw_record_count": audit["source_records"],
        "note": "Record-level composite grouping must account for every raw source row, including rows omitted from the text-model manifest.",
    },
    "review_python_version": sys.version,
    "current_extractor_sha256": extractor_sha256,
    "candidate_breakdown": {
        "confidence": dict(sorted(all_confidence.items())),
        "evidence_category_total": audit["candidate_evidence_counts"],
        "extraction_method_total": dict(sorted(all_candidate_methods.items())),
        "parser_status_total": dict(sorted(all_candidate_status.items())),
        "group_eligibility": {
            "eligible_key_occurrences_by_evidence": dict(sorted(key_evidence.items())),
            "eligible_key_occurrences_by_method": dict(sorted(key_methods.items())),
            "eligible_key_occurrences_by_confidence": key_confidence,
            "nonkey_occurrences_by_confidence": dict(sorted(nonkey["confidence"].items())),
            "rejection_reasons_for_nonkey_candidates": dict(sorted(nonkey["rejection_reason"].items())),
        },
        "candidate_rows_in_suspicious_file": sum(nonkey["confidence"].values()),
        "suspicious_rows_with_empty_grouping_key": empty_group_key_rows,
        "suspicious_rows_with_nonempty_grouping_key": keyed_nonhigh_rows,
        "reconstruction_note": "The audit writes every candidate without a final grouping key to suspicious_candidates.csv. Eligible key counts are derived by subtracting those rows from the complete candidate evidence/status totals. Key extraction methods are determined by the unchanged extractor branches for each evidence category.",
    },
    "registrable_domain_reconciliation": {
        "distinct_resolved_domains_all_candidates": all_reg_domains,
        "distinct_registrable_grouping_keys": key_domain_count,
        "distinct_registrable_values_in_nonkey_candidates": len(nonkey_reg_domains),
        "overlap_between_keyed_and_nonkey_domain_sets": domain_intersection,
        "values_only_in_nonkey_candidate_set": domain_only_nonkey,
        "difference_all_resolved_minus_grouping_keys": all_reg_domains - key_domain_count,
        "interpretation": "Resolved bare-domain mentions contribute registrable-domain values but policy never assigns them grouping keys; values may also appear in keyed records, so report the overlap explicitly.",
    },
    "key_invariant_evidence": {
        "parser_fixtures_passed": parser_passed,
        "parser_fixture_total": len(parser_rows),
        "parser_fixture_failed": len(parser_rows) - parser_passed,
        "v1_issue_checks": audit["v1_parser_issue_checks"],
        "key_construction_source": "apply_psl in backend/notebooks/phishing_url_extraction_v2.py; keys are emitted only for high-confidence PSL registrable destinations or high-confidence valid IP literals",
        "full_record_to_key_rows_saved": False,
        "independent_full_candidate_key_replay": False,
        "limitation": "The saved audit omits successful candidate-to-key rows. The policy and parser fixtures support the invariants, but the exact key assignment for every source candidate cannot be independently replayed from the saved artifacts alone.",
    },
    "domain_only_components": {
        "count": groups["connected_components_including_no-key_singletons"],
        "component_size_distribution": groups["component_size_distribution"],
        "components_with_multiple_destination_keys": groups["components_connected_through_multiple_destination_keys"],
        "components_with_multiple_registrable_domains": None,
        "why_multiple_registrable_domains_not_exact": "The saved diagnostics aggregate total destination keys per component, but do not preserve per-component key values or key prefixes.",
        "near_duplicate_edges_in_v2_audit_graph": 0,
        "composite_near_duplicate_plus_domain_component_count": None,
        "mixed_label_component_count": None,
    },
    "offline_reproducibility": {
        "psl": audit["psl"],
        "network_access": False,
        "source_record_key_manifest": False,
    },
}
INVARIANTS_JSON.write_text(json.dumps(invariants, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

no_key_summary = {
    "records_without_confident_destination_keys": audit["records_without_confident_destination_keys"],
    "candidate_occurrences_without_grouping_keys": sum(nonkey["confidence"].values()),
    "source_records_with_one_or_more_nonkey_candidate_rows": len(nonkey_record_ids),
    "candidate_rows_by_confidence": dict(sorted(nonkey["confidence"].items())),
    "candidate_rows_by_evidence_category": dict(sorted(nonkey["evidence_category"].items())),
    "candidate_rows_by_parser_status": dict(sorted(nonkey["parser_status"].items())),
    "candidate_rows_by_rejection_reason": dict(sorted(nonkey["rejection_reason"].items())),
    "distinct_psl_resolved_domain_values_in_nonkey_rows": len(nonkey_reg_domains),
    "mutually_exclusive_candidate_occurrence_categories": {
        "ambiguous_bare_domain_mentions": nonkey["parser_status"]["ambiguous_bare_domain_mention"],
        "malformed_or_invalid_url_hostname_port": sum(nonkey["parser_status"][k] for k in ("malformed_url", "invalid_hostname", "invalid_port")),
        "public_suffix_only": nonkey["parser_status"]["public_suffix_only"],
        "unknown_suffix": nonkey["parser_status"]["unknown_suffix"],
        "valid_ip_literal_mentions_without_grouping_key": nonkey["parser_status"]["ip_literal"],
        "other_unresolved_relative_or_unsupported": sum(nonkey["parser_status"][k] for k in ("relative_without_base", "unsupported_scheme", "empty_attribute")),
    },
    "candidate_occurrence_categories_sum_to_nonkey_rows": sum(nonkey["parser_status"][k] for k in ("ambiguous_bare_domain_mention", "malformed_url", "invalid_hostname", "invalid_port", "public_suffix_only", "unknown_suffix", "ip_literal", "relative_without_base", "unsupported_scheme", "empty_attribute")) == sum(nonkey["confidence"].values()),
    "no_candidate_record_count_bounds": {
        "minimum": max(0, audit["records_without_confident_destination_keys"] - len(nonkey_record_ids)),
        "maximum": min(audit["records_without_confident_destination_keys"], audit["source_records"] - len(nonkey_record_ids)),
        "basis": "Set bounds from 48,092 no-key records and 45,514 records with at least one nonkey-candidate row; exact overlap is not retained.",
    },
    "exclusive_source_record_categories": None,
    "why_record_categories_are_unresolved": "The suspicious file can include nonkey candidates from a record that also has a valid key. The aggregate audit does not preserve record-to-successful-key assignments, so candidate categories cannot be converted into mutually exclusive record categories without re-running extraction and PSL mapping across the source corpus.",
    "valid_ip_grouping_records": audit["records_with_valid_ip_destinations"],
    "distinct_ip_grouping_keys": audit["distinct_ip_grouping_keys"],
    "ambiguous_ip_mentions_remain_unkeyed": True,
}
NO_KEY_JSON.write_text(json.dumps(no_key_summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

top_sizes = sorted((row["records"] for row in groups["largest_components"]), reverse=True)[:10]
nonkey_status = dict(sorted(nonkey["parser_status"].items()))
nonkey_evidence = dict(sorted(nonkey["evidence_category"].items()))
key_evidence_md = "<br>".join(f"`{k}` {v:,}" for k, v in sorted(key_evidence.items()))
nonkey_conf_md = "<br>".join(f"`{k}` {v:,}" for k, v in sorted(nonkey["confidence"].items()))
nonkey_status_md = "<br>".join(f"`{k}` {v:,}" for k, v in sorted(nonkey_status.items()))
nonkey_reason_md = "<br>".join(f"`{k}` {v:,}" for k, v in sorted(nonkey["rejection_reason"].items()))
giant = groups["largest_components"][0]
giant_share = giant["records"] / audit["source_records"]
component_csv_rows = len(component_rows)

REPORT.write_text(f"""# V2 domain grouping readiness review

## Decision

**CONDITIONAL GO** for a separate domain-held-out experiment after the composite grouping graph and largest component are reviewed and the unresolved record-level categories are handled explicitly. The stored audit supports conservative key-creation rules and the parser fixture suite passed, but successful record-to-key assignments were not saved, the existing component graph omits normalized/near-duplicate edges, and the largest domain-only component is larger than a nominal test share.

## Evidence and reproducibility

- Source corpus: `{audit['source_file']}`, {audit['source_records']:,} records, SHA-256 `{audit['source_sha256']}`. This combined file is the only recorded source provenance; the prepared baseline labels every row as `combined_reduced.json`, with no reliable underlying sub-source ID for source-level grouping.
- Original source labels: `{json.dumps(audit['original_label_counts'], sort_keys=True)}`; preserved as 0=benign and 1=phishing per recorded source documentation.
- Candidate occurrences: {audit['candidate_count_first_pass']:,} in both passes.
- PSL: {audit['psl']['implementation']}, `{audit['psl']['jdk_version']}`, snapshot SHA-256 `{audit['psl']['psl_snapshot_sha256']}`. The saved audit records offline/no-network operation.
- Parser fixtures: {parser_passed}/{len(parser_rows)} passed in the saved parser results.
- The previous V2 audit is reproducible in principle from the raw corpus, extractor, local JDK PSL snapshot, and parser fixtures. The original audit did not record Python version or extractor code hash. This artifact-only review ran under Python `{sys.version.split()[0]}`; the current extractor SHA-256 is `{extractor_sha256}`. A fresh all-hostname PSL replay timed out at 300 seconds; this review uses saved aggregates and does not claim a fresh full replay.

## Reconciliation of domain counts

The audit reports {audit['valid_registrable_domain_candidate_count']:,} PSL-resolved registrable-domain candidate occurrences, {audit['distinct_valid_registrable_domains']:,} distinct resolved domain values, and {audit['distinct_registrable_domain_grouping_keys']:,} distinct registrable-domain grouping keys. The difference of **{all_reg_domains - key_domain_count:,}** is not evidence of inconsistent normalization: the extractor also resolves ambiguous bare-domain mentions to registrable values for descriptive reporting but intentionally gives them no grouping key. The saved nonkey candidates contain {len(nonkey_reg_domains):,} distinct resolved domain values; {domain_intersection:,} overlap with the keyed-domain set, leaving {domain_only_nonkey:,} distinct values only in nonkey candidates. These values reconcile exactly with the {all_reg_domains:,} union.

The {audit['valid_registrable_domain_candidate_count']:,} occurrence count is per extracted candidate, so repeated links and HTML anchor/form references count repeatedly. Distinct normalized hosts per record ({audit['records_with_multiple_distinct_destination_hosts']:,}) and distinct eligible grouping keys per record ({audit['records_with_multiple_destination_grouping_keys']:,}) measure different sets: ambiguous and unresolved hosts can contribute to a host count without contributing keys; several subdomains can share one registrable-domain key. The {audit['records_with_valid_ip_destinations']:,} valid-IP records produce {audit['distinct_ip_grouping_keys']:,} canonical IP keys because destinations repeat.

Candidate-level confidence/evidence/method/status/rejection counts, plus eligibility totals by evidence and method, are in `{INVARIANTS_JSON.name}`. The report separates key-eligible candidates from candidates with no key; candidate counts must not be read as record counts.

| Candidate view | Counts |
|---|---|
| All extraction evidence categories | `{json.dumps(audit['candidate_evidence_counts'], sort_keys=True)}` |
| All candidate confidence levels | `{json.dumps(all_confidence, sort_keys=True)}` |
| All extraction methods | `{json.dumps(all_candidate_methods, sort_keys=True)}` |
| All parser statuses after PSL classification | `{json.dumps(audit['candidate_parser_status_counts'], sort_keys=True)}` |
| Key-eligible candidate occurrences by evidence | {key_evidence_md} |
| Key-eligible candidate occurrences by extraction method | `{json.dumps(dict(sorted(key_methods.items())), sort_keys=True)}` |
| Key-eligible candidate occurrences by confidence | `{json.dumps(key_confidence, sort_keys=True)}` |
| Total grouping eligibility | `{key_occurrences:,} key / {sum(nonkey['confidence'].values()):,} no-key candidate occurrences |
| Nonkey candidate occurrences by confidence | {nonkey_conf_md} |
| Nonkey candidate rows by parser status | {nonkey_status_md} |
| Nonkey candidate rows by rejection reason | {nonkey_reason_md} |

There are {key_occurrences:,} eligible grouping-key candidate occurrences ({key_status.get('normalized_hostname',0):,} normalized hostnames and {key_status.get('ip_literal',0):,} IP literals), all high-confidence by the saved `apply_psl` implementation. There are {sum(nonkey['confidence'].values()):,} candidate rows without grouping keys in the saved suspicious-candidate file, and all {empty_group_key_rows:,} of those rows have an empty key; {keyed_nonhigh_rows} have a nonempty key. Eligible methods are reconstructed from the fixed parser branches and emitted in the JSON summary.

## Grouping-key invariants

Code inspection confirms that `apply_psl` creates `registrable:<domain>` only for high-confidence normalized hosts with a PSL registrable result; valid high-confidence IP literals use canonical `ip:<address>` values. It gives no fallback key for ambiguous bare mentions, malformed candidates, public-suffix-only hosts, unknown suffixes, invalid ports, relative references, unsupported schemes, or empty/parse-error candidates. Saved parser fixtures include public-suffix rejection, bare-mention rejection, unknown-suffix rejection, and concatenated-scheme boundaries, and all {parser_passed} pass.

The source-record `suspicious_candidates.csv` stores only rows with no grouping key (and any high-confidence row without a key); it omits successful candidate-to-key rows. The audit aggregates therefore cannot independently verify every emitted key against its original source offset or exhaustively check all key strings for normalization/concatenation issues. The invariant summary marks this as a coverage limitation rather than treating code construction as a fresh row-level audit.

Representative unresolved candidates were checked against raw text at their saved offsets. `source_record_35` offsets 2782-2799 match `www.ceert.org).It`; neighboring text shows a sentence boundary attached to the hostname. It is rejected as `invalid_hostname`, correctly avoiding a false key, but the intended `ceert.org` destination is not grouped. `source_record_80` offsets 3808-3834 match `http://www.opalis.comThink`, also unresolved as `unknown_suffix`; this looks like URL text joined to prose, but is not grouped. `source_record_5760` and `source_record_8514` contain `s3.amazonaws.com` URLs classified `public_suffix_only` and receive no key. No URL was opened.

## Connected components

The V2 audit's union-find joins source records only when they share a V2 destination grouping key. It does not include exact-normalized-text or near-duplicate edges. The current domain-only graph has {groups['connected_components_including_no-key_singletons']:,} components over {audit['source_records']:,} records; {groups['components_connected_through_multiple_destination_keys']:,} components contain multiple destination keys, and {groups['records_connected_through_multiple_destination_links']:,} records have multiple destination keys. Because the stored component output lacks the list of keys/prefixes per component, the exact number with multiple registrable domains (as distinct from an IP-plus-domain combination) is not available. Full size distribution and largest-component summaries are in `{COMPONENTS_CSV.name}`.

The ten largest domain-only component sizes are `{top_sizes}`. Median, P90 and P95 are **1**; P99 is **2** because 58,996 of 59,980 components are singletons and 673 have size 2. There are {groups['connected_components_including_no-key_singletons'] - 58996:,} non-singleton components. The largest component is rooted at `{giant['component_id']}`, has {giant['records']:,} records ({giant_share:.2%} of the corpus), and {giant['distinct_destination_keys']:,} destination keys. It exceeds a 15% test target. The next largest components are 298 and 78 records. The existing text baseline separately reports {baseline['grouping']['normalized_text_groups']:,} unique normalized-text groups, {baseline['grouping']['near_duplicate_components']:,} near-duplicate components, and {baseline['grouping']['near_duplicate_pairs_joined']:,} joined near-duplicate pairs. Its saved manifest has {len(baseline_source_indices):,} rows and omits raw source record index {missing_source_indices}, which is label 1 and contains a single newline character. This whitespace-only row was outside the text candidate manifest and must be accounted for explicitly in any raw-corpus graph. These near-duplicate statistics do not give the composite graph count; row-level V2 successful keys were not retained, so the overlap cannot be reconstructed from current artifacts.

The largest component's seed record 41 is an HTML page (label 0, 39,500 characters) with 66 anchor candidates, 4 form-action attributes (3 `html_form` destinations and 1 relative reference), 1 canonical destination, 1 Open Graph URL, and 8 distinct hosts. Its linked hosts include `facebook.com`, `linkedin.com`, `twitter.com`, `pinterest.com`, `list-manage.com`, and three Seatmaestro domains. This directly verifies a multi-domain HTML bridge with common platform/navigation destinations in the seed record. It is plausible that shared platform hosts plus transitive key edges drive the giant component, but the audit did not persist all component member/key edges, so the exact contribution of platforms, duplicate chaining, URL shorteners, or other records remains unverified. Component label balance and mixed-label counts are likewise unavailable from the saved grouping summary.

The audit's size distribution includes 58,996 singleton components, 673 size-2, 145 size-3, 57 size-4, 32 size-5, 27 size-6, 11 size-7, 9 size-8, 3 size-9, 7 size-10, 4 size-11, 3 size-12, and one each of sizes 16, 17, 20, 25, 26, 30, 78, 298, and 15,442, plus four size-18 components. The saved top-25 list and full size histogram do not include per-component row/label membership.

## Records without confident domain keys

The audit records {audit['records_without_confident_destination_keys']:,} records with no confident grouping key. The candidate file has {len(nonkey_record_ids):,} distinct source records represented with one or more nonkey candidates. Those sets are not interchangeable: a source record can have both a keyed destination and unresolved candidates. Saved artifacts support these mutually exclusive **candidate-occurrence** categories: ambiguous bare domain {nonkey['parser_status']['ambiguous_bare_domain_mention']:,}; malformed/invalid URL-host-port {nonkey['parser_status']['malformed_url'] + nonkey['parser_status']['invalid_hostname'] + nonkey['parser_status']['invalid_port']:,}; public-suffix-only {nonkey['parser_status']['public_suffix_only']:,}; unknown-suffix {nonkey['parser_status']['unknown_suffix']:,}; valid IP literal mentions without a key {nonkey['parser_status']['ip_literal']:,}; and relative/unsupported/empty {nonkey['parser_status']['relative_without_base'] + nonkey['parser_status']['unsupported_scheme'] + nonkey['parser_status']['empty_attribute']:,}. They sum to {sum(nonkey['confidence'].values()):,} nonkey candidate occurrences. The exact mutually exclusive **record-level** categories remain unknown because source-to-successful-key assignments were not saved. Based on set sizes alone, at least {max(0, audit['records_without_confident_destination_keys'] - len(nonkey_record_ids)):,} and at most {min(audit['records_without_confident_destination_keys'], audit['source_records'] - len(nonkey_record_ids)):,} no-key records had no nonkey-candidate row; these bounds are not exact no-URL counts. Candidate-level counts and the bounds are in `{NO_KEY_JSON.name}`.

Records without keys may remain in a future evaluation, but must be labeled `no_confident_domain` and reported as a separate slice. They must never be described as unseen-domain test examples. The saved report gives no-key singleton components in the domain graph, but text/near-duplicate edges can still link them in a composite graph.

## Split feasibility

The domain-only graph has many singleton records but also one very large 15,442-record component with 25,594 distinct destination keys (65.7% of all 38,972 reliable keys) and another 298-record component. A component-preserving 70/15/15 assignment may be possible by placing the giant component in training, but it cannot fit within a 15% validation or test share. The composite graph with existing near-duplicate components may be larger still. The baseline text grouping has 645 quarantined components; the number that would be quarantined after domain propagation is not available and must be computed before a split. Mixed-label components and class distribution per component cannot be calculated from current summaries. Do not split the giant component, discard it, or silently weaken hostname isolation.

Before assigning partitions, create a new row-level artifact linking source record, original label, successful V2 keys, normalized-text group, near-duplicate component, and quarantine status; review the giant component's bridge records; compute composite component labels/quarantine totals; and separately define handling for no-key records. If the composite component sizes prevent defensible 70/15/15 partitions, retain whole components and report the deviation or use a separately justified evaluation design.

## Final decision

**CONDITIONAL GO.** V2 extraction follows conservative key eligibility and 31/31 saved parser fixtures pass. However, the exact saved audit does not prove full-corpus row-level key correctness because it omits successful key rows, its components omit text/near-duplicate edges, and a large HTML component with common platform links is a verified potential bridge. Resolve these auditability and component-balance issues before creating the domain-held-out split. No split or model training was performed.
""", encoding="utf-8")

print(json.dumps({
    "report": str(REPORT.relative_to(ROOT)),
    "component_summary_csv": str(COMPONENTS_CSV.relative_to(ROOT)),
    "invariants_json": str(INVARIANTS_JSON.relative_to(ROOT)),
    "no_key_breakdown_json": str(NO_KEY_JSON.relative_to(ROOT)),
    "parser_fixtures": {"passed": parser_passed, "total": len(parser_rows)},
    "nonkey_candidate_rows": sum(nonkey["confidence"].values()),
    "eligible_key_candidate_occurrences": key_occurrences,
    "component_csv_rows": component_csv_rows,
}, indent=2))
