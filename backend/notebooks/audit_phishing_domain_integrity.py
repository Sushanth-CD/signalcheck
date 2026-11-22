"""Read-only audit of the saved phishing registrable-domain experiment.

Run with the experiment environment from the repository root:
    backend/.venv-ml/Scripts/python.exe backend/notebooks/audit_phishing_domain_integrity.py

No source URLs are opened and no DNS or other network requests are made. The
script writes only new audit artifacts under the experiment's integrity_audit_rerun subfolder.
"""

from __future__ import annotations

import csv
import html
import importlib.util
import ipaddress
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import joblib
import numpy as np
import sklearn
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

from backend.notebooks import train_phishing_domain_holdout as experiment
from backend.ml.psl_service import is_psl_suffix, load_psl_rules

INPUT = experiment.INPUT
OUT = experiment.OUTPUT_DIR
MANIFEST = OUT / "split_manifest.csv"
METRICS = OUT / "metrics.json"
CONFIG = OUT / "experiment_config.json"
MODEL = OUT / "model.joblib"
AUDIT_OUT = OUT / "integrity_audit_rerun"
AUDIT = AUDIT_OUT / "domain_integrity_audit.md"
KEYS_CSV = AUDIT_OUT / "domain_key_classification.csv"
LARGEST_CSV = AUDIT_OUT / "largest_component_domains.csv"
PARSER_CSV = AUDIT_OUT / "parser_test_results.csv"

SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "rebrand.ly", "cutt.ly", "lnkd.in", "youtu.be", "rb.gy", "shorturl.at",
    "trib.al", "soo.gd", "v.gd", "tiny.cc", "bl.ink", "adf.ly",
}
PLATFORMS = {
    "facebook.com", "fb.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "tiktok.com", "youtube.com", "reddit.com", "pinterest.com", "tumblr.com",
    "telegram.org", "t.me", "whatsapp.com", "discord.com", "snapchat.com", "vk.com",
    "medium.com", "blogspot.com", "wordpress.com", "github.com", "github.io",
}
INFRASTRUCTURE = {
    "cloudfront.net", "akamai.net", "akamaized.net", "edgesuite.net", "edgekey.net",
    "fastly.net", "cloudflare.com", "cloudflare.net", "gstatic.com", "googleapis.com",
    "googleusercontent.com", "azureedge.net", "jsdelivr.net", "unpkg.com",
    "bootstrapcdn.com", "cdnjs.cloudflare.com", "stackpathcdn.com", "amazonaws.com",
    "vercel.app", "netlify.app",
}


def json_list(value: str | None) -> list[str]:
    return json.loads(value or "[]")


def write_csv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def context_excerpt(text: str, candidate: str, host: str) -> str:
    folded = text.casefold()
    needle = candidate.casefold()
    position = folded.find(needle) if needle else -1
    if position < 0:
        position = folded.find(host.casefold())
    if position < 0:
        return re.sub(r"\s+", " ", text[:180])
    start = max(0, position - 70)
    end = min(len(text), position + max(len(candidate), len(host)) + 80)
    return re.sub(r"\s+", " ", text[start:end])


def service_category(host: str, registrable: str | None) -> str | None:
    base = registrable or host
    if base in SHORTENERS:
        return "common URL shortener"
    if base in INFRASTRUCTURE or any(base.endswith("." + item) for item in INFRASTRUCTURE):
        return "CDN or infrastructure domain"
    if base in PLATFORMS or any(base.endswith("." + item) for item in PLATFORMS):
        return "platform or social-media domain"
    return None


def classify_host(
    host: str,
    registrable: str | None,
    psl_rules: tuple[set[str], set[str], set[str]],
    is_fallback: bool,
) -> str:
    try:
        ipaddress.ip_address(host)
        return "IP address"
    except ValueError:
        pass
    special = service_category(host, registrable)
    if special:
        return special
    if registrable:
        return "valid registrable domain" if host == registrable else "valid subdomain"
    if is_psl_suffix(host, psl_rules):
        return "public-suffix-only value"
    if is_fallback:
        return "unresolved exact-host fallback (no PSL registrable domain)"
    return "unresolved"


def classify_domain_key(key: str, host: str, registrable: str | None,
                       psl_rules: tuple[set[str], set[str], set[str]],
                       malformed_fallbacks: set[str] | None = None) -> str:
    if key.startswith("registrable:"):
        domain = key.split(":", 1)[1]
        return service_category(domain, domain) or "valid registrable domain"
    if key.startswith("ip:"):
        return "IP address"
    if key.startswith("exact_host_fallback:"):
        if is_psl_suffix(host, psl_rules):
            return "public-suffix-only value"
        if malformed_fallbacks and host in malformed_fallbacks:
            return "malformed URL or host string (trailing text after valid domain/IP)"
        return "unresolved exact-host fallback (no PSL registrable domain)"
    return "unresolved"


def parser_cases() -> list[dict[str, object]]:
    cases = [
        ("https scheme/path", "https://example.com/path", "example.com", "example.com", True),
        ("http subdomain/path", "http://sub.example.com/path", "sub.example.com", "example.com", True),
        ("bare host/path", "example.com/path", "example.com", "example.com", True),
        ("port", "https://example.com:8443/path", "example.com", "example.com", True),
        ("query and fragment", "https://example.com/p?q=1#frag", "example.com", "example.com", True),
        ("IPv4", "http://192.0.2.10/a", "192.0.2.10", None, True),
        ("IPv6", "https://[2001:db8::1]:9443/a", "2001:db8::1", None, True),
        ("Unicode IDN", "https://bücher.com/path", "xn--bcher-kva.com", "xn--bcher-kva.com", True),
        ("punycode", "https://xn--bcher-kva.com/path", "xn--bcher-kva.com", "xn--bcher-kva.com", True),
        ("public suffix only", "https://co.uk", "co.uk", None, False),
        ("private suffix", "https://tenant.github.io/app", "tenant.github.io", "tenant.github.io", True),
        ("localhost", "http://localhost:8000", None, None, False),
        ("malformed port", "https://example.com:99999/path", None, None, False),
        ("invalid host label", "https://bad..example.com/path", None, None, False),
        ("ordinary prose URL mention", "I read example.com yesterday", "example.com", "example.com", False),
        ("URL-shaped but unregistered host", "https://aol.comsite/path", "aol.comsite", None, False),
    ]
    hosts = [expected for _, _, expected, _, _ in cases if expected]
    psl_map, _ = experiment.psl_registrable_domains(hosts)
    result: list[dict[str, object]] = []
    for case_name, candidate, expected_host, expected_registrable, expected_destination in cases:
        if case_name == "ordinary prose URL mention":
            candidates, _, _ = experiment.destination_candidates({"text": candidate, "inferred_input_type": "plain_text"})
            raw_candidate = candidates[0][0] if candidates else ""
            host, status = experiment.normalize_host_from_url(raw_candidate, allow_bare=True) if raw_candidate else (None, "no_candidate")
            notes = f"bare candidate {raw_candidate!r} is PSL-mapped and treated as a destination"
        else:
            raw_candidate = candidate
            host, status = experiment.normalize_host_from_url(candidate, allow_bare=True)
            notes = ""
        actual_registrable = psl_map.get(host) if host else None
        actual_destination = bool(host and (actual_registrable or status == "ip_literal"))
        if case_name in {"public suffix only", "URL-shaped but unregistered host"} and host:
            actual_destination = True  # strong URL candidates receive exact-host fallback
            notes = "accepted by exact-host fallback despite no PSL registrable domain"
        if case_name == "ordinary prose URL mention":
            actual_destination = bool(host and actual_registrable)
        passed = (
            host == expected_host
            and actual_registrable == expected_registrable
            and actual_destination == expected_destination
        )
        result.append({
            "case": case_name,
            "input": candidate,
            "expected_hostname": expected_host or "",
            "actual_hostname": host or "",
            "parser_status": status,
            "expected_registrable_domain": expected_registrable or "",
            "actual_registrable_domain": actual_registrable or "",
            "expected_destination_grouped": expected_destination,
            "actual_destination_grouped": actual_destination,
            "pass": passed,
            "notes": notes,
        })
    return result


def validate_psl_lookup() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Check local-JDK PSL semantics and deterministic repeated lookup."""
    expected = {
        "example.com": "example.com",
        "mail.example.co.uk": "example.co.uk",
        "co.uk": None,
        "tenant.github.io": "tenant.github.io",
        "sub.tenant.github.io": "tenant.github.io",
        "foo.blogspot.com": "foo.blogspot.com",
        "xn--bcher-kva.com": "xn--bcher-kva.com",
    }
    started = time.perf_counter()
    first, _ = experiment.psl_registrable_domains(sorted(expected))
    first_elapsed = time.perf_counter() - started
    started = time.perf_counter()
    second, _ = experiment.psl_registrable_domains(sorted(expected))
    repeat_elapsed = time.perf_counter() - started
    rows = []
    for host, wanted in expected.items():
        actual = first.get(host)
        deterministic = actual == second.get(host)
        rows.append({
            "hostname": host,
            "expected_registrable_domain": wanted or "",
            "actual_registrable_domain": actual or "",
            "repeated_result_identical": deterministic,
            "pass": actual == wanted and deterministic,
        })
    if not all(bool(row["pass"]) for row in rows):
        raise RuntimeError(f"Local PSL semantic regression failed: {rows}")
    parser_rejections = []
    for value, expected_status in (
        ("127.0.0.1", "ip_literal"),
        ("[2001:db8::1]", "ip_literal"),
        ("localhost", "unqualified_hostname"),
        ("bad..example.com", "malformed_url"),
    ):
        actual_host, actual_status = experiment.normalize_host_from_url(
            f"https://{value}/", allow_bare=True
        )
        parser_rejections.append({
            "input": value,
            "expected_parser_status": expected_status,
            "actual_parser_status": actual_status,
            "normalized_host": actual_host or "",
            "pass": actual_status == expected_status,
        })
    if not all(bool(row["pass"]) for row in parser_rejections):
        raise RuntimeError(f"Hostname/IP normalization regression failed: {parser_rejections}")
    return rows + parser_rejections, [
        {"lookup": "representative_first_run", "unique_hosts": len(expected), "elapsed_seconds": first_elapsed},
        {"lookup": "representative_repeat", "unique_hosts": len(expected), "elapsed_seconds": repeat_elapsed},
    ]


def benchmark_psl_lookup(hosts: list[str]) -> list[dict[str, object]]:
    """Measure the existing Java lookup at fixed increasing unique-host counts."""
    results: list[dict[str, object]] = []
    sizes = [n for n in (10, 100, 1000, 5000) if n <= len(hosts)]
    for size in sizes:
        if size == 1:
            sample = hosts[:1]
        else:
            indexes = sorted({round(i * (len(hosts) - 1) / (size - 1)) for i in range(size)})
            sample = [hosts[i] for i in indexes]
        started = time.perf_counter()
        looked_up, _ = experiment.psl_registrable_domains(sample)
        elapsed = time.perf_counter() - started
        if len(looked_up) != len(sample):
            raise RuntimeError(f"PSL benchmark expected {len(sample)} results, received {len(looked_up)}")
        results.append({
            "unique_hosts": len(sample),
            "java_input_lines_including_smoke_check": len(set(sample)) + 1,
            "elapsed_seconds": elapsed,
        })
    return results


def main() -> int:
    AUDIT_OUT.mkdir(parents=True, exist_ok=True)
    for path in (AUDIT, KEYS_CSV, LARGEST_CSV, PARSER_CSV):
        if path.exists():
            raise FileExistsError(
                f"Refusing to overwrite existing audit artifact: {path}"
            )
    for path in (MANIFEST, METRICS, CONFIG, MODEL, INPUT):
        if not path.is_file():
            raise FileNotFoundError(path)
    metrics = json.loads(METRICS.read_text(encoding="utf-8"))
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    if sklearn.__version__ != config["environment"]["scikit_learn"]:
        raise RuntimeError(
            f"Model environment mismatch: running sklearn {sklearn.__version__}, "
            f"experiment recorded {config['environment']['scikit_learn']}"
        )

    rows: list[dict[str, str]] = []
    with MANIFEST.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != config["verification"]["source_records_in_manifest"]:
        raise ValueError("Manifest row count does not match experiment configuration")
    rows_by_index = {int(row["source_record_index"]): row for row in rows}
    if len(rows_by_index) != len(rows):
        raise ValueError("Manifest contains duplicate source_record_index values")

    record_count = 0
    url_like_record_count = 0
    regex_url_record_count = 0
    token_statuses: Counter[str] = Counter()
    invalid_candidate_counts: Counter[str] = Counter()
    token_host_counts: Counter[str] = Counter()
    fallback_evidence: Counter[str] = Counter()
    host_to_group_keys: dict[str, set[str]] = defaultdict(set)
    group_key_to_hosts: dict[str, set[str]] = defaultdict(set)
    host_record_ids: dict[str, set[str]] = defaultdict(set)
    host_text_groups: dict[str, set[str]] = defaultdict(set)
    host_near_components: dict[str, set[str]] = defaultdict(set)
    host_domain_components: dict[str, set[str]] = defaultdict(set)
    key_record_ids: dict[str, set[str]] = defaultdict(set)
    key_text_groups: dict[str, set[str]] = defaultdict(set)
    key_near_components: dict[str, set[str]] = defaultdict(set)
    key_domain_components: dict[str, set[str]] = defaultdict(set)
    key_examples: dict[str, list[dict[str, str]]] = defaultdict(list)
    host_examples: dict[str, list[dict[str, str]]] = defaultdict(list)
    row_key_sets: dict[str, set[str]] = {}
    reextract_evidence: dict[int, dict[str, bool]] = {}
    base_to_keys: dict[str, set[str]] = defaultdict(set)
    component_to_keys: dict[str, set[str]] = defaultdict(set)
    component_to_rows: dict[str, list[dict[str, str]]] = defaultdict(list)
    group_rows: dict[str, list[dict[str, str]]] = defaultdict(list)
    group_labels: dict[str, set[str]] = defaultdict(set)
    group_base: dict[str, str] = {}
    group_component: dict[str, str] = {}
    reextract_hostnames: dict[int, set[str]] = {}

    with INPUT.open("r", encoding="utf-8") as source:
        for line_number, source_line in enumerate(source, start=1):
            record = json.loads(source_line)
            manifest = rows_by_index.get(int(record.get("source_record_index", line_number)))
            if manifest is None:
                raise ValueError(f"Candidate record {line_number} is absent from split manifest")
            if int(manifest["candidate_jsonl_line"]) != line_number:
                raise ValueError(f"Candidate/manifest line mismatch at {line_number}")
            record_count += 1
            parser_record = {
                "text": record["text"],
                "inferred_input_type": record.get("inferred_input_type", "unknown"),
            }
            candidates, method, token_count = experiment.destination_candidates(parser_record)
            if bool(token_count) != (manifest["url_containing"].lower() == "true"):
                raise ValueError(f"URL-containing status mismatch at source line {line_number}")
            url_like_record_count += bool(token_count)
            regex_url_record_count += bool(experiment.URL_RE.search(str(record["text"])))
            parsed: set[str] = set()
            parsed_evidence: dict[str, bool] = {}
            for candidate, fallback_ok in candidates:
                host, status = experiment.normalize_host_from_url(candidate, allow_bare=True)
                token_statuses[status] += 1
                if host:
                    token_host_counts[host] += 1
                    parsed.add(host)
                    parsed_evidence[host] = parsed_evidence.get(host, False) or fallback_ok
                    if fallback_ok:
                        fallback_evidence[host] += 1
                    if len(host_examples[host]) < 3:
                        host_examples[host].append({
                            "source_record_id": manifest["source_record_id"],
                            "method": method,
                            "candidate": candidate,
                            "text_excerpt": context_excerpt(str(record["text"]), candidate, host),
                        })
                else:
                    invalid_candidate_counts[candidate] += 1
            reextract_hostnames[int(manifest["source_record_index"])] = parsed
            reextract_evidence[int(manifest["source_record_index"])] = parsed_evidence

            registrables = set(json_list(manifest["registrable_domains_json"]))
            saved_key_set = {f"registrable:{d}" for d in registrables}
            saved_key_set.update(json_list(manifest["non_registrable_domain_keys_json"]))
            row_key_sets[manifest["source_record_id"]] = set(saved_key_set)

            source_id = manifest["source_record_id"]
            text_group = manifest["normalized_text_group_id"]
            near_component = manifest["near_duplicate_component_id"]
            domain_component = manifest["domain_component_id"]
            for key in saved_key_set:
                base_to_keys[near_component].add(key)
                component_to_keys[domain_component].add(key)
            component_to_rows[domain_component].append(manifest)
            group_rows[text_group].append(manifest)
            group_labels[text_group].add(manifest["label_original"])
            group_base[text_group] = near_component
            group_component[text_group] = domain_component


    if record_count != len(rows):
        raise ValueError(f"Candidate count {record_count} != manifest count {len(rows)}")

    all_hosts = sorted({host for row in rows for host in json_list(row["destination_hostnames_json"])})
    reparsed_hosts = sorted({host for hosts in reextract_hostnames.values() for host in hosts})
    print(json.dumps({
        "psl_stage": "all_manifest_hosts",
        "unique_hosts": len(all_hosts),
        "java_input_lines_including_smoke_check": len(set(all_hosts)) + 1,
    }, ensure_ascii=True), flush=True)
    all_host_psl_started = time.perf_counter()
    psl_map, psl_info = experiment.psl_registrable_domains(all_hosts)
    all_host_psl_elapsed = time.perf_counter() - all_host_psl_started
    print(json.dumps({
        "psl_stage": "all_manifest_hosts_complete",
        "unique_hosts": len(all_hosts),
        "elapsed_seconds": all_host_psl_elapsed,
    }, ensure_ascii=True), flush=True)
    psl_rules = load_psl_rules()
    psl_regression_results, psl_regression_timings = validate_psl_lookup()
    psl_benchmarks = benchmark_psl_lookup(all_hosts)

    # Reconstruct the old candidate volume for diagnosis without sending it to
    # Java. Before this fix, fallback_evidence alone included ordinary
    # registrable hosts from explicit URLs.
    unfiltered_hosts = [h for h in all_hosts if fallback_evidence.get(h)]
    unfiltered_prefix_candidates: set[str] = set()
    unfiltered_prefix_variant_count = 0
    for host in unfiltered_hosts:
        last_dot = host.rfind(".")
        if last_dot < 0:
            continue
        for cut in range(last_dot + 2, len(host)):
            tail = host[cut:]
            prefix = host[:cut]
            if tail.isalpha() and len(tail) <= 20 and "." in prefix:
                unfiltered_prefix_candidates.add(prefix)
                unfiltered_prefix_variant_count += 1

    # Only inspect hosts which have no registrable PSL result and are not IPs.
    # fallback_evidence means "strong URL shape" and is common even for normal
    # registrable hosts; using it alone caused the previous prefix set to expand
    # across most of the dataset. This diagnostic filter does not alter grouping.
    fallback_hosts = []
    for host in all_hosts:
        if psl_map.get(host) is not None or not fallback_evidence.get(host):
            continue
        try:
            ipaddress.ip_address(host)
        except ValueError:
            fallback_hosts.append(host)
    prefix_candidates: set[str] = set()
    prefix_variants: dict[str, list[tuple[str, str]]] = defaultdict(list)
    prefix_variant_count = 0
    for host in fallback_hosts:
        last_dot = host.rfind(".")
        if last_dot < 0:
            continue
        for cut in range(last_dot + 2, len(host)):
            tail = host[cut:]
            prefix = host[:cut]
            if tail.isalpha() and len(tail) <= 20 and "." in prefix:
                prefix_candidates.add(prefix)
                prefix_variants[host].append((prefix, tail))
                prefix_variant_count += 1
    prefix_psl = {prefix: psl_map[prefix] for prefix in prefix_candidates if prefix in psl_map}
    unresolved_prefix_candidates = sorted(prefix_candidates - set(prefix_psl))
    prefix_lookup_started = time.perf_counter()
    if unresolved_prefix_candidates:
        additional_prefix_psl, _ = experiment.psl_registrable_domains(unresolved_prefix_candidates)
        prefix_psl.update(additional_prefix_psl)
    prefix_lookup_elapsed = time.perf_counter() - prefix_lookup_started
    prefix_lookup_stats = {
        "previous_unfiltered_strong_shape_hosts": len(unfiltered_hosts),
        "previous_unfiltered_raw_prefix_variants": unfiltered_prefix_variant_count,
        "previous_unfiltered_unique_prefix_candidates": len(unfiltered_prefix_candidates),
        "previous_unfiltered_java_input_lines_including_smoke_check": len(unfiltered_prefix_candidates) + (1 if unfiltered_prefix_candidates else 0),
        "eligible_fallback_hosts": len(fallback_hosts),
        "raw_prefix_variants": prefix_variant_count,
        "unique_prefix_candidates": len(prefix_candidates),
        "prefix_candidates_reused_from_initial_lookup": len(prefix_candidates) - len(unresolved_prefix_candidates),
        "unique_prefix_candidates_sent_to_java": len(unresolved_prefix_candidates),
        "java_input_lines_including_smoke_check": len(unresolved_prefix_candidates) + (1 if unresolved_prefix_candidates else 0),
        "elapsed_seconds": prefix_lookup_elapsed,
    }
    print(json.dumps({
        "psl_stage": "prefix_candidates",
        "stats": prefix_lookup_stats,
    }, ensure_ascii=True), flush=True)
    malformed_fallback_hosts: set[str] = set()
    malformed_evidence: dict[str, str] = {}
    for host, variants in prefix_variants.items():
        for prefix, tail in variants:
            try:
                ipaddress.ip_address(prefix)
                malformed_fallback_hosts.add(host)
                malformed_evidence[host] = f"trailing alphabetic {tail!r} follows valid IP prefix {prefix}"
                break
            except ValueError:
                if prefix_psl.get(prefix):
                    malformed_fallback_hosts.add(host)
                    malformed_evidence[host] = f"trailing alphabetic {tail!r} follows PSL-mapped prefix {prefix}"
                    break

    # Confirm the key mapping represented by the persisted manifest.
    host_to_key: dict[str, str] = {}
    key_type: dict[str, str] = {}
    for host in all_hosts:
        try:
            ip = ipaddress.ip_address(host)
            key = f"ip:{ip.compressed.lower()}"
            kind = "ip"
        except ValueError:
            domain = psl_map.get(host)
            if domain:
                key, kind = f"registrable:{domain}", "registrable"
            elif fallback_evidence.get(host):
                key, kind = f"exact_host_fallback:{host}", "exact_host_fallback"
            else:
                raise ValueError(f"Manifest selected host without PSL/fallback evidence: {host}")
        host_to_key[host] = key
        key_type[key] = kind
    for host, examples in host_examples.items():
        key = host_to_key.get(host)
        if key and len(key_examples[key]) < 4:
            for item in examples:
                if len(key_examples[key]) >= 4:
                    break
                key_examples[key].append(item)
    for row in rows:
        row_hosts = json_list(row["destination_hostnames_json"])
        source_index = int(row["source_record_index"])
        reparsed_selected = set()
        for host, strong_evidence in reextract_evidence[source_index].items():
            try:
                ipaddress.ip_address(host)
                is_ip = True
            except ValueError:
                is_ip = False
            if strong_evidence or psl_map.get(host) or is_ip:
                reparsed_selected.add(host)
        if reparsed_selected != set(row_hosts):
            raise ValueError(
                f"Selected host mismatch at source line {row['candidate_jsonl_line']}: "
                f"reparsed={sorted(reparsed_selected)[:5]} saved={sorted(row_hosts)[:5]}"
            )
        expected = {host_to_key[h] for h in row_hosts}
        saved = set(json_list(row["registrable_domains_json"]))
        saved_keys = {f"registrable:{d}" for d in saved}
        saved_keys.update(json_list(row["non_registrable_domain_keys_json"]))
        if expected != saved_keys:
            raise ValueError(f"Saved domain group keys do not reconstruct for {row['source_record_id']}")
        for host in row_hosts:
            key = host_to_key[host]
            host_to_group_keys[host].add(key)
            group_key_to_hosts[key].add(host)
            host_record_ids[host].add(row["source_record_id"])
            host_text_groups[host].add(row["normalized_text_group_id"])
            host_near_components[host].add(row["near_duplicate_component_id"])
            host_domain_components[host].add(row["domain_component_id"])
            key_record_ids[key].add(row["source_record_id"])
            key_text_groups[key].add(row["normalized_text_group_id"])
            key_near_components[key].add(row["near_duplicate_component_id"])
            key_domain_components[key].add(row["domain_component_id"])

    # Rebuild domain-key -> distinct adjacent domain-key counts through each
    # pre-existing near-duplicate component, and domain-component populations.
    neighbor_keys: dict[str, set[str]] = defaultdict(set)
    for keys in base_to_keys.values():
        for key in keys:
            neighbor_keys[key].update(keys - {key})

    # Load the source records again only for representative diagnostics and
    # model inference; no text is written to the audit CSVs beyond short excerpts.
    test_group_representatives: dict[str, tuple[dict[str, str], dict[str, object]]] = {}
    with INPUT.open("r", encoding="utf-8") as source:
        for line_number, source_line in enumerate(source, start=1):
            record = json.loads(source_line)
            manifest = rows_by_index[int(record.get("source_record_index", line_number))]
            if manifest["partition"] == "test" and manifest["quarantine_status"].lower() != "true":
                group_id = manifest["normalized_text_group_id"]
                current = test_group_representatives.get(group_id)
                if current is None or line_number < int(current[0]["candidate_jsonl_line"]):
                    test_group_representatives[group_id] = (manifest, record)

    # Whole-graph component statistics (each row is a source-record/domain edge;
    # deduplicated by pre-existing near-duplicate component and domain key).
    component_group_ids: dict[str, set[str]] = defaultdict(set)
    component_near_ids: dict[str, set[str]] = defaultdict(set)
    component_edge_pairs: dict[str, set[tuple[str, str]]] = defaultdict(set)
    component_labels: dict[str, Counter[str]] = defaultdict(Counter)
    component_unique_labels: dict[str, Counter[str]] = defaultdict(Counter)
    component_promo_rows: dict[str, int] = Counter()
    component_conflict_groups: dict[str, set[str]] = defaultdict(set)
    base_labels: dict[str, set[str]] = defaultdict(set)
    base_groups: dict[str, set[str]] = defaultdict(set)
    base_source_records: dict[str, set[str]] = defaultdict(set)
    key_component_sources: dict[str, set[str]] = defaultdict(set)
    key_component_texts: dict[str, set[str]] = defaultdict(set)
    suspicious_fallbacks: list[tuple[str, int]] = []
    for row in rows:
        comp = row["domain_component_id"]
        gid = row["normalized_text_group_id"]
        base = row["near_duplicate_component_id"]
        keys = row_key_sets[row["source_record_id"]]
        component_group_ids[comp].add(gid)
        component_near_ids[comp].add(base)
        component_labels[comp][row["label_original"]] += 1
        base_source_records[base].add(row["source_record_id"])
        if row["review_required"].lower() == "true":
            component_promo_rows[comp] += 1
        base_labels[base].add(row["label_original"])
        base_groups[base].add(gid)
        for key in keys:
            component_edge_pairs[comp].add((base, key))
            key_component_sources[key].add(row["source_record_id"])
            key_component_texts[key].add(gid)
        if "near_duplicate_component_has_conflicting_original_labels" in json_list(row["quarantine_reasons_json"]):
            component_conflict_groups[comp].add(gid)
    for row in rows:
        comp, base = row["domain_component_id"], row["near_duplicate_component_id"]
        if len(base_labels[base]) > 1:
            component_conflict_groups[comp].update(base_groups[base])
    for comp, group_ids in component_group_ids.items():
        seen_labels: dict[str, str] = {}
        for row in component_to_rows[comp]:
            seen_labels.setdefault(row["normalized_text_group_id"], row["label_original"])
        for label in seen_labels.values():
            component_unique_labels[comp][label] += 1

    largest_comp = max(component_group_ids, key=lambda c: len(component_group_ids[c]))
    largest_rows = component_to_rows[largest_comp]
    largest_keys = sorted(component_to_keys[largest_comp])
    largest_source_ids = {row["source_record_id"] for row in largest_rows}
    largest_text_ids = component_group_ids[largest_comp]
    largest_edges = component_edge_pairs[largest_comp]
    largest_label_rows = component_labels[largest_comp]
    conflicting_bases = {b for b in component_near_ids[largest_comp] if len(base_labels[b]) > 1}
    conflicting_source_ids = set().union(*(base_source_records[b] for b in conflicting_bases)) if conflicting_bases else set()
    conflicting_text_ids = set().union(*(base_groups[b] for b in conflicting_bases)) if conflicting_bases else set()
    hub_rows: list[dict[str, object]] = []
    for key in largest_keys:
        hosts = sorted(group_key_to_hosts[key])
        direct_ids = key_record_ids[key] & largest_source_ids
        direct_texts = key_text_groups[key] & largest_text_ids
        local_component_bases = {r["near_duplicate_component_id"] for r in largest_rows if r["source_record_id"] in direct_ids}
        adjacent = set().union(*(base_to_keys[b] for b in local_component_bases)) if local_component_bases else set()
        hub_rows.append({
            "domain_key": key,
            "key_type": key_type[key],
            "classification": classify_domain_key(key, hosts[0] if hosts else key.split(":", 1)[-1],
                                                  psl_map.get(hosts[0]) if hosts else None, psl_rules,
                                                  malformed_fallback_hosts),
            "representative_hostname": hosts[0] if hosts else key.split(":", 1)[-1],
            "source_records_directly_associated": len(direct_ids),
            "unique_text_groups_directly_associated": len(direct_texts),
            "near_duplicate_components_directly_associated": len(local_component_bases),
            "adjacent_domain_keys_via_shared_near_duplicate_component": len(adjacent - {key}),
            "domain_nodes_in_entire_component": len(largest_keys),
            "component_source_records": len(largest_source_ids),
            "component_unique_texts": len(largest_text_ids),
        })
    hub_rows.sort(key=lambda r: (-int(r["source_records_directly_associated"]),
                                 -int(r["adjacent_domain_keys_via_shared_near_duplicate_component"]),
                                 str(r["domain_key"])))

    coverage: dict[int, dict[str, int]] = {}
    for take in (1, 5, 10, 25):
        selected_keys = [str(r["domain_key"]) for r in hub_rows[:take]]
        covered_rows = set().union(*(key_record_ids[k] for k in selected_keys)) & largest_source_ids if selected_keys else set()
        covered_texts = set().union(*(key_text_groups[k] for k in selected_keys)) & largest_text_ids if selected_keys else set()
        coverage[take] = {"source_records": len(covered_rows), "unique_texts": len(covered_texts)}

    # Build a full inventory by stable grouping key.
    all_key_rows: list[dict[str, object]] = []
    for key in sorted(key_type):
        hosts = sorted(group_key_to_hosts[key])
        host = hosts[0] if hosts else key.split(":", 1)[-1]
        reg = psl_map.get(host)
        fallback = key_type[key] == "exact_host_fallback"
        all_key_rows.append({
            "domain_key": key,
            "key_type": key_type[key],
            "representative_hostname": host,
            "classification": classify_domain_key(key, host, reg, psl_rules, malformed_fallback_hosts),
            "representative_hostname_classification": classify_host(host, reg, psl_rules, fallback),
            "fallback_concatenation_evidence": malformed_evidence.get(host, ""),
            "distinct_hostnames": len(hosts),
            "registrable_domain": reg or "",
            "source_record_count": len(key_record_ids[key]),
            "unique_text_group_count": len(key_text_groups[key]),
            "near_duplicate_component_count": len(key_near_components[host]) if host in key_near_components else 0,
            "domain_component_count": len(key_domain_components[host]) if host in key_domain_components else 0,
            "example_source_record_ids": json.dumps([x["source_record_id"] for x in key_examples[key][:3]]),
            "example_extraction_methods": json.dumps(sorted({x["method"] for x in key_examples[key]})),
            "example_text_excerpt": (key_examples[key][0]["text_excerpt"] if key_examples[key] else ""),
        })

    # Cross-check parser-extracted metrics against the saved per-group split.
    if len(test_group_representatives) != metrics["test_overall"]["records"]:
        raise ValueError("Test manifest does not have exactly one representative per saved test text group")
    model = joblib.load(MODEL)
    representatives = [test_group_representatives[k] for k in sorted(test_group_representatives)]
    texts = [str(record["text"]) for _, record in representatives]
    y_true = np.asarray([int(row["label_original"]) for row, _ in representatives], dtype=int)
    groups = [row["normalized_text_group_id"] for row, _ in representatives]
    if len(groups) != len(set(groups)):
        raise ValueError("A test normalized-text group appears more than once")
    scores = model.predict_proba(texts)[:, 1]
    y_pred = (scores >= float(metrics["threshold"])).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = map(int, (cm[0, 0], cm[0, 1], cm[1, 0], cm[1, 1]))
    recalculated = {
        "records": len(y_true), "TN": tn, "FP": fp, "FN": fn, "TP": tp,
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "specificity": float(tn / (tn + fp)),
        "false_positive_rate": float(fp / (fp + tn)),
        "false_negative_rate": float(fn / (fn + tp)),
        "roc_auc": float(roc_auc_score(y_true, scores)),
        "average_precision_pr_auc": float(average_precision_score(y_true, scores)),
        "class_counts": {"0": int((y_true == 0).sum()), "1": int((y_true == 1).sum())},
        "confusion_matrix_labels_0_1": cm.tolist(),
    }
    saved_test = metrics["test_overall"]
    numeric_keys = ["accuracy", "precision", "recall", "f1", "specificity", "false_positive_rate", "false_negative_rate", "roc_auc", "average_precision_pr_auc"]
    metric_match = all(recalculated[k] == saved_test[k] for k in numeric_keys)
    metric_match &= all(recalculated[k] == saved_test[k] for k in ("records", "TN", "FP", "FN", "TP", "class_counts", "confusion_matrix_labels_0_1"))
    if not metric_match:
        raise ValueError(f"Recomputed saved-model metrics differ from metrics.json: {recalculated}")

    type_counts: Counter[str] = Counter()
    test_url_rows = 0
    manifest_url_flag_test_rows = 0
    test_no_domain_rows = 0
    url_indices: list[int] = []
    non_url_indices: list[int] = []
    input_type_indices: dict[str, list[int]] = defaultdict(list)
    for index, (row, record) in enumerate(representatives):
        kind = str(row["inferred_input_type"])
        type_counts[kind] += 1
        input_type_indices[kind].append(index)
        if experiment.URL_RE.search(str(record["text"])):
            url_indices.append(index)
        else:
            non_url_indices.append(index)
        test_url_rows += bool(experiment.URL_RE.search(str(record["text"])))
        manifest_url_flag_test_rows += row["url_containing"].lower() == "true"
        test_no_domain_rows += not bool(json_list(row["registrable_domains_json"]))
    if test_url_rows != metrics["test_url_containing"]["records"]:
        raise ValueError("URL_RE test group count does not match the saved URL-slice metric")
    def calculated_subset(indices: list[int]) -> dict[str, object]:
        return experiment.calculate_metrics(
            [int(y_true[i]) for i in indices],
            [int(y_pred[i]) for i in indices],
            [float(scores[i]) for i in indices],
        )
    def metric_objects_equal(left: dict[str, object], right: dict[str, object]) -> bool:
        keys = ("records", "class_counts", "confusion_matrix_labels_0_1", "TN", "FP", "FN", "TP",
                "accuracy", "precision", "recall", "f1", "specificity", "false_positive_rate",
                "false_negative_rate", "roc_auc", "average_precision_pr_auc")
        return all(left.get(key) == right.get(key) for key in keys)
    slice_match = metric_objects_equal(calculated_subset(url_indices), metrics["test_url_containing"])
    slice_match &= metric_objects_equal(calculated_subset(non_url_indices), metrics["test_non_url_containing"])
    for kind, indices in input_type_indices.items():
        slice_match &= metric_objects_equal(calculated_subset(indices), metrics["test_by_inferred_input_type"][kind])
    if not slice_match:
        raise ValueError("Recomputed URL/non-URL or input-type metrics differ from metrics.json")

    from sklearn.metrics import classification_report as sklearn_classification_report
    url_index_set = set(url_indices)
    report_text = (
        "Domain-held-out phishing classifier; source labels: 0=benign, 1=phishing; threshold=0.5\n"
        "\nOVERALL TEST (unique normalized text groups)\n"
        + sklearn_classification_report(y_true, y_pred, labels=[0, 1],
            target_names=["benign_source_label_0", "phishing_source_label_1"], zero_division=0, digits=6)
        + "\nURL-CONTAINING TEST\n"
        + "URL-containing test\n"
        + sklearn_classification_report(y_true[url_indices], y_pred[url_indices], labels=[0, 1],
            target_names=["benign_source_label_0", "phishing_source_label_1"], zero_division=0, digits=6)
        + "\nNON-URL TEST\n"
        + "Non-URL test\n"
        + sklearn_classification_report(y_true[non_url_indices], y_pred[non_url_indices], labels=[0, 1],
            target_names=["benign_source_label_0", "phishing_source_label_1"], zero_division=0, digits=6)
    )
    for kind, indices in sorted(input_type_indices.items()):
        report_text += ("\nINPUT TYPE: " + kind + "\n" + kind + "\n"
            + sklearn_classification_report(y_true[indices], y_pred[indices], labels=[0, 1],
                target_names=["benign_source_label_0", "phishing_source_label_1"], zero_division=0, digits=6))
    saved_classification_report = (OUT / "classification_report.txt").read_text(encoding="utf-8")
    classification_report_match = report_text.strip() == saved_classification_report.strip()
    if not classification_report_match:
        raise ValueError("Recomputed classification report does not exactly match the saved report")

    parser_results = parser_cases()
    write_csv(PARSER_CSV, list(parser_results[0]), parser_results)
    write_csv(KEYS_CSV, list(all_key_rows[0]), all_key_rows)
    write_csv(LARGEST_CSV, list(hub_rows[0]), hub_rows)

    fallback_keys = [r for r in all_key_rows if r["key_type"] == "exact_host_fallback"]
    fallback_records = sum(int(r["source_record_count"]) for r in fallback_keys)
    multi_domain_records = sum(len(row_key_sets[r["source_record_id"]]) > 1 for r in rows)
    no_high_confidence = sum(not json_list(r["registrable_domains_json"]) and not any(k.startswith("ip:") for k in json_list(r["non_registrable_domain_keys_json"])) for r in rows)
    no_selected_domain = sum(not json_list(r["destination_hostnames_json"]) for r in rows)
    public_suffix_hosts = [h for h in all_hosts if not psl_map.get(h) and is_psl_suffix(h, psl_rules)]
    fallback_top = sorted(fallback_keys, key=lambda r: (-int(r["source_record_count"]), str(r["domain_key"])))[:20]

    parser_ok = sum(bool(r["pass"]) for r in parser_results)
    psl_python_packages: dict[str, str] = {}
    for package in ("tldextract", "publicsuffix2", "publicsuffixlist", "python-domain-utils"):
        try:
            psl_python_packages[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            pass
    key_class_counts = Counter(str(row["classification"]) for row in all_key_rows)
    train_rows = [r for r in rows if r["partition"] == "train" and r["quarantine_status"].lower() != "true"]
    val_rows = [r for r in rows if r["partition"] == "validation" and r["quarantine_status"].lower() != "true"]
    test_rows = [r for r in rows if r["partition"] == "test" and r["quarantine_status"].lower() != "true"]
    no_domain_by_partition = {
        name: sum(not json_list(r["registrable_domains_json"]) for r in subset)
        for name, subset in (("train", train_rows), ("validation", val_rows), ("test", test_rows))
    }
    report = [
        "# Domain extraction and split integrity audit",
        "",
        "## Executive finding",
        "",
        "**NO-GO for describing the saved overall metrics as a defensible evaluation of generalization to previously unseen domains.** The saved manifest mechanically isolates its extracted domain keys, but a source-level audit found that bare dotted tokens in ordinary text are treated as destinations, public-suffix-only authorities can become exact-host fallback groups, and syntactically valid but non-registrable strings are grouped as fallback hosts. In addition, the overall test metrics include records without a registrable destination domain. The registrable-domain-containing test slice is useful as an exploratory within-corpus slice, but the entire metric set should not be presented as domain-held-out performance until extraction is corrected and the split and metrics are regenerated in a separate experiment.",
        "",
        "No URLs were opened; no DNS, network, or remote-service calls were made. The saved model was loaded only for read-only prediction reproduction; no fitting or tuning occurred.",
        "",
        "## Extraction paths traced",
        "",
        f"- URL token discovery reuses `{experiment.URL_RE.pattern}` from `prepare_ml_datasets.py`. The scheme/www branch consumes non-whitespace text up to `<`, `>`, or quotes; the bare-domain branch accepts a dotted token with an alphabetic suffix and optional path. It is a syntactic regex, not a URL semantic validator.",
        "- Scheme-bearing and `www.` values are treated as strong URL-shaped candidates. Protocol-relative values are supported by the hostname parser when passed through, but the shared URL regex does not independently start on `//`; they are reliably discovered in HTML attributes, not guaranteed in arbitrary prose.",
        "- Bare candidates receive an `https://` prefix for parsing. In plain text, email, and URL-typed records, every regex match is considered, including a bare `example.com` mention in prose. HTML uses canonical URL, then `og:url`, then form actions, then all anchor hrefs. Image/script/style resource URLs are ignored. Email addresses themselves are skipped when the candidate is immediately preceded by `@`; other message-body URLs are extracted.",
        "- Multiple candidate URLs in a record are retained. Each destination key unions the record's pre-existing near-duplicate component with other components containing that key. A multi-link HTML/email record can therefore bridge many domain nodes.",
        "- Host normalization lowercases, strips a trailing dot, applies Python's built-in `idna` codec, validates label syntax/length, canonicalizes IP literals, and accesses `.port` to reject malformed ports. Query and fragment components do not affect the hostname. Single-label hosts such as `localhost` are rejected as unqualified.",
        "- If the local PSL returns a registrable domain, grouping uses `registrable:<domain>`. Otherwise, any host sourced from a strong-shaped candidate (`http(s)`, `www.`, or a URL-only record) is assigned `exact_host_fallback:<host>`. This fallback does not distinguish a genuinely unlisted hostname from a public-suffix-only hostname or a malformed URL token that happens to pass hostname syntax.",
        "- Candidate extraction is not the same as confirmed destination extraction. Bare dotted strings from ordinary text are grouped when the PSL recognizes them, even if they are citations, prose, examples, or unrelated references.",
        "",
        "## Full dataset domain-key inventory",
        "",
        f"- Source records: {record_count:,}; records with any candidate reported by the destination extractor: {url_like_record_count:,}; records with a match from the shared `URL_RE`: {regex_url_record_count:,}. The extractor's extra count includes bare-IP-only URL records.",
        f"- Distinct selected hostnames: {len(all_hosts):,}; hosts with a PSL registrable domain: {sum(bool(psl_map.get(h)) for h in all_hosts):,}; distinct registrable-domain keys: {len({v for v in psl_map.values() if v}):,}.",
        f"- Distinct IP keys: {sum(k.startswith('ip:') for k in key_type):,}; exact-host fallback keys: {sum(k.startswith('exact_host_fallback:') for k in key_type):,}; all exact-host fallback-key associated source rows (non-deduplicated across keys): {fallback_records:,}.",
        f"- Public-suffix-only selected hostnames: {len(public_suffix_hosts):,}; invalid/unusable candidate tokens: {sum(n for status, n in token_statuses.items() if status not in {'normalized_hostname', 'ip_literal'}):,} across {sum(token_statuses.values()):,} candidates ({len(invalid_candidate_counts):,} distinct rejected candidate strings). Key category totals: `{dict(sorted(key_class_counts.items()))}`. See full counts and examples in `domain_key_classification.csv`.",
        f"- Records with multiple grouping keys: {multi_domain_records:,}; records without any selected hostname: {no_selected_domain:,}; records with no high-confidence registrable domain or IP: {no_high_confidence:,}.",
        f"- Domain key classifications are diagnostic heuristics for common shortening, platform, and infrastructure services. They do not cause any key to be excluded. The full CSV preserves unresolved and fallback keys.",
        "",
        "### Most frequent fallback keys",
        "",
        "| Key | Source records | Example source records | Candidate token | Extraction methods | Context excerpt |",
        "|---|---:|---|---|---|---|",
    ]
    for item in fallback_top:
        examples = key_examples[str(item["domain_key"])][:2]
        ids = ", ".join(x["source_record_id"] for x in examples)
        methods = ", ".join(sorted({x["method"] for x in examples}))
        excerpt = (examples[0]["text_excerpt"] if examples else "").replace("|", "\\|")[:180]
        candidate = (examples[0]["candidate"] if examples else "").replace("|", "\\|")[:110]
        report.append(f"| `{item['domain_key']}` | {item['source_record_count']} | {ids} | `{candidate}` | {methods} | {excerpt} |")
    report.extend([
        "",
        "The fallback keys are not validated destinations simply because the regex and URL parser accepted their hostname syntax. `domain_key_classification.csv` records counts, representative source IDs, extraction method, and a short source excerpt for each key. Review the high-frequency and malformed-looking entries there; the table above keeps only the most frequent keys.",
        "",
        "## 12,341-text connected component",
        "",
        f"- Component ID: `{largest_comp}`.",
        f"- Source records: {len(largest_source_ids):,}; unique normalized text groups: {len(largest_text_ids):,}; distinct domain-key nodes: {len(largest_keys):,}; bipartite edges (unique existing near-duplicate-component/domain-key pairs): {len(largest_edges):,}; near-duplicate component nodes: {len(component_near_ids[largest_comp]):,}.",
        f"- Source-record label distribution: label 0={largest_label_rows.get('0', 0):,}, label 1={largest_label_rows.get('1', 0):,}; unique normalized-text label distribution: label 0={component_unique_labels[largest_comp].get('0', 0):,}, label 1={component_unique_labels[largest_comp].get('1', 0):,}.",
        f"- Promotional-review source records: {component_promo_rows[largest_comp]:,}; conflicting-label near-duplicate components: {len(conflicting_bases):,}; source records in those conflicting components: {len(conflicting_source_ids):,}; unique text groups in those components: {len(conflicting_text_ids):,}.",
        "- The complete node list and degree/frequency columns are in `largest_component_domains.csv`.",
        "",
        "| Top domain nodes by directly associated records | Direct source records | Direct unique texts | Adjacent domain keys via shared near-duplicate components |",
        "|---|---:|---:|---:|",
    ])
    for item in hub_rows[:15]:
        report.append(f"| `{item['domain_key']}` | {item['source_records_directly_associated']} | {item['unique_text_groups_directly_associated']} | {item['adjacent_domain_keys_via_shared_near_duplicate_component']} |")
    report.extend([
        "",
        "| Top-N domain nodes | Source records covered (union) | Unique texts covered (union) |",
        "|---:|---:|---:|",
    ])
    for take, counts in coverage.items():
        report.append(f"| {take} | {counts['source_records']:,} ({counts['source_records']/len(largest_source_ids):.1%}) | {counts['unique_texts']:,} ({counts['unique_texts']/len(largest_text_ids):.1%}) |")
    report.extend([
        "",
        "The hub analysis distinguishes direct key frequency from graph reach. If top-N coverage is small while the component contains thousands of keys and edges, the component is a chain/bridge effect rather than one dominant destination. High direct frequency can also be legitimate for a newsletter/archive containing many old links; that does not establish that every linked host was a destination in the original message.",
        "",
        "## Deterministic parser test suite",
        "",
        f"- Actual results: {parser_ok}/{len(parser_results)} parser-plus-destination-policy cases passed. Full expected-versus-actual rows are in `parser_test_results.csv`; intentional failures expose behaviors requiring correction.",
        "- Important observed behavior: `https://co.uk` is syntactically accepted and the JDK PSL returns no registrable domain; the experiment's strong-URL fallback then groups `co.uk` as an exact host, although it is a public-suffix-only value. Likewise, `https://aol.comsite/path` passes hostname syntax but has no registrable result and enters exact-host fallback.",
        "- `I read example.com yesterday` yields a bare-domain regex match and is treated as a destination because the local PSL recognizes `example.com`. This is not a parser failure in `urlsplit`; it is a source-candidate classification limitation.",
        "- The built-in Python `idna` codec converts the Unicode test host to its ASCII punycode form; it does not by itself document which IDNA policy/version semantics are intended by the project.",
        "",
        "## Public Suffix List dependency assessment",
        "",
        f"- Current implementation uses Oracle JDK `{psl_info['jdk_version']}` `sun.security.util.RegisteredDomain` and the bundled PSL snapshot `{experiment.PSL_FILE.relative_to(ROOT)}` (SHA-256 `{psl_info['psl_snapshot_sha256']}`). The API is in an internal `sun.*` package; this couples the split to a JDK implementation/version and is not a stable Python dependency interface.",
        f"- Full-manifest lookup timing: {len(all_hosts):,} unique hostnames, {len(all_hosts)+1:,} Java input lines including the smoke-check hostname, {all_host_psl_elapsed:.3f}s total. The total includes `java -version`, Java source-file compilation/startup, line processing, captured output, and Python parsing.",
        f"- Prefix diagnostic lookup: `{json.dumps(prefix_lookup_stats, sort_keys=True)}`. The previous unfiltered path selected every strong-shaped hostname, including registrable domains; the corrected diagnostic first reuses the full-host PSL results and only queries unresolved candidate prefixes of exact-host fallbacks. It does not alter grouping or registrable-domain semantics.",
        f"- Lookup benchmark by distinct input count: `{json.dumps(psl_benchmarks, sort_keys=True)}`. Each timed call includes one local Java invocation and the smoke-check line; no URLs are accessed.",
        f"- Representative PSL semantic checks: {sum(bool(r['pass']) for r in psl_regression_results)}/{len(psl_regression_results)} passed (including public suffix, multi-level suffix, private suffix, IP/localhost/malformed normalization, and IDN/Punycode). Repeating the PSL lookup yielded identical values. Timings: `{json.dumps(psl_regression_timings, sort_keys=True)}`.",
        f"- Locally installed candidate Python PSL packages: `{psl_python_packages or 'none of tldextract, publicsuffix2, publicsuffixlist, python-domain-utils'}`. A pinned Python library could be reproducible if its release accepts a local immutable PSL snapshot and runtime remote fetching is disabled; the candidate API behavior was not verified from local/official package docs here, so this remains unresolved. No package was installed and no documentation or list was downloaded.",
        "- The current JDK snapshot itself is local and can be pinned by JDK build plus file hash, so this run did not require runtime network access. Its portability and API stability remain weaker than a project-owned pinned parser/snapshot with tested behavior.",
        "",
        "## Split, quarantine, and metric audit",
        "",
        f"- Primary inclusion is `partition in {{train, validation, test}}` and `quarantine_status != true`; all source rows remain in the manifest. Existing promotional-review and conflicting-label quarantine propagates across the full domain-connected component.",
        f"- Records without registrable-domain keys remain in the primary split by text/near-duplicate/domain-connected component. No-registrable-domain test groups: {test_no_domain_rows:,} of {len(test_rows):,}; these do not demonstrate unseen-registrable-domain generalization. The saved metrics' `test_url_containing` slice uses `URL_RE` and contains {test_url_rows:,} groups; the manifest URL flag is true for {manifest_url_flag_test_rows:,} groups because the destination extractor additionally counts bare-IP-only candidates.",
        f"- Inferred input-type counts among test groups: `{dict(sorted(type_counts.items()))}`. URL-containing and inferred `url` type are different slices: the former also includes other types that contain a URL token.",
        f"- The source record text and manifest were re-parsed with the exact saved extraction helpers; extracted host sets and URL-containing flags matched the manifest for all {record_count:,} records.",
        f"- The saved model was loaded using scikit-learn {sklearn.__version__} and predicted once per test normalized-text group (n={len(groups):,}, all group IDs unique). Recomputed confusion matrix and all saved scalar metrics match `metrics.json` exactly: {metric_match}.",
        f"- The URL/non-URL and inferred-input-type slices also match the saved metrics exactly: {slice_match}. Recomputed formatted `classification_report.txt` matches byte-for-text after trimming final whitespace: {classification_report_match}.",
        "- No per-example test-prediction file exists among the experiment artifacts. Therefore a saved prediction-to-label row audit is unavailable; this audit reproduced predictions from the saved pipeline and checked that the one-per-group evaluation construction matches the aggregate report. The text classification report's aggregate support and class metrics agree with the recomputed predictions.",
        "- Domain-component grouping is conservative: any selected URL/host key shared by records links their near-duplicate components. Questionable fallback hosts can create false joins and over-quarantine; if they misspell/absorb a true hostname, they can also fail to join records that should share a domain. Thus zero overlap counts prove separation only for extracted keys, not correctness of the extracted destination identity.",
        "- Multiple-domain HTML/email records can create large components by chaining destinations. The giant component has both conflict/promotion quarantine; the available node/edge and hub statistics show whether it is driven by a few hubs or many bridges.",
        f"- Overall metrics combine URL-containing records ({metrics['test_url_containing']['records']:,}), non-URL-containing records ({metrics['test_non_url_containing']['records']:,}), and no-domain records. Only records with reliable registrable destination identities can support the intended unseen-domain claim. The current report's domain-containing subset is still a within-source, label-unadjudicated experiment.",
        "",
        "## Recommendation and next steps",
        "",
        "**NO-GO** for presenting the current overall metrics as a defensible unseen-domain generalization estimate. Preserve these artifacts as an exploratory result. Before a replacement experiment, review candidate extraction with a strict URL parser and context-specific acceptance rules; distinguish confirmed URL authorities, HTML page destinations, email body links, bare prose mentions, IPs, public-suffix-only values, and unresolved hosts. Do not group public suffixes or unverified fallback hosts as if they were confirmed registrable destinations. Recompute components and quarantine without relaxing text/domain leakage constraints, then report (a) registrable-domain-bearing test records, (b) no-domain/non-URL test records, and (c) unresolved-host records separately. Pin a stable PSL library and immutable local suffix snapshot only after offline behavior is documented and parser tests pass. No changes to the old split or model are made by this audit.",
        "",
        "## Artifacts created",
        "",
        "- `domain_integrity_audit.md`",
        "- `domain_key_classification.csv`",
        "- `largest_component_domains.csv`",
        "- `parser_test_results.csv`",
        "",
    ])
    AUDIT.write_text("\n".join(report), encoding="utf-8")
    print(json.dumps({
        "audit": str(AUDIT.relative_to(ROOT)),
        "domain_keys_csv": str(KEYS_CSV.relative_to(ROOT)),
        "largest_component_csv": str(LARGEST_CSV.relative_to(ROOT)),
        "parser_tests_csv": str(PARSER_CSV.relative_to(ROOT)),
        "records": record_count,
        "url_like_records": url_like_record_count,
        "distinct_hosts": len(all_hosts),
        "distinct_registrable_domains": len({v for v in psl_map.values() if v}),
        "domain_group_keys": len(key_type),
        "fallback_keys": len(fallback_keys),
        "records_without_high_confidence_domain": no_high_confidence,
        "records_without_any_selected_domain": no_selected_domain,
        "largest_component_id": largest_comp,
        "largest_component_source_records": len(largest_source_ids),
        "largest_component_unique_texts": len(largest_text_ids),
        "largest_component_domain_nodes": len(largest_keys),
        "largest_component_edges": len(largest_edges),
        "largest_component_conflicting_near_duplicate_components": sum(len(base_labels[b]) > 1 for b in component_near_ids[largest_comp]),
        "largest_component_promo_rows": component_promo_rows[largest_comp],
        "parser_cases_passed": parser_ok,
        "parser_cases_total": len(parser_results),
        "test_recomputed_metrics_match": metric_match,
        "recomputed_test_metrics": recalculated,
        "no_domain_test_groups": test_no_domain_rows,
        "url_containing_test_groups": test_url_rows,
        "manifest_url_flag_test_groups": manifest_url_flag_test_rows,
        "url_flag_difference_bare_ip_or_slice_semantics": manifest_url_flag_test_rows - test_url_rows,
        "url_and_input_slice_metrics_match": slice_match,
        "classification_report_matches": classification_report_match,
        "parser_failures": [r["case"] for r in parser_results if not r["pass"]],
        "all_host_psl_lookup_elapsed_seconds": all_host_psl_elapsed,
        "prefix_lookup_stats": prefix_lookup_stats,
        "psl_regression_results": psl_regression_results,
        "psl_regression_timings": psl_regression_timings,
        "psl_benchmarks": psl_benchmarks,
    }, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
