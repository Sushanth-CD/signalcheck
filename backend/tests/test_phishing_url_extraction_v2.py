"""Parser regression cases for the offline Phishing URL Extraction V2 pipeline."""
from __future__ import annotations

import sys
import unittest
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.notebooks import phishing_url_extraction_v2 as extraction
from backend.ml.psl_service import is_psl_suffix, load_psl_rules, psl_registrable_domains


@dataclass(frozen=True)
class Case:
    name: str
    text: str
    expected_count: int
    candidate: str
    hostname: str | None
    registrable: str | None
    evidence: str
    confidence: str
    grouping_key: str | None
    reason: str | None = None
    status: str | None = None


CASES = [
    Case("standard HTTP", "http://example.com/path", 1, "http://example.com/path", "example.com", "example.com", "explicit_http_url", "high", "registrable:example.com"),
    Case("standard HTTPS", "https://example.org", 1, "https://example.org", "example.org", "example.org", "explicit_http_url", "high", "registrable:example.org"),
    Case("URL without scheme", "example.com/path", 1, "example.com/path", "example.com", "example.com", "probable_bare_destination", "medium", None, "bare domain is not an explicit URL destination", "ambiguous_bare_domain_mention"),
    Case("www domain", "www.example.net/page", 1, "www.example.net/page", "www.example.net", "example.net", "www_url", "high", "registrable:example.net"),
    Case("hostname casing and trailing dot", "https://Example.COM./x", 1, "https://Example.COM./x", "example.com", "example.com", "explicit_http_url", "high", "registrable:example.com"),
    Case("subdomain", "https://mail.news.example.co.uk/inbox", 1, "https://mail.news.example.co.uk/inbox", "mail.news.example.co.uk", "example.co.uk", "explicit_http_url", "high", "registrable:example.co.uk"),
    Case("port", "https://example.com:8443/a", 1, "https://example.com:8443/a", "example.com", "example.com", "explicit_http_url", "high", "registrable:example.com"),
    Case("query string", "https://example.com/search?q=abc", 1, "https://example.com/search?q=abc", "example.com", "example.com", "explicit_http_url", "high", "registrable:example.com"),
    Case("fragment", "https://example.com/page#part", 1, "https://example.com/page#part", "example.com", "example.com", "explicit_http_url", "high", "registrable:example.com"),
    Case("trailing punctuation", "See (https://example.com/path).", 1, "https://example.com/path", "example.com", "example.com", "explicit_http_url", "high", "registrable:example.com"),
    Case("IPv4", "http://192.0.2.10:8080/a", 1, "http://192.0.2.10:8080/a", "192.0.2.10", None, "explicit_http_url", "high", "ip:192.0.2.10", status="ip_literal"),
    Case("IPv6", "https://[2001:db8::1]/a", 1, "https://[2001:db8::1]/a", "2001:db8::1", None, "explicit_http_url", "high", "ip:2001:db8::1", status="ip_literal"),
    Case("internationalized domain", "https://bücher.com/shop", 1, "https://bücher.com/shop", "xn--bcher-kva.com", "xn--bcher-kva.com", "explicit_http_url", "high", "registrable:xn--bcher-kva.com"),
    Case("punycode", "https://xn--bcher-kva.com/shop", 1, "https://xn--bcher-kva.com/shop", "xn--bcher-kva.com", "xn--bcher-kva.com", "explicit_http_url", "high", "registrable:xn--bcher-kva.com"),
    Case("public suffix only", "https://co.uk", 1, "https://co.uk", "co.uk", None, "explicit_http_url", "unresolved", None, "hostname is a public suffix without a registrable label", "public_suffix_only"),
    Case("private suffix", "https://sub.tenant.github.io/a", 1, "https://sub.tenant.github.io/a", "sub.tenant.github.io", "tenant.github.io", "explicit_http_url", "high", "registrable:tenant.github.io"),
    Case("localhost", "http://localhost:8080/", 1, "http://localhost:8080/", None, None, "explicit_http_url", "unresolved", None, "hostname is unqualified or exceeds DNS length limits", "invalid_hostname"),
    Case("invalid hostname", "https://bad..example.com/", 1, "https://bad..example.com/", None, None, "explicit_http_url", "unresolved", None, "hostname contains an invalid DNS label", "invalid_hostname"),
    Case("invalid port", "http://example.com:99999/x", 1, "http://example.com:99999/x", None, None, "explicit_http_url", "unresolved", None, "port is not numeric or outside the valid range", "invalid_port"),
    Case("malformed HTTP scheme", "https:/example.com/path", 1, "https:/example.com/path", None, None, "malformed_url_syntax", "unresolved", None, "HTTP URL is missing // authority syntax", "malformed_url"),
    Case("bare domain prose", "Our company is example.com today.", 1, "example.com", "example.com", "example.com", "bare_domain_mention", "low", None, "bare domain is not an explicit URL destination", "ambiguous_bare_domain_mention"),
    Case("bare domain destination context", "Visit example.com for the details.", 1, "example.com", "example.com", "example.com", "probable_bare_destination", "medium", None, "bare domain is not an explicit URL destination", "ambiguous_bare_domain_mention"),
    Case("concatenated URLs", "http://a.example.comhttp://b.example.net", 2, "http://a.example.com", "a.example.com", "example.com", "explicit_http_url", "high", "registrable:example.com"),
    Case("multiple separated URLs", "https://example.com/a, https://example.net/b", 2, "https://example.com/a", "example.com", "example.com", "explicit_http_url", "high", "registrable:example.com"),
    Case("URL followed by prose", "http://www.internationalfreecall.comIf", 1, "http://www.internationalfreecall.comIf", "www.internationalfreecall.comif", None, "explicit_http_url", "unresolved", None, "no registrable domain in pinned PSL; suffix may be unknown or host malformed", "unknown_suffix"),
    Case("HTML canonical URL", '<link rel="canonical" href="https://example.com/page">', 1, "https://example.com/page", "example.com", "example.com", "html_canonical", "high", "registrable:example.com"),
    Case("HTML Open Graph URL", '<meta property="og:url" content="https://example.org/post">', 1, "https://example.org/post", "example.org", "example.org", "html_open_graph", "high", "registrable:example.org"),
    Case("HTML anchor", '<a href="https://example.net/path">go</a>', 1, "https://example.net/path", "example.net", "example.net", "html_anchor", "high", "registrable:example.net"),
    Case("HTML form action", '<form action="https://example.com/submit"></form>', 1, "https://example.com/submit", "example.com", "example.com", "html_form", "high", "registrable:example.com"),
    Case("HTML relative link", '<a href="../login">login</a>', 1, "../login", None, None, "html_relative", "unresolved", None, "relative reference has no verified document base URL", "relative_without_base"),
    Case("HTML non-HTTP and empty attributes", '<a href="mailto:user@example.com"></a><a href="javascript:void(0)"></a><a href=""></a>', 3, "mailto:user@example.com", None, None, "html_anchor", "unresolved", None, "mailto is not an HTTP destination", "unsupported_scheme"),
]


def run_parser_cases() -> list[dict[str, object]]:
    """Run all parser fixtures against the pinned local PSL and return audit rows."""
    candidates_by_case: dict[str, list[extraction.Candidate]] = {
        case.name: extraction.extract_candidates(f"parser:{case.name}", case.text) for case in CASES
    }
    hosts = sorted({
        candidate.normalized_hostname
        for candidates in candidates_by_case.values()
        for candidate in candidates
        if candidate.normalized_hostname and candidate.parser_status not in {"ip_literal", "ambiguous_ip_mention"}
    })
    psl_map, _ = psl_registrable_domains(hosts)
    psl_rules = load_psl_rules()
    rows: list[dict[str, object]] = []
    for case in CASES:
        candidates = candidates_by_case[case.name]
        first = candidates[0] if candidates else None
        if first:
            first = extraction.apply_psl(
                first,
                psl_map.get(first.normalized_hostname or ""),
                is_public_suffix=bool(first.normalized_hostname and is_psl_suffix(first.normalized_hostname, psl_rules)),
            )
        actual = {
            "candidate_count": len(candidates),
            "candidate_text": first.candidate_text if first else "",
            "hostname": first.normalized_hostname if first else None,
            "registrable_domain": first.registrable_domain if first else None,
            "evidence": first.evidence_category if first else "",
            "confidence": first.confidence if first else "",
            "grouping_key": first.domain_grouping_key if first else None,
            "reason": first.rejection_reason if first else None,
            "status": first.parser_status if first else "",
        }
        expected = {
            "candidate_count": case.expected_count,
            "candidate_text": case.candidate,
            "hostname": case.hostname,
            "registrable_domain": case.registrable,
            "evidence": case.evidence,
            "confidence": case.confidence,
            "grouping_key": case.grouping_key,
            "reason": case.reason,
            "status": case.status or ("normalized_hostname" if case.hostname else first.parser_status if first else ""),
        }
        # Special case: a concatenated token must preserve and validate both boundaries.
        if case.name in {"concatenated URLs", "multiple separated URLs"}:
            second = candidates[1] if len(candidates) > 1 else None
            actual["second_candidate"] = second.candidate_text if second else ""
            actual["second_hostname"] = second.normalized_hostname if second else None
            actual["second_grouping_key"] = (
                extraction.apply_psl(second, psl_map.get(second.normalized_hostname or "")).domain_grouping_key
                if second else None
            )
            if case.name == "concatenated URLs":
                expected.update({"second_candidate": "http://b.example.net", "second_hostname": "b.example.net",
                                 "second_grouping_key": "registrable:example.net"})
            else:
                expected.update({"second_candidate": "https://example.net/b", "second_hostname": "example.net",
                                 "second_grouping_key": "registrable:example.net"})
        # The multi-attribute HTML fixture verifies all candidate classes, not just the first.
        if case.name == "HTML non-HTTP and empty attributes":
            actual["all_statuses"] = [c.parser_status for c in candidates]
            actual["all_evidence"] = [c.evidence_category for c in candidates]
            expected["all_statuses"] = ["unsupported_scheme", "unsupported_scheme", "empty_attribute"]
            expected["all_evidence"] = ["html_anchor", "html_anchor", "html_empty_attribute"]
        actual["pass"] = all(actual.get(k) == v for k, v in expected.items())
        rows.append({"case": case.name, "input": case.text, **actual, "expected": expected})
    return rows


class PhishingURLExtractionV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rows = run_parser_cases()

    def test_all_parser_fixtures_match_full_expectations(self) -> None:
        failures = [row for row in self.rows if not row["pass"]]
        self.assertEqual(failures, [], msg=f"Parser regressions: {failures}")

    def test_offsets_and_original_candidate_substrings_are_exact(self) -> None:
        for case in CASES:
            candidates = extraction.extract_candidates(f"parser:{case.name}", case.text)
            for candidate in candidates:
                self.assertEqual(candidate.original_text[candidate.start:candidate.end], candidate.candidate_text)
                self.assertEqual(candidate.source_record_id, f"parser:{case.name}")

    def test_only_high_confidence_destinations_receive_group_keys(self) -> None:
        for case in CASES:
            candidates = extraction.extract_candidates(f"parser:{case.name}", case.text)
            for candidate in candidates:
                if candidate.domain_grouping_key:
                    self.assertEqual(candidate.confidence, "high")

    def test_no_fixture_generates_exact_host_fallback_group_key(self) -> None:
        for case in CASES:
            candidates = extraction.extract_candidates(f"parser:{case.name}", case.text)
            for candidate in candidates:
                self.assertFalse((candidate.domain_grouping_key or "").startswith("exact_host_fallback:"))

    def test_malformed_hostname_ip_and_ambiguous_domain_are_distinguished(self) -> None:
        rows = {row["case"]: row for row in self.rows}
        self.assertEqual(rows["malformed HTTP scheme"]["status"], "malformed_url")
        self.assertIsNone(rows["malformed HTTP scheme"]["grouping_key"])
        self.assertEqual(rows["invalid hostname"]["status"], "invalid_hostname")
        self.assertIsNone(rows["invalid hostname"]["grouping_key"])
        for name, key in (("IPv4", "ip:192.0.2.10"), ("IPv6", "ip:2001:db8::1")):
            self.assertEqual(rows[name]["status"], "ip_literal")
            self.assertEqual(rows[name]["grouping_key"], key)
        self.assertEqual(rows["URL without scheme"]["status"], "ambiguous_bare_domain_mention")
        self.assertEqual(rows["URL without scheme"]["confidence"], "medium")
        self.assertIsNone(rows["URL without scheme"]["grouping_key"])

    def test_parser_import_graph_does_not_load_ml_or_heavy_data_libraries(self) -> None:
        import subprocess

        cmd = [
            sys.executable,
            "-c",
            (
                "import sys\n"
                "from backend.notebooks import phishing_url_extraction_v2\n"
                "from backend.ml.psl_service import is_psl_suffix\n"
                "forbidden = {\n"
                "    'pandas', 'joblib', 'numpy', 'scipy', 'sklearn',\n"
                "    'backend.notebooks.train_phishing_domain_holdout',\n"
                "    'backend.notebooks.audit_phishing_domain_integrity',\n"
                "}\n"
                "loaded = sorted(name for name in sys.modules if name in forbidden or any(name.startswith(f'{item}.') for item in forbidden))\n"
                "if loaded:\n"
                "    print(','.join(loaded))\n"
                "    sys.exit(1)\n"
            ),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
        self.assertEqual(res.returncode, 0, f"Parser import graph loaded heavy modules: {res.stdout.strip()}")


if __name__ == "__main__":
    unittest.main()
