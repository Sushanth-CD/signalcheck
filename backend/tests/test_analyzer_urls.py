"""Independent tests for URL extraction and enabled URL rules."""

import socket
import urllib.request

from app.analyzer.urls import analyze_urls, extract_url_candidates


def _rule_ids(text: str) -> set[str]:
    return {finding.rule_id for finding in analyze_urls(text)}


def test_extracts_http_https_www_and_bare_domains_with_sentence_punctuation() -> None:
    text = "See https://example.com/a, then http://bit.ly/x! www.example.org/path?x=1."
    candidates = extract_url_candidates(text)

    assert [candidate.raw for candidate in candidates] == [
        "https://example.com/a",
        "http://bit.ly/x",
        "www.example.org/path?x=1",
    ]
    assert all(candidate.is_valid for candidate in candidates)


def test_url001_matches_exact_shortener_host_and_valid_subdomains() -> None:
    assert _rule_ids("Use https://bit.ly/abc carefully") == {"URL001"}
    assert _rule_ids("Use https://go.bit.ly/abc carefully") == {"URL001"}


def test_url001_does_not_match_a_shortener_name_inside_a_deceptive_domain() -> None:
    assert _rule_ids("https://bit.ly.attacker.example/login") == set()


def test_url001_uses_injected_configuration_for_shortener_domains() -> None:
    from app.analyzer.urls import analyze_urls

    findings = analyze_urls("https://short.example/path", shortener_domains={"short.example"})
    assert [(finding.rule_id, finding.score_contribution) for finding in findings] == [("URL001", 10)]


def test_url002_matches_ipv4_and_ipv6_url_hosts() -> None:
    findings = analyze_urls("Links: http://192.0.2.10/login and https://[2001:db8::1]/account")

    assert [finding.rule_id for finding in findings] == ["URL002"]
    assert findings[0].score_contribution == 15


def test_url002_does_not_match_a_normal_domain_host() -> None:
    assert "URL002" not in _rule_ids("https://example.com/account")


def test_unusual_port_is_parsed_but_does_not_score_while_url006_is_disabled() -> None:
    candidates = extract_url_candidates("Check https://example.com:8443/login")

    assert len(candidates) == 1
    assert candidates[0].is_valid
    assert candidates[0].port == 8443
    assert analyze_urls("Check https://example.com:8443/login") == []


def test_malformed_candidate_is_retained_as_parse_failure_without_finding() -> None:
    candidates = extract_url_candidates("Broken link: http://[not-an-ip")

    assert len(candidates) == 1
    assert not candidates[0].is_valid
    assert candidates[0].parse_error
    assert analyze_urls("Broken link: http://[not-an-ip") == []


def test_malformed_url_does_not_stop_suspicious_text_analysis() -> None:
    from app.analyzer import analyze_content

    result = analyze_content("Your account is at risk. Send your OTP now. http://[broken")

    assert {finding.rule_id for finding in result.detected_indicators} == {"PH001"}
    assert result.risk_score == 25
    assert "could not be parsed" in result.summary


def test_malformed_url_in_benign_text_adds_no_points() -> None:
    from app.analyzer import analyze_content

    result = analyze_content("This is a security-awareness note with a broken link http://[broken")

    assert result.detected_indicators == []
    assert result.risk_score == 0
    assert result.risk_level == "low"
    assert "could not be parsed" in result.summary


def test_malformed_and_valid_suspicious_urls_are_processed_independently() -> None:
    from app.analyzer import analyze_content

    result = analyze_content("Links: http://[broken and https://192.0.2.20/login")

    assert [finding.rule_id for finding in result.detected_indicators] == ["URL002"]
    assert result.risk_score == 15
    assert "could not be parsed" in result.summary


def test_ph011_matches_with_malformed_url_and_valid_url_does_not_duplicate_rule() -> None:
    from app.analyzer import analyze_content

    content = (
        "Your account will be blocked. Complete KYC verification at http://[broken "
        "or https://verify.example.test."
    )
    result = analyze_content(content)
    assert [item.rule_id for item in result.detected_indicators] == ["PH011"]
    assert result.risk_score == 25
    assert "could not be parsed" in result.summary


def test_text_without_urls_is_analyzed_without_url_findings() -> None:
    from app.analyzer import analyze_content

    result = analyze_content("Please send your OTP to this number.")

    assert [finding.rule_id for finding in result.detected_indicators] == ["PH001"]
    assert not {"URL001", "URL002"} & {finding.rule_id for finding in result.detected_indicators}


def test_multiple_urls_are_extracted_and_each_url_rule_only_counts_once() -> None:
    text = "https://bit.ly/first, https://bit.ly/second, and http://192.0.2.50/x"
    findings = analyze_urls(text)

    assert {finding.rule_id for finding in findings} == {"URL001", "URL002"}
    assert len(findings) == 2


def test_unicode_hostname_is_normalized_locally_without_extra_rule_match() -> None:
    candidate = extract_url_candidates("https://bücher.example/path")[0]

    assert candidate.is_valid
    assert candidate.ascii_hostname == "xn--bcher-kva.example"
    assert analyze_urls("https://bücher.example/path") == []


def test_url_userinfo_is_parsed_by_hostname_but_not_scored_by_disabled_rule() -> None:
    candidate = extract_url_candidates("https://trusted.example@other.example/path")[0]

    assert candidate.is_valid
    assert candidate.hostname == "other.example"
    assert analyze_urls("https://trusted.example@other.example/path") == []


def test_punycode_and_deep_subdomains_are_not_scored_by_disabled_rules() -> None:
    assert analyze_urls("https://xn--bcher-kva.example/path") == []
    assert analyze_urls("https://a.b.c.d.e.example/path") == []


def test_malformed_port_is_zero_url_score() -> None:
    text = "https://example.com:99999/login"
    assert any(not candidate.is_valid for candidate in extract_url_candidates(text))
    assert analyze_urls(text) == []


def test_url_analysis_never_uses_common_network_apis(monkeypatch) -> None:
    def fail_if_network_used(*args, **kwargs):
        raise AssertionError("URL analysis attempted network access")

    monkeypatch.setattr(socket, "getaddrinfo", fail_if_network_used)
    monkeypatch.setattr(socket, "gethostbyname", fail_if_network_used)
    monkeypatch.setattr(socket, "create_connection", fail_if_network_used)
    monkeypatch.setattr(urllib.request, "urlopen", fail_if_network_used)

    assert _rule_ids("https://bit.ly/opaque https://192.0.2.1/path") == {"URL001", "URL002"}
