"""Local URL candidate extraction and enabled URL-rule analysis."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from collections.abc import Collection, Iterable
from urllib.parse import SplitResult, urlsplit

from app.schemas import DetectedIndicator


# Exact host boundaries are used; matching a provider name inside a larger,
# unrelated hostname is deliberately insufficient.
DEFAULT_SHORTENER_DOMAINS = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
)

_SCHEME_URL = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")
_WWW_URL = re.compile(r"(?i)(?<![\w@])www\.[^\s<>\"']+")
_BARE_DOMAIN = re.compile(
    r"(?i)(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?::\d{1,5})?(?:/[^\s<>\"']*)?"
)
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_TRAILING_PUNCTUATION = ".,!?;:"


@dataclass(frozen=True)
class URLCandidate:
    """A candidate extracted from text, plus local parsing results."""

    raw: str
    normalized: str
    parsed: SplitResult | None
    hostname: str | None
    ascii_hostname: str | None
    ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    port: int | None
    parse_error: str | None = None

    @property
    def is_valid(self) -> bool:
        return self.parsed is not None and self.hostname is not None


def _trim_candidate(value: str) -> str:
    candidate = value.rstrip(_TRAILING_PUNCTUATION)
    # Sentence punctuation commonly closes a parenthesized URL. Preserve balanced
    # parentheses and remove only closers that have no matching opener.
    for closing, opening in ((")", "("), ("]", "["), ("}", "{")):
        while candidate.endswith(closing) and candidate.count(closing) > candidate.count(opening):
            candidate = candidate[:-1]
    return candidate


def extract_url_candidates(content: str) -> list[URLCandidate]:
    """Extract and parse URL-like strings without any network activity."""

    if not isinstance(content, str) or not content:
        return []

    matches = [*_SCHEME_URL.finditer(content), *_WWW_URL.finditer(content), *_BARE_DOMAIN.finditer(content)]
    ordered = sorted(matches, key=lambda match: match.start())
    candidates: list[URLCandidate] = []
    accepted_spans: list[tuple[int, int]] = []

    for match in ordered:
        span = match.span()
        if any(start <= span[0] and span[1] <= end for start, end in accepted_spans):
            continue
        raw = _trim_candidate(match.group(0))
        if not raw:
            continue
        accepted_spans.append(span)
        normalized = raw if re.match(r"(?i)^https?://", raw) else f"https://{raw}"

        try:
            parsed = urlsplit(normalized)
            hostname = parsed.hostname
            if parsed.scheme.lower() not in {"http", "https"} or not hostname:
                raise ValueError("URL must have an HTTP(S) scheme and hostname")
            hostname = hostname.rstrip(".").lower()
            if not hostname:
                raise ValueError("URL hostname is empty")
            port = parsed.port  # Access validates malformed and out-of-range ports.
            try:
                address = ipaddress.ip_address(hostname)
            except ValueError:
                address = None
            try:
                ascii_hostname = hostname.encode("idna").decode("ascii").lower()
            except UnicodeError as error:
                raise ValueError("URL hostname could not be normalized") from error
            if address is None and (
                len(ascii_hostname) > 253
                or any(not _HOST_LABEL.fullmatch(label) for label in ascii_hostname.split("."))
            ):
                raise ValueError("URL hostname is malformed")
            candidates.append(
                URLCandidate(raw, normalized, parsed, hostname, ascii_hostname, address, port)
            )
        except (ValueError, UnicodeError) as error:
            candidates.append(
                URLCandidate(raw, normalized, None, None, None, None, None, str(error))
            )

    return candidates


def _is_shortener(hostname: str, domains: Collection[str]) -> bool:
    return any(hostname == domain or hostname.endswith(f".{domain}") for domain in domains)


def analyze_urls(
    content: str,
    *,
    shortener_domains: Collection[str] = DEFAULT_SHORTENER_DOMAINS,
) -> list[DetectedIndicator]:
    """Apply only URL001 and URL002; malformed candidates score no URL points."""

    return analyze_url_candidates(extract_url_candidates(content), shortener_domains=shortener_domains)


def analyze_url_candidates(
    candidates: Iterable[URLCandidate],
    *,
    shortener_domains: Collection[str] = DEFAULT_SHORTENER_DOMAINS,
) -> list[DetectedIndicator]:
    """Analyze already-extracted candidates, skipping malformed ones safely."""

    findings: list[DetectedIndicator] = []
    triggered: set[str] = set()
    configured_domains = {domain.strip(".").lower() for domain in shortener_domains}

    for candidate in candidates:
        if not candidate.is_valid or candidate.hostname is None:
            continue

        if candidate.ip_address is not None and "URL002" not in triggered:
            triggered.add("URL002")
            findings.append(
                DetectedIndicator(
                    rule_id="URL002",
                    category="phishing",
                    title="Uses an IP address instead of a recognisable domain",
                    score_contribution=15,
                    explanation="A raw IP address in an unsolicited login or payment link is unusual. Verify the sender and avoid entering credentials.",
                )
            )

        if _is_shortener(candidate.ascii_hostname or candidate.hostname, configured_domains) and "URL001" not in triggered:
            triggered.add("URL001")
            findings.append(
                DetectedIndicator(
                    rule_id="URL001",
                    category="phishing",
                    title="Uses a known URL-shortening domain",
                    score_contribution=10,
                    explanation="The link hides its final destination. Do not open it unless you can verify where it leads through a trusted method.",
                )
            )

    return findings
