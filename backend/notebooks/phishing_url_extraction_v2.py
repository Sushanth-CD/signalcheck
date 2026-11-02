"""Conservative, offline URL and destination extraction for phishing text V2.

Candidate syntax, confidence, and grouping decisions stay separate. No
network access occurs. Registrable domains come from the pinned local JDK PSL.
"""
from __future__ import annotations

import html
import ipaddress
import re
from dataclasses import asdict, dataclass, replace
from html.parser import HTMLParser
from typing import Iterable
from urllib.parse import urlsplit

SCHEME_RE = re.compile(r"(?i)(?:https?://|//)")
EXPLICIT_RE = re.compile(r"(?i)(?:https?://|//|www\.)[^\s<>\"']+")
MALFORMED_HTTP_RE = re.compile(r"(?i)https?:[^\s<>\"']+")
BARE_RE = re.compile(
    r"(?i)(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?(?::\d+)?"
    r"(?:[/\?#][^\s<>\"']*)?"
)
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>\"']*)?")
IPV6_RE = re.compile(r"(?<!\w)\[[0-9a-f:.]+\](?::\d+)?(?:/[^\s<>\"']*)?", re.I)
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
TRAILING = ".,;:!?\"'”’"
DESTINATION_CUE_RE = re.compile(
    r"(?i)\b(?:visit|go\s+to|open|browse|access|click|check|see|website|web\s+site|"
    r"link|url|find\s+us\s+at)\b"
)
ATTR_VALUE_RE = re.compile(r"""(?is)(?<![\w:-]){name}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")


@dataclass(frozen=True)
class Candidate:
    source_record_id: str
    original_text: str
    start: int
    end: int
    candidate_text: str
    extraction_method: str
    evidence_category: str
    confidence: str
    parser_status: str
    normalized_hostname: str | None = None
    registrable_domain: str | None = None
    domain_grouping_key: str | None = None
    rejection_reason: str | None = None

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def _trim_end(text: str, start: int, end: int) -> int:
    while end > start and text[end - 1] in TRAILING:
        end -= 1
    pairs = (("(", ")"), ("[", "]"), ("{", "}"))
    changed = True
    while changed and end > start:
        changed = False
        for opening, closing in pairs:
            if text[end - 1] == closing and text[start:end].count(closing) > text[start:end].count(opening):
                end -= 1
                changed = True
                break
    return end


def _offset(line_offsets: list[int], line: int, column: int) -> int:
    return line_offsets[line - 1] + column


def _attribute_span(start_tag: str, tag_offset: int, attr_name: str) -> tuple[int, int] | None:
    pattern = re.compile(ATTR_VALUE_RE.pattern.format(name=re.escape(attr_name)), re.I)
    match = pattern.search(start_tag)
    if not match:
        return None
    group = next((i for i in (1, 2, 3) if match.group(i) is not None), None)
    return (tag_offset + match.start(group), tag_offset + match.end(group)) if group else None


class _DestinationHTMLParser(HTMLParser):
    def __init__(self, source: str) -> None:
        super().__init__(convert_charrefs=True)
        self.line_offsets = [0]
        self.line_offsets.extend(m.end() for m in re.finditer("\n", source))
        self.items: list[tuple[int, int, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle(tag, attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle(tag, attrs)

    def _handle(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        values = {k.lower(): (v or "") for k, v in attrs if k}
        selected: list[tuple[str, str]] = []
        if tag == "link" and "canonical" in values.get("rel", "").lower().split():
            selected.append(("href", "html_canonical"))
        elif tag == "meta" and values.get("property", "").lower() == "og:url":
            selected.append(("content", "html_open_graph"))
        elif tag == "a":
            selected.append(("href", "html_anchor"))
        elif tag == "form":
            selected.append(("action", "html_form"))
        if not selected:
            return
        line, col = self.getpos()
        tag_offset = _offset(self.line_offsets, line, col)
        raw_tag = self.get_starttag_text() or ""
        for name, evidence in selected:
            span = _attribute_span(raw_tag, tag_offset, name)
            if span:
                self.items.append((span[0], span[1], evidence))


def _valid_host(raw_url: str) -> tuple[str | None, str, str | None]:
    value = html.unescape(raw_url).strip()
    if not value:
        return None, "empty_attribute", "destination attribute is empty"
    if value.lower().startswith(("mailto:", "javascript:", "data:")):
        return None, "unsupported_scheme", f"{value.split(':', 1)[0].lower()} is not an HTTP destination"
    if value.startswith("//"):
        value = "https:" + value
    elif value.lower().startswith(("http://", "https://")):
        pass
    elif value.lower().startswith(("http:", "https:")):
        return None, "malformed_url", "HTTP URL is missing // authority syntax"
    elif value.lower().startswith("www."):
        value = "https://" + value
    elif re.match(r"^[a-z][a-z0-9+.-]*:", value, re.I):
        return None, "unsupported_scheme", "non-HTTP scheme is not a web destination"
    else:
        return None, "relative_without_base", "relative reference has no verified document base URL"
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            return None, "malformed_url", "HTTP URL has no authority"
        if parsed.username is not None or parsed.password is not None:
            return None, "malformed_url", "userinfo in destination URL is not accepted"
        try:
            _ = parsed.port
        except ValueError:
            return None, "invalid_port", "port is not numeric or outside the valid range"
        raw_host = parsed.hostname or ""
        if not raw_host:
            return None, "malformed_url", "URL has no hostname"
        try:
            return ipaddress.ip_address(raw_host).compressed.lower(), "ip_literal", None
        except ValueError:
            pass
        if re.fullmatch(r"\d+(?:\.\d+){3}", raw_host):
            return None, "invalid_hostname", "IPv4-shaped host is not a valid IPv4 address"
        if raw_host.endswith(".."):
            return None, "invalid_hostname", "hostname has more than one trailing dot"
        raw_host = raw_host.removesuffix(".")
        raw_labels = raw_host.split(".")
        if any(not label for label in raw_labels):
            return None, "invalid_hostname", "hostname contains an invalid DNS label"
        try:
            hostname = raw_host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None, "invalid_hostname", "hostname contains a label that cannot be IDNA encoded"
        if len(hostname) > 253 or len(hostname.split(".")) < 2:
            return None, "invalid_hostname", "hostname is unqualified or exceeds DNS length limits"
        if any(not LABEL_RE.fullmatch(label) for label in hostname.split(".")):
            return None, "invalid_hostname", "hostname contains an invalid DNS label"
        return hostname, "normalized_hostname", None
    except (UnicodeError, ValueError):
        return None, "malformed_url", "URL or internationalized hostname could not be parsed"


def _candidate(record_id: str, text: str, start: int, end: int, method: str,
               evidence: str, confidence: str) -> Candidate:
    exact = text[start:end]
    parse_value = exact
    if evidence in {"bare_domain_mention", "probable_bare_destination", "bare_ip_mention"}:
        parse_value = "https://" + exact
    host, status, reason = _valid_host(parse_value)
    if status not in {"normalized_hostname", "ip_literal", "ambiguous_bare_domain_mention", "ambiguous_ip_mention"}:
        confidence = "unresolved"
    if evidence in {"bare_domain_mention", "probable_bare_destination"}:
        if host and status == "normalized_hostname":
            status, reason = "ambiguous_bare_domain_mention", "bare domain is not an explicit URL destination"
        elif host and status == "ip_literal":
            status, reason = "ambiguous_ip_mention", "IP address mention lacks explicit destination syntax"
    if evidence.startswith("html_") and status == "relative_without_base":
        evidence = "html_relative"
    return Candidate(record_id, text, start, end, exact, method, evidence, confidence,
                     status, host, None, None, reason)


def _html_candidates(record_id: str, text: str) -> list[Candidate]:
    parser = _DestinationHTMLParser(text)
    try:
        parser.feed(text)
        parser.close()
    except Exception:
        return [Candidate(record_id, text, 0, len(text), text, "html_parser", "html_parse_error",
                          "unresolved", "html_parse_error", rejection_reason="HTML parser rejected document")]
    result: list[Candidate] = []
    for start, end, evidence in parser.items:
        raw = text[start:end]
        source_method = f"{evidence}_attribute"
        if not raw:
            result.append(Candidate(record_id, text, start, end, raw, source_method,
                                    "html_empty_attribute", "unresolved", "empty_attribute",
                                    rejection_reason="destination attribute is empty"))
            continue
        confidence = "high" if re.match(r"(?i)^(?:https?://|//|www\.)", html.unescape(raw).strip()) else "unresolved"
        result.append(_candidate(record_id, text, start, end, source_method, evidence, confidence))
    return result


def _explicit_parts(record_id: str, text: str, start: int, end: int) -> list[Candidate]:
    token = text[start:end]
    boundaries = [m.start() for m in SCHEME_RE.finditer(token)]
    if token.lower().startswith("www.") or not boundaries or boundaries[0] != 0:
        boundaries = [0] + boundaries
    boundaries = sorted(set(boundaries))
    output: list[Candidate] = []
    for index, local_start in enumerate(boundaries):
        absolute_start = start + local_start
        absolute_end = start + (boundaries[index + 1] if index + 1 < len(boundaries) else len(token))
        absolute_end = _trim_end(text, absolute_start, absolute_end)
        if absolute_end <= absolute_start:
            continue
        raw = text[absolute_start:absolute_end]
        evidence = ("www_url" if raw.lower().startswith("www.") else
                    "protocol_relative_url" if raw.startswith("//") else
                    "explicit_http_url" if re.match(r"(?i)^https?://", raw) else
                    "malformed_concatenated_url")
        item = _candidate(record_id, text, absolute_start, absolute_end, "explicit_token", evidence, "high")
        if evidence == "malformed_concatenated_url":
            item = replace(item, confidence="unresolved", parser_status="malformed_url",
                           rejection_reason="concatenated URL boundary could not be parsed")
        output.append(item)
    return output


def extract_candidates(source_record_id: str, text: str) -> list[Candidate]:
    """Extract explicit URLs, bare-domain mentions, and selected HTML attributes."""
    output: list[Candidate] = []
    html_like = bool(re.search(r"(?is)<\s*(?:!doctype\s+html|html|head|body|meta|link|a|form)\b", text))
    explicit_spans: list[tuple[int, int]] = []
    tag_spans: list[tuple[int, int]] = []
    visible_spans: list[tuple[int, int]] = [(0, len(text))]
    if html_like:
        output.extend(_html_candidates(source_record_id, text))
        line_offsets = [0]
        line_offsets.extend(m.end() for m in re.finditer("\n", text))
        visible_spans = []
        class VisibleTextCollector(HTMLParser):
            def __init__(self) -> None:
                super().__init__(convert_charrefs=False)
                self.hidden_depth = 0
            def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
                begin = _offset(line_offsets, *self.getpos())
                tag_spans.append((begin, begin + len(self.get_starttag_text() or "")))
                if tag.lower() in {"script", "style"}:
                    self.hidden_depth += 1
            def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
                begin = _offset(line_offsets, *self.getpos())
                tag_spans.append((begin, begin + len(self.get_starttag_text() or "")))
            def handle_endtag(self, tag: str) -> None:
                if tag.lower() in {"script", "style"} and self.hidden_depth:
                    self.hidden_depth -= 1
            def handle_data(self, data: str) -> None:
                if self.hidden_depth or not data:
                    return
                start = _offset(line_offsets, *self.getpos())
                visible_spans.append((start, start + len(data)))
        collector = VisibleTextCollector()
        collector.feed(text)
        for span_start, span_end in visible_spans:
            for match in EXPLICIT_RE.finditer(text, span_start, span_end):
                end = _trim_end(text, match.start(), match.end())
                if end > match.start():
                    output.extend(_explicit_parts(source_record_id, text, match.start(), end))
                    explicit_spans.append((match.start(), end))
    else:
        for match in EXPLICIT_RE.finditer(text):
            end = _trim_end(text, match.start(), match.end())
            if end > match.start():
                output.extend(_explicit_parts(source_record_id, text, match.start(), end))
                explicit_spans.append((match.start(), end))
    for match in MALFORMED_HTTP_RE.finditer(text):
        if (any(a <= match.start() < b for a, b in explicit_spans)
                or any(a <= match.start() < b for a, b in tag_spans)
                or not any(a <= match.start() < b for a, b in visible_spans)):
            continue
        end = _trim_end(text, match.start(), match.end())
        if end > match.start():
            output.append(_candidate(source_record_id, text, match.start(), end,
                                     "malformed_scheme_token", "malformed_url_syntax", "unresolved"))
            explicit_spans.append((match.start(), end))
    for pattern, evidence in ((IPV4_RE, "bare_ip_mention"), (IPV6_RE, "bare_ip_mention"),
                              (BARE_RE, "bare_domain_mention")):
        for match in pattern.finditer(text):
            start, end = match.start(), _trim_end(text, match.start(), match.end())
            if (end <= start or any(a <= start < b for a, b in explicit_spans)
                    or any(a <= start < b for a, b in tag_spans)
                    or not any(a <= start < b for a, b in visible_spans)
                    or (start > 0 and text[start - 1] == "@")):
                continue
            raw = text[start:end]
            preceding, following = text[max(0, start - 70):start], text[end:min(len(text), end + 50)]
            pathish = any(mark in raw for mark in ("/", "?", "#"))
            context = bool(DESTINATION_CUE_RE.search(preceding) or DESTINATION_CUE_RE.match(following.lstrip()))
            if evidence == "bare_domain_mention" and (pathish or context):
                category, confidence = "probable_bare_destination", "medium"
            elif evidence == "bare_ip_mention":
                category, confidence = evidence, "medium"
            else:
                category, confidence = evidence, "low"
            output.append(_candidate(source_record_id, text, start, end, "bare_token", category, confidence))
    output.sort(key=lambda item: (item.start, item.end, item.evidence_category))
    return output


def apply_psl(candidate: Candidate, registrable_domain: str | None, *, is_public_suffix: bool = False) -> Candidate:
    """Apply the existing local PSL result; unresolved names get no fallback key."""
    if candidate.parser_status == "ip_literal":
        if candidate.confidence == "high":
            return replace(candidate, domain_grouping_key=f"ip:{candidate.normalized_hostname}")
        return candidate
    if candidate.parser_status not in {"normalized_hostname", "ambiguous_bare_domain_mention"}:
        return candidate
    if registrable_domain:
        key = f"registrable:{registrable_domain}" if candidate.confidence == "high" else None
        return replace(candidate, registrable_domain=registrable_domain, domain_grouping_key=key)
    if candidate.parser_status == "ambiguous_bare_domain_mention":
        return replace(candidate, rejection_reason="bare domain mention is not grouped")
    if is_public_suffix:
        return replace(candidate, parser_status="public_suffix_only", confidence="unresolved",
                       rejection_reason="hostname is a public suffix without a registrable label")
    return replace(candidate, parser_status="unknown_suffix", confidence="unresolved",
                   rejection_reason="no registrable domain in pinned PSL; suffix may be unknown or host malformed")


def destination_urls(candidates: Iterable[Candidate]) -> list[Candidate]:
    return [candidate for candidate in candidates if candidate.domain_grouping_key]
