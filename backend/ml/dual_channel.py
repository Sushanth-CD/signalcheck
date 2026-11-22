"""Dual-channel feature extraction transformers for Phishing Classifier V3.

This module provides serializable scikit-learn transformers that decouple
raw inputs into:
  1. Content Channel: HTML title, anchor text, and visible body text (or
     plain text with extractable URL spans removed).
  2. URL Channel: Structural URL features (hostname, subdomains, path tokens,
     query parameter names) extracted via the offline V2 candidate parser.

All transformers inherit from BaseEstimator and TransformerMixin to ensure full
compatibility with scikit-learn Pipelines, FeatureUnion, and joblib serialization.
"""

from __future__ import annotations

import html
import re
import sys
import unicodedata
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import parse_qsl, unquote, urlsplit

from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion, Pipeline

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from notebooks.phishing_url_extraction_v2 import extract_candidates


HTML_TAG_PATTERN = re.compile(
    r"(?is)<\s*(?:!doctype\s+html|html|head|body|meta|link|a|form|div|p|span|table|h[1-6])\b"
)


class ContentHTMLParser(HTMLParser):
    """HTML parser that extracts title, anchor text, and visible body text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.body_parts: list[str] = []
        self.anchor_parts: list[str] = []
        self._in_title = False
        self._in_anchor = False
        self._hidden_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        if tag_lower in {"script", "style", "noscript"}:
            self._hidden_depth += 1
        elif tag_lower == "title":
            self._in_title = True
        elif tag_lower == "a":
            self._in_anchor = True

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if tag_lower in {"script", "style", "noscript"}:
            if self._hidden_depth > 0:
                self._hidden_depth -= 1
        elif tag_lower == "title":
            self._in_title = False
        elif tag_lower == "a":
            self._in_anchor = False

    def handle_data(self, data: str) -> None:
        if self._hidden_depth > 0:
            return
        cleaned = data.strip()
        if not cleaned:
            return
        if self._in_title:
            self.title_parts.append(cleaned)
        elif self._in_anchor:
            self.anchor_parts.append(cleaned)
            self.body_parts.append(cleaned)
        else:
            self.body_parts.append(cleaned)


def normalize_text_convention(text: str) -> str:
    """Normalize text using Unicode NFKC, lowercase, and collapsed whitespace."""
    value = unicodedata.normalize("NFKC", str(text)).lower()
    return re.sub(r"\s+", " ", value).strip()


def extract_single_content(raw_text: str) -> str:
    """Extract visible content and title from HTML; strip URL spans in plain text."""
    if not isinstance(raw_text, str) or not raw_text.strip():
        return ""

    is_html = bool(HTML_TAG_PATTERN.search(raw_text))
    if is_html:
        parser = ContentHTMLParser()
        try:
            parser.feed(raw_text)
            parser.close()
            parts: list[str] = []
            if parser.title_parts:
                parts.append(" ".join(parser.title_parts))
            if parser.anchor_parts:
                parts.append(" ".join(parser.anchor_parts))
            if parser.body_parts:
                parts.append(" ".join(parser.body_parts))
            content = " ".join(parts)
        except Exception:
            content = re.sub(r"<[^>]+>", " ", raw_text)
    else:
        # Plain text: remove extractable confident URLs from the content channel
        try:
            candidates = extract_candidates("content_extract", raw_text)
            confident_spans = [
                (c.start, c.end)
                for c in candidates
                if c.confidence == "high"
                and c.parser_status in {"normalized_hostname", "ip_literal"}
            ]
            if confident_spans:
                confident_spans.sort(key=lambda s: s[0], reverse=True)
                chars = list(raw_text)
                for start, end in confident_spans:
                    chars[start:end] = [" "]
                content = "".join(chars)
            else:
                content = raw_text
        except Exception:
            content = raw_text

    return normalize_text_convention(content)


def extract_single_urls(raw_text: str) -> str:
    """Extract structural URL tokens from high-confidence candidates."""
    if not isinstance(raw_text, str) or not raw_text.strip():
        return ""

    try:
        candidates = extract_candidates("url_extract", raw_text)
    except Exception:
        return ""

    valid_candidates = [
        c
        for c in candidates
        if c.confidence == "high"
        and c.parser_status in {"normalized_hostname", "ip_literal"}
    ]

    if not valid_candidates:
        return ""

    tokens: list[str] = []
    seen_urls: set[str] = set()

    for cand in valid_candidates:
        url_text = cand.candidate_text.strip()
        if not url_text or url_text in seen_urls:
            continue
        seen_urls.add(url_text)

        split_target = url_text
        if split_target.startswith("//"):
            split_target = "http:" + split_target
        elif not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", split_target):
            split_target = "http://" + split_target

        try:
            parsed = urlsplit(split_target)
        except Exception:
            continue

        host = cand.normalized_hostname or parsed.hostname or ""
        host = host.lower().strip()
        if host:
            tokens.append(f"host_{host}")
            host_labels = [lbl for lbl in re.split(r"[.\-_]", host) if lbl]
            tokens.extend(host_labels)

        path = parsed.path
        if path and path != "/":
            path_unquoted = unquote(path).lower()
            path_tokens = [tok for tok in re.split(r"[/.\-_]", path_unquoted) if tok]
            tokens.extend(path_tokens)

        query = parsed.query
        if query:
            try:
                pairs = parse_qsl(query, keep_blank_values=True)
                for key, _ in pairs:
                    clean_key = re.sub(r"\W+", "", key.lower())
                    if clean_key:
                        tokens.append(f"param_{clean_key}")
            except Exception:
                pass

    if not tokens:
        return ""

    return normalize_text_convention(" ".join(tokens))


class ContentChannelExtractor(BaseEstimator, TransformerMixin):
    """scikit-learn compatible transformer extracting readable text & title."""

    def fit(self, X: Sequence[str], y: Any = None) -> "ContentChannelExtractor":
        return self

    def transform(self, X: Sequence[str]) -> list[str]:
        return [extract_single_content(text) for text in X]


class URLChannelExtractor(BaseEstimator, TransformerMixin):
    """scikit-learn compatible transformer extracting structural URL features."""

    def fit(self, X: Sequence[str], y: Any = None) -> "URLChannelExtractor":
        return self

    def transform(self, X: Sequence[str]) -> list[str]:
        return [extract_single_urls(text) for text in X]


def build_content_only_feature_pipeline() -> Pipeline:
    """Build the Content-only TF-IDF feature pipeline."""
    return Pipeline(
        [
            ("content_extractor", ContentChannelExtractor()),
            (
                "tfidf_content",
                TfidfVectorizer(
                    analyzer="word",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_df=0.995,
                    max_features=150_000,
                    sublinear_tf=True,
                    lowercase=False,
                ),
            ),
        ]
    )


def build_url_only_feature_pipeline() -> Pipeline:
    """Build the URL-only TF-IDF feature pipeline."""
    return Pipeline(
        [
            ("url_extractor", URLChannelExtractor()),
            (
                "tfidf_url",
                TfidfVectorizer(
                    analyzer="word",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_df=0.995,
                    max_features=50_000,
                    sublinear_tf=True,
                    lowercase=False,
                ),
            ),
        ]
    )


def build_dual_channel_feature_pipeline() -> FeatureUnion:
    """Combine Content and URL channels into a joint sparse feature matrix."""
    return FeatureUnion(
        [
            ("content_branch", build_content_only_feature_pipeline()),
            ("url_branch", build_url_only_feature_pipeline()),
        ]
    )
