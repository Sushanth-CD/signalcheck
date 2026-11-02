"""Stable preprocessing function referenced by persisted sklearn pipelines."""

import re
import unicodedata


def normalize_for_model(text: str) -> str:
    value = unicodedata.normalize("NFKC", str(text)).lower()
    return re.sub(r"\s+", " ", value).strip()
