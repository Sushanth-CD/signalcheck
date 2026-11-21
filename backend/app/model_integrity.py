"""Cryptographic model integrity verification helpers."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

# Authoritative trusted SHA-256 digests for models loaded at startup.
# Provenance documented in backend/models/model_integrity_manifest.json.
TRUSTED_MODEL_HASHES: dict[str, str] = {
    "phishing": "42ce5d9c5a87a904528ac0f2235d4fe50103b494d6f9aa7d560247ca9a6170ca",
    "sms": "6b7ae684cde6bf041deb4963e6e5b4adf7c31ba12ceed2b6b1f838ccd7b77587",
    "android": "c0f7aaad9e33d9609fbed32d020f6fd2c765c86637a2527acba65d6b650f6af0",
}

_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")


def compute_file_sha256(path: Path) -> str:
    """Compute the hexadecimal SHA-256 digest of a local file."""
    if not path.is_file():
        raise FileNotFoundError(f"Artifact file not found: {path}")
    hasher = hashlib.sha256()
    with open(path, "rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def verify_model_artifact_integrity(
    path: Path,
    expected_hash: str | None = None,
    model_key: str | None = None,
) -> None:
    """Verify that a model artifact exists and matches its expected SHA-256 hash.

    Raises:
        FileNotFoundError: If the artifact does not exist.
        ValueError: If the expected hash or manifest entry is missing or invalid.
        RuntimeError: If the digest does not match expected_hash.
    """
    if expected_hash is None and model_key is not None:
        if model_key not in TRUSTED_MODEL_HASHES:
            raise ValueError(f"No trusted integrity hash registered for model key: '{model_key}'")
        expected_hash = TRUSTED_MODEL_HASHES[model_key]

    if expected_hash is None:
        raise ValueError("Cannot verify model integrity without expected_hash or valid model_key.")

    expected = expected_hash.strip().lower()
    if not _HEX_64_RE.match(expected):
        raise ValueError(
            f"Invalid SHA-256 digest format '{expected_hash}'. Expected a 64-character hex string."
        )

    actual = compute_file_sha256(path)
    if actual != expected:
        raise RuntimeError(
            f"Model artifact integrity verification failed for '{path.name}'. "
            f"Expected SHA-256: {expected}, calculated: {actual}. "
            "The artifact may be corrupted or tampered with."
        )
