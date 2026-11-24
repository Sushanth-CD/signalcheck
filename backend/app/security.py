"""Security configuration and helpers for SignalCheck API."""

from __future__ import annotations

import hashlib
import ipaddress
import os
from starlette.requests import Request


def get_trusted_proxies() -> set[str]:
    """Retrieve set of explicitly trusted reverse proxy IP addresses.

    Configured via SIGNALCHECK_TRUSTED_PROXIES (comma-separated).
    Default: empty (do not trust any X-Forwarded-For by default).
    """
    raw = os.getenv("SIGNALCHECK_TRUSTED_PROXIES", "").strip()
    if not raw:
        return set()

    trusted = set()
    for item in raw.split(","):
        cleaned = item.strip()
        if cleaned:
            trusted.add(cleaned)
    return trusted


def get_client_ip(request: Request) -> str:
    """Safely determine the client IP address.

    Only trusts 'X-Forwarded-For' if the direct peer (request.client.host)
    is explicitly listed in SIGNALCHECK_TRUSTED_PROXIES. Otherwise, returns
    the direct connection peer to prevent client spoofing.
    """
    direct_peer = request.client.host if request.client else "127.0.0.1"
    trusted_proxies = get_trusted_proxies()

    if direct_peer in trusted_proxies:
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # Client IP is the first entry in the X-Forwarded-For chain
            client_candidate = forwarded_for.split(",")[0].strip()
            try:
                # Validate that the candidate is a valid IP address
                ipaddress.ip_address(client_candidate)
                return client_candidate
            except ValueError:
                pass
    return direct_peer


def get_rate_limit_storage_uri() -> str:
    """Retrieve the storage URI for the SlowAPI Limiter.

    Configured via SIGNALCHECK_RATE_LIMIT_STORAGE_URL or REDIS_URL.
    Example: redis://redis:6379/0 or redis://:password@redis:6379/0
    Default if unset or empty: memory:// (process-local storage)
    """
    url = os.getenv("SIGNALCHECK_RATE_LIMIT_STORAGE_URL", os.getenv("REDIS_URL", "")).strip()
    return url if url else "memory://"


def get_rate_limit(endpoint_key: str, default_limit: str = "30/minute") -> str:
    """Retrieve rate limit for a specific endpoint from environment variables.

    Environment variables:
        SIGNALCHECK_RATE_LIMIT_ANALYZE (default: "30/minute")
        SIGNALCHECK_RATE_LIMIT_SMS (default: "30/minute")
        SIGNALCHECK_RATE_LIMIT_ANDROID (default: "20/minute")
        SIGNALCHECK_RATE_LIMIT_DEFAULT (fallback default)
    """
    env_var_name = f"SIGNALCHECK_RATE_LIMIT_{endpoint_key.upper()}"
    return os.getenv(
        env_var_name,
        os.getenv("SIGNALCHECK_RATE_LIMIT_DEFAULT", default_limit),
    ).strip()


def get_allowed_hosts() -> list[str]:
    """Retrieve allowed hostnames for TrustedHostMiddleware.

    Configured via SIGNALCHECK_ALLOWED_HOSTS (comma-separated).
    Default: localhost, 127.0.0.1, testserver.
    """
    raw = os.getenv("SIGNALCHECK_ALLOWED_HOSTS", "").strip()
    default_hosts = ["localhost", "127.0.0.1", "testserver"]
    if not raw:
        return default_hosts

    hosts = []
    for item in raw.split(","):
        host = item.strip()
        if host and host not in hosts:
            hosts.append(host)
    return hosts if hosts else default_hosts


def hash_session_token(token: str) -> str:
    """Compute SHA-256 hash of a session token for storage and lookup."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
