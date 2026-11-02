"""Lightweight access to the project's pinned Oracle JDK Public Suffix List.

This module intentionally uses only the Python standard library. The JDK
RegisteredDomain API remains the source of registrable-domain semantics;
the bundled PSL archive is also read locally to classify suffix-only values.
No DNS or network access is performed.
"""
from __future__ import annotations

import hashlib
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
JDK_ROOT = ROOT / "backend/notebooks/oracleJdk-27"
JAVA = JDK_ROOT / "bin/java.exe"
PSL_FILE = JDK_ROOT / "lib/security/public_suffix_list.dat"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def psl_registrable_domains(hosts: list[str]) -> tuple[dict[str, str | None], dict[str, Any]]:
    """Resolve normalized hostnames with the bundled JDK PSL implementation."""
    if not JAVA.is_file() or not PSL_FILE.is_file():
        raise FileNotFoundError(
            "A local JDK with its bundled Public Suffix List is required; "
            f"expected {JAVA} and {PSL_FILE}. No fallback approximation is used."
        )
    jdk_version_result = subprocess.run(
        [str(JAVA), "-version"], capture_output=True, text=True, check=True, timeout=30
    )
    jdk_version_text = (jdk_version_result.stderr or jdk_version_result.stdout).splitlines()
    java_source = r'''import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import sun.security.util.RegisteredDomain;
class PslLookup {
  public static void main(String[] args) throws Exception {
    var in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    String host;
    while ((host = in.readLine()) != null) {
      String result = RegisteredDomain.from(host).map(RegisteredDomain::name).orElse("");
      System.out.println(result);
    }
  }
}'''
    mapping: dict[str, str | None] = {}
    if hosts:
        requested = sorted(set(hosts) | {"pslcheck.example.co.uk"})
        with tempfile.TemporaryDirectory(prefix="phishing-psl-") as temp_dir:
            source = Path(temp_dir) / "PslLookup.java"
            source.write_text(java_source, encoding="ascii")
            run = subprocess.run(
                [
                    str(JAVA),
                    "--add-exports=java.base/sun.security.util=ALL-UNNAMED",
                    str(source),
                ],
                input="\n".join(requested) + "\n",
                capture_output=True,
                text=True,
                check=True,
                timeout=300,
            )
            returned = run.stdout.splitlines()
            if len(returned) != len(requested):
                raise RuntimeError(
                    f"PSL lookup returned {len(returned)} entries for {len(requested)} hosts"
                )
            all_results = {host: (domain or None) for host, domain in zip(requested, returned)}
            if all_results.get("pslcheck.example.co.uk") != "example.co.uk":
                raise RuntimeError("Bundled PSL registrable-domain smoke check failed for example.co.uk")
            mapping = {host: all_results[host] for host in hosts}
    return mapping, {
        "implementation": "Oracle JDK sun.security.util.RegisteredDomain",
        "jdk_version": jdk_version_text[0] if jdk_version_text else "unknown",
        "psl_snapshot_path": str(PSL_FILE.relative_to(ROOT)),
        "psl_snapshot_sha256": sha256_file(PSL_FILE),
        "network_access": False,
        "note": "Uses the local JDK-bundled PSL through an internal JDK API; pin the JDK and PSL file hash for reproduction.",
    }


def load_psl_rules() -> tuple[set[str], set[str], set[str]]:
    """Read exact normal, wildcard, and exception rules from the bundled PSL."""
    normal: set[str] = set()
    wildcards: set[str] = set()
    exceptions: set[str] = set()
    with zipfile.ZipFile(PSL_FILE) as archive:
        for name in archive.namelist():
            for raw in archive.read(name).decode("utf-8").splitlines():
                rule = raw[1:] if raw[:1] in {"\x00", "\x01"} else raw
                if not rule:
                    continue
                rule = rule.lower().rstrip(".")
                if rule.startswith("!"):
                    exceptions.add(rule[1:])
                elif rule.startswith("*."):
                    wildcards.add(rule[2:])
                else:
                    normal.add(rule)
    return normal, wildcards, exceptions


def is_psl_suffix(host: str, rules: tuple[set[str], set[str], set[str]]) -> bool:
    """Return whether the exact host is itself a public suffix under these rules."""
    normal, wildcards, exceptions = rules
    host = host.lower().rstrip(".")
    if host in exceptions:
        return False
    if host in normal:
        return True
    labels = host.split(".")
    return any(".".join(labels[i:]) in wildcards for i in range(len(labels) - 1))
