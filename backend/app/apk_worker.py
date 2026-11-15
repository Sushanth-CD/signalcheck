"""apk_worker.py - Isolated static APK analyzer worker module and CLI entrypoint.

Isolates Androguard parsing and bytecode extraction into an independent execution boundary.
The main API process must NEVER import androguard or run Androguard code directly.

Can be executed as:
1. Python module function: `run_apk_worker(file_path: str, sha256_hash: str, file_size: int) -> dict[str, Any]`
2. CLI process: `python -m app.apk_worker <file_path> <sha256_hash> <file_size>` (prints JSON to stdout)
3. RQ worker task: `execute_rq_apk_job(file_path: str, sha256_hash: str, file_size: int) -> dict[str, Any]`
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import zipfile
from typing import Any, Dict, List, Set, Tuple

# Androguard imports are strictly quarantined inside this worker module
from androguard.core.apk import APK
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis

# Canonical Static Limitations Statement
CANONICAL_LIMITATIONS = [
    "This assessment is based exclusively on static analysis of package metadata, declared permissions, and bytecode references.",
    "Absence of threat indicators does not establish that an application is benign or safe.",
    "Legitimate applications frequently request sensitive permissions (e.g., location, storage, camera) for standard business functionality.",
    "Commercial packers, bytecode encryption, or native code (JNI/C++) may conceal runtime behaviors from static Dalvik inspection.",
    "This tool provides educational and technical guidance; it is not a substitute for enterprise mobile threat defense, Google Play Protect, or anti-malware verification.",
]

# Sensitive Permission Groupings
PERMISSION_MAP = {
    "sms": {
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
    },
    "call_phone": {
        "android.permission.CALL_PHONE",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.READ_PHONE_NUMBERS",
    },
    "contacts": {
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
    },
    "accessibility": {
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
    },
    "device_admin": {
        "android.permission.BIND_DEVICE_ADMIN",
    },
    "overlay": {
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.ACTION_MANAGE_OVERLAY_PERMISSION",
    },
    "install_packages": {
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.INSTALL_PACKAGES",
    },
    "read_notifications": {
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        "android.permission.ACCESS_NOTIFICATION_POLICY",
        "android.permission.POST_NOTIFICATIONS",
    },
    "location": {
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
    },
    "camera_mic": {
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
    },
    "internet": {
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_WIFI_STATE",
    },
    "boot_completed": {
        "android.permission.RECEIVE_BOOT_COMPLETED",
    },
}

# Regex to detect raw HTTP and IP URLs in strings/bytecode
URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|http://)(?:(?:\d{1,3}\.){3}\d{1,3}|[a-z0-9.-]+\.[a-z]{2,})(?::\d{1,5})?(?:/[^\s"'<>]*)?)"""
)
IP_URL_REGEX = re.compile(
    r"""(?i)\b(?:https?://|http://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:/[^\s"'<>]*)?"""
)

# Base64 string indicator pattern (minimum 24 characters of valid base64)
BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]{24,}={0,2}$")


class WorkerAnalysisError(Exception):
    """Raised when static analysis within the worker encounters an unrecoverable failure."""
    def __init__(self, message: str, error_code: str = "worker_analysis_error"):
        super().__init__(message)
        self.message = message
        self.error_code = error_code


def parse_and_analyze_apk(file_path: str, sha256_hash: str, file_size: int) -> dict[str, Any]:
    """Execute static extraction and heuristic rule checks on an APK file using Androguard."""
    if not os.path.isfile(file_path):
        raise WorkerAnalysisError(f"APK file not found: {file_path}", error_code="file_not_found")

    try:
        apk_obj = APK(file_path)
    except Exception as exc:
        raise WorkerAnalysisError(f"Failed to parse APK container: {exc}", error_code="apk_parsing_failed") from exc

    if not apk_obj.is_valid_APK():
        raise WorkerAnalysisError("Provided file is not a valid APK archive.", error_code="invalid_apk_container")

    # App basic metadata
    package_name = str(apk_obj.get_package() or "")
    version_name = str(apk_obj.get_androidversion_name() or "")
    version_code = str(apk_obj.get_androidversion_code() or "")
    min_sdk = str(apk_obj.get_min_sdk_version() or "")
    target_sdk = str(apk_obj.get_target_sdk_version() or "")

    # Grouped declared permissions
    raw_perms = set(apk_obj.get_permissions() or [])
    grouped_perms: dict[str, list[str]] = {k: [] for k in PERMISSION_MAP}
    all_assigned = set()

    for category, perm_set in PERMISSION_MAP.items():
        matched = sorted(raw_perms.intersection(perm_set))
        grouped_perms[category] = matched
        all_assigned.update(matched)

    other_perms = sorted(raw_perms - all_assigned)
    grouped_perms["other"] = other_perms
    grouped_perms["all_declared"] = sorted(raw_perms)

    # Components & Intent filters
    activities = apk_obj.get_activities() or []
    services = apk_obj.get_services() or []
    receivers = apk_obj.get_receivers() or []
    providers = apk_obj.get_providers() or []

    notable_filters: set[str] = set()
    exported_count = 0

    try:
        manifest_xml = apk_obj.get_android_manifest_xml()
        if manifest_xml is not None:
            for elem in manifest_xml.iter():
                # Strip namespace prefix if present
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                if tag in ("activity", "service", "receiver", "provider"):
                    exported_attr = None
                    for attr_k, attr_v in elem.attrib.items():
                        if attr_k.endswith("exported"):
                            exported_attr = str(attr_v).lower()
                            break
                    if exported_attr == "true":
                        exported_count += 1

                if tag == "action":
                    for attr_k, attr_v in elem.attrib.items():
                        if attr_k.endswith("name"):
                            action_name = str(attr_v)
                            if any(
                                needle in action_name
                                for needle in (
                                    "BOOT_COMPLETED",
                                    "SMS_RECEIVED",
                                    "NEW_OUTGOING_CALL",
                                    "DEVICE_ADMIN_ENABLED",
                                    "ACCESSIBILITY_SERVICE",
                                )
                            ):
                                notable_filters.add(action_name)
    except Exception:
        pass

    components_info = {
        "activities_count": len(activities),
        "services_count": len(services),
        "receivers_count": len(receivers),
        "providers_count": len(providers),
        "exported_count": exported_count,
        "notable_intent_filters": sorted(notable_filters),
    }

    # Certificate & Signing Details
    certs_info = []
    is_signed = bool(apk_obj.is_signed())
    is_debug_signed = False
    is_self_signed = False
    sig_schemes = []

    try:
        if apk_obj.is_signed_v1():
            sig_schemes.append("v1")
        if apk_obj.is_signed_v2():
            sig_schemes.append("v2")
        if apk_obj.is_signed_v3():
            sig_schemes.append("v3")
    except Exception:
        pass

    try:
        certificates = apk_obj.get_certificates() or []
        for cert in certificates:
            try:
                subject_str = cert.subject.human_friendly if hasattr(cert.subject, "human_friendly") else str(cert.subject)
                issuer_str = cert.issuer.human_friendly if hasattr(cert.issuer, "human_friendly") else str(cert.issuer)
                fingerprint = cert.sha256_fingerprint.replace(" ", "") if hasattr(cert, "sha256_fingerprint") else ""

                if "Android Debug" in subject_str or "Android Debug" in issuer_str or "androiddebugkey" in subject_str.lower():
                    is_debug_signed = True
                if subject_str == issuer_str:
                    is_self_signed = True

                valid_from_str = str(getattr(cert, "valid_after", "") or getattr(cert, "not_valid_before", ""))
                valid_to_str = str(getattr(cert, "valid_until", "") or getattr(cert, "not_valid_after", ""))

                certs_info.append({
                    "subject": subject_str,
                    "issuer": issuer_str,
                    "valid_from": valid_from_str,
                    "valid_to": valid_to_str,
                    "sha256_fingerprint": fingerprint,
                })
            except Exception:
                continue
    except Exception:
        pass

    signing_info = {
        "is_signed": is_signed,
        "signature_schemes": sig_schemes,
        "is_debug_signed": is_debug_signed,
        "is_self_signed": is_self_signed,
        "certificates": certs_info,
    }

    # Multi-DEX Bytecode and Static Indicators
    dex_classes: list[Any] = []
    dex_methods: list[Any] = []
    dex_strings: set[str] = set()

    dynamic_code_loading = False
    reflection_use = False
    runtime_exec = False
    sms_send_apis = False
    accessibility_event_handling = False
    native_library_presence = False
    base64_hints = False
    short_identifier_count = 0
    total_identifier_count = 0

    try:
        for dex_bytes in apk_obj.get_all_dex():
            try:
                d = DEX(dex_bytes)
                dex_classes.extend(d.get_classes())
                dex_methods.extend(d.get_methods())
                for s in d.get_strings():
                    try:
                        dex_strings.add(str(s))
                    except Exception:
                        pass
            except Exception:
                continue
    except Exception:
        pass

    try:
        file_list = apk_obj.get_files() or []
        for fn in file_list:
            if fn.startswith("lib/") and fn.endswith(".so"):
                native_library_presence = True
                break
    except Exception:
        pass

    # Inspect class names and method signatures
    for c in dex_classes:
        try:
            c_name = str(c.get_name())
            total_identifier_count += 1
            simple_name = c_name.split("/")[-1].rstrip(";")
            if len(simple_name) <= 2:
                short_identifier_count += 1
        except Exception:
            pass

    for m in dex_methods:
        try:
            m_name = str(m.get_name())
            total_identifier_count += 1
            if len(m_name) <= 2 and not m_name.startswith("<"):
                short_identifier_count += 1

            descriptor = str(m.get_descriptor() or "")
            class_name = str(m.get_class_name() or "")
            combined = f"{class_name}->{m_name}{descriptor}"

            if "Ljava/lang/Runtime;->exec" in combined or "Ljava/lang/ProcessBuilder;" in combined:
                runtime_exec = True
            if "Ldalvik/system/DexClassLoader;" in combined or "Ldalvik/system/PathClassLoader;" in combined:
                dynamic_code_loading = True
            if "Ljava/lang/reflect/Method;->invoke" in combined or "Ljava/lang/Class;->getMethod" in combined:
                reflection_use = True
            if "Landroid/telephony/SmsManager;->sendTextMessage" in combined:
                sms_send_apis = True
            if "Landroid/accessibilityservice/AccessibilityService;" in combined:
                accessibility_event_handling = True
        except Exception:
            pass

    discovered_urls: set[str] = set()
    for s in dex_strings:
        if not s or len(s) < 4:
            continue
        if len(s) > 30 and BASE64_PATTERN.match(s):
            base64_hints = True

        matches = URL_REGEX.findall(s)
        for m in matches:
            if len(m) <= 120 and not m.startswith("http://schemas.android.com"):
                discovered_urls.add(m)

    obfuscation_ratio = (
        round(short_identifier_count / total_identifier_count, 4)
        if total_identifier_count > 0
        else 0.0
    )

    code_indicators = {
        "dynamic_code_loading": dynamic_code_loading,
        "reflection_use": reflection_use,
        "runtime_exec": runtime_exec,
        "sms_send_apis": sms_send_apis,
        "accessibility_event_handling": accessibility_event_handling,
        "native_library_presence": native_library_presence,
        "base64_obfuscation_hints": base64_hints,
        "obfuscation_name_ratio_hint": obfuscation_ratio,
        "discovered_urls": sorted(discovered_urls)[:50],
    }

    # Deterministic Heuristic Finding Rules (R1 - R10)
    findings = []
    has_sms_perms = len(grouped_perms.get("sms", [])) > 0
    has_internet_perms = len(grouped_perms.get("internet", [])) > 0
    has_accessibility_perms = len(grouped_perms.get("accessibility", [])) > 0
    has_overlay_perms = len(grouped_perms.get("overlay", [])) > 0
    has_device_admin_perms = len(grouped_perms.get("device_admin", [])) > 0
    has_install_perms = len(grouped_perms.get("install_packages", [])) > 0
    has_boot_perms = len(grouped_perms.get("boot_completed", [])) > 0

    # Rule R1: SMS Interception & Exfiltration
    if has_sms_perms and has_internet_perms:
        findings.append({
            "id": "RULE_SMS_EXFILTRATION_CAPABILITY",
            "category": "Sensitive Permissions",
            "severity": "high",
            "title": "Combined SMS Access and Internet Communication Capability",
            "evidence": f"Declared permissions: SMS={grouped_perms.get('sms')}, INTERNET={grouped_perms.get('internet')}",
            "why_it_matters": "Malicious banking trojans frequently combine SMS read permissions with outbound internet access to steal one-time passcodes (OTPs) and transaction verification numbers.",
        })

    # Rule R2: Accessibility Service + Window Overlay
    if (has_accessibility_perms or accessibility_event_handling) and has_overlay_perms:
        findings.append({
            "id": "RULE_ACCESSIBILITY_OVERLAY_COMBO",
            "category": "Abuse of Accessibility",
            "severity": "high",
            "title": "Accessibility Service Declared with System Overlay Capabilities",
            "evidence": "Accessibility service implementation detected alongside SYSTEM_ALERT_WINDOW permission.",
            "why_it_matters": "The combination of Accessibility permissions and overlay windows enables tapjacking, covert credential capturing, and automated screen interaction without user knowledge.",
        })

    # Rule R3: Device Administration Privileges
    if has_device_admin_perms:
        findings.append({
            "id": "RULE_DEVICE_ADMIN_PRIVILEGE",
            "category": "Privileged Execution",
            "severity": "high",
            "title": "Device Administration Receiver Declared",
            "evidence": f"Declared device admin permissions: {grouped_perms.get('device_admin')}",
            "why_it_matters": "Device Admin status allows applications to enforce system lockouts, wipe device storage, and resist uninstallation. Typical of mobile ransomware.",
        })

    # Rule R4: Native Command Execution References
    if runtime_exec:
        findings.append({
            "id": "RULE_COMMAND_EXECUTION",
            "category": "Command Execution",
            "severity": "high",
            "title": "Runtime Process Execution Detected in Bytecode",
            "evidence": "Bytecode references Runtime.getRuntime().exec() or ProcessBuilder.",
            "why_it_matters": "Executing raw operating system shell commands is uncommon in standard Android applications and is commonly used by root exploits and payload downloaders.",
        })

    # Rule R5: Dynamic Code Loading (DEX/JAR)
    if dynamic_code_loading:
        findings.append({
            "id": "RULE_DYNAMIC_CODE_LOADING",
            "category": "Evasion & Modularity",
            "severity": "medium",
            "title": "Dynamic Class Loading Discovered in Bytecode",
            "evidence": "Bytecode references DexClassLoader or PathClassLoader loading external code.",
            "why_it_matters": "Dynamic code loading can allow an application to fetch and execute unvetted executable code at runtime, bypassing static analysis review.",
        })

    # Rule R6: Boot Persistence Mechanism
    if has_boot_perms and any("BOOT_COMPLETED" in filt for filt in notable_filters):
        findings.append({
            "id": "RULE_BOOT_PERSISTENCE",
            "category": "Persistence",
            "severity": "medium",
            "title": "Automatic Persistence via Device Boot Receiver",
            "evidence": "RECEIVE_BOOT_COMPLETED declared with active BOOT_COMPLETED intent receiver.",
            "why_it_matters": "Configuring services to start immediately on phone startup ensures persistent background survival for spyware and tracking services.",
        })

    # Rule R7: Unsigned APK Container
    if not is_signed:
        findings.append({
            "id": "RULE_UNSIGNED_PACKAGE",
            "category": "Cryptographic Integrity",
            "severity": "high",
            "title": "Archive Lacks Cryptographic Digital Signature",
            "evidence": "No valid digital signing certificate found within META-INF container.",
            "why_it_matters": "Unsigned APKs cannot be installed on unmodified Android devices and frequently indicate incomplete or tampered packages.",
        })

    # Rule R8: Signed with Known Debug Key
    if is_debug_signed:
        findings.append({
            "id": "RULE_DEBUG_SIGNED_CERT",
            "category": "Cryptographic Integrity",
            "severity": "medium",
            "title": "Package Signed with Public Android Debug Certificate",
            "evidence": "Certificate Subject/Issuer contains Android Debug identifier.",
            "why_it_matters": "Debug keys are publicly known and insecure. Production release applications must be signed with private developer release keys.",
        })

    # Rule R9: Unknown Package Installer Request
    if has_install_perms:
        findings.append({
            "id": "RULE_PACKAGE_INSTALLER",
            "category": "Dropper Capabilities",
            "severity": "medium",
            "title": "Application Requests Package Installation Permissions",
            "evidence": f"Declared install permissions: {grouped_perms.get('install_packages')}",
            "why_it_matters": "Permission to install secondary packages is characteristic of dropper malware that installs secondary high-risk payloads post-infection.",
        })

    # Rule R10: Hardcoded Numeric IP Endpoints
    ip_urls = [u for u in discovered_urls if IP_URL_REGEX.search(u)]
    if ip_urls:
        findings.append({
            "id": "RULE_HARDCODED_IP_URL",
            "category": "Network Indicators",
            "severity": "medium",
            "title": "Hardcoded Numeric IP Address Communication",
            "evidence": f"Discovered IP URL endpoints: {', '.join(ip_urls[:3])}",
            "why_it_matters": "Hardcoded IP addresses are often used in command-and-control infrastructure to evade DNS-based security filtering.",
        })

    # Rule R11: Strong Obfuscation Hint
    if obfuscation_ratio > 0.40 and total_identifier_count > 50:
        findings.append({
            "id": "RULE_OBFUSCATION_HINT",
            "category": "Obfuscation",
            "severity": "low",
            "title": "Elevated Short Identifier Ratio (Obfuscation Hint)",
            "evidence": f"{obfuscation_ratio * 100:.1f}% of inspected classes/methods have identifiers <= 2 characters.",
            "why_it_matters": "Heavy identifier renaming (e.g., ProGuard/DexGuard) is standard in both commercial apps and malware to hinder reverse engineering.",
        })

    # Heuristic Indicator Level Calculation
    high_count = sum(1 for f in findings if f["severity"] == "high")
    med_count = sum(1 for f in findings if f["severity"] == "medium")

    if high_count >= 2 or (high_count >= 1 and med_count >= 2) or med_count >= 4:
        indicator_level = "many_indicators"
    elif high_count >= 1 or med_count >= 1:
        indicator_level = "some_indicators"
    else:
        indicator_level = "no_notable_indicators"

    return {
        "analysis_version": "apk-static-v1",
        "sha256": sha256_hash,
        "file_size": file_size,
        "app": {
            "package_name": package_name,
            "version_name": version_name,
            "version_code": version_code,
            "min_sdk": min_sdk,
            "target_sdk": target_sdk,
        },
        "permissions": grouped_perms,
        "components": components_info,
        "signing": signing_info,
        "code_indicators": code_indicators,
        "findings": findings,
        "indicator_level": indicator_level,
        "limitations": CANONICAL_LIMITATIONS,
    }


def execute_rq_apk_job(file_path: str, sha256_hash: str, file_size: int) -> dict[str, Any]:
    """Entry point for Redis Queue (RQ) jobs."""
    return parse_and_analyze_apk(file_path, sha256_hash, file_size)


def main():
    """CLI entry point for running isolated static analysis in a subprocess.

    Usage:
        python -m app.apk_worker <file_path> <sha256_hash> <file_size>
    Outputs JSON string to stdout on success, or JSON error object with exit code 1.
    """
    if len(sys.argv) < 4:
        sys.stderr.write("Usage: python -m app.apk_worker <file_path> <sha256_hash> <file_size>\n")
        sys.exit(2)

    file_path = sys.argv[1]
    sha256_hash = sys.argv[2]
    try:
        file_size = int(sys.argv[3])
    except ValueError:
        file_size = 0

    try:
        result = parse_and_analyze_apk(file_path, sha256_hash, file_size)
        sys.stdout.write(json.dumps(result))
        sys.stdout.flush()
        sys.exit(0)
    except WorkerAnalysisError as err:
        err_dict = {"error": err.error_code, "message": err.message}
        sys.stderr.write(json.dumps(err_dict))
        sys.exit(1)
    except Exception as exc:
        err_dict = {"error": "worker_unexpected_error", "message": str(exc)}
        sys.stderr.write(json.dumps(err_dict))
        sys.exit(1)


if __name__ == "__main__":
    main()
