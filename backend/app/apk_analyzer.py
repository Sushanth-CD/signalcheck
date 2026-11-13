"""Static APK analysis module for SignalCheck (apk-static-v1).

HARD SAFETY CONSTRAINTS:
- Static analysis only. NEVER install, execute, emulate, or dynamic-load APK/DEX code.
- Treat every upload as hostile. Parse only inside sandboxed worker with strict resource caps.
- No eval/exec/subprocess on anything derived from the APK.
- Ephemeral processing: uploads are streamed to a temporary file, inspected, and deleted in a finally block.
- Zero sensitive payload logging.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import zipfile
from dataclasses import dataclass
from typing import Any, Dict, List, Set, Tuple

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


class APKValidationError(Exception):
    """Raised when an uploaded file violates APK integrity or safety boundaries."""
    def __init__(self, message: str, status_code: int = 422, error_code: str = "invalid_apk"):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code


def validate_zip_structure(
    file_path: str,
    max_entries: int = 10_000,
    max_uncompressed_bytes: int = 300 * 1024 * 1024,
    max_compression_ratio: float = 20.0,
) -> None:
    """Inspect ZIP container before extraction to protect against zip bombs and traversal attacks."""
    # Check magic bytes at start of file
    with open(file_path, "rb") as f:
        magic = f.read(4)
        if magic != b"PK\x03\x04":
            raise APKValidationError(
                "Uploaded file is not a valid ZIP/APK archive (magic bytes mismatch).",
                status_code=422,
                error_code="invalid_zip_archive",
            )

    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            infolist = zf.infolist()
            if len(infolist) > max_entries:
                raise APKValidationError(
                    f"Archive exceeds maximum allowed entry count ({len(infolist)} > {max_entries}).",
                    status_code=422,
                    error_code="zip_entry_count_exceeded",
                )

            total_uncompressed = 0
            has_manifest = False
            has_dex = False

            for info in infolist:
                # Path traversal checks
                filename = info.filename
                if ".." in filename or filename.startswith(("/", "\\")):
                    raise APKValidationError(
                        "Archive contains illegal path traversal filenames.",
                        status_code=422,
                        error_code="path_traversal_detected",
                    )

                # Compression ratio check for individual files
                compressed = max(info.compress_size, 1)
                ratio = info.file_size / compressed
                if ratio > max_compression_ratio and info.file_size > 1_000_000:
                    raise APKValidationError(
                        f"Archive entry exhibits suspicious compression ratio ({ratio:.1f}x).",
                        status_code=422,
                        error_code="zip_bomb_ratio_exceeded",
                    )

                total_uncompressed += info.file_size
                if total_uncompressed > max_uncompressed_bytes:
                    raise APKValidationError(
                        f"Total uncompressed size exceeds limit ({total_uncompressed} > {max_uncompressed_bytes} bytes).",
                        status_code=422,
                        error_code="zip_bomb_size_exceeded",
                    )

                if filename == "AndroidManifest.xml":
                    has_manifest = True
                elif filename.startswith("classes") and filename.endswith(".dex"):
                    has_dex = True

            if not has_manifest:
                raise APKValidationError(
                    "Uploaded archive does not contain AndroidManifest.xml.",
                    status_code=422,
                    error_code="missing_android_manifest",
                )

            if not has_dex:
                raise APKValidationError(
                    "Uploaded archive does not contain any executable classes*.dex files.",
                    status_code=422,
                    error_code="missing_dex_code",
                )

    except zipfile.BadZipFile as exc:
        raise APKValidationError(
            f"Corrupt or malformed ZIP archive: {exc}",
            status_code=422,
            error_code="corrupt_zip_archive",
        ) from exc


def analyze_apk_file(file_path: str, sha256_hash: str, file_size: int) -> dict[str, Any]:
    """Perform purely static inspection using Androguard and deterministic heuristic rules."""
    # 1. Parse APK container & Manifest
    try:
        apk_obj = APK(file_path)
    except Exception as exc:
        raise APKValidationError(
            f"Failed to parse APK structure or manifest: {exc}",
            status_code=422,
            error_code="apk_parsing_failed",
        ) from exc

    if not apk_obj.is_valid_APK():
        raise APKValidationError(
            "Androguard reported that the provided file is not a valid APK.",
            status_code=422,
            error_code="invalid_apk_container",
        )

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

    # Inspect activities/services/receivers for notable intent filters and exported status
    try:
        manifest_xml = apk_obj.get_android_manifest_xml()
        if manifest_xml is not None:
            for elem in manifest_xml.iter():
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                if tag in ("activity", "service", "receiver", "provider"):
                    is_exported = False
                    for attr_name, attr_val in elem.attrib.items():
                        if "exported" in attr_name:
                            is_exported = attr_val.lower() == "true"
                    if is_exported:
                        exported_count += 1

                if tag == "action":
                    for attr_name, attr_val in elem.attrib.items():
                        if "name" in attr_name:
                            if "SMS_RECEIVED" in attr_val:
                                notable_filters.add("android.provider.Telephony.SMS_RECEIVED")
                            elif "BOOT_COMPLETED" in attr_val:
                                notable_filters.add("android.intent.action.BOOT_COMPLETED")
                            elif "DEVICE_ADMIN_ENABLED" in attr_val:
                                notable_filters.add("android.app.action.DEVICE_ADMIN_ENABLED")
                            elif "AccessibilityService" in attr_val:
                                notable_filters.add("android.accessibilityservice.AccessibilityService")
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

    # Signing verification
    is_signed = bool(apk_obj.is_signed())
    sig_schemes = []
    if getattr(apk_obj, "is_signed_v1", lambda: False)():
        sig_schemes.append("v1 (JAR)")
    if getattr(apk_obj, "is_signed_v2", lambda: False)():
        sig_schemes.append("v2 (APK Signature Scheme v2)")
    if getattr(apk_obj, "is_signed_v3", lambda: False)():
        sig_schemes.append("v3 (APK Signature Scheme v3)")

    certificates_list = []
    is_debug_signed = False
    is_self_signed = False

    try:
        certs = apk_obj.get_certificates() or []
        for cert in certs:
            issuer = str(getattr(cert, "issuer", "") or "")
            subject = str(getattr(cert, "subject", "") or "")
            valid_from = str(getattr(cert, "not_valid_before", "") or "")
            valid_to = str(getattr(cert, "not_valid_after", "") or "")
            sha256_fp = ""
            try:
                sha256_fp = hashlib.sha256(cert.dump()).hexdigest()
            except Exception:
                pass

            if "Android Debug" in issuer or "Android Debug" in subject:
                is_debug_signed = True
            if issuer and subject and issuer == subject:
                is_self_signed = True

            certificates_list.append({
                "subject": subject,
                "issuer": issuer,
                "valid_from": valid_from,
                "valid_to": valid_to,
                "sha256_fingerprint": sha256_fp,
            })
    except Exception:
        pass

    signing_info = {
        "is_signed": is_signed,
        "signature_schemes": sig_schemes,
        "is_debug_signed": is_debug_signed,
        "is_self_signed": is_self_signed,
        "certificates": certificates_list,
    }

    # 2. Bytecode & Multi-DEX Traversal
    dynamic_code_loading = False
    reflection_use = False
    runtime_exec = False
    sms_send_apis = False
    accessibility_events = False
    native_library_presence = False
    base64_hints = False
    total_names = 0
    short_names = 0
    discovered_urls: set[str] = set()

    # Check for native libraries (.so files) inside ZIP
    with zipfile.ZipFile(file_path, "r") as zf:
        for name in zf.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                native_library_presence = True
                break

    try:
        dex_files = apk_obj.get_all_dex()
        for dex_bytes in dex_files:
            try:
                d = DEX(dex_bytes)
                # Analyze strings
                for s in d.get_strings():
                    val = str(s).strip()
                    # URL detection
                    for match in URL_REGEX.findall(val):
                        # Filter out common standard schema namespaces
                        if not match.startswith(("http://schemas.android.com", "http://www.w3.org")):
                            discovered_urls.add(match[:200])

                    # Base64 indicator
                    if not base64_hints and len(val) >= 24 and BASE64_PATTERN.match(val):
                        try:
                            # Verify if it actually decodes to valid bytes
                            decoded = base64.b64decode(val)
                            if len(decoded) >= 16:
                                base64_hints = True
                        except Exception:
                            pass

                # Analyze class and method names for obfuscation hint
                for cls in d.get_classes():
                    cls_name = cls.get_name().split("/")[-1].rstrip(";")
                    total_names += 1
                    if len(cls_name) <= 2:
                        short_names += 1

                    for m in cls.get_methods():
                        m_name = m.get_name()
                        if not m_name.startswith("<"):  # skip <init>, <clinit>
                            total_names += 1
                            if len(m_name) <= 2:
                                short_names += 1

                # Analyze method references / calls
                for m_ref in d.get_methods():
                    m_str = f"{m_ref.get_class_name()}->{m_ref.get_name()}"
                    if any(x in m_str for x in ("DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader")):
                        dynamic_code_loading = True
                    if any(x in m_str for x in ("java/lang/reflect/Method->invoke", "java/lang/Class->forName")):
                        reflection_use = True
                    if "java/lang/Runtime->exec" in m_str or "java/lang/ProcessBuilder->start" in m_str:
                        runtime_exec = True
                    if "SmsManager->sendTextMessage" in m_str or "SmsManager->sendMultipartTextMessage" in m_str:
                        sms_send_apis = True
                    if "AccessibilityService" in m_str or "AccessibilityNodeInfo->performAction" in m_str:
                        accessibility_events = True
            except Exception:
                # Corrupt DEX slice or parsing error
                continue
    except Exception:
        pass

    # Cap URLs to first 20 de-duplicated entries
    sorted_urls = sorted(discovered_urls)[:20]
    obfuscation_ratio = round(short_names / max(total_names, 1), 4)

    code_indicators = {
        "dynamic_code_loading": dynamic_code_loading,
        "reflection_use": reflection_use,
        "runtime_exec": runtime_exec,
        "sms_send_apis": sms_send_apis,
        "accessibility_event_handling": accessibility_events,
        "native_library_presence": native_library_presence,
        "base64_obfuscation_hints": base64_hints,
        "obfuscation_name_ratio_hint": obfuscation_ratio,
        "discovered_urls": sorted_urls,
    }

    # 3. Rule Table Evaluation & Findings Generation
    findings: list[dict[str, str]] = []

    # Rule R1: SMS Interception & Exfiltration Pattern
    has_sms_receive = bool(set(grouped_perms["sms"]).intersection({"android.permission.RECEIVE_SMS", "android.permission.READ_SMS"}))
    has_internet = bool(grouped_perms["internet"])
    if has_sms_receive and has_internet:
        findings.append({
            "id": "RULE_SMS_EXFILTRATION_CAPABILITY",
            "category": "Permission Combination",
            "severity": "high",
            "title": "SMS Interception & Network Transmission Capabilities",
            "evidence": f"SMS permissions ({', '.join(grouped_perms['sms'])}) combined with INTERNET permission.",
            "why_it_matters": "Applications with both SMS read/receive access and network connectivity can intercept two-factor authentication codes and exfiltrate them to external servers.",
        })

    # Rule R2: Accessibility Service with Screen Overlay
    has_accessibility = bool(grouped_perms["accessibility"]) or accessibility_events or ("android.accessibilityservice.AccessibilityService" in notable_filters)
    has_overlay = bool(grouped_perms["overlay"])
    if has_accessibility and has_overlay:
        findings.append({
            "id": "RULE_ACCESSIBILITY_OVERLAY_COMBO",
            "category": "Privilege Escalation",
            "severity": "high",
            "title": "Accessibility Service Combined with Window Overlay Permission",
            "evidence": "Accessibility service declaration / handling combined with SYSTEM_ALERT_WINDOW.",
            "why_it_matters": "This combination is frequently abused by Android banking trojans to perform tapjacking, inject fraudulent overlay login screens, and observe user keystrokes.",
        })

    # Rule R3: Device Administration Privileges
    has_device_admin = bool(grouped_perms["device_admin"]) or ("android.app.action.DEVICE_ADMIN_ENABLED" in notable_filters)
    if has_device_admin:
        findings.append({
            "id": "RULE_DEVICE_ADMIN_PRIVILEGE",
            "category": "Device Administration",
            "severity": "high",
            "title": "Device Administration Privilege Requested",
            "evidence": "BIND_DEVICE_ADMIN permission or DEVICE_ADMIN_ENABLED intent filter declared.",
            "why_it_matters": "Device Admin rights allow an application to lock the screen, prevent uninstallation, and wipe device storage.",
        })

    # Rule R4: Arbitrary Process / Command Execution
    if runtime_exec:
        findings.append({
            "id": "RULE_COMMAND_EXECUTION",
            "category": "Code Execution",
            "severity": "high",
            "title": "Operating System Command Execution Reference (Runtime.exec)",
            "evidence": "Bytecode references java.lang.Runtime.exec or ProcessBuilder.start.",
            "why_it_matters": "Invoking shell commands from an Android app can be used to execute downloaded binaries or probe root privileges.",
        })

    # Rule R5: Dynamic Code Loading
    if dynamic_code_loading:
        findings.append({
            "id": "RULE_DYNAMIC_CODE_LOADING",
            "category": "Evasion & Dynamic Loading",
            "severity": "medium",
            "title": "Dynamic DEX/JAR Class Loading Reference",
            "evidence": "Bytecode references DexClassLoader, PathClassLoader, or InMemoryDexClassLoader.",
            "why_it_matters": "Dynamic class loading allows applications to download and execute unverified executable payloads post-installation, bypassing initial static review.",
        })

    # Rule R6: Background Auto-Start
    if bool(grouped_perms["boot_completed"]) or ("android.intent.action.BOOT_COMPLETED" in notable_filters):
        findings.append({
            "id": "RULE_BOOT_PERSISTENCE",
            "category": "Persistence",
            "severity": "medium",
            "title": "Automatic Startup on Device Boot",
            "evidence": "RECEIVE_BOOT_COMPLETED permission or intent filter declared.",
            "why_it_matters": "Allows the application to start background services immediately after device startup without user interaction.",
        })

    # Rule R7: Debug-Signed or Unsigned Package
    if not is_signed:
        findings.append({
            "id": "RULE_UNSIGNED_PACKAGE",
            "category": "Package Integrity",
            "severity": "high",
            "title": "Unsigned APK Container",
            "evidence": "No valid cryptographic signatures found in archive.",
            "why_it_matters": "Unsigned packages cannot be installed on standard Android devices without custom ROMs or developer bypasses, and their origin cannot be cryptographically verified.",
        })
    elif is_debug_signed:
        findings.append({
            "id": "RULE_DEBUG_SIGNED_CERT",
            "category": "Package Integrity",
            "severity": "medium",
            "title": "Debug Certificate Signature",
            "evidence": "Certificate issuer or subject contains 'Android Debug'.",
            "why_it_matters": "Debug certificates are generated by developer tooling and have known private keys. They should never be used for production releases.",
        })

    # Rule R8: Package Installation Privilege
    if bool(grouped_perms["install_packages"]):
        findings.append({
            "id": "RULE_PACKAGE_INSTALLER",
            "category": "Installation Rights",
            "severity": "medium",
            "title": "Application Installation Capability (REQUEST_INSTALL_PACKAGES)",
            "evidence": "REQUEST_INSTALL_PACKAGES or INSTALL_PACKAGES permission requested.",
            "why_it_matters": "Enables the app to prompt the user to install secondary application packages, commonly seen in dropper apps.",
        })

    # Rule R9: Direct IP Address or Insecure HTTP URLs
    ip_urls = [u for u in sorted_urls if IP_URL_REGEX.search(u)]
    if ip_urls:
        findings.append({
            "id": "RULE_HARDCODED_IP_URL",
            "category": "Network Indicators",
            "severity": "medium",
            "title": "Hardcoded Numeric IP Address Communication",
            "evidence": f"Discovered IP URL endpoints: {', '.join(ip_urls[:3])}",
            "why_it_matters": "Hardcoded IP addresses are often used in command-and-control infrastructure to evade DNS-based security filtering.",
        })

    # Rule R10: Strong Obfuscation Hint
    if obfuscation_ratio > 0.40 and total_names > 50:
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
