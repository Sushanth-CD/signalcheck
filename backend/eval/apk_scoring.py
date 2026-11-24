"""apk_scoring.py - Deterministic Rule-Based Scoring Engine for Android APKs (Offline Evaluation Harness).

Version: apk-rules-v1
Heuristic indicator level calculation based on static findings and combination bonuses.
This module contains zero machine learning models, zero probabilistic estimates, and
never issues a verdict.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

# ==============================================================================
# RULE SCORING CONFIGURATION TABLE (apk-rules-v1)
# ==============================================================================

SCORING_VERSION = "apk-rules-v1"

DISCLAIMER_TEXT = "Heuristic indicator level, a signal to check and not a malware verdict."

# Cut points for indicator level mapping
CUT_POINTS = {
    "LOW_MAX": 19,       # 0 - 19: Low indicator level
    "MEDIUM_MIN": 20,    # 20 - 49: Medium indicator level
    "MEDIUM_MAX": 49,
    "HIGH_MIN": 50,      # 50+: High indicator level
}

# Per-rule base point weights
RULE_WEIGHTS: Dict[str, Dict[str, Any]] = {
    "RULE_SMS_EXFILTRATION_CAPABILITY": {
        "points": 30,
        "title": "Combined SMS Access and Internet Communication Capability",
        "description": "Sensitive SMS read/send permissions declared alongside outbound network access.",
    },
    "RULE_ACCESSIBILITY_OVERLAY_COMBO": {
        "points": 30,
        "title": "Accessibility Service Declared with System Overlay Capabilities",
        "description": "Accessibility service implementation paired with system overlay window permissions.",
    },
    "RULE_DEVICE_ADMIN_PRIVILEGE": {
        "points": 25,
        "title": "Device Administration Receiver Declared",
        "description": "Device administration receiver declared, granting system-level policy controls.",
    },
    "RULE_COMMAND_EXECUTION": {
        "points": 20,
        "title": "Runtime Process Execution Detected in Bytecode",
        "description": "Direct invocation of operating system shell processes in Dalvik bytecode.",
    },
    "RULE_DYNAMIC_CODE_LOADING": {
        "points": 20,
        "title": "Dynamic Class Loading Discovered in Bytecode",
        "description": "Bytecode references external code loading via DexClassLoader or PathClassLoader.",
    },
    "RULE_UNSIGNED_PACKAGE": {
        "points": 20,
        "title": "Archive Lacks Cryptographic Digital Signature",
        "description": "Package container lacks valid digital signature verification blocks.",
    },
    "RULE_PACKAGE_INSTALLER": {
        "points": 15,
        "title": "Application Requests Package Installation Permissions",
        "description": "Application requests permissions to prompt installation of secondary packages.",
    },
    "RULE_BOOT_PERSISTENCE": {
        "points": 10,
        "title": "Automatic Persistence via Device Boot Receiver",
        "description": "Broadcast receiver configured to start automatically on system boot completion.",
    },
    "RULE_DEBUG_SIGNED_CERT": {
        "points": 10,
        "title": "Package Signed with Public Android Debug Certificate",
        "description": "Container signed with publicly known debug certificate instead of a private release key.",
    },
    "RULE_HARDCODED_IP_URL": {
        "points": 10,
        "title": "Hardcoded Numeric IP Address Communication",
        "description": "Bytecode contains hardcoded numeric IP endpoints circumventing DNS lookups.",
    },
    "RULE_OBFUSCATION_HINT": {
        "points": 5,
        "title": "Elevated Short Identifier Ratio (Obfuscation Hint)",
        "description": "High proportion of short class and method names indicating symbol renaming.",
    },
}

# Documented combination bonuses for high-risk co-occurrences
COMBINATION_BONUSES: List[Dict[str, Any]] = [
    {
        "id": "COMBO_SMS_DYNAMIC",
        "name": "SMS Exfiltration + Dynamic Code Loading",
        "rules": ["RULE_SMS_EXFILTRATION_CAPABILITY", "RULE_DYNAMIC_CODE_LOADING"],
        "bonus_points": 15,
        "description": "Combines SMS interception capability with dynamic code retrieval in bytecode.",
    },
    {
        "id": "COMBO_OVERLAY_COMMAND",
        "name": "Accessibility Overlay + Command Execution",
        "rules": ["RULE_ACCESSIBILITY_OVERLAY_COMBO", "RULE_COMMAND_EXECUTION"],
        "bonus_points": 15,
        "description": "Combines interface overlay capabilities with raw operating system process execution.",
    },
    {
        "id": "COMBO_INSTALLER_DYNAMIC",
        "name": "Package Installer + Dynamic Code Loading",
        "rules": ["RULE_PACKAGE_INSTALLER", "RULE_DYNAMIC_CODE_LOADING"],
        "bonus_points": 15,
        "description": "Combines secondary application installation with runtime dynamic code loading.",
    },
    {
        "id": "COMBO_ADMIN_PERSISTENCE",
        "name": "Device Admin + Boot Persistence",
        "rules": ["RULE_DEVICE_ADMIN_PRIVILEGE", "RULE_BOOT_PERSISTENCE"],
        "bonus_points": 10,
        "description": "Combines elevated device administration with automatic boot startup persistence.",
    },
]


def score_findings(findings: List[Dict[str, Any]] | List[Any]) -> Dict[str, Any]:
    """Deterministically calculate the indicator score, level, and breakdown from static findings.

    Args:
        findings: List of finding dictionaries, each expected to have an 'id' key.

    Returns:
        Structured indicator summary containing scoring version, level, total points,
        contributing rules, combination bonuses, and canonical disclaimer.
    """
    fired_rule_ids: Set[str] = set()
    for finding in findings:
        if isinstance(finding, dict):
            r_id = finding.get("id")
            if r_id and isinstance(r_id, str):
                fired_rule_ids.add(r_id)

    total_points = 0
    rule_contributions: List[Dict[str, Any]] = []

    # Score base rules (stable iteration order matching RULE_WEIGHTS keys)
    for r_id, config in RULE_WEIGHTS.items():
        if r_id in fired_rule_ids:
            pts = int(config["points"])
            total_points += pts
            rule_contributions.append({
                "rule_id": r_id,
                "title": config["title"],
                "points": pts,
            })

    # Score combination bonuses (stable iteration order matching COMBINATION_BONUSES)
    combination_contributions: List[Dict[str, Any]] = []
    for combo in COMBINATION_BONUSES:
        required_rules = combo["rules"]
        if all(r in fired_rule_ids for r in required_rules):
            pts = int(combo["bonus_points"])
            total_points += pts
            combination_contributions.append({
                "id": combo["id"],
                "name": combo["name"],
                "rules": list(required_rules),
                "points": pts,
                "description": combo["description"],
            })

    # Map total points to Low / Medium / High level and canonical indicator_level string
    if total_points >= CUT_POINTS["HIGH_MIN"]:
        level = "High"
        indicator_level = "many_indicators"
    elif total_points >= CUT_POINTS["MEDIUM_MIN"]:
        level = "Medium"
        indicator_level = "some_indicators"
    else:
        level = "Low"
        indicator_level = "no_notable_indicators"

    return {
        "scoring_version": SCORING_VERSION,
        "level": level,
        "indicator_level": indicator_level,
        "total_points": total_points,
        "rule_contributions": rule_contributions,
        "combination_contributions": combination_contributions,
        "disclaimer": DISCLAIMER_TEXT,
    }


def attach_indicator_summary(result_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Attach or synchronize indicator_summary and indicator_level on an APK static result dictionary."""
    findings = result_dict.get("findings", [])
    summary = score_findings(findings)

    result_dict["indicator_summary"] = summary
    result_dict["indicator_level"] = summary["indicator_level"]
    return result_dict
