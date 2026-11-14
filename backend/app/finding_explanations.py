"""finding_explanations.py - Plain-language educational explanations for APK static analysis findings.

Every finding is an indicator or signal to check, NEVER a conclusive malware verdict or proof.
Legitimate applications frequently use these capabilities for valid operational needs.
"""

from typing import Any, Dict, List, Optional

FINDING_EXPLANATIONS: Dict[str, Dict[str, Any]] = {
    "RULE_SMS_EXFILTRATION_CAPABILITY": {
        "what_it_means": (
            "The app requests permissions to read SMS messages alongside permission to connect to the Internet."
        ),
        "why_attackers_use_it": (
            "Malware can intercept incoming one-time passcodes (OTPs), verification codes, or personal text messages "
            "and transmit them to an unauthorized remote server."
        ),
        "legit_uses": [
            "Banking, financial, and multi-factor authentication apps that automatically autofill verification SMS codes.",
            "SMS backup, restore, or default messaging applications.",
            "Delivery and ride-hailing apps verifying user phone numbers during registration.",
        ],
        "what_to_do": (
            "Check whether the app genuinely requires SMS access for its core functions. "
            "If an unrelated app (like a game, flashlight, or simple utility) requests SMS reading, deny the permission."
        ),
        "learn_more_tags": ["Privacy", "SMS", "Credential Security", "Permissions"],
    },
    "RULE_ACCESSIBILITY_OVERLAY_COMBO": {
        "what_it_means": (
            "The app combines Android Accessibility Service capabilities with permission to draw overlay windows on top of other applications."
        ),
        "why_attackers_use_it": (
            "Attackers use overlays and accessibility tools to perform 'tapjacking', capture keystrokes, and read sensitive on-screen text from banking or authentication apps."
        ),
        "legit_uses": [
            "Assistive technologies for users with visual, auditory, or motor disabilities.",
            "Legitimate password managers that autofill credentials across different applications.",
            "Display customization tools, screen recorders, and parental control monitoring suites.",
        ],
        "what_to_do": (
            "Only grant Accessibility Service permissions to trusted tools that clearly require them for assistive or utility purposes. "
            "Never grant accessibility access to unfamiliar apps from untrusted sources."
        ),
        "learn_more_tags": ["Accessibility", "Overlays", "Anti-Tapjacking", "UI Security"],
    },
    "RULE_DEVICE_ADMIN_PRIVILEGE": {
        "what_it_means": (
            "The app declares a Device Administration receiver, which allows it to manage deep device-level policies."
        ),
        "why_attackers_use_it": (
            "Ransomware and sophisticated spyware use Device Administrator privileges to prevent uninstallation, enforce lock codes, or wipe device storage remotely."
        ),
        "legit_uses": [
            "Enterprise Mobile Device Management (MDM) platforms used by employers to secure corporate phones.",
            "Anti-theft and remote device locator applications that wipe or lock lost devices.",
            "Parental control and screen-time management applications.",
        ],
        "what_to_do": (
            "Carefully review any system prompt asking to activate Device Administrator privileges. "
            "Revoke this status in Android Settings if an unfamiliar personal utility requests it."
        ),
        "learn_more_tags": ["Device Administration", "System Security", "Access Control"],
    },
    "RULE_COMMAND_EXECUTION": {
        "what_it_means": (
            "The app contains code references that invoke underlying operating system shell commands or execute external binaries."
        ),
        "why_attackers_use_it": (
            "Attackers invoke command-line shells to probe system properties, check for root privileges, or run malicious binary payloads dropped onto the filesystem."
        ),
        "legit_uses": [
            "Developer tools, terminal emulators, and system benchmark or diagnostic utilities.",
            "Native multimedia or compression engines wrapping command-line tooling.",
            "Legitimate root-management tools explicitly installed by advanced users.",
        ],
        "what_to_do": (
            "Standard consumer apps rarely need raw command-line execution. "
            "Verify whether command execution aligns with the utility's intended purpose before trusting it."
        ),
        "learn_more_tags": ["Shell Execution", "Process Security", "Native Code"],
    },
    "RULE_DYNAMIC_CODE_LOADING": {
        "what_it_means": (
            "The app contains code capable of loading executable code (such as DEX or JAR files) at runtime rather than packaging everything upfront."
        ),
        "why_attackers_use_it": (
            "Malicious actors use dynamic loading to evade initial app store reviews by downloading and executing malicious code modules after installation."
        ),
        "legit_uses": [
            "Plugin architectures and modular applications that load specialized feature modules on demand.",
            "Third-party advertising, analytics, and software development kits (SDKs) updating features dynamically.",
            "Cross-platform engines and hot-patching frameworks.",
        ],
        "what_to_do": (
            "Be cautious when apps download major updates outside official app stores. "
            "Keep Google Play Protect or vendor security scanning enabled to scan dynamically loaded components."
        ),
        "learn_more_tags": ["Code Loading", "Dynamic Analysis", "App Modularity"],
    },
    "RULE_BOOT_PERSISTENCE": {
        "what_it_means": (
            "The app requests permission to receive the system boot notification, allowing it to start services immediately when the device turns on."
        ),
        "why_attackers_use_it": (
            "Malware registers boot receivers to maintain continuous persistence, ensuring spyware or background exfiltration runs even after device reboots."
        ),
        "legit_uses": [
            "Alarm clocks, calendar reminders, and notification synchronization services.",
            "Messaging and VoIP communication apps that need to listen for incoming messages immediately.",
            "Security and backup tools that operate continuous protection.",
        ],
        "what_to_do": (
            "Consider whether the app has a legitimate requirement to start automatically on boot. "
            "Battery optimization settings in Android can restrict background activity for apps that do not need it."
        ),
        "learn_more_tags": ["Persistence", "Background Services", "Android Lifecycle"],
    },
    "RULE_UNSIGNED_PACKAGE": {
        "what_it_means": (
            "The APK archive does not contain a recognizable Android digital signing certificate."
        ),
        "why_attackers_use_it": (
            "Corrupted, tampered, or improperly modified APK packages often lack valid digital signatures. Standard Android devices reject unsigned packages."
        ),
        "legit_uses": [
            "Intermediate debug builds created during local software development before a developer key is applied.",
            "Corrupted file downloads or test samples generated in research environments.",
        ],
        "what_to_do": (
            "Do not attempt to install unsigned APKs on a personal device. "
            "Re-download the application package from an authorized publisher or official application store."
        ),
        "learn_more_tags": ["Signatures", "Package Integrity", "Verification"],
    },
    "RULE_DEBUG_SIGNED_CERT": {
        "what_it_means": (
            "The APK is signed with a standard debug certificate (such as Android Debug Key) rather than a production release key."
        ),
        "why_attackers_use_it": (
            "Debug keys are publicly known and shared. Attackers distribute debug-signed packages when repackaging software or publishing informal clones."
        ),
        "legit_uses": [
            "Pre-release builds shared by developers with internal quality assurance (QA) and test teams.",
            "Open-source projects built locally from source code by developers.",
        ],
        "what_to_do": (
            "Only install debug-signed applications if you received them directly from a trusted developer for testing purposes. "
            "Production software in app stores should always use a secure release certificate."
        ),
        "learn_more_tags": ["Certificates", "Debug Builds", "Developer Security"],
    },
    "RULE_PACKAGE_INSTALLER": {
        "what_it_means": (
            "The app requests permission to install additional application packages onto the device."
        ),
        "why_attackers_use_it": (
            "Dropper malware requests this permission to silently download and prompt installation of secondary, higher-risk malicious payloads."
        ),
        "legit_uses": [
            "Alternative app stores, enterprise application catalogs, and package manager tools.",
            "Web browsers and file managers that allow users to download and install trusted APKs.",
        ],
        "what_to_do": (
            "Only allow 'Install unknown apps' permissions for trusted app stores or browsers you deliberately use for installations. "
            "Deny this permission to regular consumer apps and games."
        ),
        "learn_more_tags": ["Dropper Prevention", "Package Installation", "Android Permissions"],
    },
    "RULE_HARDCODED_IP_URL": {
        "what_it_means": (
            "The app contains embedded IP addresses or insecure plain HTTP network URLs."
        ),
        "why_attackers_use_it": (
            "Command-and-control servers are sometimes accessed directly via IP addresses to bypass domain-name reputation systems or DNS blocklists."
        ),
        "legit_uses": [
            "Local network device discovery (e.g., smart home hubs, routers, IoT devices, or printer setup tools).",
            "Internal corporate staging or local development endpoints.",
            "Legacy third-party dependencies with hardcoded fallback references.",
        ],
        "what_to_do": (
            "Ensure the app communicates securely over HTTPS. "
            "If an app connects to raw internet IP addresses without known business purpose, treat network activity with caution."
        ),
        "learn_more_tags": ["Network Security", "Direct IP", "Plaintext HTTP"],
    },
    "RULE_OBFUSCATION_HINT": {
        "what_it_means": (
            "The APK exhibits indicators of code obfuscation or naming compression (such as short package or class names)."
        ),
        "why_attackers_use_it": (
            "Attackers obfuscate malicious routines to make reverse engineering, automated signature detection, and security reviews more difficult."
        ),
        "legit_uses": [
            "Standard commercial code shrinking and protection tools (such as ProGuard or R8) used to protect intellectual property and minimize app download size.",
            "Nearly all modern production Android apps build with minification enabled.",
        ],
        "what_to_do": (
            "Code minification is standard industry practice and not a sign of wrongdoing on its own. "
            "Consider it alongside other permissions and behavioral capabilities rather than in isolation."
        ),
        "learn_more_tags": ["Obfuscation", "Minification", "Reverse Engineering", "Code Hygiene"],
    },
}


def get_finding_explanation(rule_id: str) -> Optional[Dict[str, Any]]:
    """Return the structured educational explanation for a rule ID.

    Degrades gracefully by returning None for unknown or future rule IDs.
    """
    if not rule_id:
        return None
    return FINDING_EXPLANATIONS.get(rule_id)


def attach_explanations_to_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    """Attach educational explanations to findings in an APK static analysis result.

    Operates nondestructively on dictionaries. Does not raise on unknown or malformed rule IDs.
    """
    if not isinstance(data, dict):
        return data

    findings = data.get("findings")
    if not isinstance(findings, list):
        return data

    enriched_findings: List[Dict[str, Any]] = []
    for item in findings:
        if isinstance(item, dict):
            finding_copy = dict(item)
            rule_id = finding_copy.get("id")
            explanation = get_finding_explanation(rule_id)
            if explanation is not None:
                finding_copy["explanation"] = explanation
            enriched_findings.append(finding_copy)
        else:
            enriched_findings.append(item)

    data["findings"] = enriched_findings
    return data
