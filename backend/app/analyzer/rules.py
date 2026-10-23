"""Text-based deterministic detection rules enabled for Version 1."""

import re

from app.schemas import DetectedIndicator


_SECRET_TERMS = r"(?:one[- ]time\s+(?:password|passcode)|otp|passcode|password|upi\s+pin|cvv|security\s+code|verification\s+code|recovery\s+code)"
_SECRET_REQUEST = re.compile(
    rf"\b(?:send|share|provide|disclose|enter|submit|tell|read(?:\s+aloud)?|type|give|reply\s+with)\b"
    rf"[^.!?\n]{{0,55}}\b{_SECRET_TERMS}\b",
    re.IGNORECASE,
)
_REFERENTIAL_SECRET_REQUEST = re.compile(
    rf"\b{_SECRET_TERMS}\b[^.!?\n]{{0,70}}[.!?]?\s*"
    r"(?P<action>\b(?:please\s+)?(?:send|share|provide|disclose|enter|submit|tell|type|give|reply\s+with)\s+(?:it|this|that)\b)",
    re.IGNORECASE,
)
_NEGATION_BEFORE_ACTION = re.compile(
    r"\b(?:never|do\s+not|don't|dont|must\s+not|should\s+not|shouldn't|avoid|will\s+never)\b"
    r"[^.!?\n]{0,55}$",
    re.IGNORECASE,
)

_ACCOUNT_THREAT = re.compile(
    r"\b(?:account|bank\s+account|banking\s+service|savings\s+profile|service\s+access)\b[^.!?\n]{0,70}"
    r"\b(?:will\s+be\s+)?(?:blocked|suspended|terminated|closed|restrict(?:ed|s|ing)?)\b|"
    r"\b(?:blocked|suspended|terminated|closed|restrict(?:ed|s|ing)?)\b[^.!?\n]{0,70}"
    r"\b(?:account|bank\s+account|banking\s+service|savings\s+profile|service\s+access)\b|"
    r"\bpermanent(?:ly)?\s+(?:account\s+)?(?:suspension|restriction|termination)\b",
    re.IGNORECASE,
)
_VERIFICATION_REQUEST = re.compile(
    r"\b(?:complete|update|submit|finish)\s+(?:your\s+)?(?:kyc|know\s+your\s+customer|"
    r"account\s+verification|verification\s+details|bank(?:ing)?\s+details)\b|"
    r"\b(?:verify|confirm)\s+(?:your\s+)?(?:bank\s+)?account\b|"
    r"\b(?:kyc|account\s+verification)\s+(?:is\s+)?(?:incomplete|pending|required|complete|completed)\b",
    re.IGNORECASE,
)
_LINK_INSTRUCTION = re.compile(
    r"\b(?:click|tap|open|use|follow)\s+(?:the\s+)?(?:link|url)(?:\s+below|\s+above)?\b|"
    r"\b(?:via|through|using)\s+(?:the\s+)?(?:link|url)\b",
    re.IGNORECASE,
)
_URGENCY_CONTEXT = re.compile(
    r"\b(?:urgent|immediately|today|right\s+now|act\s+now|asap|within\s+\d+\s+"
    r"(?:minutes?|hours?))\b",
    re.IGNORECASE,
)

_AUTHORITY_NAME = (
    r"(?:cybercrime\s+(?:police|department)|cyber\s+crime\s+department|police|"
    r"law\s+enforcement|government\s+(?:official|department|agency)|cbi|"
    r"enforcement\s+directorate|ed|customs|immigration|court|investigating\s+agency)"
)
_AUTHORITY_CLAIM = re.compile(
    rf"\b(?:(?:we|i|this|caller|sender)\s+(?:are|am|is|['’]m)\s+"
    rf"(?:(?:calling|speaking)\s+)?(?:(?:from|with|of)\s+)?(?:the\s+|an?\s+)?"
    rf"(?:officer\s+of\s+)?{_AUTHORITY_NAME}|"
    rf"(?:we|i)\s+represent(?:ing)?\s+(?:the\s+)?{_AUTHORITY_NAME}|"
    rf"(?:a\s+|the\s+)?representative\s+(?:from|of)\s+(?:the\s+)?{_AUTHORITY_NAME}|"
    rf"(?:a\s+|the\s+)?(?:caller|sender|notice|message)\s+claiming\s+(?:to\s+)?"
    rf"(?:be\s+(?:from|with)\s+|to\s+represent\s+(?:the\s+)?)?{_AUTHORITY_NAME}|"
    rf"(?:calling|speaking)\s+from\s+(?:the\s+)?{_AUTHORITY_NAME})\b",
    re.IGNORECASE,
)
_PRESSURE = re.compile(
    r"\b(?:(?:transfer|send|move)\s+(?:(?:all|your|the)\s+)?(?:money|funds|balance)|"
    r"(?:ask(?:s|ed)?|instruct(?:s|ed)?)\s+(?:you\s+to\s+)?(?:transfer|send|move)\s+"
    r"(?:(?:all|your|the)\s+)?(?:money|funds|balance)|"
    r"demand(?:s|ed)?\s+(?:you\s+to\s+)?(?:make\s+)?a\s+transfer|"
    r"transfer\s+(?:them|it)\s+(?:now|immediately|today)|"
    r"pay\s+(?:now|immediately)|(?:you\s+will\s+be\s+arrested|we\s+will\s+arrest\s+you|"
    r"arrest\s+you\s+immediately|immediate\s+arrest\s+if\s+you)|"
    r"(?:act|respond|comply)\s+(?:now|immediately|within\s+\d+\s+minutes?)|"
    r"(?:send|share|provide|enter|tell)\s+(?:your\s+)?(?:otp|password|upi\s+pin|passcode)|"
    r"stay\s+on\s+(?:the\s+)?(?:video|phone)\s+call|"
    r"do\s+not\s+(?:tell|contact)|keep\s+(?:this|the\s+call)\s+secret|"
    r"keep\s+(?:this\s+)?(?:conversation|matter|interaction)\s+(?:private|secret)\s+from)\b",
    re.IGNORECASE,
)
_DIGITAL_ARREST_ASSERTION = re.compile(
    r"\b(?:you\s+(?:are|have\s+been|remain)\s+(?:(?:put|placed)\s+)?"
    r"(?:(?:under|in)\s+)?(?:a\s+)?(?:digital\s+arrest|digital\s+house\s+arrest|"
    r"digitally\s+arrested|virtual(?:ly)?\s+detain(?:ed)?|online\s+custody)|"
    r"you\s+(?:are|have\s+been)\s+(?:kept|held)\s+(?:in|under)\s+"
    r"(?:remote\s+)?(?:online|virtual)\s+custody|(?:digital\s+arrest|digital\s+house\s+arrest|"
    r"virtual\s+custody|online\s+custody)\s+(?:has\s+been\s+imposed\s+on\s+you|"
    r"order\s+against\s+you))\b",
    re.IGNORECASE,
)
_DIGITAL_ARREST_NEGATION = re.compile(
    r"\b(?:not|never|no\s+such|does\s+not\s+exist|isn't|is\s+not)\b"
    r"[^.!?\n]{0,45}$",
    re.IGNORECASE,
)
_DIGITAL_ARREST_NEGATIVE_TERM = re.compile(
    r"\b(?:digital\s+arrest|digital\s+house\s+arrest|"
    r"virtual\s+custody|online\s+custody|virtually\s+detain)\b",
    re.IGNORECASE,
)

_APP_CONTEXT = re.compile(
    r"\b(?:app|application|apk|manifest|permission|permissions|service|services)\b", re.IGNORECASE
)
_SMS_PERMISSION = re.compile(
    r"\b(?:READ_SMS|RECEIVE_SMS|SEND_SMS|read_sms|receive_sms|send_sms)\b",
    re.IGNORECASE,
)
_SMS_PERMISSION_DESCRIPTION = re.compile(
    r"(?:\b(?:app|application|apk|manifest)\b[^.!?\n]{0,90}"
    r"\b(?:requests?|declares?|includes?|contains?)\b[^.!?\n]{0,55}"
    r"\b(?:sms\s+(?:access|permission)|READ_SMS|RECEIVE_SMS|SEND_SMS)\b|"
    r"\b(?:declared\s+)?permissions?\s*[:=]\s*[^!?\n]{0,100}"
    r"\b(?:READ_SMS|RECEIVE_SMS|SEND_SMS)\b)",
    re.IGNORECASE,
)
_ACCESSIBILITY_SERVICE = re.compile(
    r"\b(?:accessibility\s+service|BIND_ACCESSIBILITY_SERVICE)\b", re.IGNORECASE
)
_APP_DECLARATION = re.compile(
    r"\b(?:app|application|apk|manifest)\b[^.!?\n]{0,90}"
    r"\b(?:declares?|includes?|contains?|requests?|has)\b[^.!?\n]{0,60}"
    r"\b(?:an?\s+)?(?:android\s+)?accessibility\s+service\b",
    re.IGNORECASE,
)
_ACCESSIBILITY_METADATA = re.compile(
    r"\b(?:service|services|service_type|accessibility_service)\s*[:=]"
    r"[^!?\n]{0,100}\b(?:BIND_ACCESSIBILITY_SERVICE|accessibility\s+service)\b",
    re.IGNORECASE,
)


def _finding(
    rule_id: str,
    category: str,
    title: str,
    score: int,
    explanation: str,
) -> DetectedIndicator:
    return DetectedIndicator(
        rule_id=rule_id,
        category=category,
        title=title,
        score_contribution=score,
        explanation=explanation,
    )


def _sentence_start(text: str, index: int) -> int:
    """Return the start of the current sentence-like segment."""

    return max(text.rfind(mark, 0, index) for mark in (".", "!", "?", "\n")) + 1


def _secret_request_is_negated(text: str, match: re.Match[str]) -> bool:
    prefix = text[_sentence_start(text, match.start()) : match.start()]
    return bool(_NEGATION_BEFORE_ACTION.search(prefix))


def _referential_secret_request_is_negated(text: str, match: re.Match[str]) -> bool:
    action_start = match.start("action")
    prefix = text[_sentence_start(text, action_start) : action_start]
    return bool(_NEGATION_BEFORE_ACTION.search(prefix))


def _has_unnegated_authority_claim(text: str) -> bool:
    return bool(_AUTHORITY_CLAIM.search(text) and _PRESSURE.search(text))


def _has_unnegated_digital_arrest_claim(text: str) -> bool:
    for match in _DIGITAL_ARREST_ASSERTION.finditer(text):
        start = _sentence_start(text, match.start())
        prefix = text[start : match.start()]
        if not (_DIGITAL_ARREST_NEGATION.search(prefix) and _DIGITAL_ARREST_NEGATIVE_TERM.search(prefix)):
            return True
    return False


def detect_text_indicators(content: str) -> list[DetectedIndicator]:
    """Return at most one finding per enabled text rule supported by content.

    App permission rules are based on explicit user-supplied metadata descriptions;
    ordinary mentions of SMS or accessibility do not establish an app permission.
    """

    if not isinstance(content, str) or not content.strip():
        return []

    text = content.strip()
    findings: list[DetectedIndicator] = []

    has_message_link = bool(re.search(r"(?i)\bhttps?://|\bwww\.", text) or _LINK_INSTRUCTION.search(text))
    if _ACCOUNT_THREAT.search(text) and _VERIFICATION_REQUEST.search(text) and has_message_link:
        urgency_note = " Urgency adds context but is not required for this match." if _URGENCY_CONTEXT.search(text) else ""
        findings.append(
            _finding(
                "PH011",
                "phishing",
                "Urgent KYC or account-blocking link",
                25,
                "The message combines an account restriction threat, a KYC or account-verification request, and a link or instruction to use one. Verify through the bank's official app or a contact method obtained independently."
                + urgency_note,
            )
        )

    secret_requested = any(
        not _secret_request_is_negated(text, match) for match in _SECRET_REQUEST.finditer(text)
    ) or any(
        not _referential_secret_request_is_negated(text, match)
        for match in _REFERENTIAL_SECRET_REQUEST.finditer(text)
    )
    if secret_requested:
        findings.append(
            _finding(
                "PH001",
                "phishing",
                "Requests a secret or authentication code",
                25,
                "The message asks you to provide an authentication secret. Never share an OTP, password, CVV, or UPI PIN with another person.",
            )
        )

    if _has_unnegated_authority_claim(text):
        findings.append(
            _finding(
                "DA001",
                "digital_arrest",
                "Claims law-enforcement or government authority",
                25,
                "Scammers may impersonate officials to make a demand seem compulsory. Verify independently and do not rely on caller ID.",
            )
        )

    if _has_unnegated_digital_arrest_claim(text):
        findings.append(
            _finding(
                "DA002",
                "digital_arrest",
                "Claims digital arrest or equivalent virtual custody",
                25,
                "A purported remote-arrest claim is a strong warning sign. Stop the interaction and contact the relevant authority through an independently verified channel.",
            )
        )

    if (
        _APP_CONTEXT.search(text)
        and _SMS_PERMISSION.search(text)
        and _SMS_PERMISSION_DESCRIPTION.search(text)
    ):
        findings.append(
            _finding(
                "APP001",
                "malicious_application",
                "Requests SMS access or sending capability",
                15,
                "SMS access can expose verification messages or allow messages to be sent. Check whether this capability is necessary for the app's stated purpose.",
            )
        )

    accessibility_metadata = bool(_APP_DECLARATION.search(text) or _ACCESSIBILITY_METADATA.search(text))
    if _APP_CONTEXT.search(text) and _ACCESSIBILITY_SERVICE.search(text) and accessibility_metadata:
        findings.append(
            _finding(
                "APP002",
                "malicious_application",
                "Declares an accessibility service",
                15,
                "Accessibility services can be legitimate assistive features, but a malicious app may abuse them to observe or interact with other apps. Verify the developer and purpose.",
            )
        )

    return findings
