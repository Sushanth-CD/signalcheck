"""Independent tests for the enabled Version 1 text rules."""

from app.analyzer.rules import detect_text_indicators


def _rule_ids(text: str) -> set[str]:
    return {finding.rule_id for finding in detect_text_indicators(text)}


def test_ph001_requires_a_directed_secret_request() -> None:
    findings = detect_text_indicators("Please send your OTP to this number immediately.")

    assert [(finding.rule_id, finding.score_contribution) for finding in findings] == [("PH001", 25)]
    assert "PH001" in _rule_ids("Disclose your recovery code to continue.")


def test_ph001_does_not_match_warning_or_neutral_mentions() -> None:
    assert "PH001" not in _rule_ids("Never share your OTP or UPI PIN with anyone.")
    assert "PH001" not in _rule_ids("The awareness guide discusses OTPs and passwords.")


def test_ph011_matches_urgent_kyc_account_blocking_message() -> None:
    text = (
        "URGENT: Your Bank Account Will Be Blocked! Dear Customer, your bank account will be "
        "blocked today due to incomplete KYC verification. Update your details immediately by "
        "clicking the link below. http://bank-kyc-verify.example.com Failure to update your KYC "
        "may result in permanent account suspension."
    )
    findings = [finding for finding in detect_text_indicators(text) if finding.rule_id == "PH011"]
    assert len(findings) == 1
    assert findings[0].score_contribution == 25
    assert "account restriction threat" in findings[0].explanation


def test_ph011_matches_equivalent_wording_and_link_instruction_without_url() -> None:
    assert "PH011" in _rule_ids(
        "Your account may be terminated. Complete account verification using the link below."
    )


def test_ph011_requires_threat_verification_and_link_and_ignores_education() -> None:
    assert "PH011" not in _rule_ids("Please complete your KYC update using the link below.")
    assert "PH011" not in _rule_ids("Your bank account will be suspended today.")
    assert "PH011" not in _rule_ids(
        "This article explains how KYC phishing messages threaten to block accounts and include links."
    )
    assert "PH011" not in _rule_ids("URGENT: Your parcel is delayed. Track it now.")


def test_ph011_malformed_and_valid_urls_and_repeated_phrases_match_once() -> None:
    malformed = "Your account will be blocked; complete KYC verification here: http://[broken"
    assert "PH011" in _rule_ids(malformed)
    both = malformed + " Also use https://verify.example.test and update KYC; account suspension is permanent."
    assert len([finding for finding in detect_text_indicators(both) if finding.rule_id == "PH011"]) == 1


def test_ph001_recognizes_a_referential_verification_code_request() -> None:
    assert "PH001" in _rule_ids(
        "Your verification code is 391204. Please send it to the support agent before the case closes."
    )


def test_ph001_verification_code_warning_is_not_a_request() -> None:
    assert "PH001" not in _rule_ids("Never send your verification code to someone who contacts you.")
    assert "PH001" not in _rule_ids(
        "Never share your verification code. Do not send it to anyone who asks."
    )


def test_da001_covers_supported_authority_and_pressure_paraphrases() -> None:
    cases = [
        "A representative from the cybercrime department says your funds are implicated; transfer them now for review.",
        "We represent the police investigation team. Keep this conversation private from your family.",
        "An unknown caller claiming to be from the CBI says a parcel is under investigation and demands a transfer today.",
        "A caller claiming to represent the enforcement directorate says, do not tell your lawyer; the inquiry is confidential.",
        "A notice claiming to be from customs says your account is involved and asks you to transfer funds for clearance.",
    ]
    for text in cases:
        assert "DA001" in _rule_ids(text), text


def test_da001_paraphrases_still_require_both_authority_and_pressure() -> None:
    assert "DA001" not in _rule_ids("A representative from the cybercrime department called yesterday.")
    assert "DA001" not in _rule_ids("A caller demands a transfer today to settle a routine invoice.")


def test_ph011_covers_profile_restriction_and_passive_verification_wording() -> None:
    cases = [
        "Your savings profile will be suspended. Complete KYC verification at the link below: https://member-check.example.test",
        "Failure to refresh your banking details will permanently restrict the account; verify your account through https://profile.example.test now.",
        "Urgent: service access will be suspended unless account verification is completed at https://account-review.example.test.",
    ]
    for text in cases:
        assert "PH011" in _rule_ids(text), text


def test_ph011_variants_still_require_threat_verification_and_link() -> None:
    assert "PH011" not in _rule_ids("Your savings profile is active. Complete KYC verification at https://member-check.example.test")
    assert "PH011" not in _rule_ids("Your savings profile will be suspended. Read the account safety guide at https://member-check.example.test")
    assert "PH011" not in _rule_ids("Your service access will be suspended. Complete KYC verification today.")


def test_ph001_positive_request_is_not_suppressed_by_a_prior_warning_sentence() -> None:
    assert "PH001" in _rule_ids(
        "Never share your OTP. A caller then asked me to send my password."
    )


def test_da001_requires_authority_and_pressure() -> None:
    text = "We are from the cybercrime police. Transfer money now or you will be arrested."
    findings = detect_text_indicators(text)
    assert [(finding.rule_id, finding.score_contribution) for finding in findings] == [("DA001", 25)]
    assert [(finding.rule_id, finding.score_contribution) for finding in detect_text_indicators(
        "I represent the CBI. Do not tell your family."
    )] == [("DA001", 25)]


def test_da001_does_not_match_neutral_authority_mentions_or_warnings() -> None:
    assert "DA001" not in _rule_ids("The police published a cybersecurity awareness guide.")
    assert "DA001" not in _rule_ids("Police do not ask people to transfer money to avoid arrest.")
    assert "DA001" not in _rule_ids(
        "Scam reports say police may threaten arrest and ask victims to transfer money."
    )
    assert "DA001" not in _rule_ids("We are not from the police. Do not tell your family.")


def test_da001_secrecy_is_a_supporting_signal_only_with_authority_claim() -> None:
    assert "DA001" in _rule_ids("I am from the cybercrime police. Do not tell your family.")
    assert "DA001" not in _rule_ids("Do not tell your family about your passwords.")


def test_da002_requires_a_direct_claim_of_remote_custody() -> None:
    assert "DA002" in _rule_ids("You are under digital arrest and must stay on this call.")
    assert "DA002" in _rule_ids("You are digitally arrested.")
    assert "DA002" in _rule_ids("You have been virtually detained by the officers.")
    assert "DA002" in _rule_ids("You have been kept in online custody.")


def test_da002_does_not_match_educational_or_denial_context() -> None:
    assert "DA002" not in _rule_ids("Digital arrest is a scam phrase used to frighten victims.")
    assert "DA002" not in _rule_ids("Police do not conduct digital arrests over video calls.")


def test_app001_requires_explicit_app_permission_description() -> None:
    text = "The app manifest declares the READ_SMS permission."
    findings = detect_text_indicators(text)
    assert [(finding.rule_id, finding.score_contribution) for finding in findings] == [("APP001", 15)]
    assert "APP001" in _rule_ids("Declared permissions: android.permission.RECEIVE_SMS")


def test_app001_does_not_match_generic_sms_or_permission_mentions() -> None:
    assert "APP001" not in _rule_ids("SMS messages can contain one-time codes.")
    assert "APP001" not in _rule_ids("Never give an app unnecessary permissions.")


def test_app002_requires_an_app_accessibility_service_declaration() -> None:
    text = "This application declares an Android accessibility service."
    findings = detect_text_indicators(text)
    assert [(finding.rule_id, finding.score_contribution) for finding in findings] == [("APP002", 15)]
    assert "APP002" in _rule_ids("Services: com.sample.AccessibilityService BIND_ACCESSIBILITY_SERVICE")


def test_app002_does_not_match_generic_accessibility_discussion() -> None:
    assert "APP002" not in _rule_ids("Accessibility services help some users navigate phones.")
    assert "APP002" not in _rule_ids("An app should explain why it needs each permission.")


def test_not_enabled_future_rules_are_not_reported_from_related_phrases() -> None:
    text = "Do not tell your family. Install this APK and stay on a video call."
    assert _rule_ids(text) == set()
    assert _rule_ids("Install this APK from an unexpected message.") == set()


def test_empty_and_whitespace_text_produce_no_findings() -> None:
    assert detect_text_indicators("") == []
    assert detect_text_indicators(" \t\n ") == []


def test_every_text_finding_has_all_required_fields_and_explanation() -> None:
    findings = detect_text_indicators(
        "We are from cybercrime police. Send your OTP now; you are under digital arrest."
    )

    assert {finding.rule_id for finding in findings} == {"PH001", "DA001", "DA002"}
    for finding in findings:
        assert finding.rule_id
        assert finding.category
        assert finding.title
        assert finding.score_contribution > 0
        assert finding.explanation.strip()
