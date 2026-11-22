# Version 1 Analysis Contract

**Project:** Cyber Security Awareness Platform for Phishing, Digital Arrest Scams, and Malicious Applications  
**Version:** 1.0  
**Status:** Initial integration contract; provisional pending implementation and evaluation

> **Historical document:** This contract describes the retired rule-based `POST /api/analyze` implementation. The active application now exposes the ML-only APIs documented in [ml-only-architecture.md](ml-only-architecture.md). The rule definitions below are not active runtime behavior.

This contract defines the first text-analysis API and its user-facing risk assessment. Rule definitions, match conditions, and weights remain governed by [detection_rules.md](../detection_rules.md). Problem scope and user context remain described in [problem_research.md](../problem_research.md). This document does not establish detection effectiveness or accuracy.

## 1. Scope and enabled rules

The endpoint accepts a message, URL, or mixed text containing URLs. Version 1 enables these eight rules:

| Canonical rule ID | Contribution | Definition |
|---|---|---:|---|
| `PH001` | 25 | Requests a secret or authentication code |
| `PH011` | 25 | Urgent KYC or account-blocking link; requires an account threat, KYC/account-verification request, and URL or explicit link instruction |
| `DA001` | 25 | Claims law-enforcement or government authority, with another demand or pressure signal |
| `DA002` | 25 | Claims digital arrest or equivalent virtual custody |
| `URL001` | 10 | Uses a known URL-shortening domain |
| `URL002` | 15 | Uses an IP address instead of a recognisable domain |
| `APP001` | 15 | Requests SMS access or sending capability |
| `APP002` | 15 | Declares an accessibility service |

The IDs in the table are the canonical identifiers used by `detection_rules.md`; no aliases are introduced. The current endpoint has no structured APK metadata input, so the two app-related rules can match only if their conditions are represented in submitted text; they do not verify an APK or manifest.

All other rules in `detection_rules.md` are future extensions for this endpoint, including `PH002`–`PH010`, `DA003`–`DA009`, `URL003`–`URL009`, and `APP003`–`APP010` and `APP101`–`APP104`. They must not contribute in this V1 contract. App rules requiring APK metadata are out of scope for this text-only request.

## 2. Endpoint and request

`POST /api/analyze` accepts `Content-Type: application/json` and exactly one field:

```json
{
  "content": "message, URL, or text containing URLs"
}
```

`content` must be a JSON string. Reject missing or additional fields, non-string values, invalid JSON, and strings longer than **10,000 characters**. Count Unicode characters consistently at the API boundary and document that convention in implementation. Whitespace-only content is empty input and must be rejected after trimming for the emptiness check. Preserve the original text for analysis (apart from safe internal normalisation); do not silently turn empty input into a clean result.

Extract candidate URLs from submitted text, then attempt to parse each candidate locally with a standards-compliant URL parser. Do not make network requests during extraction or parsing. A URL parsing failure contributes zero URL-specific risk points and is not, by itself, evidence of malicious intent. Continue analyzing other valid text and successfully parsed URLs in the same request; a malformed candidate must not prevent valid content from being analyzed. Handle malformed candidates safely without crashing the API. If no URL is present, analyze the submitted text normally and return no URL-specific indicators.

## 3. Success response

Return HTTP `200` with JSON of this shape:

```json
{
  "risk_score": 50,
  "risk_level": "high",
  "summary": "The text contains several warning signs, including a request for an authentication code and a claim of digital arrest.",
  "detected_indicators": [
    {
      "rule_id": "PH001",
      "category": "phishing",
      "title": "Requests a secret or authentication code",
      "score_contribution": 25,
      "explanation": "The message asks you to provide an authentication secret. Do not share an OTP, password, CVV, or UPI PIN."
    },
    {
      "rule_id": "DA002",
      "category": "digital_arrest",
      "title": "Claims digital arrest or equivalent virtual custody",
      "score_contribution": 25,
      "explanation": "A demand to remain in remote custody is a strong scam warning sign. Stop the interaction and verify through an independently sourced official channel."
    }
  ],
  "recommendations": [
    "Do not share authentication secrets or transfer money in response to this message.",
    "Verify any claim using contact details obtained independently."
  ],
  "disclaimer": "This is a heuristic text assessment, not a fraud determination. A low score does not prove that a message or URL is safe."
}
```

`risk_score` is an integer from 0 through 100. `risk_level` is exactly `low`, `medium`, or `high`. `summary` is plain language. `detected_indicators` contains one entry per matched enabled rule, with the fields shown above; `score_contribution` is the rule's configured contribution, not an independently estimated probability. `recommendations` is a list of actionable safety steps tied to the result. `disclaimer` states the assessment's limitations on every successful response. When no enabled rule matches, return score 0 and `low`, but do not describe the input as verified safe.

## 4. Validation errors

Errors use a structured JSON response with `error` and `message`; field errors may additionally include `details`. Example statuses and bodies:

| Condition | HTTP | Example |
|---|---:|---|
| Missing `content` | 422 | `{"error":"validation_error","message":"content is required","details":{"field":"content"}}` |
| Wrong type | 422 | `{"error":"validation_error","message":"content must be a string","details":{"field":"content"}}` |
| Empty or whitespace-only | 422 | `{"error":"empty_input","message":"Provide a message, URL, or text to analyze."}` |
| More than 10,000 characters | 413 | `{"error":"input_too_long","message":"content must not exceed 10000 characters."}` |
| Malformed JSON body | 400 | `{"error":"invalid_json","message":"Request body must be valid JSON."}` |
| Unexpected request fields | 422 | `{"error":"validation_error","message":"Only the content field is accepted."}` |

Do not include the submitted content in error responses. FastAPI validation behavior should be normalized to this public contract rather than leaking stack traces or request bodies.

## 5. Risk calculation

Risk bands are provisional pending evaluation:

- **0–19:** `low`
- **20–49:** `medium`
- **50–100:** `high`

Use the contributions in the table in Section 1, which are copied from the corresponding rules in `detection_rules.md`. Each enabled rule contributes at most once per request. Sum contributions from matched rules across categories and cap the total at 100. Multiple matching phrases for the same rule do not repeatedly increase its contribution. If several URLs are present, apply each URL rule at most once across the request, consistent with the duplicate-match protection in `detection_rules.md`.

These scores are deterministic heuristic points, **not fraud probabilities**, calibrated likelihoods, or evidence that a message is fraudulent. Bands and weights require evaluation against representative positive and negative examples; no accuracy claim is made here.

### Potential overlap to test

`PH001` and `DA001` can both reflect a coercive interaction when an authority impersonation also requests an OTP or other secret. They represent different signals, but may double-count related evidence. URL warnings can also coexist with a text rule triggered by the same message, and `DA002` may overlap with `DA001` when an explicit digital-arrest claim accompanies authority impersonation. Preserve the current contributions for now; measure these overlaps and false-positive/false-negative effects in evaluation before changing weights or definitions.

## 6. Security and privacy

The initial API must:

- Analyze submitted text and URL strings locally; do not use external reputation lookups in V1.
- Never automatically open, navigate to, resolve through a visit, or fetch submitted URLs. Parsing a URL string locally is allowed.
- Never download or execute APK files. This endpoint accepts no APK upload.
- Avoid database persistence for submitted content.
- Avoid logging raw submitted messages, URL strings, credentials, tokens, or excerpts. Operational logs may contain request IDs, status, timing, and safe error codes.
- Validate request shape, type, size, and emptiness, and handle malformed URLs without unsafe parsing or crashes.
- Never state or imply that a low-risk result proves safety.

## 7. React and FastAPI integration

The React client sends the user's text as JSON to `POST /api/analyze`, with `Content-Type: application/json` and body `{ "content": value }`. It should disable duplicate submissions while a request is pending, then render the returned score, risk label, summary, indicator list (including rule ID and explanation), recommendations, and disclaimer as structured data. Render untrusted text as text, not injected HTML.

For empty or whitespace-only input, the client should show an inline prompt and may avoid making the request; the API must still return the defined `empty_input` validation error if called. For validation errors, show the server's safe message and allow correction. For network errors, non-JSON responses, timeouts, or HTTP 5xx failures, show a generic retry-later message; do not fabricate a score or retain the submitted content in logs. Keep the form content available locally for a user-initiated retry only as needed by the interface.

## 8. Testing requirements

Create acceptance and unit tests before release for:

1. A positive example for each enabled rule: `PH001`, `PH011`, `DA001`, `DA002`, `APP001`, `APP002`, `URL001`, and `URL002`, asserting the canonical matched ID and exact contribution.
2. A false-positive example for each enabled rule, including neutral educational text and negative-context examples where applicable; assert the rule does not match by keyword alone.
3. Empty and whitespace-only input; missing `content`; wrong JSON type; invalid JSON; additional fields; exactly 10,000 and over 10,000 characters.
4. A malformed URL inside an otherwise suspicious message: score applicable text rules, give the malformed candidate zero URL-specific points, and do not fail the request.
5. A malformed URL inside an otherwise benign message: return no URL-specific points, do not treat parse failure as malicious intent, and do not fail the request.
6. A message containing one malformed URL and one valid suspicious URL: ignore the malformed candidate for URL scoring, apply applicable rules to the valid URL and text, and return their contributions once each.
7. A message with no URL: analyze text rules normally and return no URL-specific indicators or points.
8. Deceptive subdomains, including a trusted-looking prefix followed by an unrelated registrable host; enforce exact host boundaries.
9. IP-address URLs (IPv4 and IPv6 where supported) and unusual ports; confirm URL002 matches the former and unusual ports do not add points because URL006 is not enabled.
10. One input triggering multiple distinct enabled rules; assert each rule contributes once and the response lists all matches.
11. Score lower/upper bounds, band boundaries (19/20 and 49/50), cap at 100, and repeated phrase/URL matches not increasing the same rule contribution.
12. Inputs containing both ordinary text and one or more URLs; ensure text and URL parsing are both applied without fetching URLs.

Use the concrete positive and negative examples in `detection_rules.md` where applicable. Add explicit fixtures for app permission phrases in text only, and document that this does not constitute APK inspection.

## 9. Capabilities and limitations

V1 can identify only configured phrase patterns in submitted text and the enabled URL-string signals: known shortener hostname and IP-literal hostname. It may identify app-related phrases or user-described permission metadata as text, but cannot verify installed applications or app permissions.

The following require separate future capabilities and are not part of this contract:

- **Email-header inspection:** sender authentication, routing, reply-to mismatches, SPF/DKIM/DMARC, and attachment metadata.
- **Image processing:** QR-code extraction, screenshots, logos, forged documents, or visual evidence.
- **Speech transcription:** scam content spoken during calls or voice messages.
- **Threat-intelligence integration:** current domain/IP reputation, newly registered domains, live blocklists, and destination analysis; any future lookup needs explicit privacy and network controls.
- **APK binary analysis:** safe static parsing of the manifest, permissions, signing details, code, or behavior. Dynamic execution is explicitly excluded from this API.

Text heuristics can miss novel wording, context, and encoded or obfuscated content; they can also flag benign content. No rule match means only that these enabled checks did not match. Thresholds and overlaps remain provisional until tested; this contract neither proves effectiveness nor supplies experimental accuracy results.
