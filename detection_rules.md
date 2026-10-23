# Detection Rules — Version 1

**Project:** Cyber Security Awareness Platform  
**Version:** 1.0  
**Status:** Baseline specification for the first working release  
**Detection approach:** Explainable, deterministic rules; no machine-learning model required

## 1. Purpose

This document defines the Version 1 rules used to flag potential:

1. **Phishing and online fraud** in messages and URLs.
2. **Digital-arrest scams** and related law-enforcement impersonation.
3. **Potentially risky Android applications** using user-provided app metadata and permissions.

Every positive result must show the user which rule matched, the evidence that triggered it, why that evidence is risky, and what the user should do next.

> **Important:** A score is a rule-based risk indicator, not a probability that something is malicious. A high score does not prove criminal activity, and a low score does not prove that content or an application is safe.

## 2. Version 1 scope

### Supported inputs

- **Message analysis:** text copied from an SMS, email, chat, social-media message, or other communication.
- **URL analysis:** one or more URLs supplied directly or extracted from a message.
- **Android app analysis:** a package name, declared permissions, selected manifest metadata, and optional information about where the APK was obtained. Inputs may be manually supplied or extracted by a safe static metadata parser.

### Out of scope for Version 1

- Executing, installing, or dynamically testing an APK.
- Reverse engineering application code or proving that an APK contains malware.
- Opening submitted URLs, following redirects, downloading page content, or interacting with a suspicious website.
- Live domain reputation, antivirus-vendor, threat-intelligence, or law-enforcement database lookups.
- Making a definitive legal determination or guaranteeing that a message, URL, or app is safe.

**Do not open URLs or execute APKs as part of these rules.** Version 1 can analyse the supplied text and static metadata without contacting suspicious destinations or running untrusted code.

## 3. Scoring model

### 3.1 Rule weights

Each rule has a fixed contribution from 5 to 30 points. When a rule matches, add its contribution to the single submission score. Apply each unique rule **at most once per submission**, even if several phrases or URLs trigger it. The configured contributions in the rule tables are authoritative; DA001's current contribution is provisionally calibrated to 25 points.

```text
overall_score = min(100, sum(contribution of each distinct matched rule))
```

Rule categories group findings for explanation only; they do not have separate score caps or override the submission score. Sum contributions across all triggered enabled rules, then cap the submission score at 100. A repeated match of one rule does not add points again.

The score is a prioritisation aid. It is **not** a calibrated probability, a malware verdict, or a measure of financial loss.

### 3.2 Risk bands

| Score | Label | User-facing interpretation |
|---:|---|---|
| 0–19 | **Low** | Few or no configured warning signs were found. This does not establish that the item is safe. |
| 20–49 | **Medium** | Warning signs deserve verification. |
| 50–100 | **High** | Serious or multiple warning signs are present. Do not follow instructions until verified independently. |

Use the exact numeric score alongside the label. Do not describe these bands as measured probabilities.

### 3.3 Evidence and explanations

For every matched rule, return:

- `rule_id`
- `title`
- `category`
- `weight`
- `evidence`: the short phrase, URL component, permission, or metadata field that caused the match
- `reason`: a plain-language explanation of why the signal can be risky
- `recommendation`: a practical next step

Keep evidence excerpts short and avoid unnecessarily repeating a user's full message, phone number, account number, or other sensitive data.

## 4. Rule matching principles

1. **Deterministic matching:** use documented phrase dictionaries, regular expressions, parsed URL fields, exact Android permission names, and explicit combinations of those signals. The same input and rule configuration must produce the same result.
2. **Evidence required:** do not award points merely because the topic is mentioned. The rule condition must be satisfied and the matched evidence must be recorded.
3. **Context matters:** a sentence warning people *not* to share OTPs must not be treated as an OTP-harvesting request. Apply the negative-context protections in Section 8.
4. **No single-signal verdicts:** a rule match means “warning sign detected,” not “confirmed scam/malware.”
5. **No hidden deductions:** Version 1 only adds the documented rule weights; it does not subtract points or silently change scores.
6. **Configurable lists:** maintain phrase variants, URL-shortener domains, and verified brand-domain mappings in configuration rather than scattering them throughout the application code.
7. **Safe defaults:** if an input cannot be parsed, report that limitation instead of treating the failure as proof of maliciousness.

---

## 5. Phishing and suspicious-message rules

These rules apply to message text. URL rules in Section 6 contribute to the same submission score when URLs are supplied or extracted from that message.

| Rule ID | Weight | Rule title | Match condition | Explanation shown to the user |
|---|---:|---|---|---|
| `PH001` | 25 | Requests a secret or authentication code | The sender directs the recipient to disclose, send, read aloud, or enter a password, OTP, UPI PIN, card CVV, recovery code, or similar authentication secret. A mere mention of these terms does not match. | Legitimate organisations should not ask you to disclose authentication secrets in an unsolicited message or call. Never share an OTP, password, CVV, or UPI PIN with another person. |
| `PH002` | 10 | Threatens account or service suspension | The message says an account, SIM, bank service, wallet, delivery, or similar service will be blocked, suspended, closed, or restricted, and urges the recipient to act. | Scammers often use threats of service interruption to make people act before checking the claim. Verify through the organisation's official app or website. |
| `PH003` | 10 | Uses unusual urgency or a deadline | The message pressures the recipient to act immediately or before a short deadline, such as “act now,” “within 10 minutes,” or “final warning.” Do not match ordinary dates or neutral deadlines by themselves. | Urgency can discourage independent verification. Pause and check the request through a separate, trusted channel. |
| `PH004` | 15 | Requests payment to resolve an unexpected problem | The message requests money to unlock an account, receive a parcel, release a refund, avoid a penalty, fix an unexpected issue, or complete an unsolicited process. | Do not pay using instructions from an unexpected message. Contact the organisation using contact details obtained independently. |
| `PH005` | 10 | Offers an unexpected prize, refund, job, loan, or benefit | The message claims the recipient has unexpectedly won, qualified for, or can claim a benefit and asks them to act, provide information, pay a fee, or follow a link. | Unexpected benefits that require fees or sensitive information are a common fraud pattern. Confirm the offer independently before responding. |
| `PH006` | 10 | Impersonates a trusted organisation or support role | The text claims to be from a bank, government department, delivery company, employer, platform, technical-support team, or similar trusted party. This rule contributes points only when a related action or pressure signal is also present; a name mention alone is insufficient. | A sender can claim to represent a trusted organisation without being genuine. Verify the sender and request independently. |
| `PH007` | 15 | Directs recipient to sign in or verify through a message link | The message asks the recipient to sign in, verify identity, update account details, confirm a payment, or restore access using a link included in the message. | A link in an unexpected message may lead to a fake sign-in page. Navigate to the service using its known official app or address instead. |
| `PH008` | 10 | Demands secrecy or asks the recipient to ignore safeguards | The sender tells the recipient not to tell family, bank staff, colleagues, or authorities, or to ignore browser, device, or security warnings. Match only when directed as an instruction to the recipient. | Isolation and requests to bypass warnings are concerning. Stop and seek advice from someone you trust or from the organisation through an independent channel. |
| `PH009` | 20 | Requests remote-access software in a suspicious context | The message asks the recipient to install or open a remote-control, screen-sharing, or remote-support application in connection with banking, payments, identity verification, a parcel, a refund, or a law-enforcement claim. | Remote-access tools can allow another person to view or control parts of your device. Do not install or grant access at an unsolicited person's direction. |
| `PH010` | 10 | Requests sensitive identity or financial information | The message asks for identity documents or identifiers, full card or bank details, or other sensitive personal information to resolve an unsolicited issue. Do not match public or non-sensitive contact information. | Sensitive information can be used for impersonation or financial fraud. Share it only through a verified, necessary, and secure process. |
| `PH011` | 25 | Urgent KYC or account-blocking link | Require all three: (1) a threat that an account or service will be blocked, suspended, terminated, closed, restricted, or permanently suspended; (2) a request to complete KYC, verify an account, or update banking/account-verification details; and (3) a URL in the message or an explicit instruction to use a link for verification. Urgency may support the context but is not sufficient by itself. | The message combines an account restriction threat, a verification request, and a link. Verify through the organisation's official app or contact details obtained independently. |

### Phishing-rule implementation notes

- `PH006` is a **supporting rule**: require at least one related action/pressure signal such as `PH002`, `PH003`, `PH004`, `PH007`, `PH008`, or `PH010` before it adds points.
- `PH009` should require both an installation/remote-access request and a suspicious context. Mentioning remote-support software in a neutral article must not trigger it.
- `PH011` is a combination rule: require account-threat, verification-request, and link signals. Do not match merely because a message mentions KYC, a bank, urgency, or an account. A malformed URL-like string is link evidence for PH011 only as text; parsing failure alone adds no URL-specific points.
- Keep phrase lists explicit and reviewable. Avoid broad single-word matches such as `bank`, `police`, `verify`, or `urgent` without the surrounding condition.

---

## 6. URL warning rules

These rules run on a parsed URL string. They do not visit the URL, resolve DNS, follow redirects, or claim that the destination is malicious. A shortened URL is a warning signal because its final destination is obscured; it is not proof of fraud.

| Rule ID | Weight | Rule title | Match condition | Explanation shown to the user |
|---|---:|---|---|---|
| `URL001` | 10 | Uses a known URL-shortening domain | The parsed hostname exactly matches a configured shortening domain or is its valid subdomain, according to the configured list. | The link hides its final destination. Do not open it unless you can verify where it leads through a trusted method. |
| `URL002` | 15 | Uses an IP address instead of a recognisable domain | The URL hostname parses as an IPv4 or IPv6 literal rather than a normal domain name. | A raw IP address in an unsolicited login or payment link is unusual. Verify the sender and avoid entering credentials. |
| `URL003` | 15 | Contains a punycode hostname label | One or more hostname labels begin with `xn--` after safe hostname normalisation. | Punycode can be used legitimately for internationalised domain names, but it can also make look-alike domains harder to recognise. Check the domain carefully. |
| `URL004` | 20 | Contains user-information syntax before the host | The parsed URL contains user information (for example, `trusted.example@other.example`). The actual host must be extracted using a standards-compliant URL parser. | Text before `@` in a URL can make the destination look different from the actual hostname. Inspect the real hostname and do not rely on the displayed brand-like text. |
| `URL005` | 5 | Does not use HTTPS | The URL has a valid `http` scheme rather than `https`. Missing schemes should be normalised only under a documented URL-normalisation policy. | The connection is not protected by HTTPS. This alone does not prove fraud, but do not send sensitive information over an untrusted link. |
| `URL006` | 10 | Uses a non-standard port | The URL includes an explicit port other than the scheme's normal port (`80` for HTTP or `443` for HTTPS). | An unusual port can be legitimate, but it is uncommon for ordinary consumer sign-in pages. Verify the destination before continuing. |
| `URL007` | 25 | Claimed brand does not match the verified domain | The message explicitly claims to represent a configured brand, and the URL hostname is not that brand's verified domain or a subdomain of one. This rule requires a reviewed `brand_domains` allowlist. | The message's claimed organisation and the link destination do not match. Do not sign in or enter information; open the official app or type the verified address yourself. |
| `URL008` | 10 | URL path or query suggests credential or payment collection | A path or query contains configured high-risk terms (for example, `login`, `verify`, `reset`, `wallet`, `payment`, or `kyc`) **and** the surrounding message indicates an unexpected authentication or payment request. URL keywords alone are insufficient. | The link appears connected to a sensitive action. Verify the request using the organisation's official app or website instead of the message link. |
| `URL009` | 5 | Has an unusually deep subdomain structure | The normalised hostname contains more than four labels before the public suffix, under the project's documented hostname-counting method. | Deep subdomain structures can make a destination harder to read. Inspect the registrable domain; this signal alone is weak and may be benign. |

### URL parsing requirements

- Parse URLs with a standard library; do not determine the host using a simple string split on `/`, `:`, or `@`.
- Normalise the hostname to lowercase and handle IDNs consistently before matching rules.
- Check shortener domains and brand domains using exact host boundaries. For example, a rule for `example.com` must not treat `example.com.attacker.test` as a subdomain of `example.com`.
- Treat malformed URLs as **unparseable input** and return a validation message. Do not award points for parser errors alone.
- The `brand_domains` list must contain only domains verified from official sources and reviewed by a maintainer. Do not guess official domains or treat a brand keyword in a hostname as proof of legitimacy.
- If a trustworthy public-suffix parser is not available in Version 1, describe `URL009` as a rough hostname-structure signal rather than claiming to calculate the registrable domain accurately.

---

## 7. Digital-arrest scam rules

These rules apply to the message text. They target patterns associated with scams in which someone impersonates police or another authority and claims the recipient is under investigation, in custody, or at risk of arrest. A message mentioning police or a court in a neutral context is not sufficient.

| Rule ID | Weight | Rule title | Match condition | Explanation shown to the user |
|---|---:|---|---|---|
| `DA001` | 25 | Claims law-enforcement or government authority | The sender claims to represent police, cybercrime police, CBI, ED, customs, immigration, a court, or another configured authority, **and** the message contains another suspicious demand or pressure signal. | Scammers may impersonate officials to make a demand seem compulsory. Do not rely on a caller's claimed identity or caller ID; verify independently. |
| `DA002` | 25 | Claims “digital arrest” or equivalent virtual custody | The message explicitly says the recipient is digitally arrested, virtually detained, kept in online custody, or under a similar purported remote-arrest process. Match configured phrase variants, not isolated words. | A demand to remain in remote “digital custody” is a strong scam warning sign. Stop the interaction and contact the relevant authority through an independently verified channel. |
| `DA003` | 20 | Demands continuous video or phone contact | The sender orders the recipient to stay on a video/audio call, keep the camera on, not disconnect, or remain under continuous remote supervision in connection with an investigation or arrest claim. | Scammers may use continuous calls to intimidate and prevent the recipient from seeking help. End the call and verify the claim independently. |
| `DA004` | 25 | Demands money to avoid arrest or close a case | The sender demands a transfer, fine, bail amount, settlement, security deposit, or other payment to prevent arrest, clear a case, or prove innocence. | Do not transfer money to settle an unsolicited law-enforcement threat. Contact the authority through an independently sourced official channel. |
| `DA005` | 25 | Directs money to a “safe” or verification account | The sender tells the recipient to move money to a “safe,” “verification,” “RBI,” “police,” or similar account to prove funds are legitimate or to protect them during an investigation. Require a clear transfer instruction and investigation context. | A request to transfer funds for verification or protection is a major warning sign. Do not move money; contact your bank using the number on its official card or website. |
| `DA006` | 15 | Threatens immediate arrest, warrant, or family detention | The sender threatens immediate arrest, a warrant, imprisonment, or arrest of family members in order to force compliance. | Threats are often used to create panic. Pause, do not pay or disclose information, and seek independent verification and trusted support. |
| `DA007` | 10 | Orders the recipient to keep the interaction secret | The sender says not to tell family, a lawyer, bank staff, friends, or other authorities about the alleged investigation or call. | Isolation is a common coercion tactic. Speak to someone you trust and verify the claim through a separate channel. |
| `DA008` | 10 | Requests sensitive data under an investigation claim | Under the claimed law-enforcement process, the sender asks for OTPs, UPI PINs, passwords, complete bank/card credentials, or sensitive identity details over the call or message. | Do not disclose authentication secrets or banking credentials to a caller. Contact your bank or the relevant authority independently. |
| `DA009` | 10 | Uses a frightening parcel, contraband, or identity allegation to demand action | The sender claims a parcel, SIM, identity document, or account is linked to a crime and demands immediate compliance, payment, remote access, or sensitive information. | Fraudsters can invent criminal allegations to frighten people into complying. Verify the claim independently and do not follow payment or software-installation instructions. |

### Digital-arrest rule implementation notes

- For `DA001`, the authority claim must be combined with at least one relevant coercion signal, such as a payment demand, sensitive-data request, continuous-call demand, secrecy instruction, or arrest threat.
- `DA002` is a strong signal, but still return “strong scam indicators” rather than a legal conclusion.
- `DA004` and `DA005` should require a clear demand or instruction. A neutral sentence explaining that authorities do not ask for payment must not match.
- Do not assume a specific agency name is always fraudulent. The suspicious behaviour and coercive demand are the relevant signals.

---

## 8. Android app risk rules

These rules analyse **declared permissions and supplied metadata only**. Permissions are not proof of malicious behaviour: legitimate apps may need sensitive capabilities. The result must be presented as “potentially risky app indicators,” not as a malware verdict.

### 8.1 Individual permission and metadata signals

| Rule ID | Weight | Rule title | Match condition | Explanation shown to the user |
|---|---:|---|---|---|
| `APP001` | 15 | Requests SMS access or sending capability | Manifest declares one or more configured SMS permissions, such as `READ_SMS`, `RECEIVE_SMS`, or `SEND_SMS`. Award this rule once, not once per permission. | SMS access can expose verification messages or allow messages to be sent. Check whether this capability is necessary for the app's stated purpose. |
| `APP002` | 15 | Declares an accessibility service | Manifest/service metadata indicates an accessibility service. Do not trigger from the mere word “accessibility” in an unrelated description. | Accessibility services can be legitimate assistive features, but a malicious app may abuse them to observe or interact with other apps. Verify the developer and purpose. |
| `APP003` | 10 | Requests permission to draw over other apps | Manifest declares `SYSTEM_ALERT_WINDOW` or equivalent supported metadata indicates overlay capability. | Overlay capability can be abused to display deceptive screens over trusted apps. Check whether the app genuinely needs this capability. |
| `APP004` | 10 | Requests notification access | Metadata indicates a notification-listener service or equivalent notification access. | Notification access may expose message previews and one-time codes. Grant it only to apps you trust and that need it. |
| `APP005` | 10 | Requests installation of other packages | Manifest declares `REQUEST_INSTALL_PACKAGES` or an equivalent supported capability. | The app may be able to initiate installation of other packages. Confirm why this is required and install apps only from trusted sources. |
| `APP006` | 10 | Requests device-administration capability | Metadata indicates a device-admin receiver or another supported device-management capability. | Device-administration capability can make an app harder to remove or give it elevated control. Confirm that the app and requested role are legitimate. |
| `APP007` | 5 | Requests contacts or call-log access | Manifest declares configured contacts or call-log permissions. Award once for this family of permissions. | This access can expose personal relationships or call history. Check whether it is necessary for the app's advertised function. |
| `APP008` | 5 | Requests automatic startup or persistent background behaviour | Manifest declares `RECEIVE_BOOT_COMPLETED` or configured metadata indicates automatic start/background persistence. | Automatic startup may be legitimate but can help unwanted software remain active. Review it alongside the app's purpose and other permissions. |
| `APP009` | 10 | APK was obtained through an unexpected or untrusted channel | The user reports receiving the APK unexpectedly via SMS, chat, email, a third-party download page, or another source they cannot verify. This rule depends on supplied source information and must not be inferred from missing data. | Unexpected APKs can impersonate legitimate apps. Do not install the file; obtain apps from a trusted official store or the verified developer. |
| `APP010` | 15 | App identity appears to impersonate a known organisation | App name or supplied description claims to be a configured bank, government, payment, or trusted service, but the package/developer identity does not match a reviewed official-app allowlist. This requires verified configuration. | The displayed name alone cannot establish the publisher's identity. Confirm the app through the organisation's official website or store listing. |

### 8.2 High-risk permission combinations

Combination rules add points **in addition to** matching individual rules. Each combination rule is applied at most once.

| Rule ID | Weight | Rule title | Match condition | Explanation shown to the user |
|---|---:|---|---|---|
| `APP101` | 25 | Combines accessibility with sensitive control or data access | Accessibility capability is present **and** at least one of SMS access, notification access, or overlay capability is present. | These capabilities together can enable extensive observation or interaction with a device. This can be legitimate in some apps, but it merits careful verification of the developer and purpose. |
| `APP102` | 10 | Combines SMS with contacts or call-log access | At least one SMS permission and at least one configured contacts/call-log permission are present. | The combination can expose both verification messages and personal communication data. Check whether the app has a clear need for both. |
| `APP103` | 10 | Combines sensitive capability with persistent background behaviour | At least one of accessibility, SMS access, or notification access is present **and** automatic startup/background persistence is present. | Sensitive access combined with persistence can increase the impact of unwanted software. Verify the app before granting or retaining these capabilities. |
| `APP104` | 10 | Combines sideloading capability with sensitive access | `REQUEST_INSTALL_PACKAGES` is present and at least one of accessibility, SMS, notification access, or overlay capability is present. | The combination may allow the app to facilitate additional installations while holding sensitive access. Confirm the app's origin and purpose. |

### Android app rules: guardrails

- Do **not** flag `CAMERA`, `RECORD_AUDIO`, `ACCESS_FINE_LOCATION`, or `INTERNET` as suspicious by themselves. Many ordinary apps need these permissions.
- Treat equivalent permission labels as the canonical Android permission names only after reliable normalisation. Do not use fuzzy substring matches for permission names.
- If permissions are manually pasted by a user, label the analysis as based on **user-supplied metadata**. Do not claim the platform verified the APK manifest.
- If parsing an uploaded APK is added, use a safe static parser and size/type limits. Never install or execute the APK on the server.
- A package name, app label, or icon can be forged. Only use an official-app allowlist when it has been verified and is maintained.
- Return “insufficient metadata” where required fields are absent. Do not interpret missing permission data as zero risk.

---

## 9. Negative-context and duplicate-match protections

These protections are required so that a safety-awareness platform does not routinely flag warnings, educational content, or legitimate explanations as scams.

### 9.1 Negation and warning statements

Do not trigger an action-request rule when the surrounding text clearly tells the reader **not** to perform that action. Examples that should not trigger `PH001` or `DA008` by themselves:

- “Never share your OTP with anyone.”
- “Your bank will never ask for your UPI PIN.”
- “Do not transfer money to a so-called safe account.”
- “Police do not conduct a digital arrest over a video call.”

For Version 1, implement this with explicit negative-context phrases and a small, documented window around the matched action phrase. Do not assume a simple global search for `OTP`, `transfer`, or `police` is sufficient.

### 9.2 Educational or reporting context

If practical, detect common educational/reporting introductions such as “warning signs of phishing,” “how to identify a scam,” or “this message is an example of fraud.” Such context may suppress rules **only when the text is clearly explanatory and contains no actionable demand directed at the reader**. Do not broadly suppress rules merely because the word “scam” appears.

### 9.3 Duplicate matches

- Apply each rule ID once per submitted item.
- If several terms match the same rule, record the best short evidence excerpt rather than adding points repeatedly.
- Distinct rules may match the same message when they represent separate signals. For example, a message can both request an OTP and threaten account suspension.
- For a message containing several URLs, evaluate each URL, then count each URL rule at most once per submission and record relevant URL evidence in the match details. This prevents a message with many URLs from artificially inflating its score through repetition of one signal.

---

## 10. Suggested response contract

Return structured, explainable results. Adapt field names to the project's API conventions, but keep the information equivalent to this example:

```json
{
  "overall_score": 25,
  "overall_risk": "medium",
  "analyses": [
    {
      "category": "digital_arrest",
      "score": 25,
      "risk": "High risk",
      "matched_rules": [
        {
          "rule_id": "DA001",
          "title": "Claims law-enforcement or government authority",
          "weight": 25,
          "evidence": "We are calling from the cybercrime department. Transfer money now.",
          "reason": "Scammers may impersonate officials to make a demand seem compulsory.",
          "recommendation": "Verify the claim through an independently sourced official channel."
        }
      ],
      "summary": "Several warning signs associated with a digital-arrest scam were found."
    }
  ],
  "limitations": [
    "This result is based on static rule matching; it is not a definitive verdict.",
    "The submitted URL was not opened or checked against live reputation services."
  ]
}
```

The numeric values above illustrate the response structure only; calculate all returned scores from the rules that actually matched. If an analyzer was not run, represent its score as `null` or omit it consistently. Do not return an empty analysis as “safe.”

## 11. Recommended user-facing safety actions

When results show moderate, high, or critical risk, provide actions appropriate to the detected category:

### Phishing or suspicious URL

- Do not click the link or provide passwords, OTPs, UPI PINs, CVVs, or recovery codes.
- Open the service through its known official app or by typing a verified address yourself.
- Contact the organisation using contact information obtained independently, not details in the suspicious message.

### Digital-arrest scam indicators

- Do not transfer money, disclose banking credentials, or install remote-access applications because of an unsolicited call or message.
- End the interaction if it is safe to do so, and contact a trusted person.
- Verify the allegation through independently sourced official contact details. Do not rely on a caller's displayed number or claimed identity.

### Potentially risky Android app

- Do not install an unexpected APK or grant sensitive permissions until its developer and purpose are verified.
- Prefer a trusted official app store or the developer's independently verified website.
- If the app is already installed and appears suspicious, avoid entering sensitive information through it and seek trusted device-security assistance.

The platform should display emergency or reporting resources only when the destination and instructions have been verified by the project maintainers. Do not invent hotlines or imply that the platform itself has reported an incident.

## 12. Minimum Version 1 test cases

Use these cases as acceptance tests. Exact scores depend on the documented rules and configuration; test the matched rule IDs and score calculation, not only the final label.

| Test ID | Input | Expected behaviour |
|---|---|---|
| `T-PH-01` | “Your account will be blocked today. Verify your account through this link and enter your OTP.” | Match `PH001`, `PH002`, `PH003`, and `PH007` when the configured phrase conditions are satisfied. The text should be treated as suspicious even if the URL is unavailable. |
| `T-PH-02` | “Never share your OTP or UPI PIN. Your bank will not ask for them.” | Do not match `PH001` or `DA008` solely because secret names appear. |
| `T-URL-01` | A well-formed HTTP URL whose hostname is a configured shortener domain | Match `URL001` and `URL005`. Do not claim the final destination is malicious. |
| `T-URL-02` | A URL containing `trusted.example@other.example` in the authority component | Parse the URL correctly and match `URL004`; explain the actual hostname. |
| `T-DA-01` | “We are from the cybercrime department. Stay on video and transfer money to avoid arrest. Do not tell your family.” | Match the relevant authority/coercion rules, including `DA001`, `DA003`, `DA004`, `DA006` if an arrest threat is explicit, and `DA007`. Do not require the literal phrase “digital arrest” for all digital-arrest-related warning signs. |
| `T-DA-02` | “Police do not perform digital arrests over video calls and will not ask you to transfer money to a safe account.” | Negative-context handling should prevent the warning statement from being scored as a demand. |
| `T-APP-01` | App metadata contains only `CAMERA` and `INTERNET` | Do not trigger an app-risk rule from those permissions alone. Return the configured low-indicator result or state that no listed warning signals were found, with a limitation. |
| `T-APP-02` | App metadata contains an accessibility service, SMS permissions, and overlay capability | Match the applicable enabled rules; cap the total submission score at 100. Explain that this combination merits verification, not that malware is confirmed. |
| `T-APP-03` | No permission metadata is supplied | Return a validation or insufficient-metadata message. Do not claim the app is safe or assign a definitive zero-risk result. |
| `T-INPUT-01` | Malformed URL or unsupported metadata format | Return a clear input/parse error. Do not crash and do not treat parser failure as proof of a threat. |

## 13. Version 1 implementation checklist

- [ ] Keep rule definitions, phrase dictionaries, shortener domains, and verified brand mappings in one documented configuration layer.
- [ ] Implement the rules as deterministic functions with explicit input/output types.
- [ ] Return all matched rule IDs, weights, and short evidence excerpts.
- [ ] Count each unique triggered rule once, sum contributions across categories, cap the total at 100, and apply the risk bands exactly as defined above.
- [ ] Add unit tests for every rule, negative contexts, malformed input, duplicate matching, and score caps.
- [ ] Ensure message and URL analysis never fetches or opens the target URL.
- [ ] Ensure app analysis never installs or executes a submitted APK.
- [ ] Do not log full submitted messages, credentials, OTPs, or sensitive identifiers by default.
- [ ] Show the user that the result is a heuristic warning, not a definitive security verdict.
- [ ] Review false positives and false negatives before adding a rule or changing its weight; update this document and its tests together.

## 14. Maintenance and versioning

This document is the source of truth for Version 1 rule IDs, weights, and descriptions. If a rule's condition or weight changes, update the implementation, tests, and this file in the same change. Record material changes in the project's change log. Maintain reviewed copies of configurable domain lists separately, and document when and how those lists were verified.

**Version 1 principle:** provide useful, explainable warnings while being transparent about uncertainty. Never equate “no rule matched” with “safe.”
