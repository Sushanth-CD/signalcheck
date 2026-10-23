# Problem Research

## 1. Phishing

- **Definition**:
Phishing is a form of social engineering and cybercrime where attackers deceive individuals into revealing sensitive personal, financial, or security data—such as login credentials, credit card numbers, OTPs, or tax identifiers—by masquerading as trustworthy organizations, reputable companies, or known contacts through electronic communications (emails, text messages, fraudulent websites, or direct messages).

- **Common attack patterns**:
1) Spear phishing : Spear phishing is a highly targeted form of phishing where attackers tailor electronic communications directly to a specific individual, organization, or role. Instead of sending generic mass emails, perpetrators gather reconnaissance—such as the target’s job title, company hierarchy, colleagues' names, and active projects—to craft convincing, context-aware messages that trick the victim into sharing sensitive data, credentials, or authorizing fraudulent transactions.
2) Voice phishing (vishing) : Voice phishing, or vishing, is a social engineering attack where fraudsters use telephone calls, voice-over-IP (VoIP) spoofing, or AI-generated voice cloning to manipulate victims into disclosing confidential information, providing banking credentials, or initiating financial transactions.
3) SMS Phishing (Smishing): A form of phishing conducted through SMS messages, typically to deceive recipients into clicking malicious links, disclosing sensitive information, or performing fraudulent transactions.
4) QR code phishing (quishing) : QR code phishing, or quishing, is an attack vector where malicious actors use fraudulent Quick Response (QR) codes in digital communications (emails, PDFs) or physical environments (stickers placed over legitimate merchant codes, parking meters) to direct victims to credential-stealing portals, initiate unauthorized payments, or trigger drive-by malware downloads.
5) Adversary-in-the-Middle (AiTM) Phishing: AiTM phishing is an attack in which a malicious intermediary, often operating through a phishing website acting as a proxy, intercepts communications between a victim and a legitimate service. This can allow attackers to capture credentials and session cookies, potentially bypassing some forms of multifactor authentication.

- **Warning signs**:
1) Generic Greetings & Artificial Urgency: Messages opening with "Dear Customer" accompanied by aggressive deadlines ("Account suspended within 24 hours," "Immediate payment required").
2) Mismatched or Spoofed Sender Addresses: Sender display names matching recognized brands while the actual email header reveals an unrelated public or foreign domain (e.g., support@apple-security-verify.net).
3) Unsolicited Attachments & Links: Unexpected invoice attachments (.zip, .iso, .html, or macro-enabled .xlsm/.docm) or hyperlinked text masking anomalous destinations.
4) Requests for Sensitive Personal Information: Inquiries prompting users to confirm passwords, enter complete debit card PINs, or share incoming SMS OTPs.
5) Spelling Inconsistencies & Domain Typos: Subtle character substitutions, unusual phrasing, or non-standard top-level domains mimicking legitimate corporate portals.

- **Impact on victims**:
1) Financial Fraud & Unauthorized Transactions: Direct theft from bank accounts, unauthorized credit charges, and fraudulent loans taken out under the victim's name.
2) Account Takeover & Identity Theft: Compromise of personal email, cloud storage, and social profiles, which attackers exploit to target secondary contacts or commit wider fraud.
3) Corporate Data Breaches & Ransomware Deployment: In organizational contexts, a single harvested credential often serves as the entry vector for network intrusion, enterprise extortion, or ransomware deployment.
4) Reputational and Operational Disruption: Loss of consumer trust, costly incident recovery, legal penalties under data protection regulations, and prolonged credit rehabilitation.

- **Prevention methods**:
1) Inspect Sender Headers & URLs Carefully: Verify the actual email address behind the display name and hover over hyperlinks before clicking to confirm destination domains.
2) Enforce Phishing-Resistant MFA: Adopt hardware security keys (FIDO2/WebAuthn) or authenticator apps rather than relying solely on SMS-based OTPs, which are vulnerable to interception and interception-relay tools.
3) Access Portals Independently: Never navigate to banking, tax, or critical service accounts via unsolicited links; open a browser manually and type the official URL or use verified bookmarks.
4) Deploy Technical Defenses: Implement email authentication protocols (SPF, DKIM, DMARC), modern endpoint protection, and browser anti-phishing filters.
5) Immediate Incident Mitigation:
--> Change compromised passwords immediately across all accounts sharing the credential.
--> Revoke active web sessions and alert IT security/fraud departments.
--> Report phishing attempts to national reporting centers (such as cybercrime.gov.in / Helpline 1930 in India, or reportphishing@apwg.org globally).

- **Sources**:
1) Cybersecurity and Infrastructure Security Agency (CISA) – Multi-State Information Sharing and Analysis Center guidance on recognizing and preventing phishing.
2) Anti-Phishing Working Group (APWG) – Phishing Activity Trends Reports and threat analysis metrics.
3) ndian Computer Emergency Response Team (CERT-In) – Advisories and security best practices against phishing and social engineering campaigns.
4) Federal Trade Commission (FTC) – Consumer guidelines on identifying, handling, and reporting scam messages and fake payment requests.

## 2. Digital Arrest Scams

- **Definition**: 
A digital arrest scam is a fraudulent scheme in which criminals impersonate law-enforcement orgovernment officials, falsely accuse victims of criminal activity, and use threats, intimidation, ordemands for money to manipulate them. There is no legal concept of a "digital arrest" under Indian law.

- **Common attack patterns**:
1) The Impersonation Call: Fraudsters initiate contact via automated IVR or direct calls claiming to represent courier companies (e.g., FedEx, DHL), telecom operators (DoT), or customs officials. They claim a package containing illegal items (narcotics, forged passports, illegal SIMs) has been seized in the victim's name.
2) Escalation to "Police" or "Investigating Agencies": The victim is transferred to fake police officers or federal agents who threaten immediate physical arrest, public humiliation, and frozen bank accounts.
3) Staged Virtual Police Stations: Victims are ordered onto Skype, WhatsApp, or Zoom video calls. The background features staged police stations, official seals, national flags, and uniformed impersonators displaying counterfeit arrest warrants, Supreme Court notices, or seizure memos.
4) Continuous Surveillance & Isolation: Scammers enforce "digital house arrest," commanding the victim not to hang up, sleep, contact family members, or leave the camera frame under penalty of immediate physical remand.
5) Asset "Verification" Transfer: Victims are coerced into liquidating mutual funds, breaking fixed deposits, and wiring their entire balances to "government escrow accounts" or "RBI security vaults" for "financial audits," promising a full refund once cleared. Once funds are sent, communication is terminated.

- **Warning signs**:
1) Demands for Virtual Confinement: Claims that you are under "digital arrest" or legally bound to stay on a video call. (Legal agencies in India and internationally do not conduct arrests over video calls).
2) High-Pressure Secrecy: Strict instructions forbidding you from discussing the case with family, colleagues, or legal counsel under the guise of "national security."
3) Fund Transfers for "Verification": Any demand to transfer money to "safe accounts," "RBI audit accounts," or via RTGS/IMPS to avoid arrest.
4) Display of Official Seals over Video: Showcasing warrants, letters with government emblems, or CBI/ED logos over video chat or messaging apps.
5) Urgency and Coercion: Threats of immediate physical police arrival within minutes if the call is disconnected.

- **Impact on victims**:
1) Severe Financial Loss: Victims often lose life savings, pensions, emergency funds, and fixed deposits, sometimes running into millions of rupees.
2) Severe Psychological Trauma: Prolonged video confinement (often lasting days) leads to extreme anxiety, sleep deprivation, paranoia, and acute PTSD.
3) Reluctance to Report: Due to shame, fear of ongoing legal consequences, or disbelief, victims frequently delay reporting, hindering recovery efforts.

- **Prevention methods**:
1) Remember: "Digital Arrest" Does Not Legally Exist: Law enforcement agencies (CBI, Police, ED, Customs, Courts) never arrest individuals via WhatsApp, Skype, or phone calls.
2) Hang Up and Verify Directly: Disconnect suspicious calls immediately. Look up official contact numbers independently from verified government portals—never use numbers provided by the caller.
3) Never Transfer Money to Avoid Arrest: Legitimate government agencies never require citizens to transfer money to private bank accounts for "safekeeping," "clearing," or "forensic verification."
4) Immediate Reporting:
--> In India, report financial cyber fraud immediately through helpline 1930 and follow the official reporting procedure. Prompt reporting can help the authorities and relevant financial institutions take action to limit further losses, although recovery or blocking of funds is not guaranteed.

- **Sources**:
1) Indian Cyber Crime Coordination Centre (I4C), Ministry of Home Affairs (MHA) – Advisories on video-call impersonation and fake digital arrest schemes.
2) Reserve Bank of India (RBI) – Public awareness notifications regarding unauthorized account transfers and fake legal threats
3) Central Bureau of Investigation (CBI) – Press releases clarifying procedures regarding summons and cyber imposter warnings.
4) Telecom Regulatory Authority of India (TRAI) & Department of Telecommunications (DoT) – Notices on fraudulent disconnection threats and spoofed calls.

## 3. Malicious Applications

- **Definition**: 
Malicious applications (often termed mobile malware or rogue apps) are software programs designed for smartphones, tablets, or desktop operating systems with the intent to secretly compromise device security, steal sensitive user data, conduct unauthorized financial transactions, spy on user activity, or hijack hardware resources without legitimate user consent.

- **Distribution methods**:
1) Sideloading via Third-Party Websites & APKs: Attackers lure victims through phishing SMS, social media ads, or fraudulent websites into downloading raw installer packages (such as Android .apk files) outside official application stores.
2) Repackaged & Cloned Legitimate Apps: Threat actors decompile popular legitimate applications, inject malicious code or trojans into them, and re-upload them to alternative app repositories or forums under the guise of "cracked," "modded," or "premium unlocked" versions.
3) Malvertising & Deceptive Web Banners: Fraudulent online advertisements prompt users with fake system warnings ("Your device is infected! Tap here to clean") or fake software update notifications (e.g., "Update Chrome" or "Update Flash Player") that trigger malware downloads.
4) Dropper Apps on Official App Stores: Cybercriminals slip seemingly harmless utility apps (e.g., flashlights, document scanners, file managers, calculators) past official store security checks; once installed, the app dynamically downloads the secondary malicious payload from an attacker-controlled Command and Control (C2) server.
5) Messaging App Links & Social Engineering: Dissemination of malicious installation links or direct files via WhatsApp, Telegram, or SMS, often masked as video players, parcel tracking tools, or loan sanction apps.

- **Warning signs**:
1) Excessive or Irrelevant Permission Requests: The app demands high-risk permissions unnecessary for its stated functionality, such as SMS access, Accessibility Services, Notification Listener access, call logs, or camera/microphone access on a basic utility tool.
2) Rapid Battery Drain & Device Overheating: Unexplained background activity, continuous processor utilization, or high thermal output even when the device is idle.
3) Unexplained Spikes in Mobile Data Usage: Significant increases in cellular or Wi-Fi data consumption caused by background data exfiltration, ad-clicking bots, or communications with remote C2 servers.
4) Persistent Pop-Up Ads & Display Overlay Abuse: Aggressive ads appearing outside the application, on the lock screen, or sudden invisible overlay screens that mimic authentic banking login windows.
5) Inability to Uninstall or Missing App Icon: The application hides its launcher icon immediately after installation, requests Device Administrator privileges to prevent uninstallation, or continuously crashes when you attempt to access the app management settings.

- **Potential consequences**:
1) Financial Theft via Automated SMS Interception: Banking trojans (e.g., Cerberus, Hydra, SharkBot) intercept incoming two-factor authentication OTPs and conduct unauthorized wire transfers or UPI transactions silently in the background.
2) PII Exfiltration & Blackmail: Predatory loan apps and spyware exfiltrate contact lists, photo galleries, call records, and location data, using the stolen media to harass, defame, and extort victims and their relatives.
3) Device Takeover via Accessibility Abuse: Malware exploits OS Accessibility Services to grant itself administrative rights, execute keystroke logging, read screen contents, and auto-grant permissions without user interaction.
4) Cryptojacking & Botnet Enlistment: The compromised hardware is weaponized as an illicit cryptocurrency miner or recruited into a mobile botnet to conduct Distributed Denial of Service (DDoS) attacks or relay smishing campaigns.

- **Prevention methods**:
1) Stick Exclusively to Official App Stores: Download applications only from reputable, vetted platforms (e.g., Google Play Store, Apple App Store) and ensure Google Play Protect or equivalent built-in scanning remains enabled.
2) Restrict Sideloading & Unknown Sources: Keep the installation of apps from "Unknown Sources" disabled by default within system security settings.
3) Audit Permissions Ruthlessly: Never grant Accessibility Services, SMS, or Notification Listener permissions to third-party utility apps unless strictly necessary and verified.
4) Keep Operating System and Firmware Updated: Apply security patches and OS updates promptly to remediate known vulnerabilities exploited by privilege-escalation exploits.
5) Immediate Reporting:
--> If compromised, boot the device into Safe Mode, revoke Device Administrator privileges, uninstall the rogue app, and perform a full factory reset if needed.
--> Alert your financial institutions to freeze linked accounts and report fraudulent mobile apps to national reporting centers (cybercrime.gov.in / Helpline 1930 in India).

- **Sources**:
1) Indian Computer Emergency Response Team (CERT-In) – Security Advisories and Vulnerability Notes on Android Banking Trojans and Malicious APKs.
2) Cybersecurity and Infrastructure Security Agency (CISA) – Mobile Security Guidance and Best Practices for Securing Mobile Devices.
3) European Union Agency for Cybersecurity (ENISA) – Threat Landscape Report on Mobile Malware and Application Ecosystem Vulnerabilities.
4) Reserve Bank of India (RBI) – Advisories on Fraudulent Mobile Loan Apps and Unauthorized Digital Lending Platforms.

## 4. Problem Summary

- **Who is affected?**
1) Digital Arrest Scams: Senior citizens, retirees, homemakers, and individuals living alone or working remotely who are unfamiliar with police and judicial procedures, making them highly vulnerable to institutional intimidation.
2) Phishing Scams: Everyday digital banking and internet users, enterprise employees (spanning HR, finance, and IT administration), gig-economy workers, and C-level executives targeted via credential harvesting and targeted social engineering.
3) Malicious Applications: Mobile-first internet users, students, low-income borrowers seeking instant credit, casual mobile gamers, and smartphone users who frequently sideload applications, modded software, or click promotional APK links.

- **What difficulties do they face?**
1) Inability to Recognize Sophisticated Deception: Attackers deploy authentic-looking uniforms, fake judicial stamps, cloned enterprise login pages, reverse proxies bypassing 2FA, and disguised utility apps that are indistinguishable from legitimate services to the untrained eye.
2) Severe Psychological Manipulation: Victims are subjected to manufactured panic, artificial urgency, isolation tactics, and fear of imminent physical imprisonment, clouding rational thinking and discouraging consultation with trusted family or colleagues.
3) Catastrophic Financial & Identity Loss: Victims suffer immediate depletion of life savings, drained retirement pensions, fraudulent microloans taken in their name, and long-term identity theft that complicates personal and professional life.
4) Opaque Reporting & Recovery Procedures: Victims often do not know where to turn immediately after an incident occurs, face confusion navigating cybercrime reporting channels (e.g., helpline 1930 or portal filing), or delay reporting due to shame, guilt, and social stigma.
5) Device and Account Hijacking: Loss of access to critical primary email accounts, persistent background surveillance via spyware, and stolen session tokens that allow adversaries to maintain unauthorized enterprise and personal access silently.

- **Why is an awareness platform useful?**
1) Demystifies Legal and Procedural Realities: Proactively educates citizens that law enforcement, tax agencies, and judiciary bodies never execute "digital arrests," issue video-call summons, or demand funds for forensic verification.
2) Trains Skepticism Against Social Engineering Vectors: Equips individuals to spot subtle warning signs—such as reverse proxies, disguised QR codes, spoofed sender IDs, and excessive Android app permissions—before clicking or entering credentials.
3) Standardizes Rapid Incident Response Protocols: Delivers clear, step-by-step guidance on immediate triage actions, such as freezing bank accounts within the "golden hour," revoking OAuth tokens, booting into Safe Mode, and lodging complaints via cybercrime portals.
4) Bridges the Knowledge Gap for Vulnerable Demographics: Translates complex technical threats (AiTM proxies, APK droppers, deepfake vishing) into accessible checklists and actionable warnings for non-technical users and corporate workforces alike.
5) Reduces Stigma and Encourages Early Reporting: Normalizes vigilance and fosters an environment where victims feel empowered to report suspicious communications early rather than staying silent due to embarrassment or fear.