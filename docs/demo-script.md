# SignalCheck 3-Minute Demonstration Script

This walkthrough script is designed for live demonstrations, hackathon presentations, and university lectures to showcase SignalCheck's safe APK static analysis, educational findings, dynamic explanations, PDF export, and private history.

---

## Preparation Checklist
1. Start Backend: `python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000`
2. Start Frontend: `cd frontend && npm run dev`
3. Have the sample fixture APK ready: `backend/tests/fixtures/ANDROGUARD_TESTS_TestActivity.apk`
4. Open Chrome or Firefox to `http://127.0.0.1:5173`.

---

## Script & Timeline (Total: 3 Minutes)

### Minute 0:00 - 0:30: Introduction & Safety Architecture
- **Speaker:** "Welcome to SignalCheck. Today, mobile users and researchers frequently receive suspicious Android applications (APKs) via messaging apps or unverified websites. However, analyzing untrusted binaries directly is risky."
- **Action:** Navigate to the **"APK Static Analysis"** tab.
- **Key Point:** Point out the prominent banner:
  > *"Static Inspection Only: APKs are analyzed ephemerally in a quarantined sandbox without execution. Files are never installed, emulated, or stored."*

---

### Minute 0:30 - 1:15: Upload & Asynchronous Polling
- **Speaker:** "Let's upload an APK to inspect its permissions and bytecode indicators."
- **Action:** Drag and drop `ANDROGUARD_TESTS_TestActivity.apk` into the drop zone (or click to browse).
- **Key Point:**
  - Notice the instantaneous progression through **Queued** $\to$ **Running** $\to$ **Completed**.
  - "Under the hood, the API validated the zip structure and streamed the payload to an isolated worker process with a hard 30-second kill deadline, keeping the main web server completely decoupled from the decompiler."

---

### Minute 1:15 - 2:00: Findings, Severity Legend & "Learn More"
- **Speaker:** "Here are our static analysis results. Notice the Severity Legend explaining High, Medium, and Low signals."
- **Action:** Scroll down to the **Findings** section.
- **Key Point:**
  - Click on the expandable **"Learn more"** dropdown on a finding (e.g., *Dynamic Code Loading* or *Command Execution*).
  - Highlight the 4 educational sections:
    1. **What this means:** Plain language explanation of the technical behavior.
    2. **Why attackers use it:** Tactical attacker motivation.
    3. **Legitimate uses:** Common benign apps that also perform this action (reducing panic and false alarms).
    4. **What to do:** Clear, non-technical steps for the user.
  - Stress: *"Every finding is a signal to verify, not a definitive verdict. SignalCheck teaches users rather than giving false absolute claims."*

---

### Minute 2:00 - 2:30: PDF Export
- **Speaker:** "Users often need an offline summary to share with IT departments or incident responders."
- **Action:** Click the **"Export PDF Report"** button in the top right of the analysis card.
- **Key Point:**
  - The browser downloads the generated PDF (`signalcheck_apk_report_<id>.pdf`).
  - Open the PDF to demonstrate the clean layout, executive summary, findings with condensed educational notes, and canonical limitations statement.

---

### Minute 2:30 - 3:00: Session-Isolated History & Privacy
- **Speaker:** "Finally, let's look at history and user privacy."
- **Action:** Scroll down to the **"Analysis History"** table.
- **Key Point:**
  - The newly analyzed record appears with timestamp, package name, file size, and SHA-256 digest.
  - Explain: *"History is strictly private per browser session using an anonymous, httpOnly cookie with a 30-day retention purge and 200-record cap. There are no user accounts, no passwords, and records cannot be probed across sessions. Most importantly, raw APK binaries are never saved to disk or database."*
