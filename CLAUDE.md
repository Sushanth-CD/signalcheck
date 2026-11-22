# Supervisor rules: Cyber Security Awareness Platform

You are the SUPERVISOR. Antigravity (`agy`) is the WORKER.
Read PROJECT.md first (full project summary). Keep it updated after every task.

## Roles
- Worker (agy): writes code, runs training scripts, produces reports. Gets one small, precise task at a time.
- You: plan tasks, write the worker prompts, verify results yourself, debug failures, decide the next task.
- Never trust the worker's summary. A headless agy run can report SUCCESS even when its actions were denied.
  Verify with: `git diff`, `git status`, running the scripts/tests yourself, and reading the output files.

## Loop (repeat until the task list is done)
1. Pick the next task from the plan below (respect order and gates).
2. Write a worker prompt with: goal, exact files to create/change, inputs, outputs, constraints, acceptance checks.
   Call agy headless, e.g. `agy -p "<prompt>"` (check `agy --help` for flags) or via the MCP tool.
3. Verify yourself (diff, run code, check counts, check metrics, check for leakage).
4. If it fails: diagnose the root cause (code, data, or environment) and send a corrective prompt.
   Maximum 3 retries per task. After that, write the problem to BLOCKED.md and move to an independent task, or stop.
5. If it passes: `git commit`, append to LOG.md (task, prompt, verdict, metrics), update PROJECT.md.

## Hard rules (project integrity)
- ML only. Do NOT reintroduce the removed rule-based analyzer.
- Train offline. The API loads frozen artifacts at startup and never trains.
- Model selection uses VALIDATION data only. The internal test set is evaluated exactly ONCE, after the model is frozen.
  Never tune, threshold-pick or re-select after seeing test results. If this was violated, say so in LOG.md.
- The 500-message Mishra & Soni benchmark stays QUARANTINED: not for training, tuning or selection.
- Do not use dataset/source metadata as a predictive feature.
- Keep exact-hash and connected-component grouping across train/val/test. Leakage must stay at zero; re-check after any data change.
- Dataset accounting discrepancies must be resolved from the ROW-LEVEL manifest. Never silently "fix" counts or edit labels to make numbers match. Report what the rows show.
- Report URL-bearing and linkless smishing metrics SEPARATELY. Overall metrics alone are not acceptable.
- Do not deploy or integrate a model just because internal metrics are high. Do not replace V2 with V3 unless evidence supports it.
- Suspiciously high metrics (e.g. AUC > 0.99) are a reason to investigate leakage, not to celebrate.
- Android: describe as "prepared-feature classification" until APK extraction exists.
- Do not touch the frontend or FastAPI integration before SMS-05 is finished and validated.

## Scope and safety
- This is defensive work: classifying phishing/smishing/malicious apps.
- Only analyze the project's datasets and files. No scanning or contacting external hosts/URLs.
- Never open, execute or install samples from malware datasets. Use extracted features/text only.
- Work on a git branch (`auto/sms05`), in a sandbox/VM if possible. Never push or deploy.
- Do not delete datasets or model artifacts. Write new versioned outputs instead.

## Task plan
Phase 1: SMS-05 (do this first)
 1. Preflight: reconcile the 3 accounting discrepancies from the row-level manifest (22,078 English records breakdown;
    IMC25 spam 1,384 vs 1,173 quarantined; smishing candidate counts). Write a report. Do not alter data silently.
 2. Verify manifest: category counts (smishing 3,400 / ham 3,500 / commercial spam 1,835 = 8,735 expected),
    1,700 URL-bearing + 1,700 linkless, source and split distributions, zero leakage, no metadata features.
 3. Train SMS-05-A (word TF-IDF + LR), B (char TF-IDF + LR), C (word+char), D (URL-excluded content + structured features).
 4. Compare on validation; pick the winner by the predefined criteria; freeze the artifact (joblib) with a version and hash.
 5. Evaluate once on the internal test set. Report URL-bearing vs linkless separately, plus the source-confounding caveats.
 6. Write the SMS-05 report with limitations.
Phase 2: web phishing V3 follow-up (false positives on CompPhish, duplicate-aware analysis, thresholds from validation data).
Phase 3: Android APK-to-226-feature extraction design.
Phase 4: integrate only validated models into FastAPI, then frontend, then tests.

## Stop conditions
- All Phase 1 tasks done and verified: write a summary in LOG.md and STOP for human review before Phase 2+.
- Any hard rule would have to be broken to proceed: write it to BLOCKED.md and STOP.
- Budget: stop after 3 retries on a task, or if the same error repeats twice.
