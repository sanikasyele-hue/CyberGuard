# How CyberGuard works (explanation for the viva)

## 1. The problem and the idea in one minute
Security tools produce thousands of log lines. Analysts must find the dangerous ones, decide how serious they are
and decide what to do - slowly and by hand. CyberGuard automates this:

1. **Rules** and a **trained machine-learning model** find suspicious patterns in login logs.
2. **3 AI agents** explain each finding: what it is, how risky it is, what to do (smart and readable).
3. A **dashboard and incident console** let a security analyst manage the incidents.

## 2. The flow, step by step
```
CSV file -> Upload API -> Parser -> PostgreSQL (security_logs)
                                  -> Detection rules 1, 2, 3 -> Incident (status OPEN)
                                  -> ML model scans the same logins -> extra Incident for patterns no rule covered
                                          -> event -> background thread (after the save is committed)
                                                -> Agent 1 classify -> Agent 2 risk -> Agent 3 actions + report
                                                -> results saved on the incident
Analyst (browser) <- Dashboard + incident list + details  (JWT login, role checks)
```
Example: file contains 24 failed logins for `mkhan` in 4 minutes, then a successful login.
1. The parser checks every row (date format, allowed event types) and stores valid rows.
2. Rule 1 sees 24 failures in 10 minutes -> incident, severity CRITICAL.
3. Rule 2 sees a success right after the failures -> second incident "possible account takeover".
4. For each new incident the agents run in the background (the upload does not wait for them).
5. The analyst opens the console, sees the dashboard update, reads the AI report and sets the status
   OPEN -> UNDER_INVESTIGATION -> RESOLVED -> CLOSED.

## 3. The three detection rules
| Rule | Looks for | Why it matters |
|---|---|---|
| 1 Failed-login burst | 5+ failed logins for one user in 10 minutes | brute-force guessing |
| 2 Brute force then success | a success right after 5+ failures | the attacker may have guessed the password |
| 3 Password spray | one IP failing against 3+ different accounts | attacker tries common passwords on every account |
Rules are plain Java (`detection/DetectionRules.java`); thresholds are settings, not hard-coded.
Rules are deterministic on purpose: fast, free and always the same answer for the same data. The ML model (3b) adds judgement on top.

## 3b. The machine-learning model (this is the "trained" part)
- **Type:** supervised learning, logistic regression, written from scratch in Java (gradient descent).
- **Task:** look at one user's logins in a 10-minute window and output the probability that it is an attack.
- **Features (8):** failed attempts, share failed, different IPs, success after a failure, attempts per minute,
  night time, success from a new IP, share of failures from public IPs.
- **Training data:** 5,000 simulated login windows (normal users, typos, forgotten passwords, remote workers, broken
  scripts vs. brute force, distributed, low-and-slow takeover, stuffing, probing). Labels come from the scenario.
- **Evaluation:** 80% train / 20% test. On the 1,000 unseen test windows it scores about 95% accuracy and F1 0.94,
  while the old "5+ failures" rule scores about 83% and F1 0.78 (exact numbers are on the dashboard).
- **How it is used:** every incident gets an ML score, and after each upload the model creates incidents for suspicious
  patterns that no rule covered (example: 3-4 failures at 3 AM from a public IP, then a login from a new IP).
- **Why it can beat the rule:** the rule only counts failures; the model also weighs IP changes, public IPs and time.
- **Honest limit:** the data is simulated, so this shows a working ML pipeline, not proven real-world accuracy.
  Next step: train on a real labelled dataset or on analyst feedback.

## 4. The three AI agents
Analogy: a hospital emergency desk.
| Agent | Like | Input | Output |
|---|---|---|---|
| 1 ThreatClassificationAgent | triage nurse: "what is this?" | the incident + related log lines | category, confidence, summary |
| 2 RiskAssessmentAgent | senior doctor: "how serious?" | agent 1's result + facts (events, IPs, accounts, success after failures) | LOW / MEDIUM / HIGH / CRITICAL + reasoning |
| 3 ResponseReportAgent | case writer: "what do we do?" | results of agents 1 and 2 | recommended actions + incident report |

- Each agent is its own Java class and makes its **own** call to an OpenAI-compatible LLM; `AgentPipeline` chains them.
- Agents talk to the LLM only through the `LlmClient` interface, so the provider can be swapped.
- **They only advise.** They cannot block IPs or change accounts - a human decides.
- Answers must be valid JSON with allowed values (categories and risk levels are checked); otherwise the agent
  falls back to built-in rules. With no API key everything runs in **offline mode**, and every incident is labelled
  `OFFLINE_RULES` or `LLM:<model>` so it is always clear what produced the text.
- **The LLM behind the agents is not trained by us:** it is pre-trained and controlled with prompts. The model we DID train is the detection model in section 3b; its probability is given to agent 2 as supporting evidence.

## 5. Security features
- Passwords stored with BCrypt; login returns a JWT token that expires.
- Roles: ADMIN (users + everything), SECURITY_ANALYST (logs, incidents, dashboard), USER (nothing sensitive).
- Self-registration can only create USER; only an admin can create analysts/admins.
- Secrets (DB password, JWT secret, API key) come from environment variables.
- Log text is attacker-controlled, so it is cleaned before going to the LLM (prompt-injection defence) and shown
  in the browser as plain text (XSS defence).
- Uploads are validated row by row; file size is limited to 5 MB.

## 4b. Technology
Java 17, Spring Boot 3.3, Spring Security + JWT (jjwt), Spring Data JPA / Hibernate, PostgreSQL, Maven,
Eclipse, plain HTML/JavaScript front end. Own Java implementation of logistic regression for the ML part. Tables: `users`, `security_logs`, `incidents`.

## 6. Honest limits (say them before you are asked)
- Detection works on login events only; logs must be CSV in the given format.
- The LLM can be wrong, so the incident stays under human control.
- Usernames and IPs from logs are sent to the LLM provider when a key is configured.
- Future scope: train on a real labelled dataset or analyst feedback, audit history of who changed what, email / live alerts,
  more features (geo-location, device), React front end, Docker deployment, automated tests inside the project.

## 7. Likely questions
| Question | Short answer |
|---|---|
| Why rules **and** AI? | Rules detect reliably and cheaply; AI explains and prioritises. Together they are faster than manual review and more predictable than AI alone. |
| Why three agents instead of one prompt? | Each has one job, a clear input/output and can be tested or replaced separately; the output of one is the input of the next. |
| What if the AI is down or wrong? | Offline fallback; outputs are validated; the label shows the source; humans decide. |
| Did you train a model? | Yes - a logistic regression detector trained from scratch on simulated labelled logins (80/20 split, accuracy/precision/recall/F1 shown on the dashboard). The LLM used by the agents is pre-trained and guided by prompts. |
| Is the ML accuracy real? | It is measured on unseen simulated data, so it shows the method works; real-world accuracy needs a real labelled dataset. |
| Why logistic regression? | Simple, fast, needs little data and is explainable: each feature has a weight you can read on the dashboard. |
| What are precision and recall? | Precision = of the alerts raised, how many were real. Recall = of the real attacks, how many were caught. F1 combines both. |
| How is it secured? | JWT, BCrypt, role checks, secrets in environment variables, input validation, prompt-injection and XSS defences. |
| How would it scale? | Move to GROUP BY queries, add indexes (one exists), queue the agent work, stream logs instead of CSV. |
