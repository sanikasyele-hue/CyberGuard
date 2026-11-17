# CyberGuard - AI-Assisted Cybersecurity Incident Management

Spring Boot 3 + PostgreSQL + JWT. Upload security logs (CSV) -> rules detect suspicious logins ->
**3 AI agents** classify the incident, assess the risk and write the response + report.

---

## A. Run it in Eclipse (first time) - about 10 minutes

### 1. Things that must be installed
| What | Check it | 
|---|---|
| Java 17 or newer | open Command Prompt, type `java -version` |
| Eclipse IDE for Enterprise Java (has Maven built in) | you already use it |
| PostgreSQL, running | Windows Start menu -> "Services" -> find `postgresql-x64-..` -> Status = Running |

### 2. Create the empty database (once)
1. Open **pgAdmin** -> log in with your postgres password.
2. Right-click **Databases** -> **Create** -> **Database...** -> name: `cyberguard_db` -> Save.

The app creates all tables by itself. The default DB user/password are `postgres` / `root`.
If your password is different, see "Settings" at the bottom.

### 3. Import the project
1. Unzip the project.
2. Eclipse: **File -> Import... -> Maven -> Existing Maven Projects -> Next**.
3. **Browse** to the unzipped folder (the one that contains `cyberguard-backend`) -> make sure `pom.xml` is ticked -> **Finish**.
4. Wait until the progress bar at the bottom-right finishes (first time downloads libraries).
5. If you see red errors about Lombok (`getX()` not found): close Eclipse, double-click the Lombok jar
   (find it in `C:\Users\<you>\.m2\repository\org\projectlombok\lombok\`), click **Specify location** -> pick `eclipse.exe` -> **Install/Update**, then reopen Eclipse.

### 4. Run
1. In **Package Explorer** open `src/main/java` -> `com.cyberguard.incident` -> `IncidentManagementApplication.java`.
2. Right-click it -> **Run As -> Java Application**.
3. In the **Console** wait for: `Started IncidentManagementApplication in ... seconds`.
4. Open **http://localhost:8080** in your browser.

### 5. Use it (no Postman needed)
1. Log in: **admin** / **Admin@12345** (created automatically on first start).
2. Upload `sample-data/sample-logs.csv`.
3. After 10-30 seconds click **Refresh** - the new incident shows its AI classification and risk.
4. Click **Details** to read the recommended actions and the full report. **Run AI** re-runs the agents.

### 6. Stop
Click the **red square** in the Console. Always stop the old run before starting again - otherwise you get
`Port 8080 was already in use`.

---

## B. The 3 AI agents

| # | Class (`ai/agent/`) | Job | Output |
|---|---|---|---|
| 1 | `ThreatClassificationAgent` | Reads the incident + log lines | category + confidence + summary |
| 2 | `RiskAssessmentAgent` | Reads agent 1's result | LOW / MEDIUM / HIGH / CRITICAL + reasoning |
| 3 | `ResponseReportAgent` | Reads agent 1 + 2 results | recommended actions + Markdown report |

`AgentPipeline` calls them in this order. Each agent makes its **own** LLM call.
All of them talk to the model only through the `LlmClient` interface (`ai/LlmClient.java`);
`OpenAiCompatibleLlmClient` implements it for any OpenAI-compatible API. To change provider,
write another class implementing `LlmClient`.

**Offline mode:** with no `AI_PROVIDER_API_KEY` (or if the API call fails) every agent uses built-in rules and the
incident is labelled `OFFLINE_RULES`. With a key the label is `LLM:<model>`. Say this honestly in your viva:
offline mode is a safety net, not AI.

**Turn on the real LLM:** Eclipse -> Run -> **Run Configurations...** -> select `IncidentManagementApplication`
-> **Environment** tab -> **Add**: name `AI_PROVIDER_API_KEY`, value = your key -> Apply -> Run.
Never paste the key into code, the chat or GitHub.

**Security design (good viva points):** log text is attacker-controlled, so it is stripped of `< >` and control
characters, length-limited, wrapped in `<evidence>` tags, and the prompts say to treat it as data. The model's
answers are only accepted if the category / risk level are valid enum values, so the model can never trigger actions.
Note: usernames and IPs from your logs are sent to the LLM provider.

---

## B2. Detection rules (what creates an incident)

| # | Rule | Default | Category / risk |
|---|---|---|---|
| 1 | Too many failed logins for one user in a time window | 5 failures in 10 min | AUTHENTICATION_ANOMALY, MEDIUM / HIGH / CRITICAL by count |
| 2 | **Brute force then success** - a successful login right after the failures (possible account takeover) | 5+ failures in the 10 min before a success | SUSPICIOUS_ACCESS_ACTIVITY, HIGH (CRITICAL from 10 failures) |
| 3 | **Password spray** - one IP fails against many different accounts | 6+ failures on 3+ accounts in 10 min | AUTHENTICATION_ANOMALY, HIGH (CRITICAL from 10 accounts) |

The rule logic is plain Java in `detection/DetectionRules.java`, so it is easy to test and to extend.
Rule 3 incidents show `IP x.x.x.x` in the User column because they are about an attacker, not one user.

## B2b. Machine learning (trained model)

Besides the 3 rules, the project contains a **supervised machine-learning model** (`ml/` package):

| Step | What happens |
|---|---|
| Data | 5,000 labelled login windows are simulated: normal behaviour (typos, forgotten passwords, remote workers, broken scripts...) and attacks (brute force, distributed, low-and-slow takeover, stuffing, probing). Labels come from the simulated scenario, not from the rules. |
| Features | 8 numbers per window: failed attempts, share failed, different IPs, success after failure, attempts per minute, night time, success from a NEW IP, share of failures from PUBLIC IPs. |
| Training | Logistic regression written from scratch (gradient descent) when the app starts - takes under a second, same result every time. |
| Test | 80% trained, 20% (1,000 windows) kept unseen. The dashboard shows accuracy / precision / recall / F1 of the model **next to the old "5+ failures" rule on the same data**. |
| Use | (1) every incident gets an **ML score** (attack probability); (2) after each upload the model scans every user's logins and creates an incident for patterns **no rule covered**. |

Honest limits: the training data is simulated, so the scores prove the pipeline works but are not real-world accuracy.
A real dataset or analyst feedback (incidents marked false positive) would be the next step.
Switch off with `ML_ENABLED=false`; change sensitivity with `ML_THRESHOLD` (default 0.8).

## B3. Dashboard

The top of the page at `/` shows: total / active / critical incidents, AI-analysed count, logs stored, failed logins,
incidents by severity and status, incidents over time (by attack date) and the top attacking IP addresses.
The numbers come from `GET /api/dashboard/summary` and are calculated in `dashboard/DashboardCalculator.java`.

## C. Main API (all need `Authorization: Bearer <token>` except /api/auth)

| Method | URL | Who | What |
|---|---|---|---|
| POST | /api/auth/register | anyone | creates a plain USER |
| POST | /api/auth/login | anyone | returns the JWT |
| POST | /api/admin/users | ADMIN | create ADMIN / SECURITY_ANALYST / USER |
| GET | /api/admin/users | ADMIN | list users |
| POST | /api/logs/upload | ADMIN, ANALYST | upload CSV (form field `file`) |
| GET | /api/logs | ADMIN, ANALYST | list logs |
| GET | /api/incidents | ADMIN, ANALYST | list (filter `?status=` `?severity=`) |
| GET | /api/incidents/{id} | ADMIN, ANALYST | one incident incl. AI report |
| POST | /api/incidents/{id}/analyze | ADMIN, ANALYST | run the 3 agents now |
| PATCH | /api/incidents/{id}/status | ADMIN, ANALYST | OPEN / UNDER_INVESTIGATION / RESOLVED / CLOSED |
| PATCH | /api/incidents/{id}/assign | ADMIN, ANALYST | assign to an analyst |
| GET | /api/ai/status | ADMIN, ANALYST | LLM or offline mode |
| GET | /api/dashboard/summary | ADMIN, ANALYST | all dashboard numbers |
| GET | /api/ml/status | ADMIN, ANALYST | ML model scores, weights and settings |

---

## D. Settings (all optional - defaults work locally)

Set in Eclipse the same way as the API key (Run Configurations -> Environment).

| Variable | Default | Meaning |
|---|---|---|
| `DB_USERNAME` / `DB_PASSWORD` | `postgres` / `root` | database login |
| `JWT_SECRET` | empty = random per start | base64, 32+ bytes |
| `SEED_ADMIN_PASSWORD` | `Admin@12345` | first admin's password |
| `AI_PROVIDER_API_KEY` | empty = offline mode | your LLM key |
| `AI_MODEL`, `AI_PROVIDER_BASE_URL` | `gpt-4o-mini`, OpenAI | provider settings |
| `AI_AUTO_ANALYZE` | `true` | run agents automatically after upload |
| `FAILED_LOGIN_THRESHOLD` / `DETECTION_WINDOW_MINUTES` | `5` / `10` | rule 1 (and the time window of all rules) |
| `COMPROMISE_MIN_FAILURES` | `5` | rule 2 |
| `SPRAY_MIN_ATTEMPTS` / `SPRAY_MIN_USERS` | `6` / `3` | rule 3 |
| `ML_ENABLED` / `ML_THRESHOLD` | `true` / `0.8` | machine-learning model on/off, and the attack probability needed to create an incident |

## E. Before you deploy (checklist)
- [ ] Set `SEED_ADMIN_PASSWORD` to a strong password (or log in once, create your own admin, then `SEED_ADMIN_ENABLED=false`)
- [ ] Set `JWT_SECRET` (`openssl rand -base64 32`)
- [ ] Set `DB_PASSWORD` to the real database password
- [ ] Set `AI_PROVIDER_API_KEY` (a NEW key, not one that was ever pasted anywhere)
- [ ] In `SecurityConfig.java` change the CORS origin `http://localhost:3000` if you add a separate frontend
- [ ] Use HTTPS in front of the app (the host usually does this)

## F. If something goes wrong

| You see | Meaning / fix |
|---|---|
| `Port 8080 was already in use` | An old run is still alive. Click the red square in every Console tab (also Window -> Show View -> Debug -> Terminate), run again. |
| `password authentication failed` / `no password was provided` | The database password is not `root`. Set `DB_PASSWORD` (Run Configurations -> Environment). |
| `database "cyberguard_db" does not exist` | Do step A2 (create the database in pgAdmin). |
| `Connection refused` to port 5432 | PostgreSQL is not running (Windows Services -> start `postgresql`). |
| Login says "Invalid username or password" for `admin` | If this database was used before, `admin` may already exist with another password (e.g. `Admin@123`). Use that, or set `SEED_ADMIN_USERNAME=boss` and restart to get a fresh admin. |
| Login works but the page says "Not allowed" | That account is a plain USER. In pgAdmin run: `UPDATE users SET role='ADMIN' WHERE username='yourname';` |
| Red errors about `getX()` / `builder()` in Eclipse | Install Lombok into Eclipse (step A3.5). |
| Incident shows `OFFLINE_RULES` although you set a key | Key rejected or network blocked. The Console shows a line "LLM unusable ... (LLM API returned HTTP 401 ...)". |

## G. Test files and what they should produce (on an empty logs/incidents table)

| File | Incidents expected |
|---|---|
| `test-day1-attack-scenarios.csv` (87 rows) | 8: rule 1 x5 (mkhan, rpatel, svc_backup, svc_deploy, svc_report), rule 2 x2 (mkhan, svc_deploy), rule 3 x1 (IP 203.0.113.77) |
| `test-day2-mixed.csv` (27 rows) | 3: rule 1 x2 (mkhan, nina), rule 2 x1 (nina) |
| `test-day3-ml-demo.csv` (31 rows) | 3, all **ML-only** (no rule fires): kavya, deepa, backup_admin. Harmless look-alikes (rohit, meera, asha, vikram, priya) must NOT create incidents. |

To start again from a clean slate, run this in pgAdmin's Query Tool (it keeps your users):
`TRUNCATE TABLE incidents, security_logs RESTART IDENTITY;`
Uploading the same file twice stores the log rows twice, so reset first.

## H. Not built yet
Incident audit history, real-time alerts (email / live updates), unit tests inside the project, training on a real labelled dataset and a React frontend.
The page at `/` is a simple console.
