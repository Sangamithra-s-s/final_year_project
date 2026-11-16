# Risk-Adaptive Continuous Authentication (Review 1 build: Stages 1-3)

IAM + privacy-preserving keystroke capture + feature extraction + Isolation Forest / One-Class SVM
+ Risk Engine (Low/Medium/High) + Security Module (continue / increase monitoring / re-authenticate).

## Run (two terminals)
**Backend**
```
cd backend
python -m venv .venv
.venv\Scripts\activate        # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
**Frontend**
```
cd frontend
npm install
npm run dev
```
Open http://localhost:5173. An old Stage 1 database is backed up automatically (`.stage1.bak`).

Note: the risk gauge, timeline and alerts are admin-only (an impostor should not see how suspicious they look). Users see only the lock popup.

## Accounts
- **Admin:** `admin` / `admin12345` (created automatically; change with `KD_ADMIN_USER` / `KD_ADMIN_PASSWORD`).
  Signing in as admin opens the admin dashboard: KPIs, live sessions (refresh every 3 s), session drill-down,
  Lock and End actions, alert feed, users and enrollment status.
- **Users:** register on the login page.

## Using it
1. Register, sign in, type in the box (2+ sessions, several minutes in total).
2. When "Windows collected" reaches 30, click **Train my profile**. Mode switches to Monitoring.
3. Keep typing as yourself: risk stays Low. Let someone else type in the same session: risk climbs to High,
   the session locks, and the re-auth modal appears. Enter the password to continue.

## Pipeline (matches the sequence diagram)
keystrokes -> windows (30 keys, step 15) -> 6 features -> Isolation Forest + One-Class SVM vote per window
-> Risk Engine (anomaly ratio over last 5 windows: <0.3 Low, 0.3-0.6 Medium, >0.6 High; needs >=3 windows)
-> Security Module (Low: continue; Medium: check every 5 keys instead of 15; High: lock + re-auth + alert).

Features: mean/std dwell, mean/std flight, typing speed, backspace ratio.
Window vote: 0 (both models normal), 0.5 (one flags), 1 (both flag).
Models are trained only on the user's own enrollment windows, saved with joblib in `backend/models/`.

## Evaluation (the results table for the review)
Download the CMU benchmark CSV (DSL-StrongPasswordData.csv), put it in `backend/`, then:
```
python evaluate.py --cmu DSL-StrongPasswordData.csv --out results_cmu.csv
python evaluate.py --db keystroke_auth.db --out results_own.csv     # your own collected windows
```
It prints EER per model, single-sample vs 5-window FAR/FRR, genuine lockout rate, impostor detection rate
and detection latency. `--synthetic` only checks that the script runs; never report its numbers.

## Design decisions
- key_code only, never typed text. performance.now() timestamps. Held-key repeats ignored.
- Events stored once (segment, seq); windows are built server-side. A >2 s pause ends a segment.
- After re-auth the risk history restarts, so the genuine user is not instantly re-locked.
- Enrollment windows and monitoring windows are stored separately, so impostor typing never enters training.
- Limitation: capture works only inside the app page (browser-only).

## Config
`KD_DB`, `KD_MODELS`, `KD_JWT_SECRET` (set a real one outside dev), `VITE_API_URL`.

## Viewing the database (DB Browser for SQLite)
1. Open DB Browser for SQLite, then File > Open Database Read Only (Ctrl+Shift+O). Read-only avoids locking the file while the app runs.
2. Pick `backend/keystroke_auth.db` (created in the folder where you started uvicorn).
3. Browse Data tab: choose a table from the dropdown. Press F5 (or the Refresh button) after typing to see new rows.
4. Execute SQL tab: paste queries below and press Ctrl+Enter.

Useful queries:
```sql
SELECT user_id, username, role, created_at FROM users;
SELECT session_id, user_id, status, login_time, logout_time FROM sessions ORDER BY session_id DESC;
SELECT session_id, COUNT(*) AS events FROM keystroke_events GROUP BY session_id;
SELECT segment, seq, key_code, ROUND(release_time - press_time, 1) AS dwell_ms FROM keystroke_events ORDER BY event_id DESC LIMIT 20;
SELECT * FROM feature_vectors ORDER BY vector_id DESC LIMIT 20;
SELECT * FROM risk_scores ORDER BY score_id DESC LIMIT 20;
SELECT a.timestamp, u.username, a.risk_level, a.action_taken FROM alerts a JOIN sessions s ON s.session_id=a.session_id JOIN users u ON u.user_id=s.user_id ORDER BY a.alert_id DESC;
```
Trained models are separate files in `backend/models/`. To start clean, stop the backend and delete `keystroke_auth.db`.

## Version notes (v4): why normal typing was being flagged
- Features are now robust: Shift/Ctrl/Alt keys are ignored, dwell and flight use the median, spreads use the IQR,
  speed ignores thinking pauses. (Before, one held Shift key or one pause could distort a whole window.)
- Models are trained with slightly faster/slower copies of your windows (+-12%), so a normal change in typing
  speed between sessions is not treated as an intruder.
- At Medium risk the check runs every 5 keys, and the risk looks back over 15 windows, so the evidence still covers
  about the same amount of typing.
- Dashboard: sessions with no typing for 90 s show as Idle; open sessions idle for 30 min are closed automatically.
- First start after upgrading: stored windows are recomputed from the raw keystrokes and profiles are retrained
  automatically; everyone signs in again. No data is lost.
- Simulated-typing check (assumptions are mine, not measured on people): genuine typing reached Medium or higher
  about 18% of the time and High about 1%, with about 93% of impostors caught. Real results will differ.

## Session numbers
The dashboard numbers sessions per user: `sara #1`, `sara #2`, ... The database column `sessions.session_id` is a global
counter shared by all users, so it can differ (hover a session number in the table to see its database id).
