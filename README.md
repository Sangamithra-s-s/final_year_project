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
