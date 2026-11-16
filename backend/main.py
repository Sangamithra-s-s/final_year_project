"""
Risk-Adaptive Continuous Authentication - backend (Stages 1-3)
IAM + keystroke ingestion + feature extraction + one-class ML + risk engine + security response.

Run:  uvicorn main:app --reload --port 8000
Docs: http://localhost:8000/docs
"""
import datetime
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from typing import List

import bcrypt
import jwt
import numpy as np
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

import engine

# ----------------------------------------------------------------- config
DB_PATH = os.environ.get("KD_DB", "keystroke_auth.db")
MODELS_DIR = os.environ.get("KD_MODELS", "models")
JWT_SECRET = os.environ.get("KD_JWT_SECRET", "dev-only-secret-change-me-before-any-real-use")
JWT_ALG = "HS256"
JWT_HOURS = 8
MIN_TRAIN_WINDOWS = 30  # enrollment windows needed before a profile can be trained
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
os.makedirs(MODELS_DIR, exist_ok=True)

# ----------------------------------------------------------------- schema
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    role           TEXT NOT NULL DEFAULT 'user'   -- user | admin
);
CREATE TABLE IF NOT EXISTS sessions (
    session_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(user_id),
    login_time   TEXT NOT NULL,
    logout_time  TEXT,
    status       TEXT NOT NULL DEFAULT 'active',  -- active | reauth_required | closed
    risk_floor   INTEGER NOT NULL DEFAULT 0,      -- risk scores up to this id are ignored (reset on re-auth)
    last_seen    TEXT                             -- last typing activity (used to show idle / expire stale sessions)
);
CREATE TABLE IF NOT EXISTS keystroke_events (
    event_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER NOT NULL REFERENCES sessions(session_id),
    segment       INTEGER NOT NULL,
    seq           INTEGER NOT NULL,
    key_code      TEXT NOT NULL,
    press_time    REAL NOT NULL,
    release_time  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ke_session ON keystroke_events(session_id, segment, seq);
CREATE TABLE IF NOT EXISTS feature_vectors (
    vector_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       INTEGER NOT NULL REFERENCES sessions(session_id),
    window_number    INTEGER NOT NULL,
    segment          INTEGER NOT NULL,
    start_idx        INTEGER NOT NULL,            -- window start inside its segment
    phase            TEXT NOT NULL,               -- enrollment | monitoring
    dwell_time       REAL,
    flight_time      REAL,
    typing_speed     REAL,
    dwell_std        REAL,
    flight_std       REAL,
    backspace_ratio  REAL
);
CREATE INDEX IF NOT EXISTS idx_fv_session ON feature_vectors(session_id, segment, start_idx);
CREATE TABLE IF NOT EXISTS behavioral_profiles (
    profile_id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id                  INTEGER NOT NULL REFERENCES users(user_id),
    baseline_feature_summary TEXT,
    n_windows                INTEGER,
    model_path               TEXT,
    created_at               TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS risk_scores (
    score_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id     INTEGER NOT NULL REFERENCES sessions(session_id),
    window_number  INTEGER NOT NULL,
    risk_level     TEXT NOT NULL,
    anomaly_ratio  REAL NOT NULL,
    vote           REAL NOT NULL,
    window_label   TEXT NOT NULL,
    timestamp      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER NOT NULL REFERENCES sessions(session_id),
    risk_level    TEXT NOT NULL,
    action_taken  TEXT NOT NULL,
    timestamp     TEXT NOT NULL
);
"""


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def ensure_schema():
    """A Stage 1 database lacks the new columns: back it up and start fresh."""
    if os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        cols = [r[1] for r in conn.execute("PRAGMA table_info(sessions)")]
        conn.close()
        if cols and "risk_floor" not in cols:
            backup = DB_PATH + ".stage1.bak"
            os.replace(DB_PATH, backup)
            print(f"[schema] old Stage 1 database moved to {backup}; creating a fresh one")
    with db() as c:
        c.executescript(SCHEMA)
        if "role" not in [r[1] for r in c.execute("PRAGMA table_info(users)")]:
            c.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        if "last_seen" not in [r[1] for r in c.execute("PRAGMA table_info(sessions)")]:
            c.execute("ALTER TABLE sessions ADD COLUMN last_seen TEXT")


ensure_schema()

# ----------------------------------------------------------------- app
app = FastAPI(title="Continuous Authentication")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)
bearer = HTTPBearer(auto_error=False)


class Credentials(BaseModel):
    username: str
    password: str


class ReauthBody(BaseModel):
    password: str


class Event(BaseModel):
    key_code: str = Field(min_length=1, max_length=32)
    press_time: float = Field(ge=0)
    release_time: float = Field(ge=0)


class Batch(BaseModel):
    new_segment: bool = False
    events: List[Event] = Field(min_length=1, max_length=200)


# ----------------------------------------------------------------- helpers
def make_token(user_id: int, session_id: int) -> str:
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=JWT_HOURS)
    return jwt.encode({"sub": str(user_id), "sid": session_id, "exp": exp}, JWT_SECRET, algorithm=JWT_ALG)


def hash_pw(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def check_pw(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except ValueError:
        return False


def current(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    if creds is None:
        raise HTTPException(401, "Missing token")
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        user_id, session_id = int(payload["sub"]), int(payload["sid"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(401, "Invalid or expired token")
    with db() as c:
        s = c.execute(
            "SELECT s.session_id, s.user_id, s.status, s.risk_floor, u.username, u.role FROM sessions s "
            "JOIN users u ON u.user_id = s.user_id WHERE s.session_id=? AND s.user_id=?",
            (session_id, user_id),
        ).fetchone()
    if s is None or s["status"] == "closed":
        raise HTTPException(401, "Session closed")
    return dict(s)


ADMIN_USER = os.environ.get("KD_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("KD_ADMIN_PASSWORD", "admin12345")  # dev default: change it


def seed_admin():
    with db() as c:
        if not c.execute("SELECT 1 FROM users WHERE username=?", (ADMIN_USER,)).fetchone():
            c.execute("INSERT INTO users(username, password_hash, created_at, role) VALUES (?,?,?, 'admin')",
                      (ADMIN_USER, hash_pw(ADMIN_PASSWORD), now_iso()))


seed_admin()


def admin_only(auth: dict = Depends(current)) -> dict:
    if auth["role"] != "admin":
        raise HTTPException(403, "Admin only")
    return auth


def latest_profile(c, user_id):
    return c.execute(
        "SELECT * FROM behavioral_profiles WHERE user_id=? ORDER BY profile_id DESC LIMIT 1", (user_id,)
    ).fetchone()


_model_cache = {}


def get_models(profile):
    pid = profile["profile_id"]
    if pid not in _model_cache:
        _model_cache[pid] = engine.load_models(profile["model_path"])
    return _model_cache[pid]


def current_risk(c, session_id, floor):
    r = c.execute(
        "SELECT window_number, risk_level, anomaly_ratio, window_label FROM risk_scores "
        "WHERE session_id=? AND score_id>? ORDER BY score_id DESC LIMIT 1",
        (session_id, floor),
    ).fetchone()
    if r is None:
        return None
    return {
        "window_number": r["window_number"],
        "level": r["risk_level"],
        "ratio": r["anomaly_ratio"],
        "label": r["window_label"],
        "action": engine.action_for(r["risk_level"]),
    }


def process_windows(c, sid: int, uid: int) -> dict:
    """Feature Module -> ML Module -> Risk Engine -> Security Module for every new window."""
    sess = c.execute("SELECT status, risk_floor FROM sessions WHERE session_id=?", (sid,)).fetchone()
    floor, status = sess["risk_floor"], sess["status"]
    prof = latest_profile(c, uid)
    mode = "monitoring" if prof else "enrollment"
    models = get_models(prof) if prof else None

    prev = current_risk(c, sid, floor)
    level_prev = prev["level"] if prev else "low"
    step = engine.STEP_MONITOR if (mode == "monitoring" and level_prev == "medium") else engine.STEP_NORMAL
    span = engine.RISK_WINDOWS * (engine.STEP_NORMAL // step)   # denser windows -> look back proportionally further

    segs = c.execute(
        "SELECT segment, COUNT(*) AS n FROM keystroke_events WHERE session_id=? GROUP BY segment ORDER BY segment",
        (sid,),
    ).fetchall()
    last_start = {
        r["segment"]: r["m"]
        for r in c.execute(
            "SELECT segment, MAX(start_idx) AS m FROM feature_vectors WHERE session_id=? GROUP BY segment", (sid,)
        )
    }
    wn = c.execute("SELECT COUNT(*) AS n FROM feature_vectors WHERE session_id=?", (sid,)).fetchone()["n"]
    votes = [
        r["vote"]
        for r in c.execute(
            "SELECT vote FROM risk_scores WHERE session_id=? AND score_id>? ORDER BY score_id DESC LIMIT ?",
            (sid, floor, engine.RISK_WINDOWS * (engine.STEP_NORMAL // engine.STEP_MONITOR) - 1),
        )
    ][::-1]

    new_windows, scoring, latest = 0, mode == "monitoring", None
    for seg in segs:
        s0 = last_start.get(seg["segment"], -1)
        starts = [s for s in range(0, seg["n"] - engine.WINDOW_SIZE + 1, step) if s > s0]
        if not starts:
            continue
        rows = c.execute(
            "SELECT key_code, press_time, release_time FROM keystroke_events "
            "WHERE session_id=? AND segment=? ORDER BY seq",
            (sid, seg["segment"]),
        ).fetchall()
        ev = [(r["key_code"], r["press_time"], r["release_time"]) for r in rows]
        for s in starts:
            f = engine.extract_features(ev[s : s + engine.WINDOW_SIZE])
            wn += 1
            new_windows += 1
            c.execute(
                "INSERT INTO feature_vectors(session_id, window_number, segment, start_idx, phase, dwell_time, "
                "flight_time, typing_speed, dwell_std, flight_std, backspace_ratio) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (sid, wn, seg["segment"], s, mode, f["dwell_time"], f["flight_time"], f["typing_speed"],
                 f["dwell_std"], f["flight_std"], f["backspace_ratio"]),
            )
            if not scoring:
                continue
            label, vote = engine.score_window(models, [f[k] for k in engine.FEATURES])
            votes.append(vote)
            ratio, level = engine.risk_from_votes(votes, span)
            ts = now_iso()
            c.execute(
                "INSERT INTO risk_scores(session_id, window_number, risk_level, anomaly_ratio, vote, window_label, timestamp) "
                "VALUES (?,?,?,?,?,?,?)",
                (sid, wn, level, ratio, vote, label, ts),
            )
            latest = {"window_number": wn, "level": level, "ratio": ratio, "label": label,
                      "action": engine.action_for(level)}
            if level == "high":
                c.execute("UPDATE sessions SET status='reauth_required' WHERE session_id=?", (sid,))
                c.execute("INSERT INTO alerts(session_id, risk_level, action_taken, timestamp) VALUES (?,?,?,?)",
                          (sid, "high", engine.action_for("high"), ts))
                status, scoring = "reauth_required", False  # stop scoring, still record remaining windows
            elif level == "medium" and level_prev != "medium":
                c.execute("INSERT INTO alerts(session_id, risk_level, action_taken, timestamp) VALUES (?,?,?,?)",
                          (sid, "medium", engine.action_for("medium"), ts))
            level_prev = level
    return {"mode": mode, "session_status": status, "new_windows": new_windows,
            "risk": latest or current_risk(c, sid, floor)}


def fit_profile(c, uid: int):
    """Train + save both models on a user's enrollment windows. Returns (profile_id, n_windows, models, summary)."""
    cols = ", ".join(f"fv.{f}" for f in engine.FEATURES)
    rows = c.execute(
        f"SELECT {cols} FROM feature_vectors fv JOIN sessions s ON s.session_id=fv.session_id "
        "WHERE s.user_id=? AND fv.phase='enrollment' ORDER BY fv.vector_id",
        (uid,),
    ).fetchall()
    if len(rows) < MIN_TRAIN_WINDOWS:
        raise HTTPException(400, f"Need at least {MIN_TRAIN_WINDOWS} enrollment windows, have {len(rows)}")
    X = np.array([[r[f] for f in engine.FEATURES] for r in rows], dtype=float)
    models = engine.train_models(X)
    summary = {f: {"mean": float(X[:, i].mean()), "std": float(X[:, i].std())} for i, f in enumerate(engine.FEATURES)}
    cur = c.execute(
        "INSERT INTO behavioral_profiles(user_id, baseline_feature_summary, n_windows, created_at) VALUES (?,?,?,?)",
        (uid, json.dumps(summary), len(rows), now_iso()),
    )
    pid = cur.lastrowid
    path = os.path.join(MODELS_DIR, f"user{uid}_profile{pid}.joblib")
    engine.save_models(path, models)
    c.execute("UPDATE behavioral_profiles SET model_path=? WHERE profile_id=?", (path, pid))
    return pid, len(rows), models, summary


FEATURE_VERSION = 2  # 2 = robust features (modifier keys excluded, medians) + drift-aware training


def migrate_features():
    """Older databases hold features computed the old way. Raw keystrokes are stored, so recompute every
    window's features and retrain profiles, then close sessions left open by earlier versions."""
    with db() as c:
        if c.execute("PRAGMA user_version").fetchone()[0] >= FEATURE_VERSION:
            return
        rows = c.execute("SELECT vector_id, session_id, segment, start_idx FROM feature_vectors "
                         "ORDER BY session_id, segment, start_idx").fetchall()
        key, ev = None, []
        for r in rows:
            if (r["session_id"], r["segment"]) != key:
                key = (r["session_id"], r["segment"])
                ev = [(e["key_code"], e["press_time"], e["release_time"]) for e in c.execute(
                    "SELECT key_code, press_time, release_time FROM keystroke_events "
                    "WHERE session_id=? AND segment=? ORDER BY seq", key)]
            f = engine.extract_features(ev[r["start_idx"]: r["start_idx"] + engine.WINDOW_SIZE])
            c.execute("UPDATE feature_vectors SET dwell_time=?, flight_time=?, typing_speed=?, dwell_std=?, "
                      "flight_std=?, backspace_ratio=? WHERE vector_id=?",
                      (f["dwell_time"], f["flight_time"], f["typing_speed"], f["dwell_std"], f["flight_std"],
                       f["backspace_ratio"], r["vector_id"]))
        for u in c.execute("SELECT DISTINCT user_id FROM behavioral_profiles").fetchall():
            try:
                fit_profile(c, u["user_id"])
            except HTTPException:
                pass
        c.execute("UPDATE sessions SET status='closed', logout_time=? WHERE status != 'closed'", (now_iso(),))
        c.execute(f"PRAGMA user_version = {FEATURE_VERSION}")
        print(f"[migrate] recomputed {len(rows)} windows with the robust features and retrained profiles")


migrate_features()


# ----------------------------------------------------------------- IAM
@app.get("/")
def root():
    return {"service": "Continuous Authentication API", "docs": "/docs"}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/auth/register", status_code=201)
def register(body: Credentials):
    if not USERNAME_RE.match(body.username):
        raise HTTPException(400, "Username: 3-32 chars, letters/digits/._- only")
    if len(body.password) < 8 or len(body.password.encode()) > 72:
        raise HTTPException(400, "Password must be 8-72 characters")
    try:
        with db() as c:
            c.execute("INSERT INTO users(username, password_hash, created_at) VALUES (?,?,?)",
                      (body.username, hash_pw(body.password), now_iso()))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Username already taken")
    return {"message": "Registered"}


@app.post("/auth/login")
def login(body: Credentials):
    with db() as c:
        u = c.execute("SELECT * FROM users WHERE username=?", (body.username,)).fetchone()
        if u is None or not check_pw(body.password, u["password_hash"]):
            raise HTTPException(401, "Invalid credentials")
        t = now_iso()
        # one open session per user: signing in again closes any earlier session of the same user
        c.execute("UPDATE sessions SET status='closed', logout_time=? WHERE user_id=? AND status != 'closed'",
                  (t, u["user_id"]))
        cur = c.execute("INSERT INTO sessions(user_id, login_time, status, last_seen) VALUES (?,?, 'active', ?)",
                        (u["user_id"], t, t))
        sid = cur.lastrowid
        no = session_no(c, sid)
    return {"token": make_token(u["user_id"], sid), "session_id": sid, "session_no": no,
            "username": u["username"], "role": u["role"]}


@app.post("/auth/logout")
def logout(auth: dict = Depends(current)):
    with db() as c:
        c.execute("UPDATE sessions SET status='closed', logout_time=? WHERE session_id=?",
                  (now_iso(), auth["session_id"]))
    return {"message": "Session closed"}


@app.get("/auth/me")
def me(auth: dict = Depends(current)):
    return {"username": auth["username"], "role": auth["role"], "session_id": auth["session_id"], "status": auth["status"]}


@app.post("/sessions/{session_id}/reauth")
def reauth(session_id: int, body: ReauthBody, auth: dict = Depends(current)):
    """Password re-check. Session returns to 'active' and the risk history restarts."""
    if session_id != auth["session_id"]:
        raise HTTPException(403, "Not your session")
    with db() as c:
        u = c.execute("SELECT password_hash FROM users WHERE user_id=?", (auth["user_id"],)).fetchone()
        if not check_pw(body.password, u["password_hash"]):
            raise HTTPException(401, "Wrong password")
        floor = c.execute("SELECT COALESCE(MAX(score_id),0) AS m FROM risk_scores WHERE session_id=?",
                          (session_id,)).fetchone()["m"]
        c.execute("UPDATE sessions SET status='active', risk_floor=? WHERE session_id=?", (floor, session_id))
        c.execute("INSERT INTO alerts(session_id, risk_level, action_taken, timestamp) VALUES (?,?,?,?)",
                  (session_id, "low", "reauthenticated", now_iso()))
    return {"status": "active"}


@app.post("/sessions/{session_id}/force-reauth")
def force_reauth(session_id: int, auth: dict = Depends(current)):
    """Manual test hook (the Security Module does this automatically on High risk)."""
    if session_id != auth["session_id"]:
        raise HTTPException(403, "Not your session")
    with db() as c:
        c.execute("UPDATE sessions SET status='reauth_required' WHERE session_id=?", (session_id,))
        c.execute("INSERT INTO alerts(session_id, risk_level, action_taken, timestamp) VALUES (?,?,?,?)",
                  (session_id, "high", "forced_reauth", now_iso()))
    return {"status": "reauth_required"}


# ----------------------------------------------------------------- Keystrokes + live pipeline
@app.post("/keystrokes")
def ingest(batch: Batch, auth: dict = Depends(current)):
    if auth["status"] != "active":
        raise HTTPException(423, "Re-authentication required")
    for e in batch.events:
        if e.release_time < e.press_time:
            raise HTTPException(400, "release_time before press_time")
    sid = auth["session_id"]
    with db() as c:
        last = c.execute(
            "SELECT COALESCE(MAX(seq), -1) AS s, COALESCE(MAX(segment), -1) AS g FROM keystroke_events WHERE session_id=?",
            (sid,),
        ).fetchone()
        seq0 = last["s"] + 1
        segment = last["g"] + 1 if (batch.new_segment or last["g"] == -1) else last["g"]
        c.executemany(
            "INSERT INTO keystroke_events(session_id, segment, seq, key_code, press_time, release_time) VALUES (?,?,?,?,?,?)",
            [(sid, segment, seq0 + i, e.key_code, e.press_time, e.release_time) for i, e in enumerate(batch.events)],
        )
        total = c.execute("SELECT COUNT(*) AS n FROM keystroke_events WHERE session_id=?", (sid,)).fetchone()["n"]
        c.execute("UPDATE sessions SET last_seen=? WHERE session_id=?", (now_iso(), sid))
        result = process_windows(c, sid, auth["user_id"])
    return {"stored": len(batch.events), "segment": segment, "total_events": total, **result}


@app.get("/sessions/current/stats")
def stats(auth: dict = Depends(current)):
    with db() as c:
        segs = c.execute("SELECT COUNT(DISTINCT segment) AS n, COUNT(*) AS e FROM keystroke_events WHERE session_id=?",
                         (auth["session_id"],)).fetchone()
        wins = c.execute("SELECT COUNT(*) AS n FROM feature_vectors WHERE session_id=?",
                         (auth["session_id"],)).fetchone()["n"]
        status = c.execute("SELECT status FROM sessions WHERE session_id=?", (auth["session_id"],)).fetchone()["status"]
    return {"session_id": auth["session_id"], "status": status, "event_count": segs["e"],
            "segments": segs["n"], "windows_formed": wins}


@app.get("/keystrokes/recent")
def recent(limit: int = 15, auth: dict = Depends(current)):
    limit = max(1, min(limit, 100))
    with db() as c:
        rows = c.execute(
            "SELECT event_id, segment, seq, key_code, press_time, release_time FROM keystroke_events "
            "WHERE session_id=? ORDER BY event_id DESC LIMIT ?",
            (auth["session_id"], limit),
        ).fetchall()
    return [dict(r) for r in rows]


# ----------------------------------------------------------------- Profile (enrollment + training)
@app.get("/profile")
def profile_status(auth: dict = Depends(current)):
    with db() as c:
        n = c.execute(
            "SELECT COUNT(*) AS n FROM feature_vectors fv JOIN sessions s ON s.session_id=fv.session_id "
            "WHERE s.user_id=? AND fv.phase='enrollment'",
            (auth["user_id"],),
        ).fetchone()["n"]
        p = latest_profile(c, auth["user_id"])
    return {"enrolled": p is not None, "enrollment_windows": n, "min_windows": MIN_TRAIN_WINDOWS,
            "trained_at": p["created_at"] if p else None, "trained_on": p["n_windows"] if p else None}


@app.post("/profile/train")
def train_profile(auth: dict = Depends(current)):
    """Train Isolation Forest + One-Class SVM on this user's enrollment windows only."""
    with db() as c:
        pid, n, models, summary = fit_profile(c, auth["user_id"])
        floor = c.execute("SELECT COALESCE(MAX(score_id),0) AS m FROM risk_scores WHERE session_id=?",
                          (auth["session_id"],)).fetchone()["m"]
        c.execute("UPDATE sessions SET risk_floor=? WHERE session_id=?", (floor, auth["session_id"]))
    _model_cache[pid] = models
    return {"trained": True, "windows": n, "summary": summary}


# ----------------------------------------------------------------- Risk + alerts (for the UI)
@app.get("/sessions/current/risk")
def risk(limit: int = 40, auth: dict = Depends(current)):
    limit = max(1, min(limit, 200))
    sid = auth["session_id"]
    with db() as c:
        floor = c.execute("SELECT risk_floor FROM sessions WHERE session_id=?", (sid,)).fetchone()["risk_floor"]
        prof = latest_profile(c, auth["user_id"])
        tl = c.execute(
            "SELECT window_number, risk_level, anomaly_ratio, window_label, timestamp FROM risk_scores "
            "WHERE session_id=? ORDER BY score_id DESC LIMIT ?",
            (sid, limit),
        ).fetchall()
        al = c.execute(
            "SELECT risk_level, action_taken, timestamp FROM alerts WHERE session_id=? ORDER BY alert_id DESC LIMIT 10",
            (sid,),
        ).fetchall()
        cur = current_risk(c, sid, floor)
    return {"mode": "monitoring" if prof else "enrollment", "current": cur,
            "timeline": [dict(r) for r in tl][::-1], "alerts": [dict(r) for r in al]}


# ----------------------------------------------------------------- Admin dashboard API
STALE_MINUTES = 30   # open sessions with no typing for this long are closed automatically
IDLE_SECONDS = 90    # shown as Idle in the dashboard after this long without typing


def session_no(c, session_id: int) -> int:
    """Per-user session number: Sara's 1st session is 1, her 2nd is 2, whatever other users did in between.
    (session_id is the global database id and is not shown to people.)"""
    return c.execute("SELECT COUNT(*) AS n FROM sessions s2 WHERE s2.user_id=(SELECT user_id FROM sessions WHERE session_id=?) "
                     "AND s2.session_id<=?", (session_id, session_id)).fetchone()["n"]


def idle_seconds(ts):
    t = datetime.datetime.fromisoformat(ts)
    return int((datetime.datetime.now(datetime.timezone.utc) - t).total_seconds())


@app.get("/admin/overview")
def admin_overview(_: dict = Depends(admin_only)):
    with db() as c:
        q = lambda sql: c.execute(sql).fetchone()[0]
        return {
            "users": q("SELECT COUNT(*) FROM users WHERE role='user'"),
            "enrolled": q("SELECT COUNT(DISTINCT user_id) FROM behavioral_profiles"),
            "active_sessions": q("SELECT COUNT(*) FROM sessions s JOIN users u ON u.user_id=s.user_id "
                                 "WHERE u.role='user' AND s.status IN ('active','reauth_required')"),
            "locked_sessions": q("SELECT COUNT(*) FROM sessions s JOIN users u ON u.user_id=s.user_id "
                                 "WHERE u.role='user' AND s.status='reauth_required'"),
            "events": q("SELECT COUNT(*) FROM keystroke_events"),
            "windows": q("SELECT COUNT(*) FROM feature_vectors"),
            "high_alerts": q("SELECT COUNT(*) FROM alerts WHERE risk_level='high'"),
        }


@app.get("/admin/sessions")
def admin_sessions(limit: int = 50, _: dict = Depends(admin_only)):
    limit = max(1, min(limit, 200))
    with db() as c:
        cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=STALE_MINUTES)).isoformat(timespec="seconds")
        c.execute("UPDATE sessions SET status='closed', logout_time=? WHERE status != 'closed' "
                  "AND COALESCE(last_seen, login_time) < ?", (now_iso(), cutoff))
        rows = c.execute(
            "SELECT s.session_id, s.user_id, u.username, s.status, s.login_time, s.logout_time, s.risk_floor, s.last_seen, "
            "(SELECT COUNT(*) FROM sessions s2 WHERE s2.user_id=s.user_id AND s2.session_id<=s.session_id) AS session_no, "
            "(SELECT COUNT(*) FROM keystroke_events k WHERE k.session_id=s.session_id) AS events, "
            "(SELECT COUNT(*) FROM feature_vectors f WHERE f.session_id=s.session_id) AS windows, "
            "EXISTS(SELECT 1 FROM behavioral_profiles b WHERE b.user_id=s.user_id) AS enrolled "
            "FROM sessions s JOIN users u ON u.user_id=s.user_id WHERE u.role='user' "
            "ORDER BY (s.status='closed'), s.session_id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["enrolled"] = bool(d["enrolled"])
            d["risk"] = current_risk(c, r["session_id"], r["risk_floor"]) if d["enrolled"] else None
            d["idle_seconds"] = idle_seconds(r["last_seen"] or r["login_time"])
            d["timeline"] = []
            if d["enrolled"] and r["status"] != "closed":
                d["timeline"] = [dict(t) for t in c.execute(
                    "SELECT window_number, risk_level, anomaly_ratio FROM risk_scores WHERE session_id=? "
                    "ORDER BY score_id DESC LIMIT 30", (r["session_id"],))][::-1]
            del d["risk_floor"]
            out.append(d)
    return out


@app.get("/admin/sessions/{session_id}/timeline")
def admin_timeline(session_id: int, _: dict = Depends(admin_only)):
    with db() as c:
        s = c.execute("SELECT s.session_id, s.user_id, s.risk_floor, s.last_seen, s.login_time, u.username, s.status FROM sessions s "
                      "JOIN users u ON u.user_id=s.user_id WHERE s.session_id=?", (session_id,)).fetchone()
        if s is None:
            raise HTTPException(404, "No such session")
        tl = c.execute("SELECT window_number, risk_level, anomaly_ratio, window_label, timestamp FROM risk_scores "
                       "WHERE session_id=? ORDER BY score_id DESC LIMIT 60", (session_id,)).fetchall()
        al = c.execute("SELECT risk_level, action_taken, timestamp FROM alerts WHERE session_id=? "
                       "ORDER BY alert_id DESC LIMIT 15", (session_id,)).fetchall()
        enrolled = latest_profile(c, s["user_id"]) is not None
        cur = current_risk(c, session_id, s["risk_floor"]) if enrolled else None
        no = session_no(c, session_id)
    return {"session_id": s["session_id"], "session_no": no, "username": s["username"], "status": s["status"],
            "enrolled": enrolled, "current": cur, "idle_seconds": idle_seconds(s["last_seen"] or s["login_time"]),
            "timeline": [dict(r) for r in tl][::-1], "alerts": [dict(r) for r in al]}


@app.get("/admin/sessions/{session_id}/keystrokes")
def admin_keystrokes(session_id: int, limit: int = 50, _: dict = Depends(admin_only)):
    """Raw keystroke history (key codes and timings only) for one session. Full data: table keystroke_events."""
    limit = max(1, min(limit, 500))
    with db() as c:
        total = c.execute("SELECT COUNT(*) AS n FROM keystroke_events WHERE session_id=?", (session_id,)).fetchone()["n"]
        rows = c.execute("SELECT event_id, segment, seq, key_code, press_time, release_time FROM keystroke_events "
                         "WHERE session_id=? ORDER BY event_id DESC LIMIT ?", (session_id, limit)).fetchall()
    return {"total": total, "events": [dict(r) for r in rows]}


@app.get("/admin/alerts")
def admin_alerts(limit: int = 30, _: dict = Depends(admin_only)):
    limit = max(1, min(limit, 200))
    with db() as c:
        rows = c.execute(
            "SELECT a.alert_id, a.session_id, u.username, a.risk_level, a.action_taken, a.timestamp, "
            "(SELECT COUNT(*) FROM sessions s2 WHERE s2.user_id=s.user_id AND s2.session_id<=s.session_id) AS session_no "
            "FROM alerts a "
            "JOIN sessions s ON s.session_id=a.session_id JOIN users u ON u.user_id=s.user_id "
            "ORDER BY a.alert_id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


@app.get("/admin/users")
def admin_users(_: dict = Depends(admin_only)):
    with db() as c:
        rows = c.execute(
            "SELECT u.user_id, u.username, u.created_at, "
            "(SELECT COUNT(*) FROM sessions s WHERE s.user_id=u.user_id) AS sessions, "
            "(SELECT MAX(login_time) FROM sessions s WHERE s.user_id=u.user_id) AS last_login, "
            "(SELECT COUNT(*) FROM feature_vectors f JOIN sessions s ON s.session_id=f.session_id "
            " WHERE s.user_id=u.user_id AND f.phase='enrollment') AS enrollment_windows, "
            "EXISTS(SELECT 1 FROM behavioral_profiles b WHERE b.user_id=u.user_id) AS enrolled "
            "FROM users u WHERE u.role='user' ORDER BY u.user_id").fetchall()
    return [{**dict(r), "enrolled": bool(r["enrolled"])} for r in rows]


@app.post("/admin/sessions/{session_id}/force-reauth")
def admin_force_reauth(session_id: int, _: dict = Depends(admin_only)):
    with db() as c:
        s = c.execute("SELECT status FROM sessions WHERE session_id=?", (session_id,)).fetchone()
        if s is None or s["status"] == "closed":
            raise HTTPException(404, "No open session with that id")
        c.execute("UPDATE sessions SET status='reauth_required' WHERE session_id=?", (session_id,))
        c.execute("INSERT INTO alerts(session_id, risk_level, action_taken, timestamp) VALUES (?,?,?,?)",
                  (session_id, "high", "admin_forced_reauth", now_iso()))
    return {"status": "reauth_required"}


@app.post("/admin/sessions/{session_id}/end")
def admin_end_session(session_id: int, _: dict = Depends(admin_only)):
    with db() as c:
        s = c.execute("SELECT status FROM sessions WHERE session_id=?", (session_id,)).fetchone()
        if s is None or s["status"] == "closed":
            raise HTTPException(404, "No open session with that id")
        c.execute("UPDATE sessions SET status='closed', logout_time=? WHERE session_id=?", (now_iso(), session_id))
        c.execute("INSERT INTO alerts(session_id, risk_level, action_taken, timestamp) VALUES (?,?,?,?)",
                  (session_id, "high", "admin_ended_session", now_iso()))
    return {"status": "closed"}
