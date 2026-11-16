"""
engine.py - Feature Module + ML Module + Risk Engine + Security Module logic.
Pure functions: no database, no HTTP. Used by main.py (live system) and evaluate.py.
"""
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

# ------------------------------------------------------------- parameters
WINDOW_SIZE = 30      # keystrokes per window
STEP_NORMAL = 15      # 50% overlap
STEP_MONITOR = 5      # "increase monitoring": 3x more frequent checks
FEATURES = ["dwell_time", "dwell_std", "flight_time", "flight_std", "typing_speed", "backspace_ratio"]

RISK_WINDOWS = 5      # sliding window over the last N window votes
MIN_EVIDENCE = 3      # never judge on fewer windows (drift tolerance)
LOW_MAX = 0.3         # ratio <  0.3          -> low
HIGH_MIN = 0.6        # ratio >  0.6          -> high, otherwise medium

ACTIONS = {"collecting": "continue", "low": "continue", "medium": "increase_monitoring", "high": "reauthenticate"}


# ------------------------------------------------------------- Feature Module
# Modifier keys (Shift, Ctrl, Alt, ...) are held while other keys are typed, so their "dwell" measures how long
# the NEXT letters take, not the user's rhythm. They are left out of the timing features.
MODIFIERS = {"ShiftLeft", "ShiftRight", "ControlLeft", "ControlRight", "AltLeft", "AltRight",
             "MetaLeft", "MetaRight", "CapsLock", "ContextMenu"}
DWELL_CAP_MS = 500       # a key held longer than this is not typing rhythm
FLIGHT_MIN_MS = -150     # overlap deeper than this is noise
FLIGHT_CAP_MS = 1000     # a gap longer than this is a thinking pause, not rhythm


def _spread(a):
    """Interquartile range: a spread measure that one outlier cannot blow up."""
    q1, q3 = np.percentile(a, [25, 75])
    return float(q3 - q1)


def extract_features(events):
    """events: list of (key_code, press_time_ms, release_time_ms) -> one feature dict (robust version).

    Column names are kept for the database, but the meaning is robust:
      dwell_time / flight_time  = MEDIAN (not mean)       dwell_std / flight_std = IQR (not standard deviation)
      typing_speed              = 60000 / median press-to-press interval (pauses do not slow it)
      backspace_ratio           = share of Backspace among non-modifier keys
    Events are sorted by press_time first (they are stored in release order)."""
    ev = sorted(events, key=lambda e: e[1])
    keys = [e for e in ev if e[0] not in MODIFIERS]
    if len(keys) < 5:
        keys = ev
    press = np.array([e[1] for e in keys], dtype=float)
    release = np.array([e[2] for e in keys], dtype=float)
    dwell = np.clip(release - press, 0, DWELL_CAP_MS)
    flight = np.clip(press[1:] - release[:-1], FLIGHT_MIN_MS, FLIGHT_CAP_MS)
    interval = np.clip(np.diff(press), 20, FLIGHT_CAP_MS)
    return {
        "dwell_time": float(np.median(dwell)),
        "dwell_std": _spread(dwell),
        "flight_time": float(np.median(flight)),
        "flight_std": _spread(flight),
        "typing_speed": float(60000.0 / max(np.median(interval), 20.0)),
        "backspace_ratio": sum(1 for e in keys if e[0] == "Backspace") / len(keys),
    }


# ------------------------------------------------------------- ML Module
TIMING_COLS = [0, 1, 2, 3]   # dwell_time, dwell_std, flight_time, flight_std (FEATURES order)
SPEED_COL = 4                # typing_speed
DRIFT_FACTORS = (0.88, 0.94, 1.0, 1.06, 1.12)   # people type a little faster/slower from session to session


def augment_for_drift(X, factors=DRIFT_FACTORS):
    """Training copies at slightly different tempo: timings x s, speed / s. Teaches the models that a
    slightly faster or slower session is still the same person (drift tolerance), while a different
    typing style is still far outside."""
    X = np.asarray(X, dtype=float)
    out = []
    for s in factors:
        Y = X.copy()
        Y[:, TIMING_COLS] *= s
        Y[:, SPEED_COL] /= s
        out.append(Y)
    return np.vstack(out)


def train_models(X, contamination=0.05, nu=0.05, augment=True):
    """Fit both one-class models on the legitimate user's own windows only."""
    X = np.asarray(X, dtype=float)
    if augment:
        X = augment_for_drift(X)
    iso = make_pipeline(
        StandardScaler(),
        IsolationForest(n_estimators=200, contamination=contamination, random_state=42),
    ).fit(X)
    svm = make_pipeline(StandardScaler(), OneClassSVM(kernel="rbf", gamma="scale", nu=nu)).fit(X)
    return {"iso": iso, "svm": svm}


def votes_for(models, X):
    """Per-window vote in {0, 0.5, 1}: the share of models that flag the window as anomalous."""
    X = np.atleast_2d(np.asarray(X, dtype=float))
    iso = (models["iso"].predict(X) == -1).astype(float)
    svm = (models["svm"].predict(X) == -1).astype(float)
    return (iso + svm) / 2.0


def label_for(vote):
    return "anomaly" if vote >= 1.0 else "suspicious" if vote >= 0.5 else "normal"


def score_window(models, x):
    vote = float(votes_for(models, np.asarray(x, dtype=float).reshape(1, -1))[0])
    return label_for(vote), vote


def save_models(path, models):
    joblib.dump(models, path)


def load_models(path):
    return joblib.load(path)


# ------------------------------------------------------------- Risk Engine
def risk_from_votes(votes, span=RISK_WINDOWS):
    """votes: window votes, oldest first. Aggregates the last `span` votes into (ratio, level).
    span is RISK_WINDOWS normally, and 3x larger when windows are 3x denser (step 5), so the evidence
    always covers about the same amount of typing."""
    recent = list(votes)[-span:]
    if not recent:
        return 0.0, "low"
    ratio = round(sum(recent) / len(recent), 4)
    if len(recent) < MIN_EVIDENCE:
        return ratio, "collecting"   # not enough windows to judge yet
    if ratio > HIGH_MIN:
        return ratio, "high"
    if ratio >= LOW_MAX:
        return ratio, "medium"
    return ratio, "low"


# ------------------------------------------------------------- Security Module
def action_for(level):
    return ACTIONS[level]
