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

ACTIONS = {"low": "continue", "medium": "increase_monitoring", "high": "reauthenticate"}


# ------------------------------------------------------------- Feature Module
def extract_features(events):
    """events: list of (key_code, press_time_ms, release_time_ms). Returns one feature dict.
    Events are sorted by press_time first (they are stored in release order)."""
    ev = sorted(events, key=lambda e: e[1])
    press = np.array([e[1] for e in ev], dtype=float)
    release = np.array([e[2] for e in ev], dtype=float)
    dwell = release - press
    flight = press[1:] - release[:-1]          # negative = overlapping keys (kept on purpose)
    span = max(release.max() - press[0], 1.0)
    return {
        "dwell_time": float(dwell.mean()),
        "dwell_std": float(dwell.std()),
        "flight_time": float(flight.mean()),
        "flight_std": float(flight.std()),
        "typing_speed": float(len(ev) / span * 60000.0),   # keys per minute
        "backspace_ratio": sum(1 for e in ev if e[0] == "Backspace") / len(ev),
    }


# ------------------------------------------------------------- ML Module
def train_models(X, contamination=0.05, nu=0.05):
    """Fit both one-class models on the legitimate user's own windows only."""
    X = np.asarray(X, dtype=float)
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
def risk_from_votes(votes):
    """votes: window votes, oldest first. Aggregates the last RISK_WINDOWS into (ratio, level)."""
    recent = list(votes)[-RISK_WINDOWS:]
    if not recent:
        return 0.0, "low"
    ratio = round(sum(recent) / len(recent), 4)
    if len(recent) < MIN_EVIDENCE:
        return ratio, "low"
    if ratio > HIGH_MIN:
        return ratio, "high"
    if ratio >= LOW_MAX:
        return ratio, "medium"
    return ratio, "low"


# ------------------------------------------------------------- Security Module
def action_for(level):
    return ACTIONS[level]
