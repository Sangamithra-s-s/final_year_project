"""
evaluate.py - benchmark evaluation of the one-class detectors and the risk engine.

Usage (run from the backend folder):
  python evaluate.py --cmu DSL-StrongPasswordData.csv      # CMU benchmark (public dataset)
  python evaluate.py --db keystroke_auth.db                # your own self-collected windows
  python evaluate.py --synthetic                           # plumbing check ONLY, not results

Protocol (per genuine user, one-class: models never see impostor data):
  train on the first part of the user's samples, test on the rest (genuine),
  impostors = other users' samples (first --imp samples of each other user).

Reported per user, then averaged:
  EER_iso / EER_svm / EER_ens   single-sample EER (score based, threshold-free)
  EER_ens_k                     EER after averaging scores over k consecutive samples (drift tolerance)
  FAR1 / FRR1                   single-sample decision (ensemble, either model flags)
  lockout                       risk engine (5-window): share of genuine positions that reach HIGH
  detect / latency              share of impostor streams reaching HIGH, mean samples until HIGH
"""
import argparse
import sqlite3
import sys

import numpy as np
import pandas as pd

import engine


# ------------------------------------------------------------- data loaders
def load_cmu(path):
    df = pd.read_csv(path)
    df = df.sort_values(["subject", "sessionIndex", "rep"])
    feats = [c for c in df.columns if c not in ("subject", "sessionIndex", "rep")]
    return {s: g[feats].to_numpy(float) for s, g in df.groupby("subject")}


def load_db(path):
    conn = sqlite3.connect(path)
    cols = ", ".join(f"fv.{f}" for f in engine.FEATURES)
    rows = conn.execute(
        f"SELECT u.username, {cols} FROM feature_vectors fv JOIN sessions s ON s.session_id=fv.session_id "
        "JOIN users u ON u.user_id=s.user_id ORDER BY fv.vector_id"
    ).fetchall()
    conn.close()
    data = {}
    for r in rows:
        data.setdefault(r[0], []).append(r[1:])
    return {u: np.array(v, float) for u, v in data.items() if len(v) >= 40}


def synthetic(n_users=12, n=300, d=12, seed=0):
    rng = np.random.default_rng(seed)
    base = rng.normal(0.2, 0.05, d)
    out = {}
    for i in range(n_users):
        mu = base + rng.normal(0, 0.03, d)
        out[f"u{i}"] = np.abs(rng.normal(mu, 0.02, (n, d)))
    return out


# ------------------------------------------------------------- metrics
def far_frr_eer(gen, imp):
    """gen/imp are anomaly scores (higher = more suspicious). Threshold sweep."""
    gen, imp = np.sort(gen), np.sort(imp)
    th = np.unique(np.concatenate([gen, imp]))
    frr = 1.0 - np.searchsorted(gen, th, side="right") / len(gen)   # genuine rejected
    far = np.searchsorted(imp, th, side="right") / len(imp)         # impostor accepted
    i = int(np.argmin(np.abs(far - frr)))
    return float((far[i] + frr[i]) / 2)


def rolling_mean(a, k):
    a = np.asarray(a, float)
    if len(a) < k:
        return np.array([])
    return np.convolve(a, np.ones(k) / k, mode="valid")


def run_levels(votes):
    """Risk levels after every sample of a stream (what the live Risk Engine would output)."""
    return [engine.risk_from_votes(votes[: i + 1])[1] for i in range(len(votes))]


def evaluate_user(user, data, n_train, n_imp, k, augment=False):
    X = data[user]
    Xtr, Xg = X[:n_train], X[n_train:]
    models = engine.train_models(Xtr, augment=augment)   # drift augmentation only fits our own 6 features

    def raw(M):
        return {"iso": -models["iso"].decision_function(M), "svm": -models["svm"].decision_function(M)}

    tr = raw(Xtr)
    mu = {m: tr[m].mean() for m in tr}
    sd = {m: (tr[m].std() or 1.0) for m in tr}

    def scores(M):
        r = raw(M)
        r["ens"] = sum((r[m] - mu[m]) / sd[m] for m in ("iso", "svm")) / 2
        return r

    G = scores(Xg)
    streams = [data[o][:n_imp] for o in data if o != user]
    I = [scores(S) for S in streams]
    out = {}
    for m in ("iso", "svm", "ens"):
        out[f"EER_{m}"] = far_frr_eer(G[m], np.concatenate([s[m] for s in I]))
    g_k = rolling_mean(G["ens"], k)
    i_k = np.concatenate([rolling_mean(s["ens"], k) for s in I])
    out["EER_ens_k"] = far_frr_eer(g_k, i_k) if len(g_k) and len(i_k) else np.nan

    vg = engine.votes_for(models, Xg)
    vi = [engine.votes_for(models, S) for S in streams]
    out["FRR1"] = float((vg >= 0.5).mean())
    out["FAR1"] = float(np.mean(np.concatenate([(v < 0.5) for v in vi])))
    lv_g = run_levels(list(vg))
    out["lockout"] = float(np.mean([l == "high" for l in lv_g]))
    first = []
    for v in vi:
        lv = run_levels(list(v))
        first.append(lv.index("high") + 1 if "high" in lv else None)
    hit = [f for f in first if f is not None]
    out["detect"] = len(hit) / len(first)
    out["latency"] = float(np.mean(hit)) if hit else np.nan
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmu")
    ap.add_argument("--db")
    ap.add_argument("--synthetic", action="store_true")
    ap.add_argument("--train-frac", type=float, default=0.5, help="share of each user's samples used for training")
    ap.add_argument("--imp", type=int, default=20, help="impostor samples taken from each other user (5 = classic CMU)")
    ap.add_argument("--k", type=int, default=5, help="aggregation window for EER_ens_k")
    ap.add_argument("--out", default="results.csv")
    a = ap.parse_args()

    if a.cmu:
        data, name = load_cmu(a.cmu), "CMU benchmark"
    elif a.db:
        data, name = load_db(a.db), "self-collected"
    elif a.synthetic:
        data, name = synthetic(), "SYNTHETIC (plumbing check only)"
    else:
        sys.exit("Give one of --cmu PATH, --db PATH or --synthetic")
    if len(data) < 3:
        sys.exit(f"Need at least 3 users, found {len(data)}")

    rows = {}
    for u in data:
        n_train = int(len(data[u]) * a.train_frac)
        rows[u] = evaluate_user(u, data, n_train, a.imp, a.k, augment=bool(a.db))
        print(f"  done {u}", file=sys.stderr)
    df = pd.DataFrame(rows).T
    df.to_csv(a.out)

    m, s = df.mean(), df.std()
    print(f"\nDataset: {name}   users: {len(df)}   train fraction: {a.train_frac}   impostor samples/user: {a.imp}\n")
    print("| Metric | Mean | Std |\n|---|---|---|")
    labels = {
        "EER_iso": "EER, Isolation Forest (single sample)",
        "EER_svm": "EER, One-Class SVM (single sample)",
        "EER_ens": "EER, ensemble (single sample)",
        "EER_ens_k": f"EER, ensemble averaged over {a.k} samples",
        "FAR1": "FAR, single-sample decision",
        "FRR1": "FRR, single-sample decision",
        "lockout": "Genuine lockout rate, 5-window risk engine",
        "detect": "Impostor detection rate (reaches HIGH)",
        "latency": "Detection latency (samples until HIGH)",
    }
    for key, lab in labels.items():
        print(f"| {lab} | {m[key]:.4f} | {s[key]:.4f} |")
    print(f"\nPer-user results saved to {a.out}")


if __name__ == "__main__":
    main()
