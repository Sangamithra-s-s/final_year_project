/*
 * Continuous Authentication - Stage 1 frontend (self-contained, one file)
 *  - Login / Register (IAM)
 *  - useKeystrokeCapture hook: records ONLY key_code + press/release time, never typed text
 *  - Collector page with live capture panel and "stored in database" panel
 *  - Enrollment (train your profile) + live risk badge, timeline and alerts
 *  - Re-authentication modal (opened automatically when the Risk Engine says HIGH)
 */
import { useCallback, useEffect, useRef, useState } from "react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const WINDOW_SIZE = 30; // keystrokes per window (50% overlap -> step 15)
const STEP = 15;
const PAUSE_MS = 2000; // a gap longer than this ends the current segment

const PROMPTS = [
  "The quiet harbour woke slowly as the first fishing boats slipped out past the lighthouse. Gulls circled above the market stalls, where vendors stacked crates of ice and silver fish while the smell of salt and diesel drifted over the water.",
  "Learning to code feels like learning a new language. At first every line is a struggle, but patterns start to appear, and one evening a program you wrote runs correctly on the very first try and the whole afternoon suddenly feels worth it.",
  "Write a few sentences about your favourite place to study, what you usually eat while working, and the one tool or habit that helps you focus. Type naturally, there is no right or wrong answer.",
];

/* ------------------------------------------------------------------ api */
async function api(path, { method = "GET", body, token } = {}) {
  const res = await fetch(API + path, {
    method,
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* empty body */
  }
  if (!res.ok) {
    const msg = typeof data?.detail === "string" ? data.detail : "Please check your input";
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return data;
}

/* ------------------------------------------------- keystroke capture hook */
/*
 * Records key_code (e.code, e.g. "KeyA"), press_time, release_time in ms from performance.now().
 * Privacy: e.key and the textarea value are never read or stored.
 * - repeated keydown events from a held key are ignored (e.repeat)
 * - events are emitted on keyup, so they arrive in release order; the Feature
 *   Module (Stage 2) must sort by press_time before computing flight times
 * - chunks of STEP events are emitted; a pause > PAUSE_MS flushes the partial
 *   chunk and marks the next chunk as a new segment
 */
function useKeystrokeCapture({ onChunk, onEvent }) {
  const pressed = useRef(new Map());
  const buffer = useRef([]);
  const newSegment = useRef(true);
  const timer = useRef(null);
  const cb = useRef({ onChunk, onEvent });
  cb.current = { onChunk, onEvent };

  const flush = useCallback(() => {
    if (buffer.current.length === 0) return;
    const events = buffer.current;
    buffer.current = [];
    cb.current.onChunk({ new_segment: newSegment.current, events });
    newSegment.current = false;
  }, []);

  const onKeyDown = useCallback((e) => {
    if (e.repeat || e.isComposing) return;
    clearTimeout(timer.current);
    if (!pressed.current.has(e.code)) pressed.current.set(e.code, performance.now());
  }, []);

  const onKeyUp = useCallback(
    (e) => {
      const p = pressed.current.get(e.code);
      if (p === undefined) return;
      pressed.current.delete(e.code);
      const ev = {
        key_code: e.code,
        press_time: Math.round(p * 100) / 100,
        release_time: Math.round(performance.now() * 100) / 100,
      };
      buffer.current.push(ev);
      cb.current.onEvent(ev);
      if (buffer.current.length >= STEP) flush();
      clearTimeout(timer.current);
      timer.current = setTimeout(() => {
        flush();
        newSegment.current = true;
      }, PAUSE_MS);
    },
    [flush]
  );

  const onBlur = useCallback(() => pressed.current.clear(), []);

  useEffect(() => () => clearTimeout(timer.current), []);

  return { onKeyDown, onKeyUp, onBlur, flush };
}

/* ------------------------------------------------------------- auth view */
function AuthScreen({ onAuthed }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [info, setInfo] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setErr("");
    setInfo("");
    setBusy(true);
    try {
      if (mode === "register") {
        await api("/auth/register", { method: "POST", body: { username, password } });
        setInfo("Account created. You can sign in now.");
        setMode("login");
        setPassword("");
      } else {
        const r = await api("/auth/login", { method: "POST", body: { username, password } });
        onAuthed({ token: r.token, sessionId: r.session_id, username: r.username });
      }
    } catch (ex) {
      setErr(ex.message === "Failed to fetch" ? "Cannot reach the server. Is the backend running on port 8000?" : ex.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="center">
      <form className="card auth" onSubmit={submit}>
        <h1>Continuous Authentication</h1>
        <p className="muted">Keystroke dynamics based identity verification</p>
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={mode === "login" ? "current-password" : "new-password"}
            required
          />
        </label>
        {mode === "register" && <p className="hint">3-32 characters for the username, at least 8 for the password.</p>}
        {err && <p className="error">{err}</p>}
        {info && <p className="ok">{info}</p>}
        <button className="primary" disabled={busy}>
          {busy ? "Please wait..." : mode === "login" ? "Sign in" : "Create account"}
        </button>
        <button
          type="button"
          className="link"
          onClick={() => {
            setMode(mode === "login" ? "register" : "login");
            setErr("");
            setInfo("");
          }}
        >
          {mode === "login" ? "No account? Register" : "Have an account? Sign in"}
        </button>
      </form>
    </div>
  );
}

/* ------------------------------------------------------ re-auth modal */
function ReauthModal({ auth, onDone, onLogout }) {
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");

  async function submit(e) {
    e.preventDefault();
    setErr("");
    try {
      await api(`/sessions/${auth.sessionId}/reauth`, { method: "POST", body: { password }, token: auth.token });
      onDone();
    } catch (ex) {
      setErr(ex.message);
    }
  }

  return (
    <div className="overlay">
      <form className="card modal" onSubmit={submit}>
        <h2>Verify it's you</h2>
        <p className="muted">Unusual activity was detected in this session. Enter your password to continue.</p>
        <input type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" />
        {err && <p className="error">{err}</p>}
        <div className="row">
          <button className="primary">Continue session</button>
          <button type="button" className="ghost" onClick={onLogout}>
            Sign out
          </button>
        </div>
      </form>
    </div>
  );
}

/* ------------------------------------------------------- collector page */
const avg = (a) => (a.length ? a.reduce((s, x) => s + x, 0) / a.length : 0);

function Collector({ auth, onLogout }) {
  const [promptIdx, setPromptIdx] = useState(0);
  const [live, setLive] = useState([]); // last WINDOW_SIZE local events with dwell / flight
  const [captured, setCaptured] = useState(0);
  const [stats, setStats] = useState({ event_count: 0, segments: 0, windows_formed: 0 });
  const [dbRows, setDbRows] = useState([]);
  const [profile, setProfile] = useState({ enrolled: false, enrollment_windows: 0, min_windows: 30 });
  const [riskInfo, setRiskInfo] = useState({ mode: "enrollment", current: null, timeline: [], alerts: [] });
  const [training, setTraining] = useState(false);
  const [locked, setLocked] = useState(false);
  const [err, setErr] = useState("");
  const lastRelease = useRef(null);

  const refresh = useCallback(async () => {
    try {
      const [s, r, p, k] = await Promise.all([
        api("/sessions/current/stats", { token: auth.token }),
        api("/keystrokes/recent?limit=10", { token: auth.token }),
        api("/profile", { token: auth.token }),
        api("/sessions/current/risk?limit=40", { token: auth.token }),
      ]);
      setStats(s);
      setDbRows(r);
      setProfile(p);
      setRiskInfo(k);
      setLocked(s.status === "reauth_required");
    } catch (ex) {
      if (ex.status === 401) onLogout();
    }
  }, [auth.token, onLogout]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const onChunk = useCallback(
    async (chunk) => {
      try {
        const r = await api("/keystrokes", { method: "POST", body: chunk, token: auth.token });
        setErr("");
        if (r.session_status === "reauth_required") setLocked(true);
        refresh();
      } catch (ex) {
        if (ex.status === 423) setLocked(true);
        else if (ex.status === 401) onLogout();
        else setErr(ex.message);
      }
    },
    [auth.token, refresh, onLogout]
  );

  const onEvent = useCallback((ev) => {
    const flight = lastRelease.current === null ? null : Math.round((ev.press_time - lastRelease.current) * 10) / 10;
    lastRelease.current = ev.release_time;
    const row = { ...ev, dwell: Math.round((ev.release_time - ev.press_time) * 10) / 10, flight };
    setLive((l) => [...l.slice(-(WINDOW_SIZE - 1)), row]);
    setCaptured((c) => c + 1);
  }, []);

  const { onKeyDown, onKeyUp, onBlur, flush } = useKeystrokeCapture({ onChunk, onEvent });

  const flights = live.map((r) => r.flight).filter((f) => f !== null);
  const span = live.length > 1 ? live[live.length - 1].release_time - live[0].press_time : 0;
  const speed = span > 0 && span < 60000 && live.length >= 5 ? Math.round((live.length / span) * 60000) : null;

  async function finish() {
    flush();
    try {
      await api("/auth/logout", { method: "POST", token: auth.token });
    } catch {
      /* session may already be closed */
    }
    onLogout();
  }

  async function trainProfile() {
    flush();
    setTraining(true);
    setErr("");
    try {
      await api("/profile/train", { method: "POST", token: auth.token });
      await refresh();
    } catch (ex) {
      setErr(ex.message);
    } finally {
      setTraining(false);
    }
  }

  async function simulateHighRisk() {
    flush();
    try {
      await api(`/sessions/${auth.sessionId}/force-reauth`, { method: "POST", token: auth.token });
      setLocked(true);
    } catch (ex) {
      setErr(ex.message);
    }
  }

  return (
    <div className="page">
      <header>
        <div>
          <strong>Continuous Authentication</strong>
          <span className="muted"> &middot; Data collector</span>
        </div>
        <div className="row">
          <span className={`badge ${locked ? "bad" : "good"}`}>{locked ? "Re-auth required" : "Session active"}</span>
          <span className="badge mode">{riskInfo.mode === "monitoring" ? "Monitoring" : "Enrollment"}</span>
          <span className="muted">
            {auth.username} &middot; session #{auth.sessionId}
          </span>
          <button className="ghost" onClick={finish}>
            Finish &amp; sign out
          </button>
        </div>
      </header>

      <p className="consent">
        Only key timings (which key, when pressed, when released) are recorded for this study. What you type is never stored.
        By typing here you consent to this.
      </p>

      <div className="stats">
        <Stat label="Keys captured" value={captured} />
        <Stat label="Stored in DB" value={stats.event_count} />
        <Stat label="Segments" value={stats.segments} />
        <Stat label={`Windows (${WINDOW_SIZE}/${STEP})`} value={stats.windows_formed} />
        <Stat label="Avg dwell (ms)" value={live.length ? avg(live.map((r) => r.dwell)).toFixed(0) : "-"} />
        <Stat label="Avg flight (ms)" value={flights.length ? avg(flights).toFixed(0) : "-"} />
        <Stat label="Speed (keys/min)" value={speed ?? "-"} />
      </div>

      <div className="grid2">
        <EnrollPanel profile={profile} mode={riskInfo.mode} training={training} onTrain={trainProfile} />
        <RiskPanel info={riskInfo} />
      </div>

      <div className="card">
        <div className="between">
          <h3>Type this passage (or anything you like)</h3>
          <button className="ghost" onClick={() => setPromptIdx((promptIdx + 1) % PROMPTS.length)}>
            Next passage
          </button>
        </div>
        <p className="prompt">{PROMPTS[promptIdx]}</p>
        <textarea
          rows={6}
          placeholder="Start typing here..."
          spellCheck={false}
          autoComplete="off"
          autoCorrect="off"
          disabled={locked}
          onKeyDown={onKeyDown}
          onKeyUp={onKeyUp}
          onBlur={onBlur}
        />
        {err && <p className="error">{err}</p>}
        <div className="row">
          <button className="ghost" onClick={simulateHighRisk}>
            Simulate high risk (test)
          </button>
        </div>
      </div>

      <div className="grid2">
        <div className="card">
          <h3>Live capture (browser)</h3>
          <Table
            head={["Key", "Dwell ms", "Flight ms"]}
            rows={live.slice(-10).reverse().map((r) => [r.key_code, r.dwell, r.flight ?? "-"])}
          />
        </div>
        <div className="card">
          <h3>Stored in database</h3>
          <Table
            head={["Seg", "Seq", "Key", "Press", "Release"]}
            rows={dbRows.map((r) => [r.segment, r.seq, r.key_code, r.press_time, r.release_time])}
          />
        </div>
      </div>

      {locked && (
        <ReauthModal
          auth={auth}
          onDone={() => {
            setLocked(false);
            refresh();
          }}
          onLogout={finish}
        />
      )}
    </div>
  );
}

function EnrollPanel({ profile, mode, training, onTrain }) {
  const pct = Math.min(100, Math.round((profile.enrollment_windows / profile.min_windows) * 100));
  const ready = profile.enrollment_windows >= profile.min_windows;
  return (
    <div className="card">
      <h3>Behavioral profile</h3>
      {mode === "monitoring" ? (
        <p className="ok">
          Profile trained on {profile.trained_on} windows. Every new window is now scored by Isolation Forest and
          One-Class SVM.
        </p>
      ) : (
        <p className="muted">
          Type normally across a few minutes (ideally 2+ sessions). Windows collected: {profile.enrollment_windows} /{" "}
          {profile.min_windows} minimum.
        </p>
      )}
      <div className="bar">
        <div className="bar-fill" style={{ width: `${mode === "monitoring" ? 100 : pct}%` }} />
      </div>
      <div className="row" style={{ marginTop: 10 }}>
        <button className="primary" disabled={!ready || training} onClick={onTrain}>
          {training ? "Training..." : mode === "monitoring" ? "Retrain profile" : "Train my profile"}
        </button>
        {mode !== "monitoring" && <span className="hint">Models use only your own data, no impostor data.</span>}
      </div>
    </div>
  );
}

const LEVEL_TEXT = {
  low: "Low risk: continue session",
  medium: "Medium risk: monitoring increased (checks every 5 keys)",
  high: "High risk: re-authentication required",
};

function RiskPanel({ info }) {
  const cur = info.current;
  return (
    <div className="card">
      <h3>Session risk</h3>
      {info.mode !== "monitoring" ? (
        <p className="muted">Risk scoring starts after the profile is trained.</p>
      ) : !cur ? (
        <p className="muted">Waiting for enough typing (about 3 windows) before judging.</p>
      ) : (
        <>
          <div className={`risk risk-${cur.level}`}>{LEVEL_TEXT[cur.level]}</div>
          <p className="hint" style={{ marginTop: 6 }}>
            Anomaly ratio {cur.ratio} over the last 5 windows &middot; latest window: {cur.label}
          </p>
        </>
      )}
      <div className="timeline" title="Anomaly ratio per scored window">
        {info.timeline.map((t) => (
          <div
            key={t.window_number}
            className={`tbar risk-bg-${t.risk_level}`}
            style={{ height: `${Math.max(6, t.anomaly_ratio * 100)}%` }}
            title={`window ${t.window_number}: ${t.risk_level} (${t.anomaly_ratio})`}
          />
        ))}
      </div>
      {info.alerts.length > 0 && (
        <div className="alerts">
          {info.alerts.slice(0, 4).map((a, i) => (
            <div key={i} className="alert-row">
              <span className={`dot risk-bg-${a.risk_level}`} />
              {a.action_taken.replace(/_/g, " ")} <span className="muted">{a.timestamp.slice(11, 19)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Stat({ label, value }) {
  return (
    <div className="stat">
      <div className="stat-v">{value}</div>
      <div className="stat-l">{label}</div>
    </div>
  );
}

function Table({ head, rows }) {
  return (
    <div className="tablewrap">
      <table>
        <thead>
          <tr>
            {head.map((h) => (
              <th key={h}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={head.length} className="muted">
                No events yet
              </td>
            </tr>
          ) : (
            rows.map((r, i) => (
              <tr key={i}>
                {r.map((c, j) => (
                  <td key={j}>{c}</td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

/* ------------------------------------------------------------------ app */
export default function App() {
  const [auth, setAuth] = useState(() => {
    try {
      return JSON.parse(sessionStorage.getItem("kd_auth"));
    } catch {
      return null;
    }
  });

  const handleAuthed = (a) => {
    sessionStorage.setItem("kd_auth", JSON.stringify(a));
    setAuth(a);
  };
  const handleLogout = useCallback(() => {
    sessionStorage.removeItem("kd_auth");
    setAuth(null);
  }, []);

  return auth ? <Collector auth={auth} onLogout={handleLogout} /> : <AuthScreen onAuthed={handleAuthed} />;
}
