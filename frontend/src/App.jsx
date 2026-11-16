/*
 * Continuous Authentication - frontend (self-contained, one file)
 *  - Auth screen (login / register); role decides the app: user workspace or admin dashboard
 *  - User workspace: typing collector, enrollment + training, live risk gauge, timeline, alerts, re-auth modal
 *  - Admin dashboard: KPIs, live sessions (auto-refresh), session drill-down, lock / end session, alerts feed, users
 *  - useKeystrokeCapture records ONLY key_code + press/release time; typed text is never read
 */
import { useCallback, useEffect, useRef, useState } from "react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const WINDOW_SIZE = 30;
const STEP = 15;
const PAUSE_MS = 2000;
const POLL_MS = 3000;
const IDLE_SECONDS = 90; /* no typing for this long: the risk shown is the last known one, not live */

/* One fixed paragraph: 502 characters is about 32 windows (30 keys per window, step 15). */
const PARAGRAPH =
  "The quiet harbour woke slowly as the first fishing boats slipped out past the lighthouse. Gulls circled above the market stalls, where vendors stacked crates of ice and silver fish while the smell of salt and diesel drifted over the water. By noon the sun was high, the streets were busy, and children raced along the pier, laughing as the waves crashed against the old stone wall. In the evening, the lamps flickered on one by one, and the whole town settled into a calm and peaceful night by the sea.";
const TARGET_WINDOWS = 30;

const LEVELS = {
  collecting: { name: "Collecting", note: "Needs 3 scored windows before judging" },
  low: { name: "Low risk", note: "Session continues normally" },
  medium: { name: "Medium risk", note: "Monitoring increased: checks every 5 keys" },
  high: { name: "High risk", note: "Re-authentication required" },
};
const ACTION_TEXT = {
  reauthenticate: "Locked: re-authentication required",
  increase_monitoring: "Monitoring increased",
  reauthenticated: "User re-authenticated",
  forced_reauth: "Re-auth forced (test)",
  admin_forced_reauth: "Admin forced re-authentication",
  admin_ended_session: "Admin ended the session",
  continue: "Continue",
};

/* ------------------------------------------------------------------ helpers */
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
    const err = new Error(typeof data?.detail === "string" ? data.detail : "Please check your input");
    err.status = res.status;
    throw err;
  }
  return data;
}
const clock = (iso) => (iso ? new Date(iso).toLocaleTimeString() : "-");
const avg = (a) => (a.length ? a.reduce((s, x) => s + x, 0) / a.length : 0);
const netError = (m) => (m === "Failed to fetch" ? "Cannot reach the server. Is the backend running on port 8000?" : m);

/* ------------------------------------------------- keystroke capture hook */
/* Records key_code (e.code), press_time, release_time (ms, performance.now()). Held-key repeats ignored.
   Events arrive on keyup (release order); the Feature Module sorts by press_time. Chunks of STEP events are
   emitted; a pause > PAUSE_MS flushes the partial chunk and starts a new segment. */
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

/* ------------------------------------------------------------ small UI bits */
function Badge({ kind = "idle", children }) {
  return <span className={`badge b-${kind}`}>{children}</span>;
}

function Gauge({ ratio }) {
  return (
    <div className="gauge" role="img" aria-label={`Anomaly ratio ${ratio}`}>
      <div className="zones">
        <i className="z-low" style={{ width: "30%" }} />
        <i className="z-medium" style={{ width: "30%" }} />
        <i className="z-high" style={{ width: "40%" }} />
      </div>
      <div className="marker" style={{ left: `${Math.min(100, Math.max(0, ratio * 100))}%` }} />
      <div className="ticks">
        <span>0</span>
        <span style={{ left: "30%" }}>0.3</span>
        <span style={{ left: "60%" }}>0.6</span>
        <span style={{ left: "100%" }}>1</span>
      </div>
    </div>
  );
}

function Timeline({ items, empty = "No scored windows yet" }) {
  if (!items.length) return <div className="tl-empty">{empty}</div>;
  return (
    <div className="timeline" title="Anomaly ratio per scored window">
      {items.map((t) => (
        <div
          key={t.window_number}
          className={`tbar bg-${t.risk_level}`}
          style={{ height: `${Math.max(8, t.anomaly_ratio * 100)}%` }}
          title={`window ${t.window_number}: ${t.risk_level} (${t.anomaly_ratio})`}
        />
      ))}
    </div>
  );
}

function AlertList({ alerts, withUser }) {
  if (!alerts.length) return <p className="muted small">No alerts yet.</p>;
  return (
    <ul className="alerts">
      {alerts.map((a, i) => (
        <li key={a.alert_id ?? i}>
          <span className={`dot bg-${a.risk_level}`} />
          <span className="grow">
            {withUser && (
              <strong>
                {a.username} #{a.session_no}{" "}
              </strong>
            )}
            {ACTION_TEXT[a.action_taken] || a.action_taken}
          </span>
          <span className="muted small">{clock(a.timestamp)}</span>
        </li>
      ))}
    </ul>
  );
}

function Table({ head, rows, empty = "Nothing here yet" }) {
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
                {empty}
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

function TopBar({ role, user, right }) {
  return (
    <header className="topbar">
      <div className="brand">
        <span className="logo">KD</span>
        <div>
          <strong>Continuous Authentication</strong>
          <div className="brand-sub">{role === "admin" ? "Administrator console" : "Keystroke dynamics session guard"}</div>
        </div>
      </div>
      <div className="row">
        {right}
        <span className="who">{user}</span>
      </div>
    </header>
  );
}

/* ------------------------------------------------------------- auth screen */
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
        setInfo("Account created. Sign in to continue.");
        setMode("login");
        setPassword("");
      } else {
        const r = await api("/auth/login", { method: "POST", body: { username, password } });
        onAuthed({ token: r.token, sessionId: r.session_id, sessionNo: r.session_no, username: r.username, role: r.role });
      }
    } catch (ex) {
      setErr(netError(ex.message));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="split">
      <section className="hero">
        <span className="logo big">KD</span>
        <h1>Your session stays yours.</h1>
        <p>Passwords check you once. This system keeps checking how you type, and reacts when someone else takes over.</p>
        <ul className="points">
          <li>Learns your typing rhythm from timings only</li>
          <li>Never stores what you type</li>
          <li>Responds in steps: continue, watch closely, re-authenticate</li>
        </ul>
      </section>
      <section className="formside">
        <form className="card auth" onSubmit={submit}>
          <h2>{mode === "login" ? "Sign in" : "Create your account"}</h2>
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
          {mode === "register" && <p className="hint">Username 3-32 characters, password at least 8.</p>}
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
            {mode === "login" ? "New here? Create an account" : "Have an account? Sign in"}
          </button>
        </form>
      </section>
    </div>
  );
}

/* ------------------------------------------------------------ re-auth modal */
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
        <div className="lock-ic">!</div>
        <h2>Verify it's you</h2>
        <p className="muted">Your typing looks different from usual, so this session is paused. Enter your password to continue.</p>
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

function Tile({ label, value }) {
  return (
    <div className="tile">
      <div className="tile-v">{value}</div>
      <div className="tile-l">{label}</div>
    </div>
  );
}

/* ----------------------------------------------------------- user workspace */
function Workspace({ auth, onLogout }) {
  const [live, setLive] = useState([]);
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
    const id = setInterval(refresh, 4000); /* also picks up an admin forcing re-auth */
    return () => clearInterval(id);
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
        else setErr(netError(ex.message));
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
  const monitoring = riskInfo.mode === "monitoring";
  const pct = Math.min(100, Math.round((profile.enrollment_windows / profile.min_windows) * 100));
  const ready = profile.enrollment_windows >= profile.min_windows;

  async function finish() {
    flush();
    try {
      await api("/auth/logout", { method: "POST", token: auth.token });
    } catch {
      /* already closed */
    }
    onLogout();
  }

  async function train() {
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
    <>
      <TopBar
        user={`${auth.username} · session #${auth.sessionNo ?? auth.sessionId}`}
        right={
          <>
            <Badge kind={locked ? "high" : "low"}>{locked ? "Re-auth required" : "Session active"}</Badge>
            <Badge kind="info">{monitoring ? "Monitoring" : "Enrollment"}</Badge>
            <button className="ghost light" onClick={finish}>
              Finish and sign out
            </button>
          </>
        }
      />
      <main className="page">
        <p className="consent">Only key timings (which key, when pressed, when released) are recorded. What you type is never stored.</p>

        <div className="cols">
          <div className="stack">
            <section className="card">
              <h3>Type this paragraph</h3>
              <p className="hint">Type it once at your natural pace. It gives about 30 windows, the minimum needed to train your profile.</p>
              <p className="prompt">{PARAGRAPH}</p>
              <div className="bar">
                <div className="bar-fill" style={{ width: `${Math.min(100, Math.round((stats.windows_formed / TARGET_WINDOWS) * 100))}%` }} />
              </div>
              <p className="small muted" style={{ margin: "4px 0 0" }}>
                {stats.windows_formed} of {TARGET_WINDOWS} windows from this session
              </p>
              <textarea
                rows={7}
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
              <div className="tiles">
                <Tile label="Keys captured" value={captured} />
                <Tile label="Stored in DB" value={stats.event_count} />
                <Tile label={`Windows (${WINDOW_SIZE}/${STEP})`} value={stats.windows_formed} />
                <Tile label="Avg dwell" value={live.length ? `${avg(live.map((r) => r.dwell)).toFixed(0)} ms` : "-"} />
                <Tile label="Avg flight" value={flights.length ? `${avg(flights).toFixed(0)} ms` : "-"} />
                <Tile label="Speed" value={speed ? `${speed}/min` : "-"} />
              </div>
              <div className="row" style={{ marginTop: 12 }}>
                <button className="ghost" onClick={simulateHighRisk}>
                  Simulate high risk (test)
                </button>
              </div>
            </section>

            <details className="card">
              <summary>Under the hood: captured and stored data</summary>
              <div className="grid2" style={{ marginTop: 12 }}>
                <div>
                  <h4>Live capture (browser)</h4>
                  <Table
                    head={["Key", "Dwell ms", "Flight ms"]}
                    rows={live.slice(-8).reverse().map((r) => [r.key_code, r.dwell, r.flight ?? "-"])}
                    empty="No keys yet"
                  />
                </div>
                <div>
                  <h4>Stored in database</h4>
                  <Table
                    head={["Seg", "Seq", "Key", "Press", "Release"]}
                    rows={dbRows.map((r) => [r.segment, r.seq, r.key_code, r.press_time, r.release_time])}
                    empty="No rows yet"
                  />
                </div>
              </div>
            </details>
          </div>

          <div className="stack">
            <section className="card">
              <h3>Behavioral profile</h3>
              {monitoring ? (
                <p className="ok">Trained on {profile.trained_on} windows. Isolation Forest and One-Class SVM score every new window.</p>
              ) : (
                <p className="muted">
                  Type for a few minutes, ideally across 2 or more sessions. {profile.enrollment_windows} of {profile.min_windows} windows collected.
                </p>
              )}
              <div className="bar">
                <div className="bar-fill" style={{ width: `${monitoring ? 100 : pct}%` }} />
              </div>
              <div className="row" style={{ marginTop: 12 }}>
                <button className="primary" disabled={!ready || training} onClick={train}>
                  {training ? "Training..." : monitoring ? "Retrain profile" : "Train my profile"}
                </button>
              </div>
            </section>

          </div>
        </div>
      </main>

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
    </>
  );
}

/* ---------------------------------------------------------- admin dashboard */
function Kpi({ label, value, tone = "" }) {
  return (
    <div className={`kpi ${tone}`}>
      <div className="kpi-v">{value ?? "-"}</div>
      <div className="kpi-l">{label}</div>
    </div>
  );
}

function RiskMeter({ s, selected, onSelect }) {
  const cur = s.risk;
  const idle = s.idle_seconds > IDLE_SECONDS;
  return (
    <div className={`card meter${selected ? " picked" : ""}`} onClick={() => onSelect(s.session_id)}>
      <div className="between">
        <strong>
          {s.username} <span className="muted small">session #{s.session_no}</span>
        </strong>
        {s.status === "reauth_required" ? <Badge kind="high">Locked</Badge> : idle ? <Badge>Idle</Badge> : <Badge kind="low">Active</Badge>}
      </div>
      {!s.enrolled ? (
        <p className="muted small">Profile not trained yet: learning mode, no risk scoring.</p>
      ) : !cur ? (
        <p className="muted small">No windows scored yet.</p>
      ) : (
        <>
          <div className={`riskbox r-${cur.level}${idle ? " stale" : ""}`}>
            <div className="risk-name">{LEVELS[cur.level].name}</div>
            <div>{LEVELS[cur.level].note}</div>
          </div>
          <p className="small muted" style={{ margin: "8px 0 4px" }}>
            Anomaly ratio {cur.ratio} over the last 5 windows. Latest window: {cur.label}.
          </p>
          {cur.level !== "collecting" && <Gauge ratio={cur.ratio} />}
          <Timeline items={s.timeline} />
        </>
      )}
    </div>
  );
}

function SessionRiskCard({ detail, onClose }) {
  if (!detail)
    return (
      <section className="card">
        <h3>Session risk</h3>
        <p className="muted">Select a session in the table to see its risk.</p>
      </section>
    );
  const cur = detail.current;
  const ended = detail.status === "closed";
  const idle = !ended && detail.idle_seconds > IDLE_SECONDS;
  const stale = ended || idle;
  return (
    <section className="card">
      <div className="between">
        <h3>
          Session risk · {detail.username} #{detail.session_no}
        </h3>
        <button className="mini" onClick={onClose}>
          Close
        </button>
      </div>
      {!detail.enrolled ? (
        <p className="muted">This user has no trained profile yet, so the session is not scored.</p>
      ) : !cur ? (
        <p className="muted">No windows scored yet.</p>
      ) : (
        <>
          {stale && (
            <p className="stale-note">
              {ended ? "Session ended." : `No typing for ${Math.max(1, Math.round(detail.idle_seconds / 60))} min.`} This is the
              last known risk, not a live reading.
            </p>
          )}
          <div className={`riskbox r-${cur.level}${stale ? " stale" : ""}`}>
            <div className="risk-name">{LEVELS[cur.level].name}</div>
            <div>{LEVELS[cur.level].note}</div>
          </div>
          <p className="small muted" style={{ margin: "10px 0 4px" }}>
            Anomaly ratio {cur.ratio} over the last 5 windows. Latest window: {cur.label}.
          </p>
          {cur.level !== "collecting" && <Gauge ratio={cur.ratio} />}
        </>
      )}
      <Timeline items={detail.timeline} empty="No scored windows for this session yet" />
      {detail.alerts.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <AlertList alerts={detail.alerts.slice(0, 5)} />
        </div>
      )}
    </section>
  );
}

function AdminApp({ auth, onLogout }) {
  const [ov, setOv] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [users, setUsers] = useState([]);
  const [sel, setSel] = useState(null);
  const [showAll, setShowAll] = useState(false);
  const [detail, setDetail] = useState(null);
  const [keys, setKeys] = useState({ total: 0, events: [] });
  const autoSel = useRef(false);
  const [err, setErr] = useState("");
  const [updated, setUpdated] = useState(null);

  const load = useCallback(async () => {
    try {
      const t = auth.token;
      const [o, s, a, u] = await Promise.all([
        api("/admin/overview", { token: t }),
        api("/admin/sessions", { token: t }),
        api("/admin/alerts?limit=25", { token: t }),
        api("/admin/users", { token: t }),
      ]);
      setOv(o);
      setSessions(s);
      setAlerts(a);
      setUsers(u);
      setUpdated(new Date());
      setErr("");
    } catch (ex) {
      if (ex.status === 401 || ex.status === 403) onLogout();
      else setErr(netError(ex.message));
    }
  }, [auth.token, onLogout]);

  useEffect(() => {
    load();
    const id = setInterval(load, POLL_MS);
    return () => clearInterval(id);
  }, [load]);

  useEffect(() => {
    /* open the first live session once, so the risk panel is never empty on arrival */
    if (!autoSel.current && sessions.length) {
      autoSel.current = true;
      setSel(
        (
          sessions.find((s) => s.status !== "closed" && s.idle_seconds <= IDLE_SECONDS) ||
          sessions.find((s) => s.status !== "closed") ||
          sessions[0]
        ).session_id
      );
    }
  }, [sessions]);

  useEffect(() => {
    if (sel == null) {
      setDetail(null);
      setKeys({ total: 0, events: [] });
      return;
    }
    api(`/admin/sessions/${sel}/timeline`, { token: auth.token }).then(setDetail).catch(() => setDetail(null));
    api(`/admin/sessions/${sel}/keystrokes?limit=50`, { token: auth.token }).then(setKeys).catch(() => {});
  }, [sel, sessions, auth.token]);

  async function act(id, what) {
    try {
      await api(`/admin/sessions/${id}/${what}`, { method: "POST", token: auth.token });
      await load();
    } catch (ex) {
      setErr(ex.message);
    }
  }

  const riskCell = (s) => {
    if (s.status === "closed") return <Badge>Closed</Badge>;
    if (!s.enrolled) return <Badge kind="info">Enrolling</Badge>;
    if (!s.risk) return <Badge>Collecting</Badge>;
    return <Badge kind={s.risk.level}>{LEVELS[s.risk.level].name}</Badge>;
  };
  const statusCell = (st, idle) =>
    st === "reauth_required" ? (
      <Badge kind="high">Locked</Badge>
    ) : st === "active" ? (
      idle ? <Badge>Idle</Badge> : <Badge kind="low">Active</Badge>
    ) : (
      <Badge>Closed</Badge>
    );

  return (
    <>
      <TopBar
        role="admin"
        user={auth.username}
        right={
          <>
            <span className="live">
              <i /> Live {updated ? `· ${updated.toLocaleTimeString()}` : ""}
            </span>
            <button className="ghost light" onClick={onLogout}>
              Sign out
            </button>
          </>
        }
      />
      <main className="page">
        {err && <p className="error">{err}</p>}
        <div className="kpis">
          <Kpi label="Registered users" value={ov?.users} />
          <Kpi label="Profiles trained" value={ov?.enrolled} />
          <Kpi label="Active sessions" value={ov?.active_sessions} />
          <Kpi label="Locked sessions" value={ov?.locked_sessions} tone={ov?.locked_sessions ? "high" : ""} />
          <Kpi label="Windows scored" value={ov?.windows} />
          <Kpi label="High-risk alerts" value={ov?.high_alerts} tone={ov?.high_alerts ? "high" : ""} />
        </div>

        <section>
          <h3 className="sec">Live risk monitor</h3>
          <div className="meters">
            {sessions.filter((s) => s.status !== "closed").length === 0 ? (
              <div className="card muted">No live sessions. Sign in as a user and start typing.</div>
            ) : (
              sessions
                .filter((s) => s.status !== "closed")
                .map((s) => <RiskMeter key={s.session_id} s={s} selected={sel === s.session_id} onSelect={setSel} />)
            )}
          </div>
        </section>

        <div className="cols wide">
          <section className="card">
            <div className="between">
              <h3>Sessions</h3>
              <div className="row" style={{ gap: 6 }}>
                <button className={`mini${!showAll ? " on" : ""}`} onClick={() => setShowAll(false)}>
                  Live ({sessions.filter((s) => s.status !== "closed").length})
                </button>
                <button className={`mini${showAll ? " on" : ""}`} onClick={() => setShowAll(true)}>
                  All ({sessions.length})
                </button>
              </div>
            </div>
            <div className="tablewrap">
              <table className="clickable">
                <thead>
                  <tr>
                    <th>Session</th>
                    <th>User</th>
                    <th>Status</th>
                    <th>Risk</th>
                    <th>Ratio</th>
                    <th>Windows</th>
                    <th>Started</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {(showAll ? sessions : sessions.filter((s) => s.status !== "closed")).length === 0 && (
                    <tr>
                      <td colSpan={8} className="muted">
                        {showAll ? "No sessions yet." : "No live sessions. Sign in as a user and start typing, or choose All to see past sessions."}
                      </td>
                    </tr>
                  )}
                  {(showAll ? sessions : sessions.filter((s) => s.status !== "closed")).map((s) => (
                    <tr key={s.session_id} className={sel === s.session_id ? "sel" : ""} onClick={() => setSel(s.session_id)}>
                      <td title={`Database id ${s.session_id}`}>#{s.session_no}</td>
                      <td>{s.username}</td>
                      <td>{statusCell(s.status, s.idle_seconds > IDLE_SECONDS)}</td>
                      <td>{riskCell(s)}</td>
                      <td>{s.risk ? s.risk.ratio : "-"}</td>
                      <td>{s.windows}</td>
                      <td>{clock(s.login_time)}</td>
                      <td className="acts" onClick={(e) => e.stopPropagation()}>
                        {s.status !== "closed" && (
                          <>
                            <button className="mini" onClick={() => act(s.session_id, "force-reauth")}>
                              Lock
                            </button>
                            <button className="mini danger" onClick={() => act(s.session_id, "end")}>
                              End
                            </button>
                          </>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {detail && (
              <details className="detail" open>
                <summary>
                  Keystroke history, {detail.username} session #{detail.session_no}: {keys.total} events stored, latest {keys.events.length} shown
                </summary>
                <Table
                  head={["Seq", "Segment", "Key", "Press ms", "Release ms", "Dwell ms"]}
                  rows={keys.events.map((e) => [
                    e.seq,
                    e.segment,
                    e.key_code,
                    e.press_time,
                    e.release_time,
                    Math.round((e.release_time - e.press_time) * 10) / 10,
                  ])}
                  empty="No keystrokes stored for this session"
                />
              </details>
            )}
          </section>

          <div className="stack">
            <SessionRiskCard detail={detail} onClose={() => setSel(null)} />
            <section className="card">
              <h3>Recent alerts</h3>
              <AlertList alerts={alerts} withUser />
            </section>
          </div>
        </div>

        <section className="card">
          <h3>Users</h3>
          <Table
            head={["User", "Profile", "Enrollment windows", "Sessions", "Last login"]}
            rows={users.map((u) => [
              u.username,
              u.enrolled ? <Badge kind="low">Trained</Badge> : <Badge kind="info">Not trained</Badge>,
              u.enrollment_windows,
              u.sessions,
              u.last_login ? new Date(u.last_login).toLocaleString() : "-",
            ])}
            empty="No registered users yet"
          />
        </section>
      </main>
    </>
  );
}

/* --------------------------------------------------------------------- app */
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

  if (!auth) return <AuthScreen onAuthed={handleAuthed} />;
  return auth.role === "admin" ? (
    <AdminApp auth={auth} onLogout={handleLogout} />
  ) : (
    <Workspace auth={auth} onLogout={handleLogout} />
  );
}
