import React, { useState, useMemo, useRef, useEffect } from "react";
import {
  Shield, Search, Bell, ChevronDown, Circle, Play, RotateCcw,
  AlertTriangle, Link2, Globe, Clock, KeyRound, Paperclip, UserX,
  Banknote, Fingerprint, Ban, Trash2, Send, ShieldCheck, ScanLine,
  CircleAlert, Sparkles, Terminal, ArrowRight, Copy, Lock
} from "lucide-react";

/* ============================================================
   CyberShield AI — analyst workspace (demo)
   Flow: message input -> classification -> risk score & threat type
         -> explainability -> highlighted indicators -> recommended response
   ============================================================ */

/* ---- sample messages for a fast stage demo ---- */
const SAMPLES = {
  phishing: {
    label: "Phishing",
    from: "support@amaz0n-security.com",
    text:
`Dear Customer,

We detected unusual sign-in activity on your account. For your protection your account will be suspended within 24 hours unless you verify your identity immediately.

Please confirm your password and billing details here: http://203.0.113.45/verify-account

Failure to act now will result in permanent closure of your account.

Amazon Security Team`
  },
  scam: {
    label: "Payout scam",
    from: "claims@intl-lottery-winners.top",
    text:
`CONGRATULATIONS!!!

You have won 2,500,000 USD in the International Email Lottery. To release your prize we only need a small processing fee paid via gift card or bitcoin.

Reply with your full name, bank routing number and a photo of your ID to claim your inheritance today. This is a limited time offer.

Claims Department`
  },
  safe: {
    label: "Legitimate",
    from: "notes@calendar.company.com",
    text:
`Hi Najmi,

Just a reminder that our design review is scheduled for Thursday at 3pm in the Aurora room. The agenda and last week's notes are attached.

Let me know if that time still works for you.

Thanks,
Priya`
  }
};

/* ---- detection signals ---- */
/* severity weights */
const W = { low: 6, medium: 13, high: 21 };

const RULES = [
  {
    id: "ip-url", category: "phishing", severity: "high",
    why: "Link points to a raw IP address, not a real domain",
    re: /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}[^\s)]*/gi
  },
  {
    id: "spoof-domain", category: "phishing", severity: "high",
    why: "Look-alike domain impersonating a trusted brand",
    re: /\b(?:amaz0n|paypa1|payp4l|g00gle|micros0ft|netfl1x|app1e|faceb00k|0utlook|linkedln)[\w.-]*/gi
  },
  {
    id: "credential", category: "phishing", severity: "high",
    why: "Asks you to confirm a password or log in to 'verify'",
    re: /\b(?:verify your (?:account|identity|password)|confirm your (?:password|account|identity|billing details)|update your (?:payment|billing|account)|re-?enter your password|click (?:here )?to verify)\b/gi
  },
  {
    id: "sensitive", category: "phishing", severity: "high",
    why: "Requests sensitive personal or financial data",
    re: /\b(?:social security|ssn|credit card number|cvv|pin number|bank routing number|routing number|photo of your id)\b/gi
  },
  {
    id: "attachment", category: "malware", severity: "high",
    why: "References an executable or risky attachment",
    re: /\b[\w-]+\.(?:exe|scr|zip|iso|js|bat)\b|\benable (?:macros|content)\b|\bopen the attachment\b/gi
  },
  {
    id: "payout", category: "scam", severity: "medium",
    why: "Payout / prize bait — classic advance-fee scam",
    re: /\b(?:you have won|you've won|lottery|prize|inheritance|processing fee|gift ?card|bitcoin|wire transfer|western union|\d[\d,]*\s?(?:usd|dollars))\b/gi
  },
  {
    id: "urgency", category: "phishing", severity: "medium",
    why: "Urgency / pressure tactic to make you act fast",
    re: /\b(?:immediately|within 24 hours|act now|as soon as possible|final (?:notice|warning)|limited time|failure to act|account (?:will be )?(?:suspended|locked|closed|terminated)|suspended within)\b/gi
  },
  {
    id: "tld", category: "phishing", severity: "medium",
    why: "Uncommon top-level domain often used in abuse",
    re: /\bhttps?:\/\/[^\s]*\.(?:top|xyz|click|verify|zip|mov|tk|ml|ga|cf)\b/gi
  },
  {
    id: "generic", category: "phishing", severity: "low",
    why: "Generic, impersonal greeting",
    re: /\bdear (?:customer|user|account holder|valued (?:member|customer)|sir\/madam)\b/gi
  }
];

const CAT_LABEL = {
  phishing: "Phishing",
  scam: "Payout scam",
  malware: "Malware / payload",
  safe: "Legitimate"
};

/* severity -> palette (the ONE place color is allowed to vary) */
function band(score) {
  if (score < 20) return { key: "safe", label: "Safe", c: "#2DD4A7" };
  if (score < 40) return { key: "low", label: "Low", c: "#7BCB6B" };
  if (score < 60) return { key: "medium", label: "Elevated", c: "#E6B94E" };
  if (score < 80) return { key: "high", label: "High", c: "#EE8B42" };
  return { key: "critical", label: "Critical", c: "#F0575C" };
}

const SEV_ORDER = { high: 3, medium: 2, low: 1 };

/* ---- rule-based fallback engine (used when the Fireworks call fails) ---- */
function heuristicAnalyze(text) {
  const matches = [];
  const catPoints = { phishing: 0, scam: 0, malware: 0 };
  let raw = 0;

  RULES.forEach((rule) => {
    rule.re.lastIndex = 0;
    let m;
    let hit = 0;
    while ((m = rule.re.exec(text)) !== null) {
      if (m[0].length === 0) { rule.re.lastIndex++; continue; }
      matches.push({
        start: m.index,
        end: m.index + m[0].length,
        text: m[0],
        ruleId: rule.id,
        severity: rule.severity,
        why: rule.why,
        category: rule.category
      });
      hit++;
      if (hit >= 4) break; // cap per rule
    }
    if (hit > 0) {
      const pts = W[rule.severity] * Math.min(hit, 2);
      raw += pts;
      catPoints[rule.category] += pts;
    }
  });

  const score = matches.length === 0
    ? Math.min(9, 3 + Math.round(text.length / 400))
    : Math.min(97, raw + 6);

  // dominant category
  let category = "safe";
  if (matches.length > 0) {
    category = Object.entries(catPoints).sort((a, b) => b[1] - a[1])[0][0];
  }
  const b = band(score);
  if (b.key === "safe") category = "safe";

  const confidence = matches.length === 0
    ? 96
    : Math.min(99, 83 + matches.length * 2);

  // unique indicators (grouped by rule)
  const seen = new Map();
  matches.forEach((mm) => {
    if (!seen.has(mm.ruleId)) {
      seen.set(mm.ruleId, {
        ruleId: mm.ruleId, why: mm.why, severity: mm.severity,
        category: mm.category, count: 0
      });
    }
    seen.get(mm.ruleId).count++;
  });
  const indicators = [...seen.values()].sort(
    (a, b2) => SEV_ORDER[b2.severity] - SEV_ORDER[a.severity]
  );

  return {
    score,
    band: b,
    threatType: CAT_LABEL[category],
    confidence,
    matches,
    indicators
  };
}

/* recommended response fallback, driven by verdict (used when the model
   returns no recommendations, e.g. the heuristic fallback path) */
function heuristicRecommend(result) {
  if (result.band.key === "safe") {
    return [
      { icon: ShieldCheck, t: "No action needed", d: "Message shows no signs of compromise" },
      { icon: Circle, t: "Deliver normally", d: "Route to the recipient's inbox" }
    ];
  }
  const t = result.threatType;
  if (t.startsWith("Malware")) {
    return [
      { icon: Ban, t: "Do not open the attachment", d: "Block the payload before it runs" },
      { icon: Lock, t: "Isolate the device", d: "Contain any machine that already opened it" },
      { icon: ScanLine, t: "Run an endpoint scan", d: "Check the host for indicators of compromise" },
      { icon: Send, t: "Report to IT security", d: "Escalate for wider threat hunting" }
    ];
  }
  if (t.startsWith("Payout")) {
    return [
      { icon: Ban, t: "Do not reply or send funds", d: "Never pay a fee to release a 'prize'" },
      { icon: UserX, t: "Block the sender", d: "Stop further messages from this address" },
      { icon: Send, t: "Report as a scam", d: "Flag to your provider and security team" }
    ];
  }
  // phishing
  return [
    { icon: Trash2, t: "Quarantine the message", d: "Move it out of the inbox and hold it" },
    { icon: UserX, t: "Block sender and domain", d: "Stop the source from reaching users" },
    { icon: KeyRound, t: "Reset exposed credentials", d: "Rotate any password that may be compromised" },
    { icon: Send, t: "Report to the security team", d: "Warn other likely targets" }
  ];
}

/* ---- icon for a model-generated recommendation title ---- */
function iconFor(title = "") {
  const t = title.toLowerCase();
  if (t.includes("block")) return Ban;
  if (t.includes("report")) return Send;
  if (t.includes("password") || t.includes("credential") || t.includes("reset")) return KeyRound;
  if (t.includes("quarantine") || t.includes("delete") || t.includes("remove")) return Trash2;
  if (t.includes("isolate")) return Lock;
  if (t.includes("scan")) return ScanLine;
  if (t.includes("no action") || t.includes("legitimate") || t.includes("reviewed")) return ShieldCheck;
  return Circle;
}

/* recommended response: prefer the model's own recommendations, fall back
   to the hard-coded verdict-driven list (heuristic path / model returned none) */
function recommend(result) {
  const recs = result.recommendations;
  if (recs && recs.length) {
    return recs.map((r) => ({ icon: iconFor(r.title), t: r.title, d: r.detail }));
  }
  return heuristicRecommend(result);
}

/* ---- offset finder: locate every occurrence of an exact snippet in the text ---- */
function findRanges(text, snippet, max = 4) {
  const ranges = [];
  if (!snippet) return ranges;
  const hay = text.toLowerCase();
  const needle = snippet.toLowerCase();
  let from = 0, i;
  while ((i = hay.indexOf(needle, from)) !== -1 && ranges.length < max) {
    ranges.push({ start: i, end: i + snippet.length });
    from = i + snippet.length;
  }
  return ranges;
}

/* ---- map the Fireworks model's JSON verdict to the UI's existing result shape ---- */
function adaptModelResult(model, originalText) {
  const score = Math.max(0, Math.min(100, model.risk_score ?? 0));
  const b = band(score);

  const indicators = (model.indicators || []).map((ind, idx) => ({
    ruleId: "m" + idx,
    why: ind.why,
    severity: ind.severity,
    category: ind.category,
    count: 1
  }));

  const matches = [];
  (model.indicators || []).forEach((ind, idx) => {
    findRanges(originalText, ind.snippet).forEach((r) => {
      matches.push({
        start: r.start,
        end: r.end,
        text: originalText.slice(r.start, r.end),
        ruleId: "m" + idx,
        severity: ind.severity,
        why: ind.why,
        category: ind.category
      });
    });
  });

  return {
    score,
    band: b,
    threatType: model.threat_type,
    confidence: model.confidence ?? 90,
    summary: model.summary || "",
    matches,
    indicators,
    recommendations: model.recommendations || []
  };
}

/* ---- primary analysis path: call our backend, which calls DeepSeek V4 Flash
   on Fireworks with a structured JSON schema. Falls back to the local
   rule engine on any network/parse/schema failure so the demo never dies. ---- */
async function analyze(text) {
  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: text })
    });
    if (!res.ok) throw new Error("api " + res.status);
    const model = await res.json();
    return adaptModelResult(model, text);
  } catch (e) {
    console.warn("Fireworks path failed, using heuristic fallback:", e);
    return heuristicAnalyze(text);
  }
}

/* ---- highlight builder: non-overlapping, highest severity wins ---- */
function buildSegments(text, matches, activeRule) {
  if (!matches.length) return [{ text, mark: null }];
  const claim = new Array(text.length).fill(null);
  const ordered = [...matches].sort(
    (a, b) => SEV_ORDER[b.severity] - SEV_ORDER[a.severity] || a.start - b.start
  );
  ordered.forEach((mm) => {
    let free = true;
    for (let i = mm.start; i < mm.end; i++) if (claim[i]) { free = false; break; }
    if (free) for (let i = mm.start; i < mm.end; i++) claim[i] = mm;
  });
  const segs = [];
  let i = 0;
  while (i < text.length) {
    const cur = claim[i];
    let j = i;
    while (j < text.length && claim[j] === cur) j++;
    segs.push({ text: text.slice(i, j), mark: cur });
    i = j;
  }
  return segs.map((s) => ({
    ...s,
    active: s.mark && activeRule && s.mark.ruleId === activeRule
  }));
}

/* ====================== UI ====================== */
export default function CyberShieldAI() {
  const [input, setInput] = useState("");
  const [sender, setSender] = useState("");
  const [stage, setStage] = useState("idle"); // idle | scanning | done
  const [result, setResult] = useState(null);
  const [activeRule, setActiveRule] = useState(null);
  const [scanLines, setScanLines] = useState([]);
  const [user, setUser] = useState(null);
  const [authMode, setAuthMode] = useState("signup");
  const [authForm, setAuthForm] = useState({ name: "", email: "", password: "" });
  const [authMessage, setAuthMessage] = useState("");
  const [historyOpen, setHistoryOpen] = useState(false);
  const [historyItems, setHistoryItems] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const timers = useRef([]);

  const reduce = typeof window !== "undefined" &&
    window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  const loadSample = (k) => {
    reset();
    setInput(SAMPLES[k].text);
    setSender(SAMPLES[k].from);
  };

  const reset = () => {
    timers.current.forEach(clearTimeout);
    timers.current = [];
    setStage("idle");
    setResult(null);
    setActiveRule(null);
    setScanLines([]);
  };

  const handleAuthSubmit = async (event) => {
    event.preventDefault();
    setAuthMessage("");

    const endpoint = authMode === "login" ? "/api/auth/login" : "/api/auth/register";
    const payload = authMode === "login"
      ? { email: authForm.email, password: authForm.password }
      : authForm;

    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (!res.ok) {
        setAuthMessage(data.error || "Authentication failed");
        return;
      }
      setUser(data.user);
      setAuthForm({ name: "", email: "", password: "" });
      setAuthMessage(data.message || "Account ready");
    } catch (error) {
      setAuthMessage("Unable to reach authentication service");
    }
  };

  const openHistory = async () => {
    if (!user) {
      setAuthMessage("Sign in or create an account to view saved history");
      setAuthMode("login");
      setHistoryOpen(false);
      return;
    }

    setHistoryOpen(true);
    setHistoryLoading(true);
    try {
      const res = await fetch(`/api/history/${user.user_id}`);
      const data = await res.json();
      setHistoryItems(data.history || []);
    } catch (error) {
      setHistoryItems([]);
    } finally {
      setHistoryLoading(false);
    }
  };

  const saveHistoryEntry = async (analysis, text) => {
    if (!user) return;

    try {
      await fetch("/api/history", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userId: user.user_id,
          searchText: text,
          threatType: analysis.threatType,
          riskScore: analysis.score,
          confidence: analysis.confidence
        })
      });
    } catch (error) {
      console.warn("Unable to save history", error);
    }
  };

  const run = async () => {
    if (!input.trim()) return;
    timers.current.forEach(clearTimeout);
    timers.current = [];
    setActiveRule(null);
    setResult(null);
    setStage("scanning");
    setScanLines([]);

    const steps = [
      "Initializing CyberShield analysis engine",
      "Parsing message headers and body",
      "Extracting links, domains and indicators",
      "Running classification model  (DeepSeek V4 Flash)",
      "Scoring risk and correlating signals"
    ];
    const gap = reduce ? 60 : 300;
    steps.forEach((line, idx) => {
      timers.current.push(
        setTimeout(() => setScanLines((p) => [...p, { line, last: false }]),
          gap * (idx + 1))
      );
    });

    const minAnimation = new Promise((resolve) => {
      timers.current.push(setTimeout(resolve, gap * steps.length));
    });
    const [r] = await Promise.all([analyze(input), minAnimation]);

    setResult(r);
    await saveHistoryEntry(r, input);
    setScanLines((p) => [
      ...p,
      { line: `Verdict: ${r.threatType.toUpperCase()}  ·  risk ${r.score}/100`, last: true }
    ]);
    timers.current.push(setTimeout(() => setStage("done"), 400));
  };

  const segments = useMemo(
    () => (result ? buildSegments(input, result.matches, activeRule) : null),
    [result, input, activeRule]
  );
  const actions = result ? recommend(result) : [];
  const accent = result ? result.band.c : "#57B6E0";

  return (
    <div className="cs-root">
      <style>{CSS}</style>

      {/* ambient glow */}
      <div className="cs-glow" aria-hidden />

      {/* top bar */}
      <header className="cs-top">
        <div className="cs-brand">
          <div className="cs-logo"><Shield size={20} strokeWidth={2.4} /></div>
          <div>
            <div className="cs-brand-name">CyberShield<span> AI</span></div>
            <div className="cs-brand-sub">AI-Powered Threat Intelligence</div>
          </div>
        </div>

        <div className="cs-search">
          <Search size={16} />
          <span>Search threats, indicators, senders…</span>
          <kbd>⌘K</kbd>
        </div>

        <div className="cs-top-right">
          <div className="cs-status">
            <ShieldCheck size={15} />
            <div>
              <span className="cs-status-k">System status</span>
              <span className="cs-status-v">Secure</span>
            </div>
          </div>
          <button className="cs-bell" aria-label="Alerts">
            <Bell size={17} /><span className="cs-badge">4</span>
          </button>
          <div className="cs-user">
            <div className="cs-avatar"><Fingerprint size={15} /></div>
            <div>
              <span className="cs-user-n">Analyst</span>
              <span className="cs-user-r">Level 7</span>
            </div>
            <ChevronDown size={15} />
          </div>
        </div>
      </header>

      {/* workspace */}
      <main className="cs-main">
        {/* LEFT — input + evidence */}
        <section className="cs-col cs-left">
          <div className="cs-panel">
            <div className="cs-panel-head">
              <div className="cs-eyebrow"><Terminal size={13} /> Message input</div>
              <div className="cs-samples">
                <span className="cs-samples-l">Try a sample</span>
                <button onClick={() => loadSample("phishing")}>Phishing</button>
                <button onClick={() => loadSample("scam")}>Scam</button>
                <button onClick={() => loadSample("safe")}>Legit</button>
                <button className="cs-history-btn" onClick={openHistory}>History</button>
              </div>
            </div>

            <div className="cs-auth-card">
              <div className="cs-auth-header">
                <div className="cs-eyebrow"><Lock size={13} /> Account access</div>
                <div className="cs-auth-toggle">
                  <button className={authMode === "signup" ? "active" : ""} onClick={() => setAuthMode("signup")}>Sign up</button>
                  <button className={authMode === "login" ? "active" : ""} onClick={() => setAuthMode("login")}>Login</button>
                </div>
              </div>
              {user ? (
                <div className="cs-user-card">
                  <div>
                    <div className="cs-user-card-name">{user.name}</div>
                    <div className="cs-user-card-meta">{user.email}</div>
                    <div className="cs-user-card-meta">ID: {user.user_id}</div>
                  </div>
                </div>
              ) : (
                <form className="cs-auth-form" onSubmit={handleAuthSubmit}>
                  {authMode === "signup" && (
                    <input
                      className="cs-auth-input"
                      value={authForm.name}
                      onChange={(e) => setAuthForm((prev) => ({ ...prev, name: e.target.value }))}
                      placeholder="Full name"
                    />
                  )}
                  <input
                    className="cs-auth-input"
                    type="email"
                    value={authForm.email}
                    onChange={(e) => setAuthForm((prev) => ({ ...prev, email: e.target.value }))}
                    placeholder="Email address"
                  />
                  <input
                    className="cs-auth-input"
                    type="password"
                    value={authForm.password}
                    onChange={(e) => setAuthForm((prev) => ({ ...prev, password: e.target.value }))}
                    placeholder="Password"
                  />
                  <button className="cs-auth-submit" type="submit">
                    {authMode === "signup" ? "Create account" : "Sign in"}
                  </button>
                </form>
              )}
              {authMessage && <div className="cs-auth-message">{authMessage}</div>}
            </div>

            {historyOpen && (
              <div className="cs-history-card">
                <div className="cs-history-head">
                  <div className="cs-eyebrow"><Clock size={13} /> Search history</div>
                  <button className="cs-ghost cs-history-close" onClick={() => setHistoryOpen(false)}>Close</button>
                </div>
                {historyLoading ? (
                  <div className="cs-history-empty">Loading your history…</div>
                ) : historyItems.length === 0 ? (
                  <div className="cs-history-empty">No searches saved for this account yet.</div>
                ) : (
                  <ul className="cs-history-list">
                    {historyItems.map((item) => (
                      <li key={item.id} className="cs-history-item">
                        <div className="cs-history-top">
                          <strong>{item.search_text}</strong>
                          <span>{item.created_at}</span>
                        </div>
                        <div className="cs-history-meta">
                          Threat: {item.threat_type || "—"} · Risk: {item.risk_score ?? "—"} · Confidence: {item.confidence ?? "—"}
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            {sender && (
              <div className="cs-sender">
                <span>From</span><code>{sender}</code>
              </div>
            )}

            {stage === "idle" && (
              <>
                <textarea
                  className="cs-textarea"
                  placeholder="Paste a suspicious email or message here, then analyze it…"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  spellCheck={false}
                />
                <div className="cs-actions">
                  <button className="cs-run" onClick={run} disabled={!input.trim()}
                    style={{ opacity: input.trim() ? 1 : 0.45 }}>
                    <Play size={16} /> Analyze message
                  </button>
                  {input && (
                    <button className="cs-ghost" onClick={reset}>
                      <RotateCcw size={15} /> Clear
                    </button>
                  )}
                </div>
              </>
            )}

            {/* evidence: highlighted message */}
            {stage !== "idle" && (
              <div className="cs-evidence">
                {stage === "scanning" && <div className="cs-scanline" aria-hidden />}
                <pre className="cs-message">
                  {stage === "scanning"
                    ? input
                    : segments.map((s, i) =>
                        s.mark ? (
                          <mark
                            key={i}
                            className={"cs-hl cs-hl-" + s.mark.severity + (s.active ? " cs-hl-active" : "")}
                            onMouseEnter={() => setActiveRule(s.mark.ruleId)}
                            onMouseLeave={() => setActiveRule(null)}
                            onClick={() => setActiveRule(s.mark.ruleId)}
                            title={s.mark.why}
                          >
                            {s.text}
                          </mark>
                        ) : (
                          <span key={i}>{s.text}</span>
                        )
                      )}
                </pre>
                {stage === "done" && (
                  <div className="cs-evi-foot">
                    <Sparkles size={13} />
                    Highlighted fragments are what the model flagged — hover or tap one to see why.
                  </div>
                )}
              </div>
            )}
          </div>

          {/* terminal analysis */}
          {stage !== "idle" && (
            <div className="cs-panel cs-terminal">
              <div className="cs-term-bar">
                <span className="cs-dot" /><span className="cs-dot" /><span className="cs-dot" />
                <span className="cs-term-title">analysis.log</span>
              </div>
              <div className="cs-term-body">
                {scanLines.map((l, i) => (
                  <div key={i} className={"cs-term-line" + (l.last ? " cs-term-final" : "")}
                    style={l.last ? { color: accent } : undefined}>
                    <span className="cs-term-prompt">›</span> {l.line}
                    {!l.last && <span className="cs-ok"> [OK]</span>}
                  </div>
                ))}
                {stage === "scanning" && <span className="cs-cursor" />}
              </div>
            </div>
          )}
        </section>

        {/* RIGHT — verdict */}
        <section className="cs-col cs-right">
          {stage !== "done" && (
            <div className="cs-panel cs-empty">
              <div className="cs-empty-ring" style={{ borderColor: "#26374F" }}>
                {stage === "scanning"
                  ? <ScanLine size={26} className="cs-spin-slow" />
                  : <Shield size={26} />}
              </div>
              <div className="cs-empty-t">
                {stage === "scanning" ? "Analyzing message…" : "Awaiting a message"}
              </div>
              <div className="cs-empty-d">
                {stage === "scanning"
                  ? "Classifying threat type and scoring risk."
                  : "Paste a message and run the analysis to see the verdict, evidence and recommended response."}
              </div>
            </div>
          )}

          {stage === "done" && result && (
            <>
              {/* verdict header */}
              <div className="cs-panel cs-verdict" style={{ "--accent": accent }}>
                <div className="cs-verdict-top">
                  <div>
                    <div className="cs-eyebrow">Threat type</div>
                    <div className="cs-threat">
                      {result.band.key === "safe"
                        ? <ShieldCheck size={22} style={{ color: accent }} />
                        : <CircleAlert size={22} style={{ color: accent }} />}
                      {result.threatType}
                    </div>
                    <div className="cs-sev-badge" style={{ color: accent, borderColor: accent }}>
                      {result.band.label} risk
                    </div>
                  </div>
                  <RiskRing score={result.score} color={accent} />
                </div>

                <div className="cs-conf">
                  <div className="cs-conf-row">
                    <span>Model confidence</span>
                    <span className="cs-conf-v">{result.confidence}%</span>
                  </div>
                  <div className="cs-bar">
                    <div className="cs-bar-fill"
                      style={{ width: result.confidence + "%", background: accent }} />
                  </div>
                </div>
              </div>

              {/* indicators */}
              <div className="cs-panel">
                <div className="cs-eyebrow cs-mb">
                  Indicators detected
                  <span className="cs-count">{result.indicators.length}</span>
                </div>
                {result.indicators.length === 0 ? (
                  <div className="cs-clean">
                    <ShieldCheck size={16} style={{ color: accent }} />
                    No suspicious indicators found in this message.
                  </div>
                ) : (
                  <ul className="cs-ind">
                    {result.indicators.map((ind) => (
                      <li key={ind.ruleId}
                        className={"cs-ind-item" + (activeRule === ind.ruleId ? " cs-ind-on" : "")}
                        onMouseEnter={() => setActiveRule(ind.ruleId)}
                        onMouseLeave={() => setActiveRule(null)}
                        onClick={() => setActiveRule(ind.ruleId)}>
                        <span className={"cs-ind-dot cs-dot-" + ind.severity} />
                        <span className="cs-ind-why">{ind.why}</span>
                        <span className={"cs-ind-sev cs-sev-" + ind.severity}>{ind.severity}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {/* recommended response */}
              <div className="cs-panel">
                <div className="cs-eyebrow cs-mb">Recommended response</div>
                <div className="cs-resp">
                  {actions.map((a, i) => {
                    const Ic = a.icon;
                    return (
                      <div className="cs-resp-item" key={i}>
                        <div className="cs-resp-ic"><Ic size={16} /></div>
                        <div>
                          <div className="cs-resp-t">{a.t}</div>
                          <div className="cs-resp-d">{a.d}</div>
                        </div>
                        <ArrowRight size={15} className="cs-resp-arrow" />
                      </div>
                    );
                  })}
                </div>
                <button className="cs-take" style={{ background: accent }}
                  onClick={reset}>
                  {result.band.key === "safe" ? "Mark as reviewed" : "Take action"}
                </button>
              </div>

              <button className="cs-restart" onClick={reset}>
                <RotateCcw size={14} /> Analyze another message
              </button>
            </>
          )}
        </section>
      </main>
    </div>
  );
}

/* circular risk gauge */
function RiskRing({ score, color }) {
  const r = 46, c = 2 * Math.PI * r;
  const [dash, setDash] = useState(c);
  useEffect(() => {
    const t = setTimeout(() => setDash(c - (c * score) / 100), 120);
    return () => clearTimeout(t);
  }, [score, c]);
  return (
    <div className="cs-ring">
      <svg width="118" height="118" viewBox="0 0 118 118">
        <circle cx="59" cy="59" r={r} className="cs-ring-track" />
        <circle cx="59" cy="59" r={r} className="cs-ring-val"
          stroke={color} strokeDasharray={c} strokeDashoffset={dash}
          transform="rotate(-90 59 59)" />
      </svg>
      <div className="cs-ring-c">
        <div className="cs-ring-score" style={{ color }}>{score}</div>
        <div className="cs-ring-of">/ 100</div>
      </div>
    </div>
  );
}

/* ====================== styles ====================== */
const CSS = `
.cs-root{
  --bg:#0C1421; --bg2:#101B2B; --panel:#141F30; --panel2:#182437;
  --border:#25374F; --border2:#2E425E;
  --ink:#EAF1FA; --mut:#8A9CB6; --mut2:#63758F;
  --steel:#57B6E0;
  position:relative; min-height:100vh; width:100%;
  background:
    radial-gradient(1100px 520px at 78% -6%, rgba(87,182,224,.10), transparent 60%),
    linear-gradient(180deg,#0E1826 0%, var(--bg) 46%, #0A1019 100%);
  color:var(--ink);
  font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Inter,sans-serif;
  font-size:14px; -webkit-font-smoothing:antialiased;
}
.cs-mono{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;}
.cs-glow{position:absolute;inset:0;pointer-events:none;
  background:radial-gradient(600px 300px at 22% 8%, rgba(87,182,224,.06), transparent 70%);}

/* auth + history */
.cs-auth-card{margin:12px 0 0;padding:14px;border:1px solid var(--border);border-radius:14px;background:rgba(11,18,30,.5);}
.cs-auth-header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px;}
.cs-auth-toggle{display:flex;gap:8px;}
.cs-auth-toggle button{border:1px solid var(--border);background:transparent;color:var(--mut);border-radius:999px;padding:5px 9px;cursor:pointer;}
.cs-auth-toggle button.active{background:rgba(87,182,224,.16);color:var(--ink);border-color:var(--border2);} 
.cs-auth-form{display:flex;flex-direction:column;gap:8px;}
.cs-auth-input{width:100%;padding:10px 12px;border-radius:10px;border:1px solid var(--border);background:rgba(9,15,26,.75);color:var(--ink);} 
.cs-auth-submit{padding:9px 12px;border:0;border-radius:10px;background:linear-gradient(135deg,#6FD0F2,#3E9AC9);color:#08111d;font-weight:700;cursor:pointer;} 
.cs-auth-message{margin-top:10px;color:#8EE2C3;font-size:12px;} 
.cs-user-card{display:flex;align-items:center;justify-content:space-between;padding:8px 0;} 
.cs-user-card-name{font-weight:700;} 
.cs-user-card-meta{font-size:12px;color:var(--mut);} 
.cs-history-btn{border:1px solid var(--border);background:rgba(11,18,30,.6);color:var(--ink);padding:6px 10px;border-radius:999px;cursor:pointer;} 
.cs-history-card{margin-top:12px;padding:12px;border:1px solid var(--border);border-radius:14px;background:rgba(11,18,30,.55);} 
.cs-history-head{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:10px;} 
.cs-history-close{padding:6px 10px;border-radius:999px;} 
.cs-history-empty{font-size:12px;color:var(--mut);} 
.cs-history-list{list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:8px;} 
.cs-history-item{padding:10px;border:1px solid var(--border2);border-radius:10px;background:rgba(9,15,26,.6);} 
.cs-history-top{display:flex;justify-content:space-between;gap:8px;font-size:12px;margin-bottom:4px;} 
.cs-history-meta{font-size:11px;color:var(--mut);} 

/* top bar */
.cs-top{position:relative;z-index:2;display:flex;align-items:center;gap:18px;
  padding:14px 22px;border-bottom:1px solid var(--border);
  background:linear-gradient(180deg,rgba(20,31,48,.85),rgba(16,25,40,.7));
  backdrop-filter:blur(8px);}
.cs-brand{display:flex;align-items:center;gap:12px;min-width:210px;}
.cs-logo{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;
  color:#0B1220;background:linear-gradient(150deg,#6FD0F2,#3E9AC9);
  box-shadow:0 6px 18px rgba(62,154,201,.35);}
.cs-brand-name{font-weight:700;letter-spacing:.2px;font-size:16px;}
.cs-brand-name span{color:var(--steel);font-weight:700;}
.cs-brand-sub{font-size:10.5px;letter-spacing:1.4px;text-transform:uppercase;color:var(--mut2);}
.cs-search{flex:1;max-width:520px;display:flex;align-items:center;gap:10px;
  padding:9px 14px;border:1px solid var(--border);border-radius:11px;
  background:rgba(11,18,30,.55);color:var(--mut);}
.cs-search span{flex:1;}
.cs-search kbd{font-family:ui-monospace,monospace;font-size:11px;color:var(--mut);
  border:1px solid var(--border2);border-radius:6px;padding:2px 7px;}
.cs-top-right{margin-left:auto;display:flex;align-items:center;gap:14px;}
.cs-status{display:flex;align-items:center;gap:8px;color:#2DD4A7;}
.cs-status div{display:flex;flex-direction:column;line-height:1.2;}
.cs-status-k{font-size:9.5px;letter-spacing:1px;text-transform:uppercase;color:var(--mut2);}
.cs-status-v{font-size:12.5px;color:#3EE0B0;font-weight:600;}
.cs-bell{position:relative;width:38px;height:38px;border-radius:10px;border:1px solid var(--border);
  background:rgba(11,18,30,.5);color:var(--mut);display:grid;place-items:center;cursor:pointer;}
.cs-bell:hover{color:var(--ink);border-color:var(--border2);}
.cs-badge{position:absolute;top:-5px;right:-5px;background:#F0575C;color:#0B1220;
  font-size:10px;font-weight:700;border-radius:9px;padding:1px 5px;}
.cs-user{display:flex;align-items:center;gap:9px;padding:5px 8px;border-radius:10px;
  border:1px solid var(--border);background:rgba(11,18,30,.5);cursor:pointer;}
.cs-user:hover{border-color:var(--border2);}
.cs-avatar{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;
  background:linear-gradient(150deg,#22344b,#182437);color:var(--steel);}
.cs-user div{display:flex;flex-direction:column;line-height:1.2;}
.cs-user-n{font-size:12.5px;font-weight:600;}
.cs-user-r{font-size:10px;color:var(--mut2);}

/* layout */
.cs-main{position:relative;z-index:1;display:grid;grid-template-columns:1.55fr 1fr;
  gap:18px;padding:20px 22px 34px;max-width:1360px;margin:0 auto;align-items:start;}
.cs-col{display:flex;flex-direction:column;gap:16px;}
.cs-panel{background:linear-gradient(180deg,var(--panel),var(--panel2));
  border:1px solid var(--border);border-radius:16px;padding:18px;
  box-shadow:0 1px 0 rgba(255,255,255,.02) inset, 0 12px 30px rgba(4,8,14,.35);}

.cs-eyebrow{display:flex;align-items:center;gap:7px;font-size:10.5px;letter-spacing:1.5px;
  text-transform:uppercase;color:var(--mut);font-weight:600;}
.cs-mb{margin-bottom:14px;}
.cs-count{margin-left:auto;font-family:ui-monospace,monospace;color:var(--ink);
  background:rgba(87,182,224,.14);border:1px solid var(--border2);border-radius:7px;
  padding:1px 8px;font-size:11px;letter-spacing:0;}

.cs-panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;}
.cs-samples{display:flex;align-items:center;gap:6px;}
.cs-samples-l{font-size:10.5px;color:var(--mut2);margin-right:2px;}
.cs-samples button{font-size:11.5px;color:var(--mut);background:rgba(11,18,30,.5);
  border:1px solid var(--border);border-radius:8px;padding:4px 10px;cursor:pointer;transition:.15s;}
.cs-samples button:hover{color:var(--ink);border-color:var(--steel);
  box-shadow:0 0 0 1px rgba(87,182,224,.25);}

.cs-sender{display:flex;align-items:center;gap:9px;margin-bottom:12px;font-size:12px;}
.cs-sender span{color:var(--mut2);text-transform:uppercase;letter-spacing:1px;font-size:10px;}
.cs-sender code{font-family:ui-monospace,monospace;color:var(--ink);
  background:rgba(11,18,30,.6);border:1px solid var(--border);border-radius:7px;padding:3px 9px;}

.cs-textarea{width:100%;min-height:230px;resize:vertical;border-radius:12px;
  border:1px solid var(--border);background:rgba(9,15,24,.6);color:var(--ink);
  padding:14px;font-family:ui-monospace,"SF Mono",Menlo,monospace;font-size:13px;line-height:1.65;
  outline:none;box-sizing:border-box;}
.cs-textarea:focus{border-color:var(--steel);box-shadow:0 0 0 3px rgba(87,182,224,.14);}
.cs-textarea::placeholder{color:var(--mut2);}

.cs-actions{display:flex;gap:10px;margin-top:14px;}
.cs-run{display:inline-flex;align-items:center;gap:9px;font-weight:600;font-size:13.5px;
  color:#08131f;background:linear-gradient(150deg,#6FD0F2,#3E9AC9);border:none;
  border-radius:11px;padding:11px 18px;cursor:pointer;transition:.15s;
  box-shadow:0 8px 22px rgba(62,154,201,.32);}
.cs-run:hover{transform:translateY(-1px);}
.cs-ghost{display:inline-flex;align-items:center;gap:7px;font-size:13px;color:var(--mut);
  background:transparent;border:1px solid var(--border);border-radius:11px;padding:11px 15px;cursor:pointer;}
.cs-ghost:hover{color:var(--ink);border-color:var(--border2);}

/* evidence */
.cs-evidence{position:relative;border:1px solid var(--border);border-radius:12px;
  background:rgba(9,15,24,.55);overflow:hidden;}
.cs-message{margin:0;padding:16px;white-space:pre-wrap;word-break:break-word;
  font-family:ui-monospace,"SF Mono",Menlo,monospace;font-size:13px;line-height:1.75;color:#D4DEEC;}
.cs-hl{border-radius:4px;padding:1px 2px;cursor:pointer;color:#0B1220;font-weight:600;transition:.12s;}
.cs-hl-high{background:rgba(240,87,92,.85);}
.cs-hl-medium{background:rgba(238,139,66,.82);}
.cs-hl-low{background:rgba(230,185,78,.8);}
.cs-hl-active{outline:2px solid #EAF1FA;outline-offset:1px;}
.cs-scanline{position:absolute;left:0;right:0;height:70px;pointer-events:none;z-index:2;
  background:linear-gradient(180deg,transparent,rgba(87,182,224,.16),transparent);
  animation:scan 1.6s ease-in-out infinite;}
@keyframes scan{0%{top:-70px}100%{top:100%}}
.cs-evi-foot{display:flex;align-items:center;gap:8px;padding:11px 16px;font-size:11.5px;
  color:var(--mut);border-top:1px solid var(--border);background:rgba(11,18,30,.4);}
.cs-evi-foot svg{color:var(--steel);}

/* terminal */
.cs-terminal{padding:0;overflow:hidden;}
.cs-term-bar{display:flex;align-items:center;gap:7px;padding:10px 14px;
  border-bottom:1px solid var(--border);background:rgba(9,15,24,.6);}
.cs-term-bar .cs-dot{width:10px;height:10px;border-radius:50%;background:#2E425E;}
.cs-term-title{margin-left:8px;font-family:ui-monospace,monospace;font-size:11.5px;color:var(--mut2);}
.cs-term-body{padding:14px 16px;font-family:ui-monospace,monospace;font-size:12.5px;
  line-height:1.85;min-height:120px;}
.cs-term-line{color:#9FE7C6;animation:fade .2s ease;}
.cs-term-prompt{color:var(--steel);margin-right:6px;}
.cs-ok{color:#3EE0B0;}
.cs-term-final{font-weight:600;}
.cs-cursor{display:inline-block;width:8px;height:15px;background:var(--steel);
  vertical-align:middle;animation:blink 1s steps(1) infinite;}
@keyframes blink{50%{opacity:0}}
@keyframes fade{from{opacity:0;transform:translateY(2px)}to{opacity:1}}

/* empty / scanning state */
.cs-empty{display:flex;flex-direction:column;align-items:center;text-align:center;
  padding:46px 24px;gap:14px;}
.cs-empty-ring{width:78px;height:78px;border-radius:50%;border:1.5px dashed;
  display:grid;place-items:center;color:var(--steel);}
.cs-empty-t{font-size:15px;font-weight:600;}
.cs-empty-d{font-size:12.5px;color:var(--mut);max-width:280px;line-height:1.6;}
.cs-spin-slow{animation:spin 2.4s linear infinite;}
@keyframes spin{to{transform:rotate(360deg)}}

/* verdict */
.cs-verdict{--accent:#57B6E0;border-color:color-mix(in srgb,var(--accent) 34%,var(--border));
  background:
    radial-gradient(340px 150px at 100% 0%, color-mix(in srgb,var(--accent) 12%,transparent), transparent 70%),
    linear-gradient(180deg,var(--panel),var(--panel2));}
.cs-verdict-top{display:flex;justify-content:space-between;align-items:center;gap:12px;}
.cs-threat{display:flex;align-items:center;gap:9px;font-size:22px;font-weight:700;margin:8px 0 10px;}
.cs-sev-badge{display:inline-block;font-size:10.5px;letter-spacing:1px;text-transform:uppercase;
  font-weight:700;border:1px solid;border-radius:20px;padding:3px 11px;}
.cs-conf{margin-top:18px;}
.cs-conf-row{display:flex;justify-content:space-between;font-size:12px;color:var(--mut);margin-bottom:7px;}
.cs-conf-v{color:var(--ink);font-family:ui-monospace,monospace;font-weight:600;}
.cs-bar{height:7px;border-radius:20px;background:rgba(9,15,24,.7);overflow:hidden;}
.cs-bar-fill{height:100%;border-radius:20px;transition:width 1s cubic-bezier(.2,.8,.2,1);}

/* ring */
.cs-ring{position:relative;width:118px;height:118px;flex-shrink:0;}
.cs-ring-track{fill:none;stroke:rgba(255,255,255,.06);stroke-width:9;}
.cs-ring-val{fill:none;stroke-width:9;stroke-linecap:round;
  transition:stroke-dashoffset 1.1s cubic-bezier(.2,.8,.2,1);}
.cs-ring-c{position:absolute;inset:0;display:flex;flex-direction:column;
  align-items:center;justify-content:center;}
.cs-ring-score{font-size:30px;font-weight:700;font-family:ui-monospace,monospace;line-height:1;}
.cs-ring-of{font-size:10px;color:var(--mut2);margin-top:3px;letter-spacing:1px;}

/* indicators */
.cs-ind{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:2px;}
.cs-ind-item{display:flex;align-items:center;gap:11px;padding:10px 10px;border-radius:9px;
  cursor:pointer;transition:.12s;border:1px solid transparent;}
.cs-ind-item:hover,.cs-ind-on{background:rgba(87,182,224,.07);border-color:var(--border);}
.cs-ind-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0;}
.cs-dot-high{background:#F0575C;box-shadow:0 0 8px rgba(240,87,92,.6);}
.cs-dot-medium{background:#EE8B42;box-shadow:0 0 8px rgba(238,139,66,.55);}
.cs-dot-low{background:#E6B94E;}
.cs-ind-why{flex:1;font-size:13px;color:#D9E3F0;}
.cs-ind-sev{font-size:9.5px;letter-spacing:1px;text-transform:uppercase;font-weight:700;
  border-radius:6px;padding:2px 7px;}
.cs-sev-high{color:#F0575C;background:rgba(240,87,92,.12);}
.cs-sev-medium{color:#EE8B42;background:rgba(238,139,66,.12);}
.cs-sev-low{color:#E6B94E;background:rgba(230,185,78,.12);}
.cs-clean{display:flex;align-items:center;gap:9px;font-size:13px;color:var(--mut);
  padding:6px 2px;}

/* recommended response */
.cs-resp{display:flex;flex-direction:column;gap:8px;}
.cs-resp-item{display:flex;align-items:center;gap:12px;padding:12px;border-radius:11px;
  border:1px solid var(--border);background:rgba(9,15,24,.4);transition:.14s;cursor:pointer;}
.cs-resp-item:hover{border-color:var(--border2);background:rgba(87,182,224,.06);transform:translateX(2px);}
.cs-resp-ic{width:34px;height:34px;border-radius:9px;display:grid;place-items:center;flex-shrink:0;
  background:rgba(87,182,224,.12);color:var(--steel);}
.cs-resp-t{font-size:13.5px;font-weight:600;color:var(--ink);}
.cs-resp-d{font-size:11.5px;color:var(--mut);margin-top:1px;}
.cs-resp-arrow{margin-left:auto;color:var(--mut2);}
.cs-take{width:100%;margin-top:14px;border:none;border-radius:11px;padding:12px;
  color:#0B1220;font-weight:700;font-size:13.5px;cursor:pointer;transition:.15s;letter-spacing:.2px;}
.cs-take:hover{filter:brightness(1.06);transform:translateY(-1px);}
.cs-restart{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  font-size:12.5px;color:var(--mut);background:transparent;border:1px dashed var(--border2);
  border-radius:11px;padding:11px;cursor:pointer;}
.cs-restart:hover{color:var(--ink);border-color:var(--steel);}

@media (max-width:920px){
  .cs-main{grid-template-columns:1fr;}
  .cs-search{display:none;}
}
@media (prefers-reduced-motion:reduce){
  .cs-scanline,.cs-spin-slow,.cs-cursor{animation:none;}
}
`;
