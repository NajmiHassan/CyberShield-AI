# CyberShield AI — Implementation Brief: Replace rule-based `analyze()` with DeepSeek V4 Flash (Fireworks)

Hand this whole file to your coding assistant (Claude Code / Cursor) as the task spec. It is written to be executed against the existing `CyberShieldAI.jsx` file.

---

## 0. Goal

Replace the local, regex-based `analyze()` function in `CyberShieldAI.jsx` with a **real threat-analysis model** — DeepSeek V4 Flash on Fireworks — using **structured JSON outputs**. The model performs the full task in one call:

- **Classification** → `threat_type`, `risk_score`, `risk_level`
- **Extraction** → `indicators[]` (the exact suspicious snippets, with severity + reason)
- **Generation / reasoning** → `recommendations[]` (recommended response actions)

The UI must keep working **unchanged**. Only the "brain" behind it changes.

---

## 1. Hard constraints (do not skip)

1. **Never call Fireworks from the browser.** The API key must live server-side only. If it ships in frontend code it is exposed in the network tab and the bundle, and you'll also hit CORS. Add a tiny backend proxy (see §6). The React app calls **your own** `/api/analyze` endpoint, which calls Fireworks.
2. **Keep the UI output contract identical.** The current `analyze(text)` returns:
   ```js
   { score, band, threatType, confidence, matches, indicators }
   ```
   The new async `analyze(text)` must resolve to the **same shape**, so `buildSegments`, `RiskRing`, the indicator list, and `recommend()` all keep working. Do this with an adapter (§5) — do not rewrite the UI.
3. **Highlight offsets are computed on the client, not by the model.** Models are unreliable at counting character indices. The model returns the **exact substring** (`snippet`); the client finds its `start`/`end` by searching the original text (§5). This is the single most important robustness decision.
4. **Keep the old rule engine as a fallback only.** Rename it `heuristicAnalyze()`. On any API failure (network, timeout, bad JSON, schema violation) fall back to it so the live demo never dies on stage. The Fireworks path is primary; the heuristic is the safety net.
5. **This runs in your own project, not the claude.ai artifact sandbox.** The artifact preview can't run a backend. Move the component into a Vite + small server, or Next.js, to test the real integration.

---

## 2. Endpoint & model facts (verified)

| Item | Value |
|---|---|
| Base URL (OpenAI-compatible) | `https://api.fireworks.ai/inference/v1` |
| Chat endpoint | `POST https://api.fireworks.ai/inference/v1/chat/completions` |
| Model string | `accounts/fireworks/models/deepseek-v4-flash` |
| Auth | `Authorization: Bearer $FIREWORKS_API_KEY` |
| Context length | ~1,040k tokens (emails are tiny; non-issue) |
| Price (per 1M tokens) | ~$0.14 in / $0.28 out — a single email analysis costs a fraction of a cent |

**Gotcha — reasoning vs JSON:** on Fireworks, passing `response_format` with a `json_schema` **disables** the model's separate reasoning output. That's exactly what we want here (clean strict JSON). Do **not** try to also request reasoning — pick strict JSON.

**Gotcha — proxies:** call Fireworks **directly** with `fetch`/OpenAI SDK. Some wrapper libraries (LiteLLM, some LangChain paths) silently downgrade `json_schema` to `json_object`, which drops schema enforcement and lets the model return malformed/enum-violating output. Direct call = guaranteed schema.

---

## 3. The JSON schema the model must return

Use this as `response_format.json_schema.schema`:

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["threat_type", "risk_score", "risk_level", "confidence", "summary", "indicators", "recommendations"],
  "properties": {
    "threat_type": {
      "type": "string",
      "enum": ["Phishing", "Payout scam", "Malware / payload", "Spam", "Suspicious", "Legitimate"]
    },
    "risk_score": { "type": "integer", "minimum": 0, "maximum": 100 },
    "risk_level": {
      "type": "string",
      "enum": ["Safe", "Low", "Elevated", "High", "Critical"]
    },
    "confidence": { "type": "integer", "minimum": 0, "maximum": 100 },
    "summary": { "type": "string" },
    "indicators": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["snippet", "category", "severity", "why"],
        "properties": {
          "snippet":  { "type": "string" },
          "category": { "type": "string", "enum": ["phishing", "scam", "malware", "spam", "other"] },
          "severity": { "type": "string", "enum": ["low", "medium", "high"] },
          "why":      { "type": "string" }
        }
      }
    },
    "recommendations": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["title", "detail"],
        "properties": {
          "title":  { "type": "string" },
          "detail": { "type": "string" }
        }
      }
    }
  }
}
```

**Note:** `risk_score` is the source of truth for the risk-ring color band on the client. `risk_level` is the model's own label for consistency; the client derives the band from `risk_score` regardless.

---

## 4. The system prompt (this is the core "prompt" you asked for)

Send this as the `system` message on every call:

```
You are CyberShield AI, a defensive email and message threat-analysis engine used by security analysts. You analyze a single inbound message and return a strict JSON verdict.

Your job, in one pass:
1. CLASSIFY the message: choose one threat_type from the allowed set, assign an integer risk_score from 0 to 100, and map it to a risk_level band (0-19 Safe, 20-39 Low, 40-59 Elevated, 60-79 High, 80-100 Critical).
2. EXTRACT indicators: list every concrete piece of evidence that supports your verdict. For each indicator, quote the EXACT substring as it appears verbatim in the message (character-for-character, correct case). Never paraphrase the snippet, never invent text that is not present. Give a short "why" (one sentence, plain language) and a severity.
3. RECOMMEND response actions: 2 to 4 short, concrete next steps an analyst or user should take, ordered by priority.

Rules:
- Only flag things that are actually present. If the message is clearly legitimate, set threat_type to "Legitimate", give a low risk_score, and return an empty indicators array.
- Weight indicators by real phishing/scam/malware tradecraft: look-alike or spoofed sender domains, links whose visible domain differs from the real destination, raw-IP or shortened URLs, urgency and threat/pressure language, requests to verify/confirm credentials or reset passwords, requests for sensitive data (SSN, card number, banking, ID photo), payout/prize/gift-card/crypto lures, and suspicious attachments or "enable macros" requests.
- confidence reflects how sure you are of the classification (0-100), not the risk.
- summary is one neutral sentence describing the verdict for the analyst.
- Be decisive and concise. Output must conform exactly to the provided JSON schema. Do not add commentary outside the JSON.
```

### Few-shot anchors (optional but recommended — include as extra messages before the real user message)

These stabilize format and quality. Add them to the `messages` array as `user` (the email) / `assistant` (the JSON) pairs.

**Example A — phishing (user):**
```
From: support@amaz0n-security.com

Dear Customer,
We detected unusual sign-in activity. Your account will be suspended within 24 hours unless you verify your identity immediately. Confirm your password here: http://203.0.113.45/verify-account
```
**Example A (assistant):**
```json
{
  "threat_type": "Phishing",
  "risk_score": 92,
  "risk_level": "Critical",
  "confidence": 97,
  "summary": "Credential-phishing message impersonating Amazon using a look-alike domain and a raw-IP verification link.",
  "indicators": [
    { "snippet": "support@amaz0n-security.com", "category": "phishing", "severity": "high", "why": "Look-alike domain impersonating a trusted brand (amaz0n)." },
    { "snippet": "http://203.0.113.45/verify-account", "category": "phishing", "severity": "high", "why": "Link points to a raw IP address, not a real domain." },
    { "snippet": "verify your identity immediately", "category": "phishing", "severity": "medium", "why": "Urgency and pressure to act fast." },
    { "snippet": "Confirm your password", "category": "phishing", "severity": "high", "why": "Asks the recipient to hand over their password." },
    { "snippet": "Dear Customer", "category": "phishing", "severity": "low", "why": "Generic, impersonal greeting." }
  ],
  "recommendations": [
    { "title": "Quarantine the message", "detail": "Move it out of the inbox and hold it for review." },
    { "title": "Block sender and domain", "detail": "Stop amaz0n-security.com from reaching users." },
    { "title": "Reset exposed credentials", "detail": "Rotate any password that may have been entered." },
    { "title": "Report to the security team", "detail": "Warn other likely targets of the campaign." }
  ]
}
```

**Example B — legitimate (user):**
```
From: notes@calendar.company.com

Hi Najmi, reminder that our design review is Thursday at 3pm in the Aurora room. Agenda attached. Let me know if that still works.
Thanks, Priya
```
**Example B (assistant):**
```json
{
  "threat_type": "Legitimate",
  "risk_score": 6,
  "risk_level": "Safe",
  "confidence": 96,
  "summary": "Routine internal meeting reminder with no signs of compromise.",
  "indicators": [],
  "recommendations": [
    { "title": "No action needed", "detail": "Message shows no signs of compromise." },
    { "title": "Deliver normally", "detail": "Route to the recipient's inbox." }
  ]
}
```

---

## 5. Client adapter — map model JSON → the UI's existing shape

Add this to `CyberShieldAI.jsx`. Keep the existing `band()` helper and reuse it. Replace `analyze()` with an async version that calls the backend and adapts the result; keep the old logic renamed as `heuristicAnalyze()` for fallback.

```js
// --- offset finder: locate every occurrence of an exact snippet in the text ---
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

// --- map the model's JSON to the shape the UI already renders ---
function adaptModelResult(model, originalText) {
  const score = Math.max(0, Math.min(100, model.risk_score ?? 0));
  const b = band(score);

  // indicators list (right panel). Give each a stable id for hover-sync.
  const indicators = (model.indicators || []).map((ind, idx) => ({
    ruleId: "m" + idx,
    why: ind.why,
    severity: ind.severity,
    category: ind.category,
    count: 1,
  }));

  // matches (highlighted spans in the message). One indicator -> N ranges.
  const matches = [];
  (model.indicators || []).forEach((ind, idx) => {
    findRanges(originalText, ind.snippet).forEach((r) => {
      matches.push({
        start: r.start, end: r.end, text: originalText.slice(r.start, r.end),
        ruleId: "m" + idx, severity: ind.severity, why: ind.why, category: ind.category,
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
    recommendations: model.recommendations || [], // used by recommend() (see below)
  };
}
```

**Update `recommend()`** so it uses the model's recommendations (with keyword→icon mapping) and only falls back to hard-coded actions if the model returned none:

```js
import { Ban, Send, KeyRound, Trash2, Lock, ScanLine, ShieldCheck, Circle } from "lucide-react";

function iconFor(title = "") {
  const t = title.toLowerCase();
  if (t.includes("block"))     return Ban;
  if (t.includes("report"))    return Send;
  if (t.includes("password") || t.includes("credential") || t.includes("reset")) return KeyRound;
  if (t.includes("quarantine")|| t.includes("delete") || t.includes("remove"))   return Trash2;
  if (t.includes("isolate"))   return Lock;
  if (t.includes("scan"))      return ScanLine;
  if (t.includes("no action") || t.includes("legitimate") || t.includes("reviewed")) return ShieldCheck;
  return Circle;
}

function recommend(result) {
  const recs = result.recommendations || [];
  if (recs.length) return recs.map(r => ({ icon: iconFor(r.title), t: r.title, d: r.detail }));
  // fallback: keep your previous hard-coded lists here as a last resort
  return [{ icon: ShieldCheck, t: "Review manually", d: "No automated recommendation available." }];
}
```

**New `analyze()`** (async, calls your backend, adapts, falls back):

```js
async function analyze(text) {
  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: text }),
    });
    if (!res.ok) throw new Error("api " + res.status);
    const model = await res.json();       // the strict JSON verdict
    return adaptModelResult(model, text);
  } catch (e) {
    console.warn("Fireworks path failed, using heuristic fallback:", e);
    return heuristicAnalyze(text);        // the old rule-based function, renamed
  }
}
```

**Update `run()` to be async** (it currently calls `analyze()` synchronously):

```js
const run = async () => {
  if (!input.trim()) return;
  setStage("scanning");
  setScanLines([]);
  // ...start the terminal typing animation as you do now...
  const r = await analyze(input);         // now awaited
  setResult(r);
  // ...then flip to "done" once the terminal sequence has played...
};
```

Keep the terminal animation, but you can drive the final line from the real result (`r.threatType`, `r.score`). Everything else in the component (`buildSegments`, `RiskRing`, indicators, evidence highlighting) stays as-is.

---

## 6. Backend proxy (pick one — ~20 lines)

**Next.js App Router** — `app/api/analyze/route.js`:

```js
export async function POST(req) {
  const { message } = await req.json();

  const body = {
    model: "accounts/fireworks/models/deepseek-v4-flash",
    temperature: 0.15,
    max_tokens: 1200,
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      // ...optional few-shot user/assistant pairs...
      { role: "user", content: message },
    ],
    response_format: {
      type: "json_schema",
      json_schema: { name: "threat_analysis", schema: THREAT_SCHEMA },
    },
  };

  const r = await fetch("https://api.fireworks.ai/inference/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${process.env.FIREWORKS_API_KEY}`,
    },
    body: JSON.stringify(body),
  });

  if (!r.ok) return new Response(await r.text(), { status: r.status });

  const data = await r.json();
  const parsed = JSON.parse(data.choices[0].message.content); // strict JSON string
  return Response.json(parsed);
}
```

**Express variant** (if you're on Vite + a small Node server): same body and fetch, wrapped in `app.post("/api/analyze", ...)`.

Put `SYSTEM_PROMPT` and `THREAT_SCHEMA` (from §3/§4) in a shared server file. Set `FIREWORKS_API_KEY` in `.env` (never commit it).

---

## 7. Acceptance criteria

- [ ] API key never appears in any client bundle or network request from the browser.
- [ ] Pasting the phishing sample returns `threat_type: "Phishing"`, high `risk_score`, and highlights that line up with real substrings in the text.
- [ ] Pasting the legitimate sample returns `Legitimate`, low score, empty indicators, green ring.
- [ ] Killing the network (or bad key) still produces a verdict via `heuristicAnalyze()` — the demo never white-screens.
- [ ] Every `indicator.snippet` returned either highlights in the message or is silently dropped from highlights (never crashes; still shown in the indicator list).
- [ ] The terminal, risk ring, indicator hover-sync, and recommended-response panel all render exactly as before.

---

## 8. Necessary Fireworks documentation

Must-read (in order):

1. **Serverless Quickstart** — your first API call, auth, streaming basics — https://docs.fireworks.ai/getting-started/quickstart
2. **Structured outputs (JSON mode / json_schema)** — the feature this whole integration depends on; read the `response_format` + `json_schema` section and the reasoning caveat — https://docs.fireworks.ai/structured-responses/structured-response-formatting
3. **Querying text models** — chat completions API, `messages`, `temperature`, `max_tokens`, system prompts — https://docs.fireworks.ai/guides/querying-text-models

Reference as needed:

4. **API reference** — exact request/response fields — https://docs.fireworks.ai/api-reference/introduction
5. **Getting started / introduction** — platform overview, serverless vs deployments — https://docs.fireworks.ai/getting-started/introduction
6. **DeepSeek V4 Flash model page** — model string, live pricing, context length, "Try in Playground" to test your prompt before coding — https://fireworks.ai/models/fireworks/deepseek-v4-flash
7. **Pricing** — confirm current per-token cost against your credits — https://fireworks.ai/pricing
8. **On-demand deployments** — only if you outgrow serverless rate limits and want a dedicated GPU endpoint (stretch/scale, not needed for the demo) — https://docs.fireworks.ai/guides/ondemand-deployments
9. **Cookbooks / examples** — working code samples incl. structured extraction — https://docs.fireworks.ai/examples/introduction
10. **Changelog** — check for newer/renamed models before you hardcode the string — https://docs.fireworks.ai/updates/changelog

Tip: open the **Playground** (doc #6) and paste your system prompt + schema + a sample email first. Once it returns clean JSON there, wire it into the backend — you'll debug prompt issues in seconds instead of through the app.
```
