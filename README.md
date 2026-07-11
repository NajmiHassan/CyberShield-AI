# CyberShield AI

An analyst workspace for triaging suspicious email and messages. You paste a message, run the analysis, and get back a threat verdict: what kind of threat it is, a risk score from 0 to 100, the exact phrases that triggered the verdict, and a short list of recommended actions.

The classification is done by a language model (DeepSeek V4 Flash, served through Fireworks) that returns a strict JSON verdict. If that call fails for any reason, the app falls back to a local rule-based engine so it always returns something.

<img src="docs/screenshot.png" alt="CyberShield AI interface" width="100%" />

> The image path above is a placeholder. Drop a screenshot at `docs/screenshot.png` or remove the line.

## What it does

Given a single message, the app produces:

- **Threat type**: Phishing, Payout scam, Malware / payload, Spam, Suspicious, or Legitimate.
- **Risk score**: an integer from 0 to 100, which drives the color band on the risk ring (Safe, Low, Elevated, High, Critical).
- **Indicators**: the specific suspicious snippets found in the message, each with a severity and a one-line reason. These are highlighted directly in the message so you can see the evidence in context.
- **Recommended response**: two to four concrete next steps, ordered by priority.

The interface ships with three sample messages (a phishing email, a payout scam, and a legitimate meeting reminder) so you can try it without pasting anything.

## How it works

The important design decision is that the API key never touches the browser. The React app only ever calls its own `/api/analyze` endpoint. That endpoint runs on the server, adds the system prompt and JSON schema, and calls Fireworks with the key read from an environment variable.

```
Browser (React)                Server                       Fireworks
---------------                ------                       ---------
paste message
click Analyze
  |
  |  POST /api/analyze
  |  { message }
  v
                        adds system prompt,
                        few-shot examples,
                        JSON schema
                               |
                               |  POST /chat/completions
                               |  model: deepseek-v4-flash
                               v
                                                      returns strict
                                                      JSON verdict
                               |
                        parses and returns JSON
  |
  v
adapts JSON to the UI shape,
finds snippet positions,
renders verdict + highlights
```

A few details worth knowing:

- **Snippet positions are found on the client, not returned by the model.** The model returns the exact suspicious substring. The client then searches the original text to locate it and highlight it. Models are unreliable at counting character offsets, so this keeps the highlighting accurate.
- **The response is schema-enforced.** The request uses Fireworks structured outputs (`response_format: json_schema`), so the model is constrained to the exact JSON shape the UI expects. Fields, enums, and required keys are validated by the API.
- **The rule engine is a fallback, not the primary path.** The original regex-based detection lives on as `heuristicAnalyze()`. It runs only when the API call fails (network error, timeout, bad key, or malformed response), so a demo never ends on a blank screen.

## Project structure

```
CyberShield AI/
├── index.html                 Vite entry point
├── vite.config.js             React plugin + dev proxy for /api
├── package.json
├── src/
│   ├── main.jsx               React bootstrap
│   └── CyberShieldAI.jsx      The whole UI: analyze(), adapter, fallback, styles
├── server/
│   ├── index.js               Express server for local dev (/api/analyze)
│   └── prompt.js              System prompt, JSON schema, few-shot examples (shared)
└── api/
    └── analyze.js             Vercel serverless version of the same endpoint
```

`server/index.js` and `api/analyze.js` do the same job for two different environments. Local development uses the Express server. A Vercel deployment uses the serverless function. Both import the same prompt and schema from `server/prompt.js`, so there is one source of truth.

## Requirements

- Node.js 18 or newer (the backend uses the built-in `fetch`).
- A Fireworks API key.

## Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Create a `.env` file in the project root with your Fireworks key:

   ```
   FIREWORKS_API_KEY=your_key_here
   ```

   The variable has no `VITE_` prefix on purpose. That keeps it server-only, so it is never bundled into the frontend. `.env` is git-ignored.

## Running it

You need both the frontend and the backend running. The Vite dev server proxies `/api` requests to the Express server on port 3001 (configured in `vite.config.js`).

Run both at once:

```bash
npm run dev:all
```

Or run them in two separate terminals:

```bash
npm run server    # Express backend on http://localhost:3001
npm run dev       # Vite frontend on http://localhost:5173
```

Then open http://localhost:5173.

| Script | What it does |
|--------|--------------|
| `npm run dev` | Frontend only (Vite dev server) |
| `npm run server` | Backend only (Express API) |
| `npm run dev:all` | Both together |
| `npm run build` | Production build of the frontend |
| `npm run preview` | Serve the production build locally |

## Verifying the integration

To confirm the API is actually being called and the right model is answering, test the backend directly:

```bash
curl -s -X POST http://localhost:3001/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"message":"Dear Customer, your account will be suspended within 24 hours unless you verify your identity. Confirm your password here: http://203.0.113.45/verify-account"}'
```

You should get back a JSON verdict with `"threat_type":"Phishing"` and a high `risk_score`.

The backend also logs a line after each successful call that names the model and the token usage reported by Fireworks:

```
[cybershield] Fireworks call OK | model=accounts/fireworks/models/deepseek-v4-flash tokens(prompt/completion/total)=1331/526/1857
```

To see the fallback in action, stop the backend and analyze a message in the UI. It still returns a verdict, and the browser console logs `Fireworks path failed, using heuristic fallback`.

## Configuration reference

| Setting | Value | Where |
|---------|-------|-------|
| Model | `accounts/fireworks/models/deepseek-v4-flash` | `server/index.js`, `api/analyze.js` |
| Endpoint | `https://api.fireworks.ai/inference/v1/chat/completions` | same |
| Temperature | `0.15` | same |
| Max tokens | `1200` | same |
| Backend port (dev) | `3001` | `server/index.js`, overridable with `PORT` |

The system prompt, the JSON schema, and the few-shot examples all live in `server/prompt.js`. Edit them there and both the Express and Vercel endpoints pick up the change.

## Notes

- Costs per analysis are small. A single email is a short prompt, and DeepSeek V4 Flash is inexpensive per token.
- This is a triage aid, not a final authority. It helps an analyst see evidence quickly. It does not replace a review of anything genuinely uncertain.
