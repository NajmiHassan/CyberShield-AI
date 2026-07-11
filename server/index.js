import "dotenv/config";
import express from "express";
import { SYSTEM_PROMPT, THREAT_SCHEMA, FEW_SHOT } from "./prompt.js";
import { registerUser, loginUser, saveSearchHistory, getUserHistory } from "./db.js";

const PORT = process.env.PORT || 3001;
const FIREWORKS_API_KEY = process.env.FIREWORKS_API_KEY;
const FIREWORKS_URL = "https://api.fireworks.ai/inference/v1/chat/completions";
const MODEL = "accounts/fireworks/models/deepseek-v4-flash";

if (!FIREWORKS_API_KEY) {
  console.warn("[cybershield] FIREWORKS_API_KEY is not set — /api/analyze will return 500 until it is configured in .env");
}

const app = express();
app.use(express.json({ limit: "1mb" }));

app.post("/api/auth/register", (req, res) => {
  const result = registerUser(req.body || {});
  if (!result.ok) {
    return res.status(400).json(result);
  }
  return res.status(201).json(result);
});

app.post("/api/auth/login", (req, res) => {
  const result = loginUser(req.body || {});
  if (!result.ok) {
    return res.status(401).json(result);
  }
  return res.json(result);
});

app.post("/api/history", (req, res) => {
  const result = saveSearchHistory(req.body || {});
  if (!result.ok) {
    return res.status(400).json(result);
  }
  return res.status(201).json(result);
});

app.get("/api/history/:userId", (req, res) => {
  const history = getUserHistory(req.params.userId);
  return res.json({ user_id: req.params.userId, history });
});

app.post("/api/analyze", async (req, res) => {
  const message = (req.body && req.body.message ? String(req.body.message) : "").trim();
  if (!message) {
    return res.status(400).json({ error: "message is required" });
  }
  if (!FIREWORKS_API_KEY) {
    return res.status(500).json({ error: "FIREWORKS_API_KEY not configured on server" });
  }

  const body = {
    model: MODEL,
    temperature: 0.15,
    max_tokens: 1200,
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      ...FEW_SHOT,
      { role: "user", content: message }
    ],
    response_format: {
      type: "json_schema",
      json_schema: { name: "threat_analysis", schema: THREAT_SCHEMA }
    }
  };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);

  try {
    const r = await fetch(FIREWORKS_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${FIREWORKS_API_KEY}`
      },
      body: JSON.stringify(body),
      signal: controller.signal
    });

    if (!r.ok) {
      const text = await r.text();
      console.error("[cybershield] Fireworks API error", r.status, text);
      return res.status(502).json({ error: "fireworks_error", status: r.status });
    }

    const data = await r.json();
    console.log(
      `[cybershield] Fireworks call OK — model=${data.model} tokens(prompt/completion/total)=` +
      `${data.usage?.prompt_tokens}/${data.usage?.completion_tokens}/${data.usage?.total_tokens}`
    );
    const content = data?.choices?.[0]?.message?.content;
    const parsed = JSON.parse(content);
    return res.json(parsed);
  } catch (err) {
    console.error("[cybershield] analyze failed:", err.message || err);
    return res.status(500).json({ error: "internal_error" });
  } finally {
    clearTimeout(timeout);
  }
});

app.listen(PORT, () => {
  console.log(`[cybershield] backend listening on http://localhost:${PORT}`);
});
