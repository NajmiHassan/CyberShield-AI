// Vercel serverless function — deployed automatically at /api/analyze
// Local dev still uses server/index.js (Express); this file is what runs in production on Vercel.

import { SYSTEM_PROMPT, THREAT_SCHEMA, FEW_SHOT } from "../server/prompt.js";

const FIREWORKS_URL = "https://api.fireworks.ai/inference/v1/chat/completions";
const MODEL = "accounts/fireworks/models/deepseek-v4-flash";

// Allow the function up to 30s (Fireworks calls are usually a few seconds).
export const config = { maxDuration: 30 };

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "method_not_allowed" });
  }

  const FIREWORKS_API_KEY = process.env.FIREWORKS_API_KEY;

  // Vercel parses JSON bodies automatically, but guard in case it's a string.
  let payload = req.body;
  if (typeof payload === "string") {
    try { payload = JSON.parse(payload); } catch { payload = {}; }
  }
  const message = (payload && payload.message ? String(payload.message) : "").trim();

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
  const timeout = setTimeout(() => controller.abort(), 25000);

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
      `[cybershield] Fireworks OK | model=${data.model} tokens=` +
      `${data.usage?.prompt_tokens}/${data.usage?.completion_tokens}/${data.usage?.total_tokens}`
    );

    const content = data?.choices?.[0]?.message?.content;
    const parsed = JSON.parse(content);
    return res.status(200).json(parsed);
  } catch (err) {
    console.error("[cybershield] analyze failed:", err.message || err);
    return res.status(500).json({ error: "internal_error" });
  } finally {
    clearTimeout(timeout);
  }
}