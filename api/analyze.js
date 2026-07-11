// Vercel serverless function — deployed automatically at /api/analyze
// Local dev still uses server/index.js (Express); this file is what runs in production on Vercel.

import { SYSTEM_PROMPT, THREAT_SCHEMA, FEW_SHOT, JUDGE_SYSTEM_PROMPT } from "../server/prompt.js";

const FIREWORKS_URL = "https://api.fireworks.ai/inference/v1/chat/completions";
const MODEL = "accounts/fireworks/models/deepseek-v4-flash";
const JUDGE_MODEL = "accounts/fireworks/models/gpt-oss-120b";

// Allow the function up to 45s — the draft call and the judge pass now run
// sequentially, each with its own internal timeout below.
export const config = { maxDuration: 45 };

// Sends the DeepSeek draft verdict to a second Fireworks-hosted model
// (Llama 3.3 70B) for review; its output becomes the final verdict. Falls
// back to the draft on any failure so a flaky judge call never breaks
// analysis.
async function judgeDraft(message, draft, apiKey) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);

  try {
    const r = await fetch(FIREWORKS_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: JUDGE_MODEL,
        temperature: 0.1,
        max_tokens: 1200,
        messages: [
          { role: "system", content: JUDGE_SYSTEM_PROMPT },
          { role: "user", content: `Original message:\n${message}\n\nDraft verdict:\n${JSON.stringify(draft)}` }
        ],
        response_format: {
          type: "json_schema",
          json_schema: { name: "threat_analysis", schema: THREAT_SCHEMA }
        }
      }),
      signal: controller.signal
    });

    if (!r.ok) {
      const text = await r.text();
      console.error("[cybershield] judge error", r.status, text);
      return draft;
    }

    const data = await r.json();
    const judged = JSON.parse(data?.choices?.[0]?.message?.content);

    console.log(
      `[cybershield] judge OK | model=${data.model} tokens=` +
      `${data.usage?.prompt_tokens}/${data.usage?.completion_tokens}/${data.usage?.total_tokens}`
    );
    return judged;
  } catch (err) {
    console.error("[cybershield] judge call failed, keeping draft verdict:", err.message || err);
    return draft;
  } finally {
    clearTimeout(timeout);
  }
}

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

    const finalVerdict = await judgeDraft(message, parsed, FIREWORKS_API_KEY);
    return res.status(200).json(finalVerdict);
  } catch (err) {
    console.error("[cybershield] analyze failed:", err.message || err);
    return res.status(500).json({ error: "internal_error" });
  } finally {
    clearTimeout(timeout);
  }
}