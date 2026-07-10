// Shared system prompt, JSON schema and few-shot anchors for the
// DeepSeek V4 Flash (Fireworks) threat-analysis call.
// See ../fireworks-integration-brief.md sections 3 and 4.

export const SYSTEM_PROMPT = `You are CyberShield AI, a defensive email and message threat-analysis engine used by security analysts. You analyze a single inbound message and return a strict JSON verdict.

Your job, in one pass:
1. CLASSIFY the message: choose one threat_type from the allowed set, assign an integer risk_score from 0 to 100, and map it to a risk_level band (0-19 Safe, 20-39 Low, 40-59 Elevated, 60-79 High, 80-100 Critical).
2. EXTRACT indicators: list every concrete piece of evidence that supports your verdict. For each indicator, quote the EXACT substring as it appears verbatim in the message (character-for-character, correct case). Never paraphrase the snippet, never invent text that is not present. Give a short "why" (one sentence, plain language) and a severity.
3. RECOMMEND response actions: 2 to 4 short, concrete next steps an analyst or user should take, ordered by priority.

Rules:
- Only flag things that are actually present. If the message is clearly legitimate, set threat_type to "Legitimate", give a low risk_score, and return an empty indicators array.
- Weight indicators by real phishing/scam/malware tradecraft: look-alike or spoofed sender domains, links whose visible domain differs from the real destination, raw-IP or shortened URLs, urgency and threat/pressure language, requests to verify/confirm credentials or reset passwords, requests for sensitive data (SSN, card number, banking, ID photo), payout/prize/gift-card/crypto lures, and suspicious attachments or "enable macros" requests.
- confidence reflects how sure you are of the classification (0-100), not the risk.
- summary is one neutral sentence describing the verdict for the analyst.
- Be decisive and concise. Output must conform exactly to the provided JSON schema. Do not add commentary outside the JSON.`;

export const THREAT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["threat_type", "risk_score", "risk_level", "confidence", "summary", "indicators", "recommendations"],
  properties: {
    threat_type: {
      type: "string",
      enum: ["Phishing", "Payout scam", "Malware / payload", "Spam", "Suspicious", "Legitimate"]
    },
    risk_score: { type: "integer", minimum: 0, maximum: 100 },
    risk_level: {
      type: "string",
      enum: ["Safe", "Low", "Elevated", "High", "Critical"]
    },
    confidence: { type: "integer", minimum: 0, maximum: 100 },
    summary: { type: "string" },
    indicators: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["snippet", "category", "severity", "why"],
        properties: {
          snippet: { type: "string" },
          category: { type: "string", enum: ["phishing", "scam", "malware", "spam", "other"] },
          severity: { type: "string", enum: ["low", "medium", "high"] },
          why: { type: "string" }
        }
      }
    },
    recommendations: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["title", "detail"],
        properties: {
          title: { type: "string" },
          detail: { type: "string" }
        }
      }
    }
  }
};

// Few-shot anchors: stabilize format and quality (brief §4).
export const FEW_SHOT = [
  {
    role: "user",
    content:
      "From: support@amaz0n-security.com\n\nDear Customer,\nWe detected unusual sign-in activity. Your account will be suspended within 24 hours unless you verify your identity immediately. Confirm your password here: http://203.0.113.45/verify-account"
  },
  {
    role: "assistant",
    content: JSON.stringify({
      threat_type: "Phishing",
      risk_score: 92,
      risk_level: "Critical",
      confidence: 97,
      summary: "Credential-phishing message impersonating Amazon using a look-alike domain and a raw-IP verification link.",
      indicators: [
        { snippet: "support@amaz0n-security.com", category: "phishing", severity: "high", why: "Look-alike domain impersonating a trusted brand (amaz0n)." },
        { snippet: "http://203.0.113.45/verify-account", category: "phishing", severity: "high", why: "Link points to a raw IP address, not a real domain." },
        { snippet: "verify your identity immediately", category: "phishing", severity: "medium", why: "Urgency and pressure to act fast." },
        { snippet: "Confirm your password", category: "phishing", severity: "high", why: "Asks the recipient to hand over their password." },
        { snippet: "Dear Customer", category: "phishing", severity: "low", why: "Generic, impersonal greeting." }
      ],
      recommendations: [
        { title: "Quarantine the message", detail: "Move it out of the inbox and hold it for review." },
        { title: "Block sender and domain", detail: "Stop amaz0n-security.com from reaching users." },
        { title: "Reset exposed credentials", detail: "Rotate any password that may have been entered." },
        { title: "Report to the security team", detail: "Warn other likely targets of the campaign." }
      ]
    })
  },
  {
    role: "user",
    content:
      "From: notes@calendar.company.com\n\nHi Najmi, reminder that our design review is Thursday at 3pm in the Aurora room. Agenda attached. Let me know if that still works.\nThanks, Priya"
  },
  {
    role: "assistant",
    content: JSON.stringify({
      threat_type: "Legitimate",
      risk_score: 6,
      risk_level: "Safe",
      confidence: 96,
      summary: "Routine internal meeting reminder with no signs of compromise.",
      indicators: [],
      recommendations: [
        { title: "No action needed", detail: "Message shows no signs of compromise." },
        { title: "Deliver normally", detail: "Route to the recipient's inbox." }
      ]
    })
  }
];
