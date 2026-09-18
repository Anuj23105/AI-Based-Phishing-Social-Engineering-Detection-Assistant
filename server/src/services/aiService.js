/**
 * Optional large-language-model layer (Gemini or any OpenAI-compatible API).
 *
 * The LLM is the *last* opinion, never the first. It receives the message plus
 * the evidence the deterministic layers already found, and returns a structured
 * second assessment. Three guardrails keep it from becoming a liability:
 *
 * 1. It is time-boxed, and a timeout is a non-event: analysis completes without it.
 * 2. Its score is fused with a bounded weight (default 0.35) and can never pull
 *    a verdict below a floor the rules established — models are easily talked
 *    out of a correct answer by polished phishing copy.
 * 3. Only the JSON fields we asked for are used. Free-form text is passed
 *    through as a narrative, clearly labelled as model-generated.
 */

import { aiConfigured, config } from '../config.js';

const SYSTEM_PROMPT = `You are a cybersecurity analyst assisting a phishing-detection product.
You will receive a message (email, SMS or chat) and a list of technical findings from a rule engine and an ML classifier.
Assess the intent of the message: is it phishing, social engineering, fraud, or legitimate?

Reply with ONLY a JSON object, no markdown, using exactly these keys:
{
  "score": <integer 0-100, how dangerous this is>,
  "verdict": "<one short phrase, e.g. 'Credential phishing' or 'Legitimate service notice'>",
  "tactics": ["<manipulation techniques you recognise>"],
  "explanation": "<2-3 sentences in plain language a non-technical person can act on>",
  "recommendations": ["<concrete safe actions>"]
}

Rules:
- Judge intent, not spelling. Well-written phishing is still phishing.
- Genuine transactional messages (OTP alerts that warn you not to share the code, delivery updates, statements) are legitimate even when they mention money or accounts.
- Never invent technical findings that were not provided.
- Keep the explanation free of jargon.`;

function buildUserPrompt({ text, url, signals = [], mlProbability }) {
  const findings = signals.slice(0, 12).map((s) => `- [${s.category}] ${s.label} (weight ${s.weight})`).join('\n') || '- none';
  return [
    text ? `MESSAGE:\n"""\n${String(text).slice(0, 6000)}\n"""` : null,
    url ? `URL: ${url}` : null,
    `RULE ENGINE FINDINGS:\n${findings}`,
    typeof mlProbability === 'number' ? `ML CLASSIFIER PHISHING PROBABILITY: ${(mlProbability * 100).toFixed(1)}%` : null
  ].filter(Boolean).join('\n\n');
}

function extractJson(raw) {
  if (!raw) return null;
  const cleaned = String(raw).replace(/^```(?:json)?/i, '').replace(/```$/, '').trim();
  const start = cleaned.indexOf('{');
  const end = cleaned.lastIndexOf('}');
  if (start === -1 || end <= start) return null;
  try {
    return JSON.parse(cleaned.slice(start, end + 1));
  } catch {
    return null;
  }
}

async function callGemini(prompt, signal) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${config.ai.geminiModel}:generateContent?key=${config.ai.geminiKey}`;
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    signal,
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: SYSTEM_PROMPT }] },
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.1, maxOutputTokens: 700, responseMimeType: 'application/json' }
    })
  });
  if (!response.ok) throw new Error(`Gemini responded ${response.status}`);
  const body = await response.json();
  return body?.candidates?.[0]?.content?.parts?.map((p) => p.text).join('') || '';
}

async function callOpenAi(prompt, signal) {
  const response = await fetch(`${config.ai.openaiBaseUrl}/chat/completions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${config.ai.openaiKey}` },
    signal,
    body: JSON.stringify({
      model: config.ai.openaiModel,
      temperature: 0.1,
      max_tokens: 700,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: prompt }
      ]
    })
  });
  if (!response.ok) throw new Error(`OpenAI responded ${response.status}`);
  const body = await response.json();
  return body?.choices?.[0]?.message?.content || '';
}

/**
 * Run the optional LLM stage.
 *
 * @returns {Promise<null|{ provider:string, model:string, score:number,
 *                          verdict:string, explanation:string, tactics:string[],
 *                          recommendations:string[], signal:Object, latencyMs:number }>}
 *          `null` when the layer is not configured or the call failed.
 */
export async function runAiStage({ text = '', url = '', signals = [], mlProbability } = {}) {
  if (!aiConfigured()) return null;
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.ai.timeoutMs);

  try {
    const prompt = buildUserPrompt({ text, url, signals, mlProbability });
    const raw = config.ai.provider === 'gemini'
      ? await callGemini(prompt, controller.signal)
      : await callOpenAi(prompt, controller.signal);

    const parsed = extractJson(raw);
    if (!parsed) return null;

    const score = Math.max(0, Math.min(100, Number(parsed.score)));
    if (!Number.isFinite(score)) return null;

    const verdict = String(parsed.verdict || '').slice(0, 120) || 'Assessment completed';
    const explanation = String(parsed.explanation || '').slice(0, 900);
    const tactics = Array.isArray(parsed.tactics) ? parsed.tactics.slice(0, 8).map((t) => String(t).slice(0, 80)) : [];
    const recommendations = Array.isArray(parsed.recommendations)
      ? parsed.recommendations.slice(0, 5).map((r) => String(r).slice(0, 200))
      : [];

    // The model's own contribution to the evidence total, bounded so it can
    // never single-handedly decide a verdict.
    const signal = score >= 65
      ? {
        id: 'ai-assessment-malicious',
        category: 'ai',
        label: `AI language model assessment: ${verdict}`,
        weight: Math.round(Math.min(22, 8 + (score - 65) * 0.4)),
        detail: explanation || 'A language model reviewed the wording and intent and considers this malicious.',
        evidence: `model score ${score}/100`
      }
      : score <= 25
        ? {
          id: 'ai-assessment-benign',
          category: 'positive',
          label: `AI language model assessment: ${verdict}`,
          weight: -Math.round(Math.min(10, (25 - score) * 0.4)),
          detail: explanation || 'A language model reviewed the wording and found no malicious intent.',
          evidence: `model score ${score}/100`
        }
        : null;

    return {
      provider: config.ai.provider,
      model: config.ai.provider === 'gemini' ? config.ai.geminiModel : config.ai.openaiModel,
      score,
      verdict,
      explanation,
      tactics,
      recommendations,
      signal,
      latencyMs: Date.now() - started
    };
  } catch {
    // Silent by design: a failed optional layer must not change the verdict or
    // surface a scary error to the user.
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export function aiStatus() {
  return {
    provider: config.ai.provider,
    configured: aiConfigured(),
    model: config.ai.provider === 'gemini' ? config.ai.geminiModel : config.ai.provider === 'openai' ? config.ai.openaiModel : null,
    fusionWeight: config.ai.fusionWeight,
    reason: aiConfigured() ? null : 'no API key configured — analysis runs on the rule engine and ML models only'
  };
}
