/**
 * Client for the Python ML microservice.
 *
 * Design constraints that shaped this file:
 *
 * * **The ML tier must never be able to break analysis.** Every call is
 *   time-boxed and wrapped; on any failure the caller receives
 *   `{ used:false, reason }` and the rule engine carries on alone.
 * * **A dead service must not cost 2.5s on every request.** After
 *   `breakerThreshold` consecutive failures the circuit opens and calls
 *   short-circuit for `breakerCooldownMs`, so a stopped ML service degrades to
 *   roughly zero added latency instead of a timeout per request.
 * * **The probability becomes evidence, not a verdict.** It is converted into a
 *   normal weighted signal so it flows through the same category caps, trust
 *   damping and explanation machinery as every heuristic.
 */

import { config } from '../config.js';

const breaker = { failures: 0, openedAt: 0 };

function breakerOpen() {
  if (breaker.failures < config.ml.breakerThreshold) return false;
  if (Date.now() - breaker.openedAt > config.ml.breakerCooldownMs) {
    breaker.failures = 0;
    return false;
  }
  return true;
}

function recordFailure() {
  breaker.failures += 1;
  if (breaker.failures >= config.ml.breakerThreshold) breaker.openedAt = Date.now();
}

async function post(pathname, payload) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.ml.timeoutMs);
  try {
    const response = await fetch(`${config.ml.baseUrl}${pathname}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    if (!response.ok) throw new Error(`ML service responded ${response.status}`);
    breaker.failures = 0;
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

/** Liveness probe used by /api/health and the UI status strip. */
export async function mlHealth() {
  if (!config.ml.enabled) return { reachable: false, reason: 'ML layer disabled by configuration' };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.min(1500, config.ml.timeoutMs));
  try {
    const response = await fetch(`${config.ml.baseUrl}/health`, { signal: controller.signal });
    if (!response.ok) return { reachable: false, reason: `status ${response.status}` };
    const body = await response.json();
    return { reachable: true, ...body, baseUrl: config.ml.baseUrl };
  } catch (error) {
    return { reachable: false, reason: error.name === 'AbortError' ? 'timed out' : error.message, baseUrl: config.ml.baseUrl };
  } finally {
    clearTimeout(timer);
  }
}

/** Training metadata and gold-set metrics, surfaced on the dashboard. */
export async function mlModelInfo() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.ml.timeoutMs);
  try {
    const response = await fetch(`${config.ml.baseUrl}/model/info`, { signal: controller.signal });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Turn a phishing probability into a weighted signal.
 *
 * Deliberately non-linear and asymmetric:
 * - below 0.35 the model is *reducing* risk, but only mildly, because a model
 *   confidently calling a BEC email "legitimate" must not cancel out a
 *   spoofed-sender finding;
 * - above 0.6 it ramps up towards `maxSignalWeight`;
 * - between the two it stays near zero, which is the honest answer.
 */
export function probabilityToSignal(probability, source) {
  const max = config.ml.maxSignalWeight;
  const label = source === 'url' ? 'URL classifier' : 'Message classifier';
  const pct = Math.round(probability * 100);

  if (probability >= 0.6) {
    const weight = Math.round(max * Math.min(1, (probability - 0.6) / 0.35 + 0.45));
    return {
      id: `ml-${source}-high`,
      category: 'ml',
      label: `${label} rates this as phishing (${pct}% confidence)`,
      weight,
      detail: `A model trained on labelled phishing and legitimate ${source === 'url' ? 'links' : 'messages'} assigns a ${pct}% probability of phishing, independently of the rules above.`,
      evidence: `${source} model probability ${probability.toFixed(3)}`
    };
  }
  if (probability <= 0.35) {
    return {
      id: `ml-${source}-low`,
      category: 'positive',
      label: `${label} sees nothing suspicious (${pct}% phishing probability)`,
      weight: -Math.round(Math.min(12, (0.35 - probability) * 30)),
      detail: `The trained ${source} model puts this well inside the legitimate range. This lowers, but does not override, the rule-based findings.`,
      evidence: `${source} model probability ${probability.toFixed(3)}`
    };
  }
  return {
    id: `ml-${source}-uncertain`,
    category: 'ml',
    label: `${label} is uncertain (${pct}% phishing probability)`,
    weight: Math.round(max * 0.18),
    detail: 'The model sits between its legitimate and phishing ranges, so it adds only a small amount of evidence. Treat the rule-based findings as the primary signal.',
    evidence: `${source} model probability ${probability.toFixed(3)}`
  };
}

/**
 * Run the ML stage for one analysis.
 *
 * @param {{ text?:string, urls?:string[] }} input
 * @returns {Promise<{ used:boolean, reason?:string, probability?:number,
 *                     models?:string[], message?:Object, url?:Object,
 *                     signals:Array, latencyMs:number }>}
 */
export async function runMlStage({ text = '', urls = [] } = {}) {
  const started = Date.now();
  const empty = (reason) => ({ used: false, reason, signals: [], latencyMs: Date.now() - started });

  if (!config.ml.enabled) return empty('ML layer disabled by configuration');
  if (breakerOpen()) return empty('ML service unreachable (circuit open after repeated failures)');
  if (!text.trim() && !urls.length) return empty('nothing to classify');

  const jobs = [];
  if (text.trim()) jobs.push(post('/predict/message', { text, top_k: 8 }).then((r) => ({ kind: 'message', r })));

  // Only the riskiest-looking link is sent: it is the one that decides the
  // verdict, and one call keeps the stage inside the latency budget.
  const primaryUrl = urls[0];
  if (primaryUrl) jobs.push(post('/predict/url', { url: primaryUrl, top_k: 8 }).then((r) => ({ kind: 'url', r })));

  let settled;
  try {
    settled = await Promise.allSettled(jobs);
  } catch (error) {
    recordFailure();
    return empty(error.message);
  }

  const results = {};
  let anyFailure = false;
  for (const item of settled) {
    if (item.status === 'fulfilled') results[item.value.kind] = item.value.r;
    else anyFailure = true;
  }

  if (!Object.keys(results).length) {
    recordFailure();
    const reason = settled[0]?.reason;
    return empty(reason?.name === 'AbortError' ? `ML service timed out after ${config.ml.timeoutMs}ms` : reason?.message || 'ML service unavailable');
  }

  const signals = [];
  const models = [];
  const probabilities = [];

  if (results.message) {
    models.push('message');
    probabilities.push(results.message.probability);
    signals.push(probabilityToSignal(results.message.probability, 'message'));
  }
  if (results.url) {
    models.push('url');
    probabilities.push(results.url.probability);
    signals.push(probabilityToSignal(results.url.probability, 'url'));
  }

  return {
    used: true,
    degraded: anyFailure,
    probability: Math.max(...probabilities),
    models,
    message: results.message
      ? {
        probability: results.message.probability,
        label: results.message.label,
        threshold: results.message.threshold,
        topIndicators: results.message.top_indicators,
        statistics: results.message.statistics,
        modelVersion: results.message.model_version,
        latencyMs: results.message.latency_ms
      }
      : null,
    url: results.url
      ? {
        url: results.url.url,
        probability: results.url.probability,
        label: results.url.label,
        topIndicators: results.url.top_indicators,
        modelVersion: results.url.model_version,
        latencyMs: results.url.latency_ms
      }
      : null,
    signals,
    latencyMs: Date.now() - started
  };
}

export const mlBreakerState = () => ({ ...breaker, open: breakerOpen() });
