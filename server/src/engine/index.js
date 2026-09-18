/**
 * PhishGuard AI — detection engine entry point.
 *
 * Implements the detection pipeline:
 *
 *     Input
 *       -> Text & URL Preprocessing
 *       -> Feature Extraction   (suspicious language, urgency / manipulation,
 *                                sender & domain signals, URL characteristics,
 *                                credential / payment requests)
 *       -> AI/ML Risk Analysis  (injected by the service layer)
 *       -> Risk Scoring
 *       -> Explanation + Safe Action
 *
 * The engine itself is pure and synchronous: no network, no database, no model
 * calls. That keeps it deterministic, testable against the gold dataset, and
 * fast enough to leave the 5s response-time budget almost untouched. The two
 * asynchronous layers (Python ML service, optional LLM) are executed by
 * `services/pipeline.js` and handed back in as extra signals, so the engine
 * stays the single authority on how evidence becomes a score.
 *
 * Pass `options.trace = true` to get a stage-by-stage record of the pipeline in
 * `result.pipeline`, which is what the UI renders.
 */

import { AWARENESS_TIPS, CATEGORY_LABELS } from './constants.js';
import { analyzeSender, parseEmail } from './headerAnalyzer.js';
import { analyzePage, extractPageFeatures } from './pageAnalyzer.js';
import { explain } from './explainer.js';
import { LEVEL_META, SCORING, fuseScores, riskLevel, scoreSignals } from './riskScorer.js';
import { analyzeText, detectClaimedBrands } from './textAnalyzer.js';
import { analyzeUrl, analyzeUrls } from './urlAnalyzer.js';
import { extractEmails, extractPhones, extractUrls, hash, htmlToText, normalizeWhitespace, truncate, unique } from './utils.js';

export const ENGINE_VERSION = '1.0.0';

const CHANNEL_LABELS = {
  email: 'email',
  sms: 'SMS message',
  chat: 'chat message',
  whatsapp: 'WhatsApp message',
  social: 'social media message',
  url: 'link',
  website: 'website',
  message: 'message'
};

/**
 * The five feature groups from the pipeline diagram, mapped onto the signal
 * categories the analyzers emit. Used for the stage trace and the UI.
 */
export const FEATURE_GROUPS = [
  { id: 'language', label: 'Suspicious language', categories: ['content'] },
  { id: 'manipulation', label: 'Urgency / manipulation', categories: ['social-engineering', 'bec'] },
  { id: 'sender', label: 'Sender & domain signals', categories: ['sender', 'domain'] },
  { id: 'url', label: 'URL characteristics', categories: ['url'] },
  { id: 'credential', label: 'Credential / payment requests', categories: ['credential-theft', 'financial-fraud'] },
  { id: 'website', label: 'Website behaviour', categories: ['page'] }
];

/** Decide what we were handed when the caller says `type: 'auto'`. */
export function detectInputType(input = {}) {
  const content = String(input.content || '').trim();
  if (input.html && input.html.trim()) return 'website';
  if (input.url && !content) return 'url';
  if (!content) return input.url ? 'url' : 'message';
  if (/^<(?:!doctype|html|head|body)\b/i.test(content) || (/<html[\s>]/i.test(content) && /<\/html>/i.test(content))) return 'website';
  if (/^(?:from|to|subject|date|received|return-path|reply-to|message-id|authentication-results)\s*:/im.test(content.slice(0, 1500))) return 'email';
  if (!/\s/.test(content) && /^(?:https?:\/\/|www\.)|^[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:[/:?#]|$)/i.test(content)) return 'url';
  return content.split(/\s+/).length <= 45 ? 'sms' : 'message';
}

/**
 * Stage 2 — Text & URL preprocessing.
 *
 * Splits raw e-mail into headers and body, converts HTML to visible text, and
 * pulls out the entities every later stage needs. Exported separately so the
 * service layer can feed the ML models without waiting for, or duplicating, the
 * full analysis.
 *
 * @returns {{ type:string, channel:string, bodyText:string, headers:Object,
 *             isRawEmail:boolean, html:string, links:Array, urls:string[],
 *             emails:string[], phones:string[], claimedBrands:Array }}
 */
export function preprocess(input = {}) {
  const type = input.type && input.type !== 'auto' ? input.type : detectInputType(input);

  let bodyText = String(input.content || '');
  let headers = input.headers || {};
  let isRawEmail = false;

  if (type === 'email') {
    const parsed = parseEmail(bodyText);
    headers = { ...parsed.headers, ...(input.headers || {}) };
    bodyText = parsed.body;
    isRawEmail = parsed.isRawEmail;
  }

  let html = input.html || '';
  if (type === 'website' && !html && /<[a-z][\s\S]*>/i.test(bodyText)) {
    html = bodyText;
    bodyText = htmlToText(html);
  } else if (html && !bodyText.trim()) {
    bodyText = htmlToText(html);
  }

  const links = input.links?.length
    ? input.links
    : html
      ? extractPageFeatures(html, input.url || '').anchors.map((a) => ({ href: a.href, text: a.text }))
      : [];

  const urls = unique([
    ...(type === 'url' && input.content ? extractUrls(String(input.content)) : []),
    ...(type === 'url' && input.content && !/\s/.test(input.content.trim()) ? [input.content.trim()] : []),
    ...(input.url ? [input.url] : []),
    ...links.map((l) => l?.href).filter(Boolean),
    ...extractUrls(bodyText)
  ].filter(Boolean));

  const claimedBrands = detectClaimedBrands(
    [bodyText, headers.subject || '', headers.from || '', input.senderName || ''].join(' ')
  );

  return {
    type,
    channel: CHANNEL_LABELS[type] || 'message',
    bodyText,
    headers,
    isRawEmail,
    html,
    links,
    urls,
    emails: extractEmails(bodyText),
    phones: extractPhones(bodyText),
    claimedBrands
  };
}

/**
 * Main analysis routine.
 *
 * @param {Object} input
 * @param {'auto'|'message'|'email'|'sms'|'chat'|'whatsapp'|'social'|'url'|'website'} [input.type]
 * @param {string} [input.content]   message body, raw e-mail, or pasted HTML
 * @param {string} [input.url]       URL to analyze (or the URL the HTML came from)
 * @param {string} [input.html]      website HTML
 * @param {string} [input.senderEmail]
 * @param {string} [input.senderName]
 * @param {string} [input.replyTo]
 * @param {Array<{href:string,text:string}>} [input.links]
 * @param {Object} [options]
 * @param {Object} [options.pre]           precomputed `preprocess()` output
 * @param {Array}  [options.extraSignals]  signals from the ML / intel layers
 * @param {Object} [options.ai]            `{ score, verdict, explanation, signal, ... }`
 * @param {number} [options.aiWeight]
 * @param {Object} [options.scoring]       overrides for SCORING (used by the tuner)
 * @param {boolean}[options.trace]         record the per-stage pipeline trace
 */
export function analyze(input = {}, options = {}) {
  const startedAt = Date.now();
  const stages = [];
  const stage = (id, label, detail) => {
    if (options.trace) stages.push({ id, label, at: Date.now() - startedAt, ...detail });
  };

  /* ------------------------------ 1. input ------------------------------ */
  const pre = options.pre || preprocess(input);
  const { type, bodyText, headers, html, links, claimedBrands } = pre;
  const primaryBrand = claimedBrands[0]?.brand || null;

  stage('input', 'Input', {
    status: 'done',
    summary: `Received ${CHANNEL_LABELS[type] || 'message'} (${bodyText.length || (input.url || '').length} characters)`,
    facts: { detectedType: type, hasHeaders: pre.isRawEmail, hasHtml: Boolean(html) }
  });

  /* --------------------- 2. text & URL preprocessing -------------------- */
  stage('preprocessing', 'Text & URL Preprocessing', {
    status: 'done',
    summary: [
      pre.isRawEmail ? `${Object.keys(headers).length} headers parsed` : null,
      html ? 'HTML reduced to visible text' : null,
      `${pre.urls.length} link(s)`,
      pre.emails.length ? `${pre.emails.length} address(es)` : null,
      pre.phones.length ? `${pre.phones.length} phone number(s)` : null
    ].filter(Boolean).join(', '),
    facts: {
      urls: pre.urls.slice(0, 8),
      emails: pre.emails.slice(0, 5),
      phones: pre.phones.slice(0, 5),
      claimedBrands: claimedBrands.map((b) => b.brand)
    }
  });

  /* ------------------------ 3. feature extraction ----------------------- */
  const signals = [];

  let textResult = null;
  if (bodyText.trim() && type !== 'url') {
    textResult = analyzeText(bodyText, { channel: type, links });
    signals.push(...textResult.signals);
  }

  let senderResult = null;
  if (Object.keys(headers).length || input.senderEmail) {
    senderResult = analyzeSender({
      headers,
      senderEmail: input.senderEmail,
      senderName: input.senderName,
      replyTo: input.replyTo,
      claimedBrands,
      bodyText
    });
    signals.push(...senderResult.signals);
  }

  let urlResult = null;
  if (pre.urls.length) {
    urlResult = analyzeUrls(pre.urls, { claimedBrand: primaryBrand });
    signals.push(...urlResult.signals);
  }

  let pageResult = null;
  if (html.trim()) {
    pageResult = analyzePage({ html, url: input.url || '' });
    signals.push(...pageResult.signals);
  }

  const groupBreakdown = FEATURE_GROUPS.map((group) => {
    const hits = signals.filter((s) => group.categories.includes(s.category) && s.weight > 0);
    return {
      id: group.id,
      label: group.label,
      hits: hits.length,
      points: hits.reduce((sum, s) => sum + s.weight, 0),
      top: hits.sort((a, b) => b.weight - a.weight)[0]?.label || null
    };
  });

  stage('feature-extraction', 'Feature Extraction', {
    status: 'done',
    summary: `${signals.filter((s) => s.weight > 0).length} risk indicator(s) and ${signals.filter((s) => s.weight < 0).length} trust indicator(s) across ${groupBreakdown.filter((g) => g.hits).length} feature groups`,
    groups: groupBreakdown,
    facts: { tactics: (textResult?.tactics || []).map((t) => t.label) }
  });

  /* ----------------------- 4. AI / ML risk analysis --------------------- */
  if (options.extraSignals?.length) signals.push(...options.extraSignals);
  if (options.ai?.signal) signals.push(options.ai.signal);

  stage('ai-ml', 'AI/ML Risk Analysis', {
    status: options.ml?.used || options.ai ? 'done' : 'skipped',
    summary: [
      options.ml?.used
        ? `ML classifier: ${(options.ml.probability * 100).toFixed(1)}% phishing probability (${options.ml.models.join(' + ')})`
        : `ML classifier unavailable — ${options.ml?.reason || 'service not configured'}`,
      options.ai ? `LLM review: ${options.ai.verdict || 'completed'}` : null,
      options.intel?.checked ? `Threat intel: ${options.intel.verdict}` : null
    ].filter(Boolean).join(' · '),
    facts: {
      ml: options.ml || { used: false },
      ai: options.ai ? { provider: options.ai.provider, score: options.ai.score } : { used: false },
      intel: options.intel || { checked: false }
    }
  });

  /* --------------------------- 5. risk scoring -------------------------- */
  const scored = scoreSignals(signals, { scoring: options.scoring });
  const fused = fuseScores(scored, options.ai, options.aiWeight);
  const finalScore = fused.score;
  const finalLevel = fused.level;

  stage('risk-scoring', 'Risk Scoring', {
    status: 'done',
    summary: `${finalScore}/100 (${LEVEL_META[finalLevel].label}) from ${scored.breakdown.evidence} evidence points less ${scored.breakdown.damping} trust points`,
    facts: scored.breakdown
  });

  /* ------------------- 6. explanation + safe action --------------------- */
  const facts = {
    claimedBrand: primaryBrand,
    hasCredentialAsk: scored.signals.some((s) => s.category === 'credential-theft'),
    impersonates: urlResult?.worst?.facts?.impersonates || pageResult?.facts?.impersonates || null
  };

  const explanation = explain({
    scored: { ...scored, score: finalScore, level: finalLevel },
    tactics: textResult?.tactics || [],
    facts,
    target: CHANNEL_LABELS[type] || 'message'
  });

  if (options.ai?.explanation) {
    explanation.aiNarrative = options.ai.explanation;
    if (Array.isArray(options.ai.recommendations) && options.ai.recommendations.length) {
      explanation.recommendations = unique([...explanation.recommendations, ...options.ai.recommendations]).slice(0, 7);
    }
  }

  stage('explanation', 'Explanation + Safe Action', {
    status: 'done',
    summary: `${explanation.reasons.length} reason(s) explained, ${explanation.recommendations.length} recommended action(s)`,
    facts: { verdict: explanation.verdict, topReason: explanation.reasons[0]?.title || null }
  });

  /* ------------------------------- assemble ----------------------------- */
  const meta = LEVEL_META[finalLevel];
  const analyzedAt = new Date().toISOString();
  const preview = truncate(normalizeWhitespace(bodyText || input.url || ''), 320);

  const result = {
    id: hash(`${analyzedAt}|${preview}|${input.url || ''}`),
    analyzedAt,
    engine: { version: ENGINE_VERSION, mode: options.ml?.used || options.ai ? 'heuristic+ml' : 'heuristic' },
    input: {
      type,
      channel: CHANNEL_LABELS[type] || 'message',
      preview,
      url: input.url || null,
      subject: headers.subject || null,
      hasHeaders: pre.isRawEmail || Object.keys(headers).length > 0
    },
    score: finalScore,
    level: finalLevel,
    levelLabel: meta.label,
    levelEmoji: meta.emoji,
    levelColor: meta.color,
    confidence: scored.confidence,
    explanation,
    signals: scored.signals,
    trustSignals: scored.positives,
    categories: scored.categories,
    featureGroups: groupBreakdown,
    breakdown: { ...scored.breakdown, heuristicScore: scored.score, fusion: fused },
    tactics: textResult?.tactics || [],
    entities: {
      urls: (urlResult?.urls || []).map((u) => ({
        url: u.url,
        host: u.host,
        registrableDomain: u.registrableDomain,
        scheme: u.scheme,
        isShortener: u.isShortener,
        impersonates: u.facts?.impersonates || null,
        riskPoints: u.signals.reduce((sum, s) => sum + Math.max(0, s.weight), 0),
        signalCount: u.signals.filter((s) => s.weight > 0).length
      })),
      emails: pre.emails,
      phones: pre.phones,
      claimedBrands: claimedBrands.map((b) => b.brand)
    },
    sender: senderResult?.facts || null,
    page: pageResult ? { facts: pageResult.facts, features: pageResult.features } : null,
    stats: textResult?.stats || null,
    ml: options.ml || { used: false, reason: 'ML layer not requested' },
    ai: options.ai
      ? {
        used: true,
        provider: options.ai.provider || 'unknown',
        model: options.ai.model || null,
        score: options.ai.score ?? null,
        verdict: options.ai.verdict || null,
        weight: fused.weightApplied,
        latencyMs: options.ai.latencyMs ?? null,
        degraded: Boolean(options.ai.degraded)
      }
      : { used: false, provider: 'none', reason: options.aiReason || 'AI layer disabled' },
    intel: options.intel || { checked: false },
    durationMs: Date.now() - startedAt
  };

  if (options.trace) result.pipeline = stages;
  return result;
}

/** Convenience wrapper for a bare URL. */
export function analyzeLink(url, options = {}) {
  return analyze({ type: 'url', url }, options);
}

/** Convenience wrapper for a website given its HTML. */
export function analyzeWebsite(url, html, options = {}) {
  return analyze({ type: 'website', url, html }, options);
}

export {
  AWARENESS_TIPS,
  CATEGORY_LABELS,
  LEVEL_META,
  SCORING,
  analyzePage,
  analyzeSender,
  analyzeText,
  analyzeUrl,
  analyzeUrls,
  detectClaimedBrands,
  explain,
  extractPageFeatures,
  parseEmail,
  riskLevel,
  scoreSignals
};
