/**
 * PhishGuard AI — explanation engine.
 *
 * Converts scored signals into language a non-technical user can act on:
 * what triggered the warning, why it is dangerous, and what to do next.
 * This runs with or without the LLM layer, so every prediction is explainable.
 */

import { CATEGORY_LABELS, RECOMMENDATIONS } from './constants.js';
import { LEVEL_META } from './riskScorer.js';
import { truncate, unique } from './utils.js';

const LEVEL_OPENER = {
  high: 'This looks like a phishing attempt.',
  medium: 'This message has warning signs and should be verified before you act.',
  low: 'Nothing here looks like a phishing attempt.'
};

/** Human phrase for a category, used when narrating the summary. */
const CATEGORY_PHRASE = {
  url: 'the link it contains is built to mislead you',
  domain: 'the web address imitates a brand it does not belong to',
  sender: 'the sender is not who the message claims',
  'credential-theft': 'it is trying to collect passwords or other secret details',
  'financial-fraud': 'it is trying to move your money',
  bec: 'it mimics an internal executive or finance request',
  'social-engineering': 'it uses pressure tactics to rush your decision',
  page: 'the page behaves like a credential-harvesting clone',
  content: 'the way it is written matches known scam templates',
  intel: 'it appears in threat intelligence data',
  ai: 'the language model also assessed the intent as malicious'
};

/**
 * Build the recommendation list from the categories that actually fired,
 * strongest first, always ending with reporting guidance for risky content.
 */
export function buildRecommendations(level, categories = [], facts = {}) {
  const out = [];
  const push = (items) => {
    for (const item of items || []) if (!out.includes(item)) out.push(item);
  };

  if (level === 'low') {
    push(RECOMMENDATIONS.safe);
    return out.slice(0, 4);
  }

  const priority = ['credential-theft', 'financial-fraud', 'bec', 'sender', 'domain', 'url', 'page', 'social-engineering', 'content'];
  const fired = categories.map((c) => c.category);
  for (const key of priority) {
    if (fired.includes(key)) push(RECOMMENDATIONS[key]);
    if (out.length >= 5) break;
  }
  if (!out.length) push(RECOMMENDATIONS['social-engineering']);

  if (level === 'high') push(RECOMMENDATIONS.general);

  if (facts.claimedBrand) {
    out.unshift(`Reach ${facts.claimedBrand} only through its official app or by typing its website address yourself.`);
  }
  if (facts.hasCredentialAsk) {
    out.unshift('If you already shared a password, OTP or card detail, change it now and inform your bank.');
  }
  return unique(out).slice(0, 6);
}

/**
 * One-paragraph plain-language verdict.
 */
export function buildSummary({ level, score, categories = [], signals = [], target = 'message' }) {
  const meta = LEVEL_META[level];
  const opener = LEVEL_OPENER[level];

  if (level === 'low') {
    const reassurance = signals.length
      ? 'A few minor observations are listed below, but none of them indicate an attack on their own.'
      : 'No manipulation tactics, deceptive links or sender problems were found.';
    return `${opener} PhishGuard scored this ${target} ${score}/100 (${meta.label}). ${reassurance} Still avoid sharing passwords or OTPs with anyone who asks for them.`;
  }

  const phrases = categories
    .slice(0, 3)
    .map((c) => CATEGORY_PHRASE[c.category])
    .filter(Boolean);
  const reasonText = phrases.length
    ? phrases.length === 1
      ? phrases[0]
      : `${phrases.slice(0, -1).join(', ')} and ${phrases.slice(-1)}`
    : 'several elements do not match legitimate communication';

  const top = signals[0];
  const strongest = top ? ` The strongest single indicator is: ${top.label.toLowerCase()}.` : '';

  return `${opener} PhishGuard scored this ${target} ${score}/100 (${meta.label}) because ${reasonText}.${strongest} ${meta.action}.`;
}

/**
 * Turn signals into the numbered "Reasons" list from the product spec.
 */
export function buildReasons(signals = [], limit = 8) {
  return signals.slice(0, limit).map((s, index) => ({
    rank: index + 1,
    id: s.id,
    title: s.label,
    category: s.category,
    categoryLabel: CATEGORY_LABELS[s.category] || s.category,
    explanation: s.detail,
    evidence: s.evidence ? truncate(String(s.evidence), 160) : null,
    contribution: s.weight,
    severity: s.weight >= 22 ? 'critical' : s.weight >= 14 ? 'high' : s.weight >= 8 ? 'moderate' : 'low'
  }));
}

/** Trust indicators, so users learn what "good" looks like too. */
export function buildTrustIndicators(positives = []) {
  return positives.slice(0, 5).map((s) => ({
    id: s.id,
    title: s.label,
    explanation: s.detail,
    evidence: s.evidence ? truncate(String(s.evidence), 140) : null
  }));
}

/**
 * Assemble the complete explanation object attached to every analysis.
 *
 * @param {{ scored:Object, tactics?:Array, facts?:Object, target?:string }} input
 */
export function explain({ scored, tactics = [], facts = {}, target = 'message' }) {
  const { score, level, signals, positives, categories, confidence } = scored;
  const meta = LEVEL_META[level];

  const reasons = buildReasons(signals);
  const triggers = reasons.slice(0, 5).map((r) => r.title);

  const dangerLines = unique(
    signals
      .slice(0, 5)
      .map((s) => s.detail)
      .filter(Boolean)
  ).slice(0, 4);

  return {
    summary: buildSummary({ level, score, categories, signals, target }),
    verdict: meta.verdict,
    levelLabel: meta.label,
    levelEmoji: meta.emoji,
    levelColor: meta.color,
    confidenceLabel: confidence >= 0.8 ? 'High confidence' : confidence >= 0.6 ? 'Moderate confidence' : 'Low confidence — treat as inconclusive',
    whatTriggered: triggers,
    whyDangerous: dangerLines,
    reasons,
    tactics: tactics.map((t) => ({ id: t.id, label: t.label, why: t.why, evidence: t.evidence, hits: t.hits })),
    trustIndicators: buildTrustIndicators(positives),
    recommendations: buildRecommendations(level, categories, facts),
    categoryBreakdown: categories.map((c) => ({
      category: c.category,
      label: CATEGORY_LABELS[c.category] || c.category,
      points: c.applied,
      capped: c.capped,
      signalCount: c.signalCount,
      topSignal: c.topSignal
    }))
  };
}
