/**
 * PhishGuard AI — risk scoring.
 *
 * Turns a flat list of weighted signals into a 0-100 score with a level,
 * confidence and a full audit trail. Design goals:
 *
 *  1. Explainable   — every point is traceable to a named signal.
 *  2. Saturating    — evidence has diminishing returns, so a long message
 *                     cannot inflate its own score by repeating one tactic.
 *  3. Category caps — five urgency phrases are still "urgency", counted once
 *                     with a bounded bonus. This is what keeps false positives
 *                     on chatty-but-legitimate mail under control.
 *  4. Tunable       — all constants live in SCORING so the evaluation harness
 *                     can measure the effect of changing them.
 */

import { clamp, round } from './utils.js';

export const SCORING = {
  /** Curve constant: score = 100 * (1 - e^(-evidence / kappa)). */
  kappa: 29,

  /** Maximum positive contribution any single category may make. */
  categoryCaps: {
    url: 42,
    domain: 40,
    sender: 40,
    'credential-theft': 40,
    'financial-fraud': 34,
    bec: 32,
    'social-engineering': 42,
    page: 40,
    content: 26,
    intel: 65,
    ml: 34,
    ai: 40
  },
  defaultCategoryCap: 30,

  /** Trust signals may not subtract more than this in total. */
  positiveCap: 50,

  /**
   * Strong evidence resists trust damping: a compromised-but-authenticated
   * mailbox sending a BEC request must not be excused by its valid SPF.
   */
  dampingSchedule: [
    { minEvidence: 55, factor: 0.25 },
    { minEvidence: 40, factor: 0.5 },
    { minEvidence: 0, factor: 1 }
  ],

  /**
   * Score floors for individually conclusive findings (for example credentials
   * posted to a third-party domain, or DMARC failure on a brand-claiming mail).
   */
  floors: [
    { minWeight: 26, floor: 72 },
    { minWeight: 22, floor: 60 }
  ],

  thresholds: { low: 30, medium: 70 }
};

/** Merge duplicate signal ids, keeping the strongest instance. */
export function dedupeSignals(signals = []) {
  const byId = new Map();
  for (const s of signals) {
    if (!s || typeof s.weight !== 'number') continue;
    const existing = byId.get(s.id);
    if (!existing || Math.abs(s.weight) > Math.abs(existing.weight)) byId.set(s.id, s);
  }
  return [...byId.values()];
}

/** 0-30 low, 31-70 medium, 71-100 high. */
export function riskLevel(score, thresholds = SCORING.thresholds) {
  if (score <= thresholds.low) return 'low';
  if (score <= thresholds.medium) return 'medium';
  return 'high';
}

export const LEVEL_META = {
  low: { label: 'Low Risk', emoji: '🟢', color: '#12b76a', verdict: 'No significant phishing indicators found', action: 'Proceed with normal caution' },
  medium: { label: 'Medium Risk', emoji: '🟡', color: '#f79009', verdict: 'Suspicious — verify before you act', action: 'Do not enter credentials or pay until you have verified through an official channel' },
  high: { label: 'High Risk', emoji: '🔴', color: '#f04438', verdict: 'Very likely phishing — do not interact', action: 'Do not click, reply, pay or enter any details. Report and delete it' }
};

/**
 * Score a signal list.
 *
 * @param {Array} rawSignals
 * @param {{ scoring?:Object }} [options]
 * @returns {{
 *   score:number, level:'low'|'medium'|'high', confidence:number,
 *   signals:Array, positives:Array, categories:Array,
 *   breakdown:{ evidence:number, damping:number, netEvidence:number, curveScore:number,
 *               floorApplied:number|null, cappedCategories:string[] }
 * }}
 */
export function scoreSignals(rawSignals = [], options = {}) {
  const cfg = { ...SCORING, ...(options.scoring || {}) };
  const signals = dedupeSignals(rawSignals);

  const risky = signals.filter((s) => s.weight > 0).sort((a, b) => b.weight - a.weight);
  const positives = signals.filter((s) => s.weight < 0).sort((a, b) => a.weight - b.weight);

  /* --------------------- category aggregation with caps ------------------ */
  const categoryTotals = new Map();
  for (const s of risky) {
    const key = s.category || 'content';
    const entry = categoryTotals.get(key) || { category: key, raw: 0, signals: [] };
    entry.raw += s.weight;
    entry.signals.push(s);
    categoryTotals.set(key, entry);
  }

  const cappedCategories = [];
  let evidence = 0;
  const categories = [];
  for (const entry of categoryTotals.values()) {
    const cap = cfg.categoryCaps[entry.category] ?? cfg.defaultCategoryCap;
    const applied = Math.min(entry.raw, cap);
    if (entry.raw > cap) cappedCategories.push(entry.category);
    evidence += applied;
    categories.push({
      category: entry.category,
      raw: round(entry.raw, 1),
      applied: round(applied, 1),
      capped: entry.raw > cap,
      signalCount: entry.signals.length,
      topSignal: entry.signals.sort((a, b) => b.weight - a.weight)[0]?.label || null
    });
  }
  categories.sort((a, b) => b.applied - a.applied);

  /* ---------------------------- trust damping --------------------------- */
  const rawDamping = Math.min(cfg.positiveCap, Math.abs(positives.reduce((sum, s) => sum + s.weight, 0)));
  const factor = (cfg.dampingSchedule.find((r) => evidence >= r.minEvidence) || { factor: 1 }).factor;
  const damping = rawDamping * factor;
  const netEvidence = Math.max(0, evidence - damping);

  /* ------------------------------- curve -------------------------------- */
  const curveScore = 100 * (1 - Math.exp(-netEvidence / cfg.kappa));

  /* ------------------------------- floors ------------------------------- */
  const maxWeight = risky.length ? risky[0].weight : 0;
  let floorApplied = null;
  let score = curveScore;
  if (netEvidence > 0) {
    for (const rule of cfg.floors) {
      if (maxWeight >= rule.minWeight && score < rule.floor) {
        score = rule.floor;
        floorApplied = rule.floor;
        break;
      }
    }
  }

  score = Math.round(clamp(score, 0, 100));
  const level = riskLevel(score, cfg.thresholds);

  /* ----------------------------- confidence ----------------------------- */
  const distinctCategories = categories.length;
  const bandPenalty = score >= 35 && score <= 62 ? 0.12 : 0;
  const evidenceDepth = Math.min(0.2, netEvidence / 250);
  const corroboration = Math.min(0.28, distinctCategories * 0.07);
  const positiveCorroboration = Math.min(0.14, positives.length * 0.05);
  let confidence = 0.5 + corroboration + evidenceDepth - bandPenalty;
  if (!risky.length) confidence = 0.62 + positiveCorroboration;
  confidence = clamp(confidence, 0.35, 0.97);

  return {
    score,
    level,
    confidence: round(confidence, 2),
    signals: risky,
    positives,
    categories,
    breakdown: {
      evidence: round(evidence, 1),
      rawDamping: round(rawDamping, 1),
      dampingFactor: factor,
      damping: round(damping, 1),
      netEvidence: round(netEvidence, 1),
      curveScore: round(curveScore, 1),
      floorApplied,
      cappedCategories,
      maxSignalWeight: maxWeight
    }
  };
}

/**
 * Blend the heuristic score with an optional LLM score.
 * The heuristic always dominates so the system stays deterministic and
 * explainable even when the model is unavailable or wrong.
 */
export function fuseScores(heuristic, ai, weight = 0.35) {
  if (!ai || typeof ai.score !== 'number' || Number.isNaN(ai.score)) {
    return { score: heuristic.score, level: heuristic.level, aiUsed: false, weightApplied: 0 };
  }
  const w = clamp(weight, 0, 0.6);
  const blended = Math.round(heuristic.score * (1 - w) + clamp(ai.score, 0, 100) * w);
  // Never let the model talk the score below "medium" when the heuristics found
  // conclusive evidence: models are easily persuaded by polished phishing copy.
  const floor = heuristic.breakdown.floorApplied || 0;
  const score = Math.max(blended, floor);
  return { score, level: riskLevel(score), aiUsed: true, weightApplied: w, heuristicScore: heuristic.score, aiScore: Math.round(ai.score) };
}
