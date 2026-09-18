/**
 * Supporting endpoints: history, reports, statistics, awareness content and
 * system status.
 *
 *   GET  /api/history            recent analyses (redacted previews only)
 *   GET  /api/stats              aggregate dashboard figures
 *   POST /api/reports            report something as phishing
 *   GET  /api/reports            recent community reports
 *   GET  /api/education/tips     awareness tips
 *   GET  /api/education/tactics  the social-engineering tactic library
 *   GET  /api/health             liveness plus which layers are available
 *   GET  /api/model/info         ML training metadata and gold-set metrics
 */

import { Router } from 'express';

import { AWARENESS_TIPS, CATEGORY_LABELS, RECOMMENDATIONS, TACTICS } from '../engine/constants.js';
import { ENGINE_VERSION, FEATURE_GROUPS } from '../engine/index.js';
import { LEVEL_META, SCORING } from '../engine/riskScorer.js';
import { HttpError } from '../middleware/index.js';
import { aiStatus } from '../services/aiService.js';
import { intelStatus } from '../services/intelService.js';
import { mlBreakerState, mlHealth, mlModelInfo } from '../services/mlService.js';
import { pipelineStages } from '../services/pipelineService.js';
import { config } from '../config.js';
import { store } from '../store/index.js';

const router = Router();
const wrap = (handler) => (req, res, next) => handler(req, res, next).catch(next);

/* -------------------------------- health --------------------------------- */
router.get('/health', wrap(async (req, res) => {
  const ml = await mlHealth();
  res.json({
    status: 'ok',
    service: 'phishguard-api',
    engineVersion: ENGINE_VERSION,
    uptimeSeconds: Math.round(process.uptime()),
    layers: {
      ruleEngine: { available: true, note: 'always available, runs offline' },
      ml: { ...ml, breaker: mlBreakerState() },
      ai: aiStatus(),
      intel: intelStatus(),
      liveUrlFetch: { enabled: config.fetchUrl.enabled }
    },
    storage: { driver: config.storage.driver }
  });
}));

router.get('/model/info', wrap(async (req, res) => {
  const info = await mlModelInfo();
  if (!info) {
    return res.status(503).json({
      error: 'ml_unavailable',
      message: 'The ML service is not reachable. Start it with: uvicorn app.main:app --port 8000 (from the ml/ folder).'
    });
  }
  return res.json(info);
}));

/* ------------------------------- history --------------------------------- */
router.get('/history', wrap(async (req, res) => {
  const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit ?? '25', 10) || 25));
  const offset = Math.max(0, Number.parseInt(req.query.offset ?? '0', 10) || 0);
  const level = ['low', 'medium', 'high'].includes(req.query.level) ? req.query.level : null;
  res.json(await store.listAnalyses({ limit, offset, level }));
}));

/* -------------------------------- stats ---------------------------------- */
router.get('/stats', wrap(async (req, res) => {
  const stats = await store.stats();
  res.json({
    ...stats,
    tacticLabels: Object.fromEntries(TACTICS.map((t) => [t.id, t.label])),
    levels: LEVEL_META,
    thresholds: SCORING.thresholds
  });
}));

/* ------------------------------- reports --------------------------------- */
router.post('/reports', wrap(async (req, res) => {
  const { url, text, reason, level } = req.body || {};
  if (!url && !text) throw new HttpError(422, 'empty_input', 'Provide the "url" or the "text" you are reporting.');
  if (typeof text === 'string' && text.length > 20_000) throw new HttpError(413, 'input_too_large', 'Report text is too long.');

  const record = await store.recordReport({
    url: typeof url === 'string' ? url.slice(0, 2048) : null,
    text: typeof text === 'string' ? text : null,
    reason: typeof reason === 'string' ? reason : null,
    level: ['low', 'medium', 'high'].includes(level) ? level : null,
    // Coarse attribution only, hashed in the store. Enough to spot one client
    // spamming reports, not enough to identify anybody.
    reporter: req.ip
  });

  res.status(201).json({
    reported: true,
    id: record.id,
    domains: record.domains,
    message: record.domains.length
      ? `Thank you. ${record.domains.join(', ')} will now carry this report as threat intelligence for future checks.`
      : 'Thank you. Your report has been recorded.',
    officialChannels: [
      { region: 'India', name: 'National Cyber Crime Reporting Portal', value: 'cybercrime.gov.in' },
      { region: 'India', name: 'Cyber fraud helpline', value: '1930' },
      { region: 'Global', name: 'Anti-Phishing Working Group', value: 'reportphishing@apwg.org' }
    ]
  });
}));

router.get('/reports', wrap(async (req, res) => {
  const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit ?? '25', 10) || 25));
  res.json(await store.listReports({ limit }));
}));

/* ------------------------------ education -------------------------------- */
router.get('/education/tips', (req, res) => {
  res.json({ tips: AWARENESS_TIPS });
});

router.get('/education/tactics', (req, res) => {
  res.json({
    tactics: TACTICS.map((t) => ({
      id: t.id,
      label: t.label,
      category: t.category,
      categoryLabel: CATEGORY_LABELS[t.category] || t.category,
      why: t.why,
      maxPoints: t.cap,
      patternCount: t.patterns.length
    })),
    featureGroups: FEATURE_GROUPS.map((g) => ({ id: g.id, label: g.label, categories: g.categories })),
    recommendations: RECOMMENDATIONS,
    scoring: {
      thresholds: SCORING.thresholds,
      categoryCaps: SCORING.categoryCaps,
      kappa: SCORING.kappa,
      note: 'Evidence points are capped per category, damped by trust signals, then mapped through a saturating curve so no single tactic can dominate the score.'
    }
  });
});

/* -------------------------------- meta ----------------------------------- */
router.get('/meta', (req, res) => {
  res.json({
    engineVersion: ENGINE_VERSION,
    pipeline: pipelineStages(),
    levels: LEVEL_META,
    categoryLabels: CATEGORY_LABELS,
    featureGroups: FEATURE_GROUPS.map((g) => ({ id: g.id, label: g.label })),
    limits: {
      rateLimit: config.rateLimit,
      maxContentCharacters: 200_000,
      batchSize: 25
    }
  });
});

export default router;
