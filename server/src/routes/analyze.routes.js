/**
 * Analysis endpoints.
 *
 *   POST /api/analyze            message, e-mail, SMS, chat or pasted HTML
 *   POST /api/analyze/url        a single link (no page fetch)
 *   POST /api/analyze/website    fetch the live page, then analyse it
 *   POST /api/analyze/batch      up to 25 items in one call
 *   GET  /api/analyze/pipeline   the pipeline stage definitions
 */

import { Router } from 'express';

import { HttpError, parseAnalyzeBody } from '../middleware/index.js';
import { pipelineStages, runPipeline } from '../services/pipelineService.js';
import { fetchPage } from '../services/fetchService.js';
import { htmlToText, truncate } from '../engine/utils.js';

const router = Router();

const wrap = (handler) => (req, res, next) => handler(req, res, next).catch(next);

router.get('/pipeline', (req, res) => {
  res.json({ stages: pipelineStages() });
});

router.post('/', wrap(async (req, res) => {
  const { input, options } = parseAnalyzeBody(req.body || {});
  const result = await runPipeline(input, options);
  res.json(result);
}));

router.post('/url', wrap(async (req, res) => {
  const url = typeof req.body?.url === 'string' ? req.body.url.trim() : '';
  if (!url) throw new HttpError(422, 'empty_input', 'Provide a "url" to analyse.');
  if (url.length > 2048) throw new HttpError(413, 'input_too_large', 'URL is too long.');

  const result = await runPipeline({ type: 'url', url }, {
    useMl: req.body.useMl !== false,
    useAi: req.body.useAi !== false,
    useIntel: req.body.useIntel !== false,
    persist: req.body.persist !== false
  });
  res.json(result);
}));

router.post('/website', wrap(async (req, res) => {
  const url = typeof req.body?.url === 'string' ? req.body.url.trim() : '';
  if (!url) throw new HttpError(422, 'empty_input', 'Provide a "url" to fetch and analyse.');

  const page = await fetchPage(url);

  if (!page.ok) {
    // The link is still worth analysing even when the page will not load —
    // dead phishing sites are the normal case, not an error.
    const result = await runPipeline({ type: 'url', url }, {
      useMl: req.body.useMl !== false,
      useAi: req.body.useAi !== false
    });
    result.fetch = { attempted: true, ok: false, error: page.error, durationMs: page.durationMs };
    result.explanation.recommendations.unshift(
      'The page could not be loaded for inspection, so this verdict is based on the link itself.'
    );
    return res.json(result);
  }

  const result = await runPipeline(
    { type: 'website', url: page.finalUrl || url, html: page.html },
    { useMl: req.body.useMl !== false, useAi: req.body.useAi !== false }
  );
  result.fetch = {
    attempted: true,
    ok: true,
    status: page.status,
    finalUrl: page.finalUrl,
    redirected: page.redirected,
    contentType: page.contentType,
    bytes: page.bytes,
    truncated: page.truncated,
    durationMs: page.durationMs,
    textPreview: truncate(htmlToText(page.html), 600)
  };
  return res.json(result);
}));

router.post('/batch', wrap(async (req, res) => {
  const items = Array.isArray(req.body?.items) ? req.body.items.slice(0, 25) : null;
  if (!items?.length) throw new HttpError(422, 'empty_input', 'Provide an "items" array of things to analyse.');

  const results = [];
  for (const item of items) {
    try {
      const { input, options } = parseAnalyzeBody(item || {});
      // Batch mode skips the LLM: 25 sequential model calls would blow the
      // response-time budget for no analytical gain.
      const result = await runPipeline(input, { ...options, useAi: false });
      results.push({
        ok: true,
        id: result.id,
        score: result.score,
        level: result.level,
        confidence: result.confidence,
        summary: result.explanation.summary,
        topReasons: result.explanation.reasons.slice(0, 3).map((r) => r.title),
        mlProbability: result.ml?.used ? result.ml.probability : null
      });
    } catch (error) {
      results.push({ ok: false, error: error.code || 'request_error', message: error.message });
    }
  }

  const scored = results.filter((r) => r.ok);
  res.json({
    count: results.length,
    results,
    summary: {
      high: scored.filter((r) => r.level === 'high').length,
      medium: scored.filter((r) => r.level === 'medium').length,
      low: scored.filter((r) => r.level === 'low').length,
      failed: results.length - scored.length
    }
  });
}));

export default router;
