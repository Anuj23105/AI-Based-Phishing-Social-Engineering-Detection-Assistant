/**
 * Detection pipeline orchestrator.
 *
 *   Input
 *     -> Text & URL Preprocessing
 *     -> Feature Extraction
 *     -> AI/ML Risk Analysis
 *     -> Risk Scoring
 *     -> Explanation + Safe Action
 *
 * The rule engine owns stages 1-3, 5 and 6 and runs synchronously. This module's
 * job is stage 4: it preprocesses once, fans out to the asynchronous layers in
 * parallel (Python ML models, threat intelligence, optional LLM), and hands
 * their findings back into the engine as ordinary weighted signals.
 *
 * Two properties are worth stating explicitly:
 *
 * * **Parallel, not sequential.** ML and intelligence run concurrently, so the
 *   stage costs roughly the slowest of them rather than their sum.
 * * **No single layer can fail the request.** Each optional layer resolves to a
 *   "not used, here is why" object. A verdict is always produced, and the
 *   response says which layers contributed — that honesty is why the pipeline
 *   trace is part of the API rather than a debug flag.
 */

import { analyze, analyzeUrls, preprocess } from '../engine/index.js';
import { config } from '../config.js';
import { runAiStage } from './aiService.js';
import { runIntelStage } from './intelService.js';
import { runMlStage } from './mlService.js';
import { store } from '../store/index.js';

/**
 * Order links worst-first so the single URL sent to the ML model and the LLM is
 * the one most likely to matter. Uses the rule engine's own findings, which are
 * already computed, so this costs nothing extra.
 */
function rankUrls(preResult) {
  if (preResult.urls.length <= 1) return [...preResult.urls];
  const claimedBrand = preResult.claimedBrands[0]?.brand || null;
  const { urls } = analyzeUrls(preResult.urls, { claimedBrand });
  return urls
    .map((u) => ({ url: u.url, points: u.signals.reduce((sum, s) => sum + Math.max(0, s.weight), 0) }))
    .sort((a, b) => b.points - a.points)
    .map((u) => u.url);
}

/**
 * Run the whole pipeline.
 *
 * @param {Object} input               see engine `analyze()`
 * @param {Object} [options]
 * @param {boolean} [options.useMl=true]
 * @param {boolean} [options.useAi=true]
 * @param {boolean} [options.useIntel=true]
 * @param {boolean} [options.persist=true]
 * @param {boolean} [options.trace=true]
 * @returns {Promise<Object>} the analysis result, with `pipeline`, `ml`, `ai`
 *                            and `intel` populated
 */
export async function runPipeline(input = {}, options = {}) {
  const startedAt = Date.now();
  const useMl = options.useMl !== false;
  const useAi = options.useAi !== false;
  const useIntel = options.useIntel !== false;

  /* --------------- stages 1-2: input + preprocessing (sync) ------------- */
  const pre = preprocess(input);
  const urls = rankUrls(pre);

  /* --------------- stage 3 preview: rules only, no async layers --------- */
  // Running the engine once up front gives the LLM real findings to reason
  // about, and gives us a usable verdict even if every async layer fails.
  const baseline = analyze(input, { pre, trace: false });

  /* ------------------- stage 4: AI/ML risk analysis --------------------- */
  const [mlResult, intelResult] = await Promise.all([
    useMl
      ? runMlStage({ text: pre.type === 'url' ? '' : pre.bodyText, urls })
      : Promise.resolve({ used: false, reason: 'ML layer disabled for this request', signals: [], latencyMs: 0 }),
    useIntel
      ? runIntelStage(urls)
      : Promise.resolve({ checked: false, verdict: 'not checked', signals: [], sources: [] })
  ]);

  const aiResult = useAi
    ? await runAiStage({
      text: pre.bodyText,
      url: urls[0] || '',
      signals: baseline.signals,
      mlProbability: mlResult.used ? mlResult.probability : undefined
    })
    : null;

  /* ------------- stages 5-6: scoring + explanation (sync) --------------- */
  const extraSignals = [...(mlResult.signals || []), ...(intelResult.signals || [])];

  const result = analyze(input, {
    pre,
    trace: options.trace !== false,
    extraSignals,
    ml: mlResult,
    intel: {
      checked: intelResult.checked,
      verdict: intelResult.verdict,
      sources: intelResult.sources,
      domains: intelResult.domains,
      reportHits: intelResult.reportHits
    },
    ai: aiResult,
    aiWeight: config.ai.fusionWeight,
    aiReason: aiResult ? undefined : useAi ? 'AI layer not configured or unavailable' : 'AI layer disabled for this request'
  });

  result.timings = {
    totalMs: Date.now() - startedAt,
    engineMs: result.durationMs,
    mlMs: mlResult.latencyMs || 0,
    aiMs: aiResult?.latencyMs || 0
  };

  if (options.persist !== false) {
    try {
      await store.recordAnalysis(result);
    } catch (error) {
      // History is a convenience, not part of the verdict.
      console.warn(`[pipeline] could not record analysis: ${error.message}`);
    }
  }

  return result;
}

/** Which layers are available right now — shown in the UI status strip. */
export function pipelineStages() {
  return [
    { id: 'input', label: 'Input', description: 'Accept an email, SMS, chat message, URL or website and detect which it is.' },
    { id: 'preprocessing', label: 'Text & URL Preprocessing', description: 'Split e-mail headers from the body, reduce HTML to visible text, un-obfuscate wording and extract links, addresses and phone numbers.' },
    { id: 'feature-extraction', label: 'Feature Extraction', description: 'Suspicious language, urgency and manipulation tactics, sender and domain signals, URL characteristics, credential and payment requests.' },
    { id: 'ai-ml', label: 'AI/ML Risk Analysis', description: 'Trained message and URL classifiers, community threat intelligence, and an optional language-model review.' },
    { id: 'risk-scoring', label: 'Risk Scoring', description: 'Weighted evidence with per-category caps and trust damping, mapped to a 0-100 score and a Low/Medium/High band.' },
    { id: 'explanation', label: 'Explanation + Safe Action', description: 'Plain-language reasons, what made it dangerous, and the specific actions to take.' }
  ];
}
