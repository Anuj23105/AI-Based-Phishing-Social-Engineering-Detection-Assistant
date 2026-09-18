/**
 * Environment-driven configuration.
 *
 * Every optional integration is off by default. The product runs fully offline
 * on the rule engine alone; the ML service, the LLM layer and threat
 * intelligence each add quality when configured and are skipped cleanly when
 * they are not.
 */

import 'dotenv/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.resolve(here, '..');

const bool = (value, fallback = false) => {
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
};
const int = (value, fallback) => {
  const parsed = Number.parseInt(value ?? '', 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};
const num = (value, fallback) => {
  const parsed = Number.parseFloat(value ?? '');
  return Number.isFinite(parsed) ? parsed : fallback;
};
const list = (value, fallback = []) =>
  (value ? String(value).split(',').map((v) => v.trim()).filter(Boolean) : fallback);

export const config = {
  env: process.env.NODE_ENV || 'development',
  port: int(process.env.PORT, 4000),
  corsOrigins: list(process.env.CORS_ORIGIN, [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:4173'
  ]),

  /** Optional shared secret. When set, every /api request must send x-api-key. */
  apiKey: process.env.API_KEY || null,

  rateLimit: {
    windowMs: int(process.env.RATE_LIMIT_WINDOW_MS, 60_000),
    max: int(process.env.RATE_LIMIT_MAX, 60)
  },

  /** Python ML microservice. */
  ml: {
    enabled: bool(process.env.ML_ENABLED, true),
    baseUrl: (process.env.ML_SERVICE_URL || 'http://127.0.0.1:8000').replace(/\/$/, ''),
    timeoutMs: int(process.env.ML_TIMEOUT_MS, 2500),
    /** Consecutive failures before the client stops trying for a while. */
    breakerThreshold: int(process.env.ML_BREAKER_THRESHOLD, 3),
    breakerCooldownMs: int(process.env.ML_BREAKER_COOLDOWN_MS, 30_000),
    /** How much the ML probability can contribute to the risk score. */
    maxSignalWeight: int(process.env.ML_MAX_SIGNAL_WEIGHT, 26)
  },

  /** Optional large-language-model layer. */
  ai: {
    provider: (process.env.AI_PROVIDER || 'none').toLowerCase(),
    geminiKey: process.env.GEMINI_API_KEY || '',
    geminiModel: process.env.GEMINI_MODEL || 'gemini-2.0-flash',
    openaiKey: process.env.OPENAI_API_KEY || '',
    openaiModel: process.env.OPENAI_MODEL || 'gpt-4o-mini',
    openaiBaseUrl: (process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1').replace(/\/$/, ''),
    fusionWeight: num(process.env.AI_FUSION_WEIGHT, 0.35),
    timeoutMs: int(process.env.AI_TIMEOUT_MS, 3500)
  },

  intel: {
    safeBrowsingKey: process.env.SAFE_BROWSING_API_KEY || '',
    timeoutMs: int(process.env.INTEL_TIMEOUT_MS, 2500)
  },

  fetchUrl: {
    enabled: bool(process.env.ENABLE_LIVE_URL_FETCH, true),
    timeoutMs: int(process.env.URL_FETCH_TIMEOUT_MS, 6000),
    maxBytes: int(process.env.URL_FETCH_MAX_BYTES, 1_500_000),
    userAgent: process.env.URL_FETCH_USER_AGENT || 'PhishGuardAI/1.0 (+security-research)'
  },

  storage: {
    driver: (process.env.STORAGE_DRIVER || 'file').toLowerCase(),
    dataDir: path.resolve(serverRoot, process.env.DATA_DIR || './data'),
    historyLimit: int(process.env.HISTORY_LIMIT, 500)
  },

  paths: { serverRoot, repoRoot: path.resolve(serverRoot, '..') }
};

export function aiConfigured() {
  if (config.ai.provider === 'gemini') return Boolean(config.ai.geminiKey);
  if (config.ai.provider === 'openai') return Boolean(config.ai.openaiKey);
  return false;
}

export default config;
