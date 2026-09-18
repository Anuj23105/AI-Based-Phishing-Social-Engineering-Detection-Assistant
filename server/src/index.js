/**
 * PhishGuard AI — API server.
 *
 * Tier 2 of three:
 *   client/  React UI
 *   server/  this: rule engine, pipeline orchestration, persistence, REST API
 *   ml/      Python FastAPI service with the trained classifiers
 *
 * Start with:  npm run dev   (from server/)  or  npm run dev  (from the root,
 * which starts the API and the UI together).
 */

import cors from 'cors';
import express from 'express';

import { config } from './config.js';
import {
  apiKeyGuard,
  errorHandler,
  notFound,
  rateLimit,
  requestId,
  requestLogger,
  securityHeaders
} from './middleware/index.js';
import analyzeRoutes from './routes/analyze.routes.js';
import insightsRoutes from './routes/insights.routes.js';
import { aiStatus } from './services/aiService.js';
import { intelStatus } from './services/intelService.js';
import { mlHealth } from './services/mlService.js';
import { store } from './store/index.js';

const app = express();

app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(requestId);
app.use(securityHeaders);
app.use(requestLogger);
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false, limit: '2mb' }));

app.use(cors({
  origin(origin, callback) {
    // Same-origin/tool requests (no Origin header) are allowed; browser origins
    // must be on the configured list.
    if (!origin || config.corsOrigins.includes(origin)) return callback(null, true);
    return callback(new Error(`Origin ${origin} is not allowed by CORS_ORIGIN`));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['content-type', 'x-api-key', 'x-request-id'],
  maxAge: 600
}));

app.get('/', (req, res) => {
  res.json({
    name: 'PhishGuard AI API',
    docs: '/api/meta',
    health: '/api/health',
    endpoints: [
      'POST /api/analyze',
      'POST /api/analyze/url',
      'POST /api/analyze/website',
      'POST /api/analyze/batch',
      'GET  /api/analyze/pipeline',
      'GET  /api/history',
      'GET  /api/stats',
      'POST /api/reports',
      'GET  /api/education/tips',
      'GET  /api/education/tactics',
      'GET  /api/model/info'
    ]
  });
});

app.use('/api', rateLimit, apiKeyGuard);
app.use('/api/analyze', analyzeRoutes);
app.use('/api', insightsRoutes);

app.use(notFound);
app.use(errorHandler);

async function start() {
  await store.ready;

  const server = app.listen(config.port, () => {
    console.log(`\n  PhishGuard AI API  ->  http://localhost:${config.port}`);
    console.log(`  environment        :  ${config.env}`);
    console.log(`  storage            :  ${config.storage.driver} (${config.storage.dataDir})`);
    console.log(`  allowed origins    :  ${config.corsOrigins.join(', ')}`);
    console.log(`  api key            :  ${config.apiKey ? 'required (x-api-key)' : 'not set — open access'}`);
    if (!config.apiKey && config.env === 'production') {
      console.warn('  WARNING: running in production without API_KEY set. Every /api endpoint is publicly callable.');
    }
  });

  // Report which optional layers actually came up, so a misconfigured ML
  // service is obvious at boot rather than a mystery at request time.
  const [ml] = await Promise.all([mlHealth()]);
  const ai = aiStatus();
  const intel = intelStatus();
  console.log(`  rule engine        :  ready`);
  console.log(`  ml service         :  ${ml.reachable ? `ready at ${config.ml.baseUrl} (${Object.entries(ml.models || {}).filter(([, v]) => v).map(([k]) => k).join(', ') || 'no models'})` : `unavailable — ${ml.reason}`}`);
  console.log(`  ai layer           :  ${ai.configured ? `${ai.provider} / ${ai.model}` : `off — ${ai.reason}`}`);
  console.log(`  threat intel       :  community reports${intel.safeBrowsing ? ' + Google Safe Browsing' : ' only'}`);
  if (!ml.reachable) {
    console.log('\n  Start the ML service for the AI/ML stage:');
    console.log('    cd ml && .venv\\Scripts\\python -m uvicorn app.main:app --port 8000\n');
  } else {
    console.log('');
  }

  const shutdown = (signal) => {
    console.log(`\n[api] ${signal} received, shutting down`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

start().catch((error) => {
  console.error('[api] failed to start:', error);
  process.exit(1);
});

export default app;
