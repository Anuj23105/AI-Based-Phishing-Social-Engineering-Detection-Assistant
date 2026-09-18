/**
 * Express middleware: request ids, rate limiting, optional API key, validation
 * helpers and the error handler.
 *
 * The rate limiter is an in-process fixed window. That is the honest scope: it
 * protects a single node from a runaway client or a casual abuse attempt, and it
 * does not survive a restart or coordinate across replicas. Anything
 * multi-instance needs Redis, and the interface here is small enough to swap.
 */

import { randomUUID } from 'node:crypto';

import { config } from '../config.js';

/* ------------------------------ request id ------------------------------- */
export function requestId(req, res, next) {
  req.id = req.get('x-request-id') || randomUUID();
  res.setHeader('x-request-id', req.id);
  next();
}

/* ------------------------------- logging --------------------------------- */
export function requestLogger(req, res, next) {
  const started = process.hrtime.bigint();
  res.on('finish', () => {
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    const line = `${req.method} ${req.originalUrl} ${res.statusCode} ${ms.toFixed(1)}ms`;
    if (res.statusCode >= 500) console.error(`[api] ${line}`);
    else if (req.originalUrl !== '/api/health') console.log(`[api] ${line}`);
  });
  next();
}

/* ----------------------------- security head ----------------------------- */
export function securityHeaders(req, res, next) {
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('x-frame-options', 'DENY');
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('cross-origin-resource-policy', 'same-site');
  res.setHeader('permissions-policy', 'geolocation=(), microphone=(), camera=()');
  next();
}

/* ------------------------------ rate limit ------------------------------- */
const buckets = new Map();

setInterval(() => {
  const cutoff = Date.now() - config.rateLimit.windowMs * 2;
  for (const [key, bucket] of buckets) if (bucket.resetAt < cutoff) buckets.delete(key);
}, config.rateLimit.windowMs).unref();

export function rateLimit(req, res, next) {
  const key = req.ip || 'unknown';
  const now = Date.now();
  let bucket = buckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    bucket = { count: 0, resetAt: now + config.rateLimit.windowMs };
    buckets.set(key, bucket);
  }
  bucket.count += 1;

  const remaining = Math.max(0, config.rateLimit.max - bucket.count);
  res.setHeader('x-ratelimit-limit', String(config.rateLimit.max));
  res.setHeader('x-ratelimit-remaining', String(remaining));
  res.setHeader('x-ratelimit-reset', String(Math.ceil(bucket.resetAt / 1000)));

  if (bucket.count > config.rateLimit.max) {
    res.setHeader('retry-after', String(Math.ceil((bucket.resetAt - now) / 1000)));
    return res.status(429).json({
      error: 'rate_limited',
      message: `Too many requests. Limit is ${config.rateLimit.max} per ${Math.round(config.rateLimit.windowMs / 1000)}s.`
    });
  }
  return next();
}

/* -------------------------------- api key -------------------------------- */
export function apiKeyGuard(req, res, next) {
  if (!config.apiKey) return next();
  const provided = req.get('x-api-key');
  if (provided && provided === config.apiKey) return next();
  return res.status(401).json({ error: 'unauthorized', message: 'A valid x-api-key header is required.' });
}

/* ------------------------------ validation ------------------------------- */
export class HttpError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const MAX_CONTENT = 200_000;

/** Validate and normalise an /analyze request body. */
export function parseAnalyzeBody(body = {}) {
  const allowedTypes = ['auto', 'message', 'email', 'sms', 'chat', 'whatsapp', 'social', 'url', 'website'];

  const content = typeof body.content === 'string' ? body.content : '';
  const url = typeof body.url === 'string' ? body.url.trim() : '';
  const html = typeof body.html === 'string' ? body.html : '';

  if (!content.trim() && !url && !html) {
    throw new HttpError(422, 'empty_input', 'Provide "content" (message text), "url", or "html" to analyse.');
  }
  if (content.length > MAX_CONTENT || html.length > MAX_CONTENT) {
    throw new HttpError(413, 'input_too_large', `Input must be under ${MAX_CONTENT} characters.`);
  }

  const type = allowedTypes.includes(body.type) ? body.type : 'auto';

  const links = Array.isArray(body.links)
    ? body.links
      .filter((l) => l && typeof l.href === 'string')
      .slice(0, 100)
      .map((l) => ({ href: l.href.slice(0, 2048), text: String(l.text || '').slice(0, 300) }))
    : undefined;

  const headers = body.headers && typeof body.headers === 'object' && !Array.isArray(body.headers)
    ? Object.fromEntries(
      Object.entries(body.headers)
        .slice(0, 60)
        .map(([k, v]) => [String(k).toLowerCase().slice(0, 80), String(v ?? '').slice(0, 2000)])
    )
    : undefined;

  return {
    input: {
      type,
      content,
      url: url || undefined,
      html: html || undefined,
      senderEmail: typeof body.senderEmail === 'string' ? body.senderEmail.slice(0, 320) : undefined,
      senderName: typeof body.senderName === 'string' ? body.senderName.slice(0, 200) : undefined,
      replyTo: typeof body.replyTo === 'string' ? body.replyTo.slice(0, 320) : undefined,
      links,
      headers
    },
    options: {
      useMl: body.useMl !== false,
      useAi: body.useAi !== false,
      useIntel: body.useIntel !== false,
      persist: body.persist !== false,
      trace: body.trace !== false
    }
  };
}

/* ----------------------------- error handler ----------------------------- */
export function notFound(req, res) {
  res.status(404).json({ error: 'not_found', message: `No route for ${req.method} ${req.originalUrl}` });
}

export function errorHandler(error, req, res, _next) {
  const status = error.status || 500;
  if (status >= 500) console.error(`[api] ${req.id} ${error.stack || error.message}`);
  res.status(status).json({
    error: error.code || (status >= 500 ? 'internal_error' : 'request_error'),
    // Internal failures must not leak stack traces or paths to the client.
    message: status >= 500 ? 'Something went wrong while processing the request.' : error.message,
    details: error.details,
    requestId: req.id
  });
}
