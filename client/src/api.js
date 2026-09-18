/**
 * Thin API client.
 *
 * Every call funnels through `request()` so error handling, timeouts and the
 * optional API key live in exactly one place.
 */

const BASE = import.meta.env.VITE_API_BASE || '/api';
const API_KEY = import.meta.env.VITE_API_KEY || '';
const DEFAULT_TIMEOUT = 20_000;

export class ApiError extends Error {
  constructor(message, { status, code, requestId } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

async function request(path, { method = 'GET', body, timeout = DEFAULT_TIMEOUT } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(`${BASE}${path}`, {
      method,
      headers: {
        ...(body ? { 'content-type': 'application/json' } : {}),
        ...(API_KEY ? { 'x-api-key': API_KEY } : {})
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal
    });

    const isJson = (response.headers.get('content-type') || '').includes('application/json');
    const payload = isJson ? await response.json() : await response.text();

    if (!response.ok) {
      const message = (isJson && payload?.message) || `Request failed with status ${response.status}`;
      throw new ApiError(message, {
        status: response.status,
        code: isJson ? payload?.error : undefined,
        requestId: isJson ? payload?.requestId : undefined
      });
    }
    return payload;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error.name === 'AbortError') {
      throw new ApiError('The request took too long. Is the API server running on port 4000?', { code: 'timeout' });
    }
    throw new ApiError(
      'Could not reach the API. Start it with "npm run dev" in the server folder.',
      { code: 'network' }
    );
  } finally {
    clearTimeout(timer);
  }
}

export const api = {
  analyze: (payload) => request('/analyze', { method: 'POST', body: payload, timeout: 30_000 }),
  analyzeUrl: (payload) => request('/analyze/url', { method: 'POST', body: payload, timeout: 30_000 }),
  analyzeWebsite: (payload) => request('/analyze/website', { method: 'POST', body: payload, timeout: 40_000 }),
  analyzeBatch: (items) => request('/analyze/batch', { method: 'POST', body: { items }, timeout: 60_000 }),
  health: () => request('/health', { timeout: 6000 }),
  meta: () => request('/meta'),
  stats: () => request('/stats'),
  history: (limit = 20) => request(`/history?limit=${limit}`),
  report: (payload) => request('/reports', { method: 'POST', body: payload }),
  reports: (limit = 10) => request(`/reports?limit=${limit}`),
  tips: () => request('/education/tips'),
  tactics: () => request('/education/tactics'),
  modelInfo: () => request('/model/info')
};

export default api;
