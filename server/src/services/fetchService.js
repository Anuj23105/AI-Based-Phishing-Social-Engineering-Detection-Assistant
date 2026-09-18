/**
 * Live website fetching for the "analyse a website" flow.
 *
 * Fetching a URL the user hands us is the whole point of the feature, but it is
 * also the riskiest thing this server does, so it is fenced in:
 *
 * * only http/https, and only after the URL parses;
 * * private, loopback and link-local addresses are refused, which blocks the
 *   obvious SSRF pivot into the host network or a cloud metadata endpoint;
 * * redirects are followed by fetch but the final URL is re-validated;
 * * the response is capped by size and time, and only HTML/text is read;
 * * no cookies, no credentials, and a self-identifying user agent.
 */

import dns from 'node:dns/promises';
import net from 'node:net';

import { config } from '../config.js';
import { safeParseUrl } from '../engine/utils.js';

const BLOCKED_HOSTNAMES = new Set(['localhost', 'localhost.localdomain', 'ip6-localhost', 'metadata', 'metadata.google.internal']);

function isPrivateAddress(address) {
  if (net.isIPv4(address)) {
    const [a, b] = address.split('.').map(Number);
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true; // link-local / cloud metadata
    if (a === 100 && b >= 64 && b <= 127) return true; // carrier NAT
    if (a >= 224) return true; // multicast / reserved
    return false;
  }
  if (net.isIPv6(address)) {
    const lower = address.toLowerCase();
    return lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80') || lower === '::';
  }
  return false;
}

async function assertPublicHost(hostname) {
  if (BLOCKED_HOSTNAMES.has(hostname.toLowerCase())) {
    throw new Error('refusing to fetch a loopback or metadata host');
  }
  if (net.isIP(hostname)) {
    if (isPrivateAddress(hostname)) throw new Error('refusing to fetch a private or reserved IP address');
    return;
  }
  let records;
  try {
    records = await dns.lookup(hostname, { all: true });
  } catch {
    throw new Error(`could not resolve ${hostname}`);
  }
  if (records.some((r) => isPrivateAddress(r.address))) {
    throw new Error('host resolves to a private or reserved address');
  }
}

/**
 * Fetch a URL's HTML.
 *
 * @returns {Promise<{ ok:boolean, url?:string, finalUrl?:string, status?:number,
 *                     html?:string, bytes?:number, contentType?:string,
 *                     redirected?:boolean, error?:string, durationMs:number }>}
 */
export async function fetchPage(rawUrl) {
  const started = Date.now();
  const fail = (error) => ({ ok: false, error, durationMs: Date.now() - started });

  if (!config.fetchUrl.enabled) return fail('live URL fetching is disabled (ENABLE_LIVE_URL_FETCH=false)');

  const parsed = safeParseUrl(rawUrl);
  if (!parsed) return fail('not a valid URL');
  if (!['http:', 'https:'].includes(parsed.protocol)) return fail(`unsupported scheme ${parsed.protocol}`);

  try {
    await assertPublicHost(parsed.hostname);
  } catch (error) {
    return fail(error.message);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.fetchUrl.timeoutMs);
  try {
    const response = await fetch(parsed.href, {
      redirect: 'follow',
      signal: controller.signal,
      credentials: 'omit',
      headers: {
        'user-agent': config.fetchUrl.userAgent,
        accept: 'text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5',
        'accept-language': 'en-IN,en;q=0.9'
      }
    });

    // A redirect chain can land somewhere that was not safe to begin with.
    const finalParsed = safeParseUrl(response.url || parsed.href);
    if (finalParsed && finalParsed.hostname !== parsed.hostname) {
      try {
        await assertPublicHost(finalParsed.hostname);
      } catch (error) {
        return fail(`redirect blocked: ${error.message}`);
      }
    }

    const contentType = response.headers.get('content-type') || '';
    if (contentType && !/text\/html|text\/plain|application\/xhtml|application\/json/i.test(contentType)) {
      return {
        ok: false,
        error: `unsupported content type: ${contentType.split(';')[0]}`,
        status: response.status,
        finalUrl: response.url,
        durationMs: Date.now() - started
      };
    }

    // Stream so an enormous page cannot exhaust memory.
    const reader = response.body?.getReader();
    const chunks = [];
    let bytes = 0;
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        bytes += value.byteLength;
        chunks.push(value);
        if (bytes >= config.fetchUrl.maxBytes) {
          await reader.cancel();
          break;
        }
      }
    }
    const html = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');

    return {
      ok: true,
      url: parsed.href,
      finalUrl: response.url || parsed.href,
      redirected: (response.url || parsed.href) !== parsed.href,
      status: response.status,
      contentType: contentType.split(';')[0] || 'unknown',
      bytes,
      truncated: bytes >= config.fetchUrl.maxBytes,
      html,
      durationMs: Date.now() - started
    };
  } catch (error) {
    return fail(error.name === 'AbortError' ? `page did not respond within ${config.fetchUrl.timeoutMs}ms` : error.message);
  } finally {
    clearTimeout(timer);
  }
}
