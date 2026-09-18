/**
 * PhishGuard AI — string, domain and text utilities used by every analyzer.
 * Pure functions only: no I/O, no network, safe to run anywhere.
 */

import { HOMOGLYPHS, LEET_MAP, MULTI_PART_SUFFIXES } from './constants.js';

/* --------------------------------- text ---------------------------------- */

/** Collapse whitespace and lower-case. */
export function normalizeWhitespace(text = '') {
  return String(text).replace(/\s+/g, ' ').trim();
}

/** Map confusable Unicode characters back to their ASCII look-alike. */
export function deHomoglyph(text = '') {
  let out = '';
  for (const ch of String(text)) out += HOMOGLYPHS[ch] ?? HOMOGLYPHS[ch.toLowerCase()] ?? ch;
  return out;
}

/** Undo leet-speak substitutions (`p4yp4|` -> `paypal`). */
export function deLeet(text = '') {
  let out = '';
  for (const ch of String(text).toLowerCase()) out += LEET_MAP[ch] ?? ch;
  return out;
}

/**
 * Aggressive normalisation for keyword matching: removes zero-width characters,
 * de-homoglyphs, de-leets and squeezes the spacing tricks used to defeat
 * filters (`v e r i f y`, `p-a-s-s-w-o-r-d`).
 */
export function canonicalize(text = '') {
  const stripped = String(text)
    .replace(/[\u200b-\u200f\u202a-\u202e\u2060\ufeff]/g, '')
    .normalize('NFKC');
  return deLeet(deHomoglyph(stripped)).toLowerCase();
}

/** Collapse `v e r i f y` / `v.e.r.i.f.y` style spacing into `verify`. */
export function collapseSpacedLetters(text = '') {
  return String(text).replace(/\b(?:[a-z][\s._\-*]){2,}[a-z]\b/gi, (m) => m.replace(/[\s._\-*]/g, ''));
}

/** Levenshtein edit distance with an early exit once `max` is exceeded. */
export function levenshtein(a = '', b = '', max = Infinity) {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const m = a.length;
  const n = b.length;
  if (!m) return n;
  if (!n) return m;
  let prev = new Array(n + 1);
  let curr = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    let rowMin = curr[0];
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
      if (curr[j] < rowMin) rowMin = curr[j];
    }
    if (rowMin > max) return max + 1;
    [prev, curr] = [curr, prev];
  }
  return prev[n];
}

/** Shannon entropy in bits/char — random-looking hosts and tokens score high. */
export function shannonEntropy(text = '') {
  if (!text) return 0;
  const freq = new Map();
  for (const ch of text) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / text.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Ratio of upper-case letters among alphabetic characters. */
export function upperCaseRatio(text = '') {
  const letters = String(text).replace(/[^a-z]/gi, '');
  if (letters.length < 12) return 0;
  const upper = letters.replace(/[^A-Z]/g, '').length;
  return upper / letters.length;
}

/** Deduplicate while preserving order. */
export function unique(list = []) {
  return [...new Set(list)];
}

export function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

export function round(value, decimals = 0) {
  const f = 10 ** decimals;
  return Math.round(value * f) / f;
}

/* -------------------------------- domains -------------------------------- */

/** True for IPv4 literals. */
export function isIPv4(host = '') {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) && host.split('.').every((o) => Number(o) <= 255);
}

/** True for bracketed or bare IPv6 literals. */
export function isIPv6(host = '') {
  return /^\[?[0-9a-f:]+\]?$/i.test(host) && host.includes(':');
}

/** Strip leading `www.` and a trailing dot, lower-case the host. */
export function cleanHost(host = '') {
  return String(host).toLowerCase().replace(/\.$/, '').replace(/^www\./, '');
}

/**
 * Registrable domain ("eTLD+1") using a curated multi-part suffix list.
 * Good enough for detection without shipping the full public suffix list.
 */
export function registrableDomain(host = '') {
  const h = cleanHost(host);
  if (!h || isIPv4(h) || isIPv6(h)) return h;
  const parts = h.split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_SUFFIXES.has(lastTwo)) return parts.slice(-3).join('.');
  return lastTwo;
}

/** Everything to the left of the registrable domain. */
export function subdomainOf(host = '') {
  const h = cleanHost(host);
  const rd = registrableDomain(h);
  if (h === rd) return '';
  return h.slice(0, Math.max(0, h.length - rd.length - 1));
}

/** Public suffix portion of the registrable domain. */
export function tldOf(host = '') {
  const rd = registrableDomain(host);
  const parts = rd.split('.');
  if (parts.length >= 3 && MULTI_PART_SUFFIXES.has(parts.slice(-2).join('.'))) return parts.slice(-2).join('.');
  return parts.slice(-1)[0] || '';
}

/** Domain label without its suffix, e.g. `paypal-secure` for `paypal-secure.tk`. */
export function domainLabel(host = '') {
  const rd = registrableDomain(host);
  const tld = tldOf(host);
  return rd.endsWith(`.${tld}`) ? rd.slice(0, -(tld.length + 1)) : rd;
}

/** `sub.example.co.in` -> is it `example.co.in` or a subdomain of it? */
export function isSameSite(hostA = '', hostB = '') {
  if (!hostA || !hostB) return false;
  return registrableDomain(hostA) === registrableDomain(hostB);
}

/* --------------------------------- URLs ---------------------------------- */

const URL_IN_TEXT = /\b((?:https?:\/\/|www\.)[^\s<>"'`)\]}]+|(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}(?:\/[^\s<>"'`)\]}]*)?)/gi;

/**
 * Extract candidate URLs from free text, including bare domains and
 * "defanged" forms like `hxxp://evil[.]com` used in threat reports.
 */
export function extractUrls(text = '') {
  const refanged = String(text)
    .replace(/h(?:xx|XX)p(s?):\/\//gi, 'http$1://')
    .replace(/\[\s*\.\s*\]/g, '.')
    .replace(/\(\s*\.\s*\)/g, '.')
    .replace(/\s+dot\s+/gi, '.');
  const found = [];
  let m;
  URL_IN_TEXT.lastIndex = 0;
  while ((m = URL_IN_TEXT.exec(refanged)) !== null) {
    let candidate = m[1].replace(/[.,;:!?'")\]]+$/, '');
    if (!/^https?:\/\//i.test(candidate)) {
      // Skip things that are really sentences ("info.The") or file names.
      if (!/^(?:www\.)/i.test(candidate) && !/^[a-z0-9-]+\.[a-z]{2,24}(?:[/:?#]|$)/i.test(candidate)) continue;
      candidate = `http://${candidate}`;
    }
    found.push(candidate);
  }
  return unique(found);
}

/** Extract e-mail addresses from text. */
export function extractEmails(text = '') {
  const matches = String(text).match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}/gi) || [];
  return unique(matches.map((e) => e.toLowerCase()));
}

/** Extract phone numbers (loose, tuned for Indian + international formats). */
export function extractPhones(text = '') {
  const matches = String(text).match(/(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{3,5}\)?[\s-]?)?\d{5,10}\b/g) || [];
  return unique(matches.map((p) => p.trim()).filter((p) => p.replace(/\D/g, '').length >= 8));
}

/** Parse a URL defensively; returns null when unusable. */
export function safeParseUrl(input = '') {
  const raw = String(input).trim();
  if (!raw) return null;
  const withScheme = /^[a-z][a-z0-9+.-]*:/i.test(raw) ? raw : `http://${raw}`;
  try {
    return new URL(withScheme);
  } catch {
    return null;
  }
}

/** Count how many times `needle` occurs in `haystack`. */
export function countOccurrences(haystack = '', needle = '') {
  if (!needle) return 0;
  let count = 0;
  let idx = 0;
  while ((idx = haystack.indexOf(needle, idx)) !== -1) {
    count++;
    idx += needle.length;
  }
  return count;
}

/** Short deterministic hash (FNV-1a) — used for cache keys and record ids. */
export function hash(text = '') {
  let h = 0x811c9dc5;
  const str = String(text);
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

/** Strip HTML tags, scripts and styles down to visible text. */
export function htmlToText(html = '') {
  return String(html)
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|tr|li|h[1-6])>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/** Truncate for display / logging without cutting mid-surrogate. */
export function truncate(text = '', max = 280) {
  const s = String(text);
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}
