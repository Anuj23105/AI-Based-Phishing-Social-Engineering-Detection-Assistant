/**
 * Threat intelligence: community reports plus optional Google Safe Browsing.
 *
 * The local reputation store is the part that always works. When users report a
 * message or link through the UI, the domains involved accumulate reports, and
 * later analyses of the same domain inherit that evidence. It is deliberately
 * conservative: a single report nudges the score, repeated independent reports
 * matter more, and a domain on the trusted list is never penalised by reports
 * (otherwise one malicious user could poison google.com).
 */

import { config } from '../config.js';
import { registrableDomain, safeParseUrl } from '../engine/utils.js';
import { TRUSTED_DOMAINS } from '../engine/constants.js';
import { store } from '../store/index.js';

async function safeBrowsingLookup(urls) {
  if (!config.intel.safeBrowsingKey || !urls.length) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.intel.timeoutMs);
  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${config.intel.safeBrowsingKey}`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({
          client: { clientId: 'phishguard-ai', clientVersion: '1.0.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: urls.slice(0, 20).map((url) => ({ url }))
          }
        })
      }
    );
    if (!response.ok) return null;
    const body = await response.json();
    return Array.isArray(body.matches) ? body.matches : [];
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Run the intelligence stage.
 *
 * @param {string[]} urls
 * @returns {Promise<{ checked:boolean, verdict:string, signals:Array, sources:string[], matches:Array }>}
 */
export async function runIntelStage(urls = []) {
  const signals = [];
  const sources = [];
  const domains = [...new Set(
    urls.map((u) => {
      const parsed = safeParseUrl(u);
      return parsed ? registrableDomain(parsed.hostname) : null;
    }).filter(Boolean)
  )];

  /* ------------------------- community reports ------------------------- */
  let reportHits = [];
  if (domains.length) {
    sources.push('community reports');
    reportHits = await store.reputationFor(domains);
    for (const hit of reportHits) {
      if (TRUSTED_DOMAINS.has(hit.domain)) continue;
      const weight = hit.reports >= 5 ? 30 : hit.reports >= 2 ? 22 : 12;
      signals.push({
        id: `intel-reported-${hit.domain}`,
        category: 'intel',
        label: `"${hit.domain}" has been reported by users ${hit.reports} time${hit.reports > 1 ? 's' : ''}`,
        weight,
        detail: hit.reports > 1
          ? 'Multiple people using this system have flagged content on this domain as phishing.'
          : 'Someone using this system has already flagged content on this domain as phishing.',
        evidence: `last reported ${new Date(hit.lastReportedAt).toISOString().slice(0, 10)}`
      });
    }
  }

  /* -------------------------- Safe Browsing ---------------------------- */
  const matches = await safeBrowsingLookup(urls);
  if (matches !== null) {
    sources.push('Google Safe Browsing');
    for (const match of matches) {
      signals.push({
        id: 'intel-safe-browsing',
        category: 'intel',
        label: `Google Safe Browsing lists this link as ${String(match.threatType || '').toLowerCase().replace(/_/g, ' ')}`,
        weight: 45,
        detail: 'This URL appears in Google\'s live blocklist of dangerous sites. Browsers will normally warn or block it outright.',
        evidence: match.threat?.url || urls[0]
      });
      break;
    }
  }

  const verdict = signals.length
    ? `${signals.length} intelligence hit${signals.length > 1 ? 's' : ''}`
    : sources.length
      ? 'no hits'
      : 'not checked';

  return {
    checked: sources.length > 0,
    verdict,
    sources,
    domains,
    reportHits,
    matches: matches || [],
    signals
  };
}

export function intelStatus() {
  return {
    communityReports: true,
    safeBrowsing: Boolean(config.intel.safeBrowsingKey),
    reason: config.intel.safeBrowsingKey ? null : 'SAFE_BROWSING_API_KEY not set — using community reports only'
  };
}
