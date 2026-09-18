/**
 * PhishGuard AI — URL & domain analyzer.
 *
 * Produces weighted signals covering the classic phishing URL tells:
 * obfuscation, typosquatting, homograph tricks, throwaway infrastructure,
 * credential-flavoured paths and open redirects.
 */

import {
  BRANDS,
  DANGEROUS_EXTENSIONS,
  FREE_HOSTING_HOSTS,
  IDENTITY_PARAMS,
  OFFICIAL_DOMAINS,
  REDIRECT_PARAMS,
  SUSPICIOUS_TLDS,
  TRUSTED_DOMAINS,
  URL_SHORTENERS
} from './constants.js';
import {
  canonicalize,
  cleanHost,
  deHomoglyph,
  domainLabel,
  isIPv4,
  isIPv6,
  levenshtein,
  registrableDomain,
  safeParseUrl,
  shannonEntropy,
  subdomainOf,
  tldOf,
  truncate
} from './utils.js';

const CREDENTIAL_PATH_WORDS = [
  'login', 'signin', 'sign-in', 'logon', 'account', 'accounts', 'verify', 'verification',
  'validate', 'secure', 'security', 'update', 'confirm', 'auth', 'authenticate', 'password',
  'passwd', 'credential', 'recover', 'unlock', 'reactivate', 'suspended', 'billing', 'payment',
  'wallet', 'netbanking', 'banking', 'kyc', 'aadhaar', 'pan', 'upi', 'otp', 'webscr', 'cmd',
  'dispatch', 'session', 'token', 'invoice', 'refund', 'claim', 'reward', 'gift', 'prize', 'winner'
];

const BRAND_SEPARATORS = /[-_.]/g;

/** Detect a homograph attack: non-ASCII host that maps onto an ASCII brand. */
function homographSuspect(host) {
  const hasNonAscii = /[^\x00-\x7f]/.test(host);
  const isPunycode = /(^|\.)xn--/i.test(host);
  if (!hasNonAscii && !isPunycode) return null;
  const ascii = deHomoglyph(host);
  return { hasNonAscii, isPunycode, ascii };
}

/**
 * Compare a domain label against every known brand:
 *  - exact brand token inside the label but a different owner  -> impersonation
 *  - edit distance 1..2 from the brand's own label            -> typosquatting
 */
function brandLookalike(host) {
  const rd = registrableDomain(host);
  if (OFFICIAL_DOMAINS.has(rd)) return null;

  const label = domainLabel(host);
  const flat = canonicalize(label).replace(BRAND_SEPARATORS, '');
  const sub = canonicalize(subdomainOf(host)).replace(BRAND_SEPARATORS, '');
  const results = [];

  for (const brand of BRANDS) {
    for (const domain of brand.domains) {
      const brandLabel = canonicalize(domainLabel(domain));
      if (brandLabel.length < 4) continue;

      // Brand name embedded in the registrable label: paypal-secure-login.tk
      if (flat.includes(brandLabel) && flat !== brandLabel) {
        results.push({ brand: brand.name, type: 'embedded', official: domain, distance: 0, score: 3 });
        continue;
      }
      // Brand name pushed into the subdomain: paypal.com.verify-user.tk
      if (sub.includes(brandLabel)) {
        results.push({ brand: brand.name, type: 'subdomain', official: domain, distance: 0, score: 3 });
        continue;
      }
      // One or two character edits away: paypa1.com, gooogle.com, arnazon.com
      const maxDistance = brandLabel.length >= 8 ? 2 : 1;
      const distance = levenshtein(flat, brandLabel, maxDistance);
      if (distance > 0 && distance <= maxDistance) {
        results.push({ brand: brand.name, type: 'typosquat', official: domain, distance, score: 4 - distance });
      }
    }
  }
  if (!results.length) return null;
  results.sort((a, b) => b.score - a.score);
  return results[0];
}

/** Free-hosting / tunnelling platform match (suffix aware). */
function freeHostingMatch(host) {
  return FREE_HOSTING_HOSTS.find((h) => host === h || host.endsWith(`.${h}`)) || null;
}

/**
 * Analyze one URL.
 *
 * @param {string} rawUrl
 * @param {{ contextText?: string, claimedBrand?: string }} [options]
 * @returns {{ url:string, valid:boolean, host:string, registrableDomain:string, tld:string,
 *             scheme:string, isShortener:boolean, signals:Array, facts:Object }}
 */
export function analyzeUrl(rawUrl, options = {}) {
  const signals = [];
  const parsed = safeParseUrl(rawUrl);

  if (!parsed) {
    return {
      url: String(rawUrl || ''),
      valid: false,
      host: '',
      registrableDomain: '',
      tld: '',
      scheme: '',
      isShortener: false,
      signals: [{ id: 'url-unparseable', category: 'url', label: 'Malformed link', weight: 6, detail: 'The link could not be parsed as a normal web address, which is itself unusual.', evidence: truncate(String(rawUrl || ''), 120) }],
      facts: {}
    };
  }

  const scheme = parsed.protocol.replace(':', '');
  const host = cleanHost(parsed.hostname);
  const rd = registrableDomain(host);
  const tld = tldOf(host);
  const label = domainLabel(host);
  const path = decodeURIComponent(parsed.pathname || '');
  const query = parsed.search || '';
  const fullUrl = parsed.href;
  const lowerAll = canonicalize(`${host}${path}${query}`);
  const isTrusted = TRUSTED_DOMAINS.has(rd);
  const isOfficial = OFFICIAL_DOMAINS.has(rd);

  const add = (id, category, label_, weight, detail, evidence) => {
    signals.push({ id, category, label: label_, weight, detail, evidence });
  };

  /* ----------------------------- scheme / transport ---------------------- */
  if (scheme === 'http') {
    add('url-no-https', 'url', 'Link does not use HTTPS', 8,
      'Traffic to this page is unencrypted, so anything you type can be read in transit.', fullUrl);
  } else if (!['http', 'https'].includes(scheme)) {
    add('url-odd-scheme', 'url', `Unusual link scheme "${scheme}:"`, 14,
      'Links using schemes other than http/https can launch applications or run code instead of opening a page.', `${scheme}:`);
  }
  if (parsed.port && !['80', '443', ''].includes(parsed.port)) {
    add('url-nonstandard-port', 'url', `Non-standard port ${parsed.port}`, 7,
      'Legitimate consumer websites almost never serve login pages on unusual ports.', `:${parsed.port}`);
  }

  /* --------------------------------- host -------------------------------- */
  if (isIPv4(host) || isIPv6(host)) {
    add('url-ip-host', 'url', 'Link points to a raw IP address', 20,
      'Real services use domain names. A bare IP address usually means a disposable or compromised host.', host);
  }

  const homograph = homographSuspect(parsed.hostname);
  if (homograph) {
    const asciiRd = registrableDomain(homograph.ascii);
    const mimics = OFFICIAL_DOMAINS.has(asciiRd) || TRUSTED_DOMAINS.has(asciiRd);
    add('url-homograph', 'domain', 'Look-alike characters in the domain', mimics ? 26 : 15,
      mimics
        ? `The domain uses characters that only look like "${asciiRd}". It is a different website entirely.`
        : 'The domain mixes character sets, a trick used to make fake addresses look genuine.',
      parsed.hostname);
  }

  if (parsed.username || parsed.password || /^[^/]*@/.test(fullUrl.replace(/^https?:\/\//i, ''))) {
    add('url-userinfo', 'url', 'Link hides its real destination before an "@"', 22,
      'Everything before the @ symbol is ignored by the browser, so the page you actually reach is not the one shown.', truncate(fullUrl, 120));
  }

  if (URL_SHORTENERS.has(rd) || URL_SHORTENERS.has(host)) {
    add('url-shortener', 'url', 'Shortened link hides the destination', 16,
      'A shortener means you cannot see where the link goes until you have already opened it.', host);
  }

  const hostLabels = host.split('.').filter(Boolean);
  const subLabelCount = Math.max(0, hostLabels.length - rd.split('.').length);
  if (subLabelCount >= 3) {
    add('url-deep-subdomain', 'url', `Unusually deep subdomain chain (${subLabelCount} levels)`, 12,
      'Long chains such as secure.login.bank.example.tk are used to push the real domain out of view on small screens.', host);
  } else if (subLabelCount === 2 && !isTrusted) {
    add('url-many-subdomains', 'url', 'Multiple stacked subdomains', 6,
      'Stacked subdomains make the address look official while the real owner sits at the end.', host);
  }

  const hyphenCount = (label.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    add('url-hyphen-spam', 'domain', `Domain packed with ${hyphenCount} hyphens`, 11,
      'Phishing kits generate names like secure-account-verify-login to look descriptive and trustworthy.', rd);
  } else if (hyphenCount === 2 && !isTrusted) {
    add('url-hyphens', 'domain', 'Multiple hyphens in the domain name', 5,
      'Hyphen-heavy domains are common in throwaway phishing infrastructure.', rd);
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    add('url-suspicious-tld', 'domain', `High-abuse domain ending ".${tld}"`, 14,
      `The ".${tld}" ending is cheap or free to register and is heavily used for short-lived scam sites.`, rd);
  }

  const hosting = freeHostingMatch(host);
  if (hosting) {
    add('url-free-hosting', 'domain', `Hosted on a free platform (${hosting})`, 12,
      'Anyone can publish a page here in minutes, so a "bank" or "government" login on this platform is not genuine.', host);
  }

  if (label.length >= 25) {
    add('url-long-domain', 'domain', 'Excessively long domain name', 7,
      'Very long domain names are used to bury a recognisable brand inside noise.', rd);
  }
  if (label.length >= 8 && shannonEntropy(label.replace(/[^a-z0-9]/g, '')) > 3.6) {
    add('url-random-domain', 'domain', 'Domain looks machine-generated', 10,
      'Random-looking domains are typical of automatically registered, disposable attack infrastructure.', rd);
  }
  if (/\d{4,}/.test(label)) {
    add('url-digit-run', 'domain', 'Long run of digits in the domain', 6,
      'Digit-stuffed domains are commonly produced in bulk by scam campaigns.', rd);
  }

  /* -------------------------- brand impersonation ------------------------ */
  const lookalike = brandLookalike(host);
  if (lookalike) {
    const map = {
      typosquat: {
        weight: lookalike.distance === 1 ? 26 : 21,
        label: `Typosquatted domain imitating ${lookalike.brand}`,
        detail: `"${rd}" is only ${lookalike.distance} character${lookalike.distance > 1 ? 's' : ''} away from the official "${lookalike.official}". It is not the same website.`
      },
      embedded: {
        weight: 22,
        label: `"${lookalike.brand}" name used by an unrelated domain`,
        detail: `The brand name appears inside "${rd}", but the official domain is "${lookalike.official}". Only the part immediately before the final dot identifies the owner.`
      },
      subdomain: {
        weight: 24,
        label: `${lookalike.brand} name placed in the subdomain`,
        detail: `The address begins with the brand but the site is actually owned by "${rd}", not "${lookalike.official}".`
      }
    }[lookalike.type];
    add(`url-brand-${lookalike.type}`, 'domain', map.label, map.weight, map.detail, host);
  }

  // Claimed brand from message text does not match the link owner.
  const claimed = options.claimedBrand;
  if (claimed) {
    const brand = BRANDS.find((b) => b.name === claimed);
    if (brand && !brand.domains.some((d) => rd === d || registrableDomain(d) === rd)) {
      add('url-brand-mismatch', 'domain', `Link does not belong to ${brand.name}`, 20,
        `The message presents itself as ${brand.name}, but the link goes to "${rd}" instead of ${brand.domains[0]}.`, host);
    }
  }

  /* ------------------------------ path & query -------------------------- */
  const pathWords = CREDENTIAL_PATH_WORDS.filter((w) => lowerAll.includes(w));
  if (pathWords.length && !isOfficial) {
    const weight = Math.min(18, 7 + (pathWords.length - 1) * 4);
    add('url-credential-path', 'credential-theft', 'Link path is built around logging in or verifying', weight,
      `The address contains ${pathWords.slice(0, 4).map((w) => `"${w}"`).join(', ')}, wording typical of credential-capture pages.`, truncate(`${path}${query}`, 120) || rd);
  }

  const encodedCount = (fullUrl.match(/%[0-9a-f]{2}/gi) || []).length;
  if (encodedCount >= 6) {
    add('url-heavy-encoding', 'url', 'Link is heavily percent-encoded', 10,
      'Encoding large parts of a link hides its real content from both you and simple filters.', `${encodedCount} encoded characters`);
  }
  if (/(?:%25|%252f|%2520)/i.test(fullUrl)) {
    add('url-double-encoding', 'url', 'Double-encoded characters in the link', 12,
      'Double encoding is an evasion technique; ordinary links never need it.', truncate(fullUrl, 120));
  }

  const params = [...parsed.searchParams.entries()];
  for (const [key, value] of params) {
    const k = key.toLowerCase();
    if (REDIRECT_PARAMS.includes(k) && /https?%3a|https?:\/\//i.test(value)) {
      const target = safeParseUrl(decodeURIComponent(value));
      const targetRd = target ? registrableDomain(target.hostname) : '';
      add('url-open-redirect', 'url', 'Link bounces through a redirect to another site', 15,
        targetRd
          ? `The visible domain is "${rd}" but you are forwarded to "${targetRd}".`
          : 'The link carries another full web address as a parameter, so the destination is not what it appears to be.',
        `${key}=${truncate(value, 80)}`);
      break;
    }
  }
  const identityHits = params.filter(([k]) => IDENTITY_PARAMS.includes(k.toLowerCase()) && params.length);
  if (identityHits.length) {
    add('url-identity-params', 'credential-theft', 'Link pre-fills personal or account data', 13,
      `The address carries ${identityHits.map(([k]) => `"${k}"`).slice(0, 3).join(', ')}. Phishing kits do this to confirm a live target and personalise the fake page.`,
      truncate(query, 100));
  }
  if (/[?&](?:[a-z0-9_-]{1,12}=)?[A-Za-z0-9+/]{40,}={0,2}(?:&|$)/.test(query)) {
    add('url-encoded-blob', 'url', 'Long encoded blob in the link', 8,
      'A long base64-style token often carries the victim\'s address or a hidden redirect.', truncate(query, 90));
  }

  const extMatch = path.toLowerCase().match(/\.([a-z0-9]{2,5})(?:$|[?#])/);
  if (extMatch && DANGEROUS_EXTENSIONS.includes(extMatch[1])) {
    const ext = extMatch[1];
    const highRisk = ['exe', 'scr', 'apk', 'msi', 'jar', 'vbs', 'js', 'hta', 'bat', 'cmd', 'ps1', 'lnk'].includes(ext);
    add('url-dangerous-file', 'url', `Link downloads a "${ext}" file`, highRisk ? 24 : 13,
      highRisk
        ? `".${ext}" files run code on your device. A document or invoice should never arrive in this format.`
        : `".${ext}" attachments are frequently used to smuggle malware or a fake offline login page.`,
      truncate(path, 100));
  }

  if (fullUrl.length > 130) {
    add('url-very-long', 'url', 'Very long web address', 6,
      'Long addresses push the deceptive part out of sight, especially on phones.', `${fullUrl.length} characters`);
  }

  /* --------------------------- trust dampeners -------------------------- */
  if (isOfficial) {
    add('url-official-domain', 'positive', 'Link uses a verified official domain', -22,
      `"${rd}" is the genuine domain for this service.`, rd);
  } else if (isTrusted) {
    add('url-trusted-domain', 'positive', 'Link uses a well-known, reputable domain', -16,
      `"${rd}" is an established domain with a strong reputation.`, rd);
  }
  if (scheme === 'https' && !isTrusted && signals.length === 0) {
    add('url-clean', 'positive', 'No structural problems found in the link', -6,
      'The address is well formed, uses HTTPS and does not imitate a known brand.', rd);
  }

  return {
    url: fullUrl,
    valid: true,
    host,
    registrableDomain: rd,
    tld,
    scheme,
    isShortener: URL_SHORTENERS.has(rd) || URL_SHORTENERS.has(host),
    signals,
    facts: {
      subdomain: subdomainOf(host),
      pathLength: path.length,
      paramCount: params.length,
      isTrusted,
      isOfficial,
      freeHosting: hosting,
      impersonates: lookalike ? lookalike.brand : null,
      punycode: Boolean(homograph?.isPunycode),
      credentialKeywords: pathWords
    }
  };
}

/**
 * Analyze a batch of URLs and merge their signals, keeping the worst one per
 * signal id so a message with ten identical shortener links is not scored ten
 * times over.
 *
 * @returns {{ urls:Array, signals:Array, worst:Object|null }}
 */
export function analyzeUrls(rawUrls = [], options = {}) {
  const results = rawUrls.slice(0, 12).map((u) => analyzeUrl(u, options));
  const bySignal = new Map();
  for (const r of results) {
    for (const s of r.signals) {
      const key = s.id;
      const existing = bySignal.get(key);
      const enriched = { ...s, url: r.url };
      if (!existing || Math.abs(enriched.weight) > Math.abs(existing.weight)) bySignal.set(key, enriched);
    }
  }
  // A positive trust signal must not survive if another link in the same
  // message is malicious — attackers mix real and fake links deliberately.
  const signals = [...bySignal.values()];
  const hasBadUrl = signals.some((s) => s.weight >= 14);
  const merged = hasBadUrl ? signals.filter((s) => s.category !== 'positive') : signals;

  let worst = null;
  for (const r of results) {
    const total = r.signals.reduce((sum, s) => sum + Math.max(0, s.weight), 0);
    if (!worst || total > worst.total) worst = { ...r, total };
  }

  return { urls: results, signals: merged, worst };
}
