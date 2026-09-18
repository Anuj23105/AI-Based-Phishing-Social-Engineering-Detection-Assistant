/**
 * PhishGuard AI — website / HTML analyzer.
 *
 * Works on raw HTML (fetched by the server or pasted by the user) without a DOM
 * dependency. Focused on the behaviour that distinguishes a credential-harvesting
 * clone from a real login page: where the form posts, who the page claims to be,
 * and how hard it tries to hide what it does.
 */

import { BRANDS, OFFICIAL_DOMAINS, TRUSTED_DOMAINS } from './constants.js';
import { canonicalize, htmlToText, isSameSite, normalizeWhitespace, registrableDomain, safeParseUrl, truncate, unique } from './utils.js';

/* ------------------------------- extraction ------------------------------ */

function attr(tag, name) {
  const m = tag.match(new RegExp(`${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
  if (!m) return null;
  return (m[2] ?? m[3] ?? m[4] ?? '').trim();
}

function matchAll(html, regex) {
  const out = [];
  let m;
  const re = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : `${regex.flags}g`);
  while ((m = re.exec(html)) !== null) {
    out.push(m);
    if (out.length > 400) break;
  }
  return out;
}

/**
 * Pull the structural facts out of an HTML document.
 * Exported so the API can return them for transparency.
 */
export function extractPageFeatures(html = '', pageUrl = '') {
  const source = String(html);
  const base = safeParseUrl(pageUrl);
  const resolve = (href) => {
    if (!href) return null;
    try {
      return new URL(href, base ? base.href : 'http://localhost/').href;
    } catch {
      return null;
    }
  };

  const title = normalizeWhitespace((source.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] || '')).slice(0, 200);

  const metaTags = matchAll(source, /<meta\b[^>]*>/i).map((m) => m[0]);
  const meta = {};
  for (const tag of metaTags) {
    const key = (attr(tag, 'name') || attr(tag, 'property') || '').toLowerCase();
    if (key) meta[key] = attr(tag, 'content') || '';
  }

  const forms = matchAll(source, /<form\b[^>]*>([\s\S]*?)<\/form>/i).map((m) => {
    const openTag = m[0].match(/<form\b[^>]*>/i)?.[0] || '';
    const inner = m[1] || '';
    const inputs = matchAll(inner, /<input\b[^>]*>/i).map((i) => i[0]);
    return {
      action: attr(openTag, 'action'),
      resolvedAction: resolve(attr(openTag, 'action')) || (base ? base.href : null),
      method: (attr(openTag, 'method') || 'get').toLowerCase(),
      inputs: inputs.map((tag) => ({
        type: (attr(tag, 'type') || 'text').toLowerCase(),
        name: (attr(tag, 'name') || attr(tag, 'id') || '').toLowerCase(),
        autocomplete: (attr(tag, 'autocomplete') || '').toLowerCase()
      }))
    };
  });

  // Standalone password inputs (React apps often render inputs outside <form>).
  const looseInputs = matchAll(source, /<input\b[^>]*>/i).map((m) => ({
    type: (attr(m[0], 'type') || 'text').toLowerCase(),
    name: (attr(m[0], 'name') || attr(m[0], 'id') || '').toLowerCase()
  }));

  const anchors = matchAll(source, /<a\b[^>]*href\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)[^>]*>([\s\S]*?)<\/a>/i).map((m) => ({
    href: resolve(attr(m[0], 'href')),
    raw: attr(m[0], 'href'),
    text: normalizeWhitespace(htmlToText(m[2] || '')).slice(0, 120)
  })).filter((a) => a.raw);

  const scripts = matchAll(source, /<script\b([^>]*)>([\s\S]*?)<\/script>/i).map((m) => ({
    src: resolve(attr(`<script ${m[1]}>`, 'src')),
    inline: m[2] || ''
  }));

  const iframes = matchAll(source, /<iframe\b[^>]*>/i).map((m) => ({
    src: resolve(attr(m[0], 'src')),
    style: (attr(m[0], 'style') || '').toLowerCase(),
    width: attr(m[0], 'width'),
    height: attr(m[0], 'height'),
    hidden: /display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0/.test((attr(m[0], 'style') || '').toLowerCase()) ||
      ['0', '1'].includes(attr(m[0], 'width') || '') || ['0', '1'].includes(attr(m[0], 'height') || '')
  }));

  const images = matchAll(source, /<img\b[^>]*>/i).map((m) => ({
    src: resolve(attr(m[0], 'src')),
    alt: attr(m[0], 'alt') || ''
  }));

  const favicon = matchAll(source, /<link\b[^>]*rel\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)[^>]*>/i)
    .filter((m) => /icon/i.test(attr(m[0], 'rel') || ''))
    .map((m) => resolve(attr(m[0], 'href')))[0] || null;

  const text = htmlToText(source);

  return { title, meta, forms, looseInputs, anchors, scripts, iframes, images, favicon, text, length: source.length };
}

const CREDENTIAL_FIELD_NAMES = ['pass', 'pwd', 'password', 'passwd', 'passcode', 'pin', 'mpin', 'otp', 'cvv', 'cvc', 'card', 'cardno', 'cardnumber', 'expiry', 'aadhaar', 'aadhar', 'pan', 'ifsc', 'upi', 'vpa', 'ssn', 'dob', 'mmn', 'seed', 'mnemonic', 'privatekey'];

/**
 * Analyze a website.
 *
 * @param {{ html?:string, url?:string, features?:Object }} input
 * @returns {{ signals:Array, features:Object, facts:Object }}
 */
export function analyzePage(input = {}) {
  const pageUrl = input.url || '';
  const features = input.features || extractPageFeatures(input.html || '', pageUrl);
  const parsed = safeParseUrl(pageUrl);
  const host = parsed ? parsed.hostname : '';
  const rd = host ? registrableDomain(host) : '';
  const isOfficial = OFFICIAL_DOMAINS.has(rd);
  const isTrusted = TRUSTED_DOMAINS.has(rd);
  const isHttps = parsed ? parsed.protocol === 'https:' : false;

  const signals = [];
  const add = (id, category, label, weight, detail, evidence) => {
    signals.push({ id, category, label, weight, detail, evidence });
  };

  const allInputs = [...features.forms.flatMap((f) => f.inputs), ...features.looseInputs];
  const hasPassword = allInputs.some((i) => i.type === 'password');
  const sensitiveFields = unique(allInputs
    .filter((i) => i.type === 'password' || CREDENTIAL_FIELD_NAMES.some((n) => i.name.includes(n)))
    .map((i) => i.name || i.type)
    .filter(Boolean));

  const bodyText = features.text || '';
  const canonText = canonicalize(bodyText);
  const canonTitle = canonicalize(features.title || '');

  /* -------------------------- login page detection ---------------------- */
  const loginLanguage = /\b(sign in|log ?in|login|username|password|continue to your account|account login|net ?banking|internet banking|user id)\b/i.test(bodyText);
  const isLoginPage = hasPassword || (loginLanguage && allInputs.length >= 2);

  if (isLoginPage) {
    add('page-login-form', 'page', 'Page collects login credentials', 6,
      'This is a credential entry page, so any deception here directly leads to account takeover.',
      sensitiveFields.length ? sensitiveFields.slice(0, 5).join(', ') : 'password field detected');
  }

  if (isLoginPage && parsed && !isHttps) {
    add('page-insecure-login', 'credential-theft', 'Login form served over plain HTTP', 26,
      'Credentials typed here travel unencrypted. No legitimate bank or service does this.', pageUrl);
  }

  /* -------------------------- where the form posts ---------------------- */
  for (const form of features.forms) {
    const sensitive = form.inputs.some((i) => i.type === 'password' || CREDENTIAL_FIELD_NAMES.some((n) => i.name.includes(n)));
    if (!sensitive) continue;

    const action = form.resolvedAction;
    const actionUrl = safeParseUrl(action || '');

    if (!form.action || /^#|^javascript:/i.test(form.action)) {
      add('page-form-script-handler', 'page', 'Credential form is submitted by script, not a normal action', 9,
        'A script handler hides the real destination of your credentials from the browser and from you.', truncate(form.action || '(empty action)', 60));
    }
    if (actionUrl && host && !isSameSite(actionUrl.hostname, host)) {
      add('page-cross-domain-post', 'credential-theft', 'Credentials are sent to a different domain', 28,
        `The form on "${rd}" delivers what you type to "${registrableDomain(actionUrl.hostname)}". That third party is the collector.`,
        `${rd} → ${registrableDomain(actionUrl.hostname)}`);
    }
    if (actionUrl && actionUrl.protocol === 'http:' && isHttps) {
      add('page-downgrade-post', 'credential-theft', 'Secure page posts credentials over plain HTTP', 24,
        'The padlock is meaningless here: the data leaves the page unencrypted.', truncate(action, 90));
    }
    if (actionUrl && /(?:formspree|jotform|getform|sheetdb|script\.google\.com|api\.telegram\.org|discord(?:app)?\.com\/api\/webhooks|pipedream|requestbin|webhook\.site|ngrok)/i.test(actionUrl.hostname + actionUrl.pathname)) {
      add('page-exfil-endpoint', 'credential-theft', 'Credentials posted to a generic data-collection service', 30,
        'Form-capture services, Telegram bots and webhooks are the standard way phishing kits deliver stolen credentials to the attacker.',
        truncate(actionUrl.hostname, 60));
    }
    if (form.method === 'get' && form.inputs.some((i) => i.type === 'password')) {
      add('page-password-in-url', 'credential-theft', 'Password would be sent in the web address', 18,
        'Using GET puts the password into the URL, where it is logged by every server in the path. Real login pages never do this.', 'method="get" with a password field');
    }
  }

  /* ------------------------ brand impersonation ------------------------ */
  const brandHits = [];
  for (const brand of BRANDS) {
    const inTitle = brand.keywords.some((kw) => canonTitle.includes(canonicalize(kw).trim()));
    const inText = brand.keywords.filter((kw) => canonText.includes(canonicalize(kw).trim())).length;
    if (inTitle || inText >= 2) brandHits.push({ brand, inTitle, mentions: inText });
  }
  const impersonated = brandHits.find(({ brand }) => !brand.domains.some((d) => isSameSite(d, host)));
  if (impersonated && (isLoginPage || impersonated.inTitle)) {
    const weight = isLoginPage ? 27 : 16;
    add('page-brand-impersonation', 'domain', `Page presents itself as ${impersonated.brand.name} on an unrelated domain`, weight,
      `The content is branded as ${impersonated.brand.name}, but the page is served from "${rd}" instead of ${impersonated.brand.domains[0]}.`,
      `${features.title ? truncate(features.title, 60) : rd}`);
  }

  // Logos and assets pulled from the real brand while the page is elsewhere.
  const externalAssetHosts = unique([...features.images.map((i) => i.src), features.favicon]
    .filter(Boolean)
    .map((src) => safeParseUrl(src)?.hostname)
    .filter(Boolean)
    .filter((h) => host && !isSameSite(h, host)));
  const hotlinkedBrandAsset = externalAssetHosts.find((h) => OFFICIAL_DOMAINS.has(registrableDomain(h)));
  if (hotlinkedBrandAsset && !isOfficial) {
    add('page-hotlinked-brand-assets', 'domain', 'Logos and images loaded directly from the brand\'s real website', 17,
      `Images are pulled from "${registrableDomain(hotlinkedBrandAsset)}" to make this copy look authentic. Genuine sites host their own assets.`,
      registrableDomain(hotlinkedBrandAsset));
  }

  /* --------------------------- evasion behaviour ----------------------- */
  const inlineJs = features.scripts.map((s) => s.inline).join('\n');
  if (inlineJs) {
    const evalCount = (inlineJs.match(/\b(eval|Function\s*\(|atob|unescape|decodeURIComponent\s*\(\s*escape)\b/g) || []).length;
    const hexBlobs = (inlineJs.match(/(?:\\x[0-9a-f]{2}){12,}|(?:%[0-9a-f]{2}){20,}/gi) || []).length;
    if (evalCount >= 3 || hexBlobs) {
      add('page-obfuscated-script', 'page', 'Page runs heavily obfuscated JavaScript', 15,
        'Encoded and self-decoding scripts exist to hide what the page does from you and from security scanners.',
        `${evalCount} dynamic-execution calls, ${hexBlobs} encoded blobs`);
    }
    if (/document\.addEventListener\s*\(\s*['"]contextmenu['"][\s\S]{0,80}preventDefault|oncontextmenu\s*=\s*["']?return false/i.test(inlineJs + ' ' + (input.html || ''))) {
      add('page-right-click-blocked', 'page', 'Right-click / inspection is disabled', 11,
        'Blocking the context menu stops you from viewing the page source or checking link destinations.', 'contextmenu handler blocked');
    }
    if (/\b(?:on)?(?:paste|copy)\b[\s\S]{0,60}preventDefault/i.test(inlineJs)) {
      add('page-paste-blocked', 'page', 'Copy or paste is blocked in the form', 12,
        'Blocking paste forces you to type credentials manually and defeats password managers, which would otherwise refuse to fill a fake domain.', 'paste handler blocked');
    }
    if (/\b(?:api\.telegram\.org|sendMessage\?chat_id|discord(?:app)?\.com\/api\/webhooks)\b/i.test(inlineJs)) {
      add('page-telegram-exfil', 'credential-theft', 'Script sends collected data to a chat bot', 30,
        'Telegram and Discord bot endpoints are the most common delivery channel for stolen credentials in phishing kits.', 'bot webhook found in page script');
    }
    if (/window\.(?:location|open)\s*=?\s*\(?['"]https?:\/\//i.test(inlineJs) && isLoginPage) {
      add('page-auto-redirect', 'page', 'Page redirects elsewhere after submission', 8,
        'Fake login pages forward you to the real website afterwards so the theft goes unnoticed.', 'scripted redirect detected');
    }
  }

  const hiddenIframe = features.iframes.find((f) => f.hidden && f.src);
  if (hiddenIframe) {
    add('page-hidden-iframe', 'page', 'Invisible iframe loading external content', 16,
      'Hidden frames are used to load exploit code or silently relay what you type.', truncate(hiddenIframe.src, 80));
  }
  const brandIframe = features.iframes.find((f) => f.src && host && !isSameSite(safeParseUrl(f.src)?.hostname || '', host) && !f.hidden);
  if (brandIframe && isLoginPage) {
    add('page-framed-login', 'page', 'Login area is framed from another website', 12,
      'Wrapping a real or fake login inside a frame lets an attacker sit between you and the service.', truncate(brandIframe.src, 80));
  }

  const hiddenPrefilled = features.forms.flatMap((f) => f.inputs).filter((i) => i.type === 'hidden' && /email|mail|user|id|target|victim|bot|chat/i.test(i.name));
  if (hiddenPrefilled.length && isLoginPage) {
    add('page-hidden-target-field', 'page', 'Hidden field carrying a pre-filled identity', 13,
      `The page ships hidden values (${hiddenPrefilled.map((f) => f.name).slice(0, 3).join(', ')}), typical of a phishing kit personalised for a specific victim list.`,
      hiddenPrefilled.map((f) => f.name).slice(0, 3).join(', '));
  }

  /* --------------------------- page maturity --------------------------- */
  const externalLinks = features.anchors.filter((a) => {
    const h = safeParseUrl(a.href || '')?.hostname;
    return h && host && !isSameSite(h, host);
  });
  const deadLinks = features.anchors.filter((a) => /^#$|^javascript:void|^$/.test(a.raw || '')).length;
  if (isLoginPage && features.anchors.length >= 4 && deadLinks / features.anchors.length > 0.6) {
    add('page-dead-navigation', 'page', 'Most navigation links on the page do nothing', 12,
      'A single working form surrounded by dead links means only the credential capture was built. Real sites are complete.',
      `${deadLinks} of ${features.anchors.length} links are placeholders`);
  }
  if (isLoginPage && features.length > 0 && features.length < 2500 && !isTrusted) {
    add('page-thin-clone', 'page', 'Very small page containing only a login form', 10,
      'Phishing pages are usually single-file clones with no supporting content.', `${features.length} bytes of HTML`);
  }
  if (!/\b(privacy policy|terms of (use|service)|about us|contact us|customer care|helpline)\b/i.test(bodyText) && isLoginPage && !isTrusted) {
    add('page-no-legal-pages', 'page', 'No privacy policy, terms or contact information', 8,
      'Legitimate services are legally required to publish these. Throwaway phishing pages skip them.', 'missing policy/contact sections');
  }

  /* --------------------------- alarming copy --------------------------- */
  if (/\b(your (account|session) (has been|is) (locked|suspended|limited|disabled)|verify (your )?(identity|account) (now|immediately)|unusual (sign[-\s]?in|activity) detected|re-?confirm your (details|information))\b/i.test(bodyText)) {
    add('page-alarming-copy', 'social-engineering', 'Page uses alarming security language to push you to log in', 13,
      'Fake portals open with a scare so you enter credentials without checking the address bar.',
      truncate(normalizeWhitespace(bodyText.match(/[^.!?]{0,60}(?:locked|suspended|verify your identity|unusual sign)[^.!?]{0,60}/i)?.[0] || ''), 110));
  }
  if (/\b(enter (your )?(otp|one[-\s]?time password)|otp sent to your (mobile|registered))\b/i.test(bodyText) && !isOfficial) {
    add('page-otp-capture', 'credential-theft', 'Page asks for an OTP', 24,
      'An OTP prompt on a non-official domain means the attacker already has your password and needs the second factor to finish the login.',
      'one-time password field on the page');
  }

  /* ------------------------- positive indicators ----------------------- */
  if (isOfficial) {
    add('page-official-domain', 'positive', 'Page is served from the brand\'s verified domain', -22,
      `"${rd}" is the genuine domain for this service.`, rd);
  } else if (isTrusted) {
    add('page-trusted-domain', 'positive', 'Page is served from a reputable domain', -14, `"${rd}" is an established, well-known domain.`, rd);
  }
  if (isHttps && isLoginPage && !signals.some((s) => s.weight >= 20)) {
    add('page-https-login', 'positive', 'Login page uses an encrypted connection', -5,
      'The connection is encrypted. Remember that encryption alone does not prove the site is genuine.', pageUrl);
  }

  return {
    signals,
    features: {
      title: features.title,
      formCount: features.forms.length,
      inputCount: allInputs.length,
      scriptCount: features.scripts.length,
      iframeCount: features.iframes.length,
      anchorCount: features.anchors.length,
      externalLinkCount: externalLinks.length,
      bytes: features.length,
      textPreview: truncate(normalizeWhitespace(bodyText), 400)
    },
    facts: {
      url: pageUrl || null,
      registrableDomain: rd || null,
      https: isHttps,
      isLoginPage,
      hasPasswordField: hasPassword,
      sensitiveFields,
      impersonates: impersonated ? impersonated.brand.name : null,
      externalAssetHosts: externalAssetHosts.slice(0, 5)
    }
  };
}
