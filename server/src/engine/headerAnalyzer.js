/**
 * PhishGuard AI — sender / e-mail header analyzer.
 *
 * Accepts either a pasted raw e-mail (headers + body) or explicit sender
 * fields, and checks the things users cannot easily see: display-name spoofing,
 * reply-to redirection, SPF/DKIM/DMARC results and look-alike sender domains.
 */

import { BRANDS, DISPOSABLE_MAIL_DOMAINS, FREE_MAIL_DOMAINS, OFFICIAL_DOMAINS, SUSPICIOUS_TLDS, TRUSTED_DOMAINS } from './constants.js';
import { canonicalize, domainLabel, isSameSite, levenshtein, normalizeWhitespace, registrableDomain, tldOf, truncate } from './utils.js';

const HEADER_BLOCK = /^(?:[A-Za-z-]+:[^\n]*(?:\n[ \t][^\n]*)*\n)+/;

/**
 * Split a pasted raw e-mail into headers and body.
 * Returns `{ headers:{}, body:string, isRawEmail:boolean }`.
 */
export function parseEmail(raw = '') {
  const text = String(raw).replace(/\r\n/g, '\n');
  const looksLikeEmail = /^(?:from|to|subject|date|received|return-path|reply-to|message-id|authentication-results)\s*:/im.test(text.slice(0, 2000));
  if (!looksLikeEmail) return { headers: {}, body: text, isRawEmail: false };

  const match = text.match(HEADER_BLOCK);
  const headerText = match ? match[0] : text.split(/\n\s*\n/)[0];
  const body = match ? text.slice(match[0].length) : text.split(/\n\s*\n/).slice(1).join('\n\n');

  const headers = {};
  const unfolded = headerText.replace(/\n[ \t]+/g, ' ');
  for (const line of unfolded.split('\n')) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (!key) continue;
    if (headers[key]) headers[key] = `${headers[key]} | ${value}`;
    else headers[key] = value;
  }
  return { headers, body: body.trim() || text, isRawEmail: true };
}

/** Pull `Display Name <address@domain>` apart. */
export function parseAddress(value = '') {
  const raw = normalizeWhitespace(String(value));
  if (!raw) return { display: '', address: '', domain: '' };
  const angled = raw.match(/^(.*?)<\s*([^>]+?)\s*>$/);
  const display = angled ? angled[1].replace(/^["']|["']$/g, '').trim() : '';
  const address = (angled ? angled[2] : raw).replace(/^mailto:/i, '').trim().toLowerCase();
  const domain = address.includes('@') ? address.split('@').pop() : '';
  return { display, address, domain };
}

/** Read SPF / DKIM / DMARC verdicts out of Authentication-Results. */
function parseAuthResults(headers) {
  const sources = [headers['authentication-results'], headers['arc-authentication-results'], headers['received-spf'], headers['x-spf-result'], headers['dkim-signature'] ? 'dkim=present' : '']
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
  const pick = (name) => {
    const m = sources.match(new RegExp(`${name}\\s*=\\s*(pass|fail|softfail|neutral|none|permerror|temperror|bestguesspass)`));
    return m ? m[1] : null;
  };
  const spfHeader = headers['received-spf'] ? headers['received-spf'].toLowerCase() : '';
  const spfFromHeader = spfHeader.match(/^\s*(pass|fail|softfail|neutral|none|permerror|temperror)/);
  return {
    spf: pick('spf') || (spfFromHeader ? spfFromHeader[1] : null),
    dkim: pick('dkim'),
    dmarc: pick('dmarc'),
    present: Boolean(sources)
  };
}

/** Sender domain that looks like a brand but is not the brand. */
function senderLookalike(domain) {
  const rd = registrableDomain(domain);
  if (!rd || OFFICIAL_DOMAINS.has(rd)) return null;
  const label = canonicalize(domainLabel(rd)).replace(/[-_.]/g, '');
  for (const brand of BRANDS) {
    for (const official of brand.domains) {
      const brandLabel = canonicalize(domainLabel(official));
      if (brandLabel.length < 4) continue;
      if (label.includes(brandLabel) && label !== brandLabel) return { brand: brand.name, official, type: 'embedded' };
      const max = brandLabel.length >= 8 ? 2 : 1;
      const d = levenshtein(label, brandLabel, max);
      if (d > 0 && d <= max) return { brand: brand.name, official, type: 'typosquat', distance: d };
    }
  }
  return null;
}

/**
 * Analyze sender identity.
 *
 * @param {{ headers?:Object, senderEmail?:string, senderName?:string, replyTo?:string,
 *           claimedBrands?:Array<{brand:string,domains:string[]}>, bodyText?:string }} input
 */
export function analyzeSender(input = {}) {
  const headers = input.headers || {};
  const signals = [];
  const add = (id, category, label, weight, detail, evidence) => {
    signals.push({ id, category, label, weight, detail, evidence });
  };

  const from = parseAddress(headers.from || input.senderEmail || '');
  const displayName = from.display || input.senderName || '';
  const replyTo = parseAddress(headers['reply-to'] || input.replyTo || '');
  const returnPath = parseAddress(headers['return-path'] || '');
  const auth = parseAuthResults(headers);

  const fromRd = from.domain ? registrableDomain(from.domain) : '';
  const facts = {
    from: from.address || null,
    displayName: displayName || null,
    fromDomain: fromRd || null,
    replyTo: replyTo.address || null,
    returnPath: returnPath.address || null,
    auth,
    subject: headers.subject || null
  };

  if (!from.address) {
    return { signals, facts, hasSender: false };
  }

  /* ------------------------- display-name spoofing ---------------------- */
  if (displayName) {
    const canonName = canonicalize(displayName);
    const brandInName = BRANDS.find((b) => b.keywords.some((kw) => {
      const k = canonicalize(kw).trim();
      return k.length >= 3 && new RegExp(`(?:^|[^a-z0-9])${k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:[^a-z0-9]|$)`).test(canonName);
    }));
    if (brandInName && !brandInName.domains.some((d) => isSameSite(d, from.domain))) {
      add('sender-display-spoof', 'sender', `Display name says "${normalizeWhitespace(displayName)}" but the address is not ${brandInName.brand}`, 24,
        `Anyone can set any display name. The real address is "${from.address}", which does not belong to ${brandInName.brand} (${brandInName.domains[0]}).`,
        `${normalizeWhitespace(displayName)} <${from.address}>`);
    }
    // Display name contains a *different* e-mail address than the real one.
    const emailInName = canonName.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/);
    if (emailInName && emailInName[0] !== from.address) {
      add('sender-name-contains-email', 'sender', 'Display name imitates a different e-mail address', 20,
        `The name shows "${emailInName[0]}" while mail actually comes from "${from.address}".`, `${emailInName[0]} vs ${from.address}`);
    }
    if (/\b(ceo|cfo|md|director|manager|hr|principal|dean|accounts?|finance|payroll)\b/i.test(displayName) && FREE_MAIL_DOMAINS.has(fromRd)) {
      add('sender-exec-freemail', 'bec', 'Executive or finance role sending from a personal mailbox', 22,
        `A message signed as "${normalizeWhitespace(displayName)}" arriving from a free ${fromRd} account is the standard Business Email Compromise setup.`,
        `${normalizeWhitespace(displayName)} <${from.address}>`);
    }
  }

  /* ------------------------------ reply-to ----------------------------- */
  if (replyTo.address && replyTo.domain && !isSameSite(replyTo.domain, from.domain)) {
    add('sender-replyto-mismatch', 'sender', 'Replies are redirected to a different domain', 21,
      `Mail appears to come from "${fromRd}" but your reply would go to "${registrableDomain(replyTo.domain)}" — a classic conversation-hijack setup.`,
      `From ${from.address} → Reply-To ${replyTo.address}`);
  }
  if (returnPath.domain && !isSameSite(returnPath.domain, from.domain) && !replyTo.address) {
    add('sender-returnpath-mismatch', 'sender', 'Envelope sender differs from the visible sender', 12,
      `The technical Return-Path is "${returnPath.address}" while the visible sender is "${from.address}". Some bulk senders do this legitimately, but so does spoofed mail.`,
      `${from.address} vs ${returnPath.address}`);
  }

  /* --------------------------- authentication -------------------------- */
  if (auth.present) {
    const failed = ['spf', 'dkim', 'dmarc'].filter((k) => ['fail', 'softfail', 'permerror'].includes(auth[k]));
    if (failed.length) {
      add('sender-auth-fail', 'sender', `Sender authentication failed (${failed.map((f) => f.toUpperCase()).join(', ')})`, failed.includes('dmarc') ? 26 : 20,
        'The mail servers could not confirm this message really came from the domain it claims. This is strong evidence of spoofing.',
        failed.map((f) => `${f}=${auth[f]}`).join(' '));
    } else if (auth.spf === 'pass' && (auth.dkim === 'pass' || auth.dmarc === 'pass')) {
      add('sender-auth-pass', 'positive', 'Sender domain passed authentication checks', -14,
        'SPF/DKIM confirm the message really was sent by the domain it claims. That does not make the content safe, but it rules out simple spoofing.',
        ['spf', 'dkim', 'dmarc'].filter((k) => auth[k]).map((k) => `${k}=${auth[k]}`).join(' '));
    }
  }

  /* ---------------------------- sender domain -------------------------- */
  const lookalike = senderLookalike(from.domain);
  if (lookalike) {
    add('sender-lookalike-domain', 'sender', `Sender domain imitates ${lookalike.brand}`, lookalike.type === 'typosquat' ? 26 : 22,
      lookalike.type === 'typosquat'
        ? `"${fromRd}" differs from the official "${lookalike.official}" by ${lookalike.distance} character${lookalike.distance > 1 ? 's' : ''}.`
        : `"${fromRd}" contains the brand name but is not the official "${lookalike.official}".`,
      fromRd);
  }

  if (DISPOSABLE_MAIL_DOMAINS.has(fromRd)) {
    add('sender-disposable', 'sender', 'Sent from a disposable throwaway mailbox', 22,
      'Temporary mailboxes exist to be abandoned; no genuine organisation uses one for customer communication.', fromRd);
  }

  const senderTld = tldOf(from.domain);
  if (SUSPICIOUS_TLDS.has(senderTld)) {
    add('sender-suspicious-tld', 'sender', `Sender domain uses high-abuse ending ".${senderTld}"`, 13,
      `Domains ending in ".${senderTld}" are cheap and disposable, and are heavily represented in phishing campaigns.`, fromRd);
  }

  const claimedBrands = input.claimedBrands || [];
  for (const claim of claimedBrands) {
    const officialRds = new Set(claim.domains.map(registrableDomain));
    if (officialRds.has(fromRd)) {
      add('sender-brand-verified', 'positive', `Sender is the official ${claim.brand} domain`, -20,
        `"${fromRd}" is a genuine ${claim.brand} domain.`, fromRd);
      break;
    }
    if (FREE_MAIL_DOMAINS.has(fromRd)) {
      add('sender-brand-freemail', 'sender', `Message claims to be ${claim.brand} but comes from a free mailbox`, 22,
        `${claim.brand} sends mail from ${claim.domains[0]}, never from a personal ${fromRd} address.`, from.address);
      break;
    }
    add('sender-brand-mismatch', 'sender', `Sender domain does not belong to ${claim.brand}`, 18,
      `The message presents itself as ${claim.brand}, but it was sent from "${fromRd}" rather than ${claim.domains[0]}.`, from.address);
    break;
  }

  if (!claimedBrands.length && !lookalike && (TRUSTED_DOMAINS.has(fromRd) || OFFICIAL_DOMAINS.has(fromRd))) {
    add('sender-trusted-domain', 'positive', 'Sender uses a well-known, reputable domain', -12,
      `"${fromRd}" is an established domain.`, fromRd);
  }

  /* --------------------------- header oddities ------------------------- */
  if (headers['x-mailer'] && /\b(php ?mailer|swiftmailer|sendblaster|mass ?mailer|bulk|turbo-?smtp)\b/i.test(headers['x-mailer'])) {
    add('sender-bulk-mailer', 'sender', 'Sent with a bulk or script-based mailer', 10,
      'Scripted mailers are what phishing kits use to send from compromised servers.', truncate(headers['x-mailer'], 60));
  }
  if (headers.subject && /^(?:re|fwd?)\s*:/i.test(headers.subject) && !headers.references && !headers['in-reply-to']) {
    add('sender-fake-thread', 'sender', 'Fake reply: subject says "Re:" but there is no earlier conversation', 14,
      'Attackers prefix Re: or Fwd: so the message looks like part of a thread you already trust.', truncate(headers.subject, 70));
  }
  if (headers.to && /undisclosed[-\s]?recipients?/i.test(headers.to)) {
    add('sender-hidden-recipients', 'sender', 'Recipients hidden behind "undisclosed-recipients"', 9,
      'Your address was not addressed directly, meaning this went out in bulk.', truncate(headers.to, 60));
  }

  return { signals, facts, hasSender: true };
}
