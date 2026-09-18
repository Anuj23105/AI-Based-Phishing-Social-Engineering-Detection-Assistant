/**
 * PhishGuard AI — message / language analyzer.
 *
 * Runs the social-engineering tactic library over the text, detects the
 * manipulation techniques in play, and adds structural language signals
 * (obfuscation, shouting, brand claims, contact-channel abuse).
 */

import { BRANDS, TACTICS } from './constants.js';
import {
  canonicalize,
  collapseSpacedLetters,
  extractEmails,
  extractPhones,
  extractUrls,
  normalizeWhitespace,
  registrableDomain,
  truncate,
  unique,
  upperCaseRatio
} from './utils.js';

/** Words whose presence indicates the message is *about* money or identity. */
const SENSITIVE_TOPICS = [
  'password', 'otp', 'cvv', 'pin', 'aadhaar', 'aadhar', 'pan card', 'ifsc', 'upi',
  'net banking', 'netbanking', 'credit card', 'debit card', 'bank account', 'kyc',
  'wallet', 'seed phrase', 'private key', 'salary', 'invoice', 'refund', 'payment'
];

/**
 * Find which brands the text claims to be from.
 * @returns {Array<{ brand:string, keyword:string, domains:string[] }>}
 */
export function detectClaimedBrands(text = '') {
  const canon = ` ${canonicalize(collapseSpacedLetters(text))} `;
  const found = [];
  for (const brand of BRANDS) {
    for (const kw of brand.keywords) {
      const needle = canonicalize(kw);
      const pattern = new RegExp(`(?:^|[^a-z0-9])${needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:[^a-z0-9]|$)`);
      if (pattern.test(canon)) {
        found.push({ brand: brand.name, keyword: kw.trim(), domains: brand.domains });
        break;
      }
    }
  }
  return found;
}

/**
 * Run the tactic library.
 * @returns {{ signals:Array, tactics:Array }}
 */
function detectTactics(text) {
  const haystacks = unique([
    text,
    collapseSpacedLetters(text),
    canonicalize(text),
    canonicalize(collapseSpacedLetters(text))
  ]);

  const signals = [];
  const tactics = [];

  for (const tactic of TACTICS) {
    const matches = [];
    for (const pattern of tactic.patterns) {
      for (const hay of haystacks) {
        const m = hay.match(pattern);
        if (m) {
          matches.push(normalizeWhitespace(m[0]).slice(0, 90));
          break;
        }
      }
    }
    if (!matches.length) continue;

    const extra = Math.min(matches.length - 1, 4);
    const weight = Math.min(tactic.cap, tactic.weight + extra * tactic.repeatWeight);
    const evidence = unique(matches).slice(0, 3);

    signals.push({
      id: `tactic-${tactic.id}`,
      category: tactic.category,
      label: tactic.label,
      weight,
      detail: tactic.why,
      evidence: evidence.map((e) => `"${e}"`).join('  ·  ')
    });
    tactics.push({
      id: tactic.id,
      label: tactic.label,
      category: tactic.category,
      hits: matches.length,
      weight,
      why: tactic.why,
      evidence
    });
  }

  return { signals, tactics };
}

/**
 * Analyze a block of text (email body, SMS, chat message, social DM).
 *
 * @param {string} rawText
 * @param {{ channel?:string, senderEmail?:string, links?:Array<{href:string,text:string}> }} [options]
 */
export function analyzeText(rawText = '', options = {}) {
  const text = String(rawText || '');
  const canon = canonicalize(collapseSpacedLetters(text));
  const words = canon.split(/\s+/).filter(Boolean);
  const signals = [];

  const add = (id, category, label, weight, detail, evidence) => {
    signals.push({ id, category, label, weight, detail, evidence });
  };

  const { signals: tacticSignals, tactics } = detectTactics(text);
  signals.push(...tacticSignals);

  const urls = extractUrls(text);
  const emails = extractEmails(text);
  const phones = extractPhones(text);
  const claimedBrands = detectClaimedBrands(text);

  /* ------------------------- brand claim vs. link ----------------------- */
  if (claimedBrands.length && urls.length) {
    for (const claim of claimedBrands) {
      const officialRds = new Set(claim.domains.map(registrableDomain));
      const linkRds = unique(urls.map((u) => {
        try {
          return registrableDomain(new URL(/^[a-z]+:\/\//i.test(u) ? u : `http://${u}`).hostname);
        } catch {
          return '';
        }
      }).filter(Boolean));
      if (linkRds.length && !linkRds.some((rd) => officialRds.has(rd))) {
        add('content-brand-link-mismatch', 'domain', `Message claims to be ${claim.brand} but links elsewhere`, 19,
          `The text mentions ${claim.brand}, yet every link points to ${linkRds.slice(0, 2).map((d) => `"${d}"`).join(', ')} instead of ${claim.domains[0]}.`,
          linkRds.slice(0, 3).join(', '));
        break;
      }
    }
  }

  /* ------------------------ anchor text vs. href ------------------------ */
  for (const link of options.links || []) {
    if (!link?.href || !link?.text) continue;
    const label = normalizeWhitespace(link.text);
    const looksLikeUrl = /^(?:https?:\/\/|www\.)|\.[a-z]{2,}(?:\/|$)/i.test(label);
    if (!looksLikeUrl) continue;
    try {
      const shown = registrableDomain(new URL(/^[a-z]+:\/\//i.test(label) ? label : `http://${label}`).hostname);
      const actual = registrableDomain(new URL(link.href).hostname);
      if (shown && actual && shown !== actual) {
        add('content-anchor-mismatch', 'url', 'Displayed link text does not match its real destination', 24,
          `The link says "${shown}" but actually opens "${actual}".`, `${shown} → ${actual}`);
        break;
      }
    } catch { /* ignore unparseable anchors */ }
  }

  /* ---------------------------- obfuscation ---------------------------- */
  if (/\b(?:[a-z][\s._\-*]){3,}[a-z]\b/i.test(text)) {
    add('content-spaced-words', 'content', 'Words deliberately broken up with spaces or dots', 12,
      'Splitting words like "v e r i f y" is done purely to slip past spam filters.', truncate(normalizeWhitespace(text.match(/\b(?:[a-z][\s._\-*]){3,}[a-z]\b/i)?.[0] || ''), 60));
  }
  const leetHits = text.match(/\b[a-z]{2,}[0134578@$][a-z]{2,}\b/gi) || [];
  const leetSuspicious = leetHits.filter((w) => /(?:acc0unt|passw0rd|verif|p4y|b4nk|s3cur|l0gin|updat3|w1n|fr33)/i.test(canonicalize(w)));
  if (leetSuspicious.length) {
    add('content-leetspeak', 'content', 'Numbers substituted for letters in key words', 11,
      'Writing "acc0unt" or "passw0rd" is a filter-evasion trick, not a typo.', unique(leetSuspicious).slice(0, 3).join(', '));
  }
  if (/[\u200b-\u200f\u202a-\u202e\u2060\ufeff]/.test(text)) {
    add('content-invisible-chars', 'content', 'Hidden zero-width characters inside the text', 13,
      'Invisible characters are inserted to break up words that filters look for, and to disguise link text.', 'zero-width / bidirectional control characters');
  }
  if (/[\u0400-\u04ff\u0370-\u03ff]/.test(text) && /[a-z]/i.test(text)) {
    add('content-mixed-script', 'content', 'Latin text mixed with look-alike Cyrillic or Greek letters', 12,
      'Mixing alphabets makes a word look normal to you while reading differently to software.', 'mixed character sets detected');
  }

  /* ------------------------------- tone -------------------------------- */
  const capsRatio = upperCaseRatio(text);
  if (capsRatio > 0.55) {
    add('content-shouting', 'content', 'Large amount of text in capital letters', 8,
      'Sustained capitals are used to create alarm and force attention.', `${Math.round(capsRatio * 100)}% of letters are capitals`);
  }
  if (/[!?]{3,}/.test(text) || (text.match(/!/g) || []).length >= 4) {
    add('content-punctuation', 'content', 'Excessive exclamation or question marks', 5,
      'Emotional punctuation is used to push you into reacting quickly.', truncate(text.match(/[!?]{3,}/)?.[0] || 'repeated "!"', 20));
  }

  /* -------------------------- contact channels ------------------------- */
  if (phones.length && words.length < 90 && tactics.length >= 1) {
    add('content-callback-number', 'social-engineering', 'Short message pushing you to call a number', 9,
      'Callback phishing moves you to a phone call where an "agent" can talk you into installing software or sharing an OTP.', phones.slice(0, 2).join(', '));
  }
  if (/\b(?:wa\.me|t\.me|chat\.whatsapp\.com|api\.whatsapp\.com)\b/i.test(text)) {
    add('content-messaging-link', 'social-engineering', 'Direct WhatsApp or Telegram contact link', 12,
      'Legitimate banks, employers and government offices do not run business through personal chat links.', text.match(/\b(?:wa\.me|t\.me|chat\.whatsapp\.com|api\.whatsapp\.com)\b/i)?.[0]);
  }

  /* ------------------------ sensitive-topic weight --------------------- */
  const topics = SENSITIVE_TOPICS.filter((t) => canon.includes(t));
  if (topics.length >= 2 && tactics.length >= 2) {
    add('content-sensitive-topic', 'credential-theft', 'Message combines pressure tactics with sensitive financial or identity topics', 10,
      `It refers to ${topics.slice(0, 3).map((t) => `"${t}"`).join(', ')} while also applying pressure — the standard setup for credential theft.`,
      topics.slice(0, 4).join(', '));
  }

  /* --------------------------- structure ------------------------------- */
  if (words.length && words.length < 6 && urls.length >= 1) {
    add('content-bare-link', 'content', 'Almost no text apart from a link', 10,
      'A link with no explanation gives you nothing to verify and is a common malware or phishing delivery style.', truncate(normalizeWhitespace(text), 80));
  }
  if (urls.length >= 4) {
    add('content-many-links', 'content', `Message contains ${urls.length} links`, 5,
      'Bulk links are used to increase the chance that you click at least one.', `${urls.length} links`);
  }
  if (/\b(forward|share|send)\s+(this\s+)?(message\s+)?(to|with)\s+(\d+|as many|all your|your)\s*(friends|people|groups|contacts|whatsapp groups)?/i.test(text)
    || /\bre-?send this to\b/i.test(text)) {
    add('content-chain-message', 'social-engineering', 'Asks you to forward the message on', 9,
      'Chain-forwarding is how scams and misinformation scale; genuine notices never require it.', truncate(text.match(/forward this to[^.!?]{0,30}|share with \d+[^.!?]{0,25}/i)?.[0] || 'forwarding request', 60));
  }

  /* ------------------------- positive indicators ----------------------- */
  const hasStrongTactic = tactics.some((t) => ['credential-request', 'financial-fraud', 'reward', 'fear', 'bec', 'tech-support', 'job-scam'].includes(t.id));
  if (!tactics.length && words.length >= 12) {
    add('content-neutral-tone', 'positive', 'Neutral, non-pressuring language', -12,
      'The message does not use urgency, threats, rewards or requests for sensitive data.', 'no manipulation patterns matched');
  } else if (!hasStrongTactic && tactics.length === 1 && words.length >= 25) {
    add('content-mild-tone', 'positive', 'Only mild persuasive language', -6,
      'One soft pattern matched, which on its own is normal in ordinary business or service email.', tactics[0].label);
  }
  // Genuine transactional codes: a bank OTP alert warns you *not* to share the
  // code and never carries a link. Recognising this shape explicitly is what
  // keeps real service messages out of the medium band.
  const hasCode = /\b\d{4,8}\b/.test(text);
  const warnsNotToShare = /\b(do not|don'?t|never)\s+(share|disclose|reveal|tell|give)\b/i.test(text);
  if (hasCode && warnsNotToShare && !urls.length && words.length < 60) {
    add('content-transactional-code', 'positive', 'Standard transactional code notice', -16,
      'The message delivers a code and explicitly warns you not to share it, and it contains no link. That is how genuine OTP alerts are written.',
      'one-time code notice with no link');
  }

  if (/\b(unsubscribe|manage (your )?(email )?preferences|opt[-\s]?out|view (this )?(email )?in (your )?browser|privacy policy)\b/i.test(text)) {
    add('content-unsubscribe', 'positive', 'Contains standard bulk-mail footer elements', -7,
      'Unsubscribe and preference links are typical of genuine marketing or notification systems.', 'unsubscribe / preferences footer');
  }

  return {
    signals,
    tactics,
    extracted: { urls, emails, phones },
    claimedBrands,
    stats: {
      characters: text.length,
      words: words.length,
      links: urls.length,
      capsRatio: Math.round(capsRatio * 100) / 100,
      channel: options.channel || 'unknown'
    }
  };
}
