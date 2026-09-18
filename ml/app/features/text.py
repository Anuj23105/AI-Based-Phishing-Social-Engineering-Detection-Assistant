"""
Text normalisation for the message classifier.

The same function runs at training time and at inference time, so the model
never sees a distribution it was not fitted on.

Rather than feeding raw text to TF-IDF, we replace volatile, high-cardinality
spans (URLs, amounts, codes, phone numbers) with stable marker tokens such as
``<url_shortener>`` or ``<money>``. Two things come out of that:

* the vocabulary stays small and the model generalises across campaigns instead
  of memorising one attacker's domain or amount;
* the markers themselves are learnable evidence, and because they survive into
  the explanation output, a prediction can be justified in words the user reads
  ("a shortened link", "a money amount") rather than opaque n-grams.
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlsplit

from ..knowledge import (
    CREDENTIAL_URL_WORDS,
    FREE_HOSTING_SUFFIXES,
    HOMOGLYPH_MAP,
    LEET_MAP,
    OFFICIAL_DOMAINS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    BRAND_LABELS,
    domain_label,
    public_suffix,
    registrable_domain,
)

FREE_MAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "rediffmail.com",
    "hotmail.com", "outlook.com", "live.com", "aol.com", "protonmail.com", "proton.me",
    "yandex.com", "mail.com", "gmx.com", "icloud.com", "zoho.com",
}
DISPOSABLE_MAIL = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "temp-mail.org", "yopmail.com", "trashmail.com", "getnada.com", "maildrop.cc",
}

URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'`\)\]}]+"
    r"|(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:com|org|net|in|io|co|info|biz|xyz|top|tk|ml|ga|cf|gq|club|click|link|live|online|site|app|dev|me|ru|cn|uk|us|gov|edu|shop|store|icu|buzz|cyou|sbs|zip|mov|pw|cc|work|fit|rest|monster|quest|bid|loan|win|vip|ltd|life|world|space|website|tech|art|fun|surf|cam|bar|casa|autos|cfd)(?:/[^\s<>\"'`\)\]}]*)?",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}", re.IGNORECASE)
MONEY_RE = re.compile(
    r"(?:(?:rs\.?|inr|₹|usd|\$|€|£|aed|gbp)\s*\d[\d,]*(?:\.\d+)?(?:\s*(?:lakh|lakhs|crore|crores|k|m|million|billion))?)"
    r"|(?:\d[\d,]*(?:\.\d+)?\s*(?:rupees|rs\.?|inr|dollars?|usd|lakh|lakhs|crore|crores))",
    re.IGNORECASE,
)
PHONE_RE = re.compile(r"(?:\+\d{1,3}[\s-]?)?(?:\(?\d{3,5}\)?[\s-]?)?\d{5,10}")
CODE_RE = re.compile(r"\b\d{4,8}\b")
NUM_RE = re.compile(r"\b\d[\d,]*(?:\.\d+)?\b")
SPACED_RE = re.compile(r"\b(?:[a-z][\s._*\-]){2,}[a-z]\b", re.IGNORECASE)
ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
PUNCT_RUN_RE = re.compile(r"([!?])\1{1,}")
WS_RE = re.compile(r"\s+")
LEET_TOKEN_RE = re.compile(r"\b(?=[a-z]*[0134578@$|!])(?=[0134578@$|!]*[a-z])[a-z0134578@$|!]{4,}\b", re.IGNORECASE)


def _dehomoglyph(text: str) -> str:
    return "".join(HOMOGLYPH_MAP.get(ch, HOMOGLYPH_MAP.get(ch.lower(), ch)) for ch in text)


def _deleet_token(token: str) -> str:
    return "".join(LEET_MAP.get(ch, ch) for ch in token)


def _url_markers(raw: str) -> str:
    """Describe a URL with a handful of stable marker tokens."""
    candidate = raw if "://" in raw else "http://" + raw
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower()
        path_query = ((parts.path or "") + " " + (parts.query or "")).lower()
    except ValueError:
        return "<url>"

    if not host:
        return "<url>"

    rd = registrable_domain(host)
    markers = ["<url>"]

    if raw.lower().startswith("http://"):
        markers.append("<url_insecure>")
    if rd in URL_SHORTENERS or host in URL_SHORTENERS:
        markers.append("<url_shortener>")
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        markers.append("<url_ip_host>")
    if public_suffix(host) in SUSPICIOUS_TLDS:
        markers.append("<url_risky_tld>")
    if any(host == suffix or host.endswith("." + suffix) for suffix in FREE_HOSTING_SUFFIXES):
        markers.append("<url_free_hosting>")
    if host.count(".") >= 3:
        markers.append("<url_deep_subdomain>")
    if "xn--" in host:
        markers.append("<url_punycode>")
    if "@" in (parts.netloc or ""):
        markers.append("<url_userinfo>")
    if rd in OFFICIAL_DOMAINS:
        markers.append("<url_official_domain>")
    else:
        label = domain_label(host).replace("-", "")
        subdomain = host[: -(len(rd) + 1)] if host.endswith(rd) and host != rd else ""
        if any(b in label or b in subdomain.replace("-", "") for b in BRAND_LABELS):
            markers.append("<url_brand_lookalike>")
    if any(word in path_query or word in host for word in CREDENTIAL_URL_WORDS):
        markers.append("<url_credential_path>")
    if len(candidate) > 90:
        markers.append("<url_long>")

    return " ".join(markers)


def _email_markers(raw: str) -> str:
    domain = raw.split("@")[-1].lower()
    rd = registrable_domain(domain)
    markers = ["<email>"]
    if rd in DISPOSABLE_MAIL:
        markers.append("<email_disposable>")
    elif rd in FREE_MAIL:
        markers.append("<email_freemail>")
    elif rd in OFFICIAL_DOMAINS:
        markers.append("<email_official>")
    if public_suffix(domain) in SUSPICIOUS_TLDS:
        markers.append("<email_risky_tld>")
    return " ".join(markers)


def normalize_text(text: str) -> str:
    """Canonical representation of a message for TF-IDF vectorisation."""
    if not text:
        return ""

    raw = unicodedata.normalize("NFKC", str(text))
    raw = ZERO_WIDTH_RE.sub("", raw)

    letters = [c for c in raw if c.isalpha()]
    caps_ratio = (sum(1 for c in letters if c.isupper()) / len(letters)) if len(letters) >= 12 else 0.0
    exclamations = raw.count("!")

    work = _dehomoglyph(raw)

    # Order matters: URLs first so their contents are not eaten by the numeric
    # and e-mail rules below.
    work = URL_RE.sub(lambda m: " " + _url_markers(m.group(0)) + " ", work)
    work = EMAIL_RE.sub(lambda m: " " + _email_markers(m.group(0)) + " ", work)

    had_spaced = bool(SPACED_RE.search(work))
    work = SPACED_RE.sub(lambda m: re.sub(r"[\s._*\-]", "", m.group(0)), work)

    work = MONEY_RE.sub(" <money> ", work)
    work = work.lower()

    def _leet(match: re.Match[str]) -> str:
        token = match.group(0)
        decoded = _deleet_token(token)
        return decoded + " <leet>" if decoded != token else token

    work = LEET_TOKEN_RE.sub(_leet, work)

    work = PHONE_RE.sub(
        lambda m: " <phone> " if len(re.sub(r"\D", "", m.group(0))) >= 9 else m.group(0), work
    )
    work = CODE_RE.sub(" <code> ", work)
    work = NUM_RE.sub(" <num> ", work)

    work = PUNCT_RUN_RE.sub(r" \1 <punct_run> ", work)
    work = re.sub(r"[^a-z0-9<>_!?$%&+@#.,:;/'\-\s]", " ", work)
    work = re.sub(r"([.,:;!?/])", r" \1 ", work)

    extras = []
    if had_spaced:
        extras.append("<spaced_letters>")
    if caps_ratio > 0.55:
        extras.append("<shouting>")
    if exclamations >= 3:
        extras.append("<many_bangs>")

    work = WS_RE.sub(" ", work).strip()
    if extras:
        work = f"{work} {' '.join(extras)}"
    return work


def text_statistics(text: str) -> dict[str, float]:
    """Lightweight descriptive stats returned alongside a prediction."""
    raw = str(text or "")
    words = [w for w in WS_RE.split(raw) if w]
    letters = [c for c in raw if c.isalpha()]
    return {
        "characters": float(len(raw)),
        "words": float(len(words)),
        "links": float(len(URL_RE.findall(raw))),
        "emails": float(len(EMAIL_RE.findall(raw))),
        "digits": float(sum(c.isdigit() for c in raw)),
        "caps_ratio": round(sum(1 for c in letters if c.isupper()) / len(letters), 3) if letters else 0.0,
        "exclamations": float(raw.count("!")),
    }
