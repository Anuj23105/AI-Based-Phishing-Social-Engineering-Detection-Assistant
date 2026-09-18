"""
Engineered lexical features for the URL classifier.

No network calls: everything is derived from the string itself, which keeps
inference in the sub-millisecond range and means the model works on links that
are already dead or firewalled. Each feature is documented with a
human-readable phrase so a per-feature contribution can be turned into a
sentence in the API response.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import parse_qsl, urlsplit

import numpy as np

from ..knowledge import (
    ARCHIVE_WEB_EXTENSIONS,
    BRAND_LABELS,
    CREDENTIAL_URL_WORDS,
    EXECUTABLE_EXTENSIONS,
    FREE_HOSTING_SUFFIXES,
    IDENTITY_PARAMS,
    OFFICIAL_DOMAINS,
    REDIRECT_PARAMS,
    SUSPICIOUS_TLDS,
    COMMON_TLDS,
    URL_SHORTENERS,
    domain_label,
    public_suffix,
    registrable_domain,
)

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")
VOWELS = set("aeiou")


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _levenshtein(a: str, b: str, cap: int = 4) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        if min(current) > cap:
            return cap + 1
        previous = current
    return previous[-1]


def _max_consonant_run(value: str) -> int:
    best = run = 0
    for ch in value:
        if ch.isalpha() and ch not in VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def _nearest_brand_distance(label: str) -> tuple[int, str]:
    """Smallest edit distance from the domain label to any known brand label."""
    best = 99
    best_brand = ""
    flat = re.sub(r"[^a-z0-9]", "", label.lower())
    if not flat:
        return best, best_brand
    for brand_label in BRAND_LABELS:
        if len(brand_label) < 4:
            continue
        distance = _levenshtein(flat, brand_label, cap=3)
        if distance < best:
            best, best_brand = distance, brand_label
            if best == 0:
                break
    return best, best_brand


#: Ordered feature names. The order is part of the model contract.
URL_FEATURE_NAMES: list[str] = [
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "label_length",
    "num_dots_host",
    "num_hyphens_host",
    "num_subdomains",
    "num_path_segments",
    "num_params",
    "num_digits_host",
    "digit_ratio_host",
    "num_digits_url",
    "count_at",
    "count_percent",
    "count_equals",
    "count_ampersand",
    "count_underscore",
    "num_special_chars",
    "is_https",
    "has_port",
    "is_ip_host",
    "has_punycode",
    "non_ascii_count",
    "host_entropy",
    "path_entropy",
    "tld_suspicious",
    "tld_common",
    "tld_length",
    "is_shortener",
    "is_free_hosting",
    "is_official_domain",
    "brand_in_label",
    "brand_in_subdomain",
    "brand_in_path",
    "nearest_brand_distance",
    "typosquat_flag",
    "credential_word_count",
    "credential_word_in_host",
    "has_redirect_param",
    "has_identity_param",
    "has_executable_ext",
    "has_archive_or_html_ext",
    "has_base64_blob",
    "num_encoded_chars",
    "longest_token_length",
    "vowel_ratio_label",
    "max_consonant_run",
    "has_www",
    "double_slash_in_path",
    "hyphen_ratio_label",
]

#: Plain-language phrasing used when a feature drives a prediction.
FEATURE_DESCRIPTIONS: dict[str, str] = {
    "url_length": "overall length of the web address",
    "host_length": "length of the domain part",
    "path_length": "length of the path after the domain",
    "query_length": "length of the query string",
    "label_length": "length of the registered domain name",
    "num_dots_host": "number of dots in the domain",
    "num_hyphens_host": "number of hyphens in the domain",
    "num_subdomains": "depth of the subdomain chain",
    "num_path_segments": "number of path segments",
    "num_params": "number of query parameters",
    "num_digits_host": "digits inside the domain name",
    "digit_ratio_host": "proportion of digits in the domain",
    "num_digits_url": "digits across the whole address",
    "count_at": "presence of @ characters that hide the real destination",
    "count_percent": "percent-encoded characters",
    "count_equals": "number of key=value pairs",
    "count_ampersand": "number of chained parameters",
    "count_underscore": "underscores in the address",
    "num_special_chars": "density of special characters",
    "is_https": "use of an encrypted HTTPS connection",
    "has_port": "an explicit non-standard port",
    "is_ip_host": "a raw IP address instead of a domain name",
    "has_punycode": "punycode encoding used for look-alike characters",
    "non_ascii_count": "non-Latin characters inside the domain",
    "host_entropy": "randomness of the domain name",
    "path_entropy": "randomness of the path",
    "tld_suspicious": "a domain ending known for abuse",
    "tld_common": "a mainstream domain ending",
    "tld_length": "length of the domain ending",
    "is_shortener": "a URL shortener hiding the destination",
    "is_free_hosting": "hosting on a free, anyone-can-publish platform",
    "is_official_domain": "a verified official brand domain",
    "brand_in_label": "a brand name inside an unrelated domain",
    "brand_in_subdomain": "a brand name pushed into the subdomain",
    "brand_in_path": "a brand name in the path rather than the domain",
    "nearest_brand_distance": "closeness to a real brand domain (typosquatting)",
    "typosquat_flag": "a domain one or two characters away from a real brand",
    "credential_word_count": "login/verify/account wording in the address",
    "credential_word_in_host": "login/verify wording inside the domain itself",
    "has_redirect_param": "a redirect parameter forwarding you elsewhere",
    "has_identity_param": "personal data pre-filled in the address",
    "has_executable_ext": "a link to an executable or macro-enabled file",
    "has_archive_or_html_ext": "a link to an archive or standalone web page",
    "has_base64_blob": "a long encoded blob in the address",
    "num_encoded_chars": "percent-encoding used to obscure content",
    "longest_token_length": "an unusually long single token",
    "vowel_ratio_label": "vowel balance of the domain name",
    "max_consonant_run": "long consonant runs typical of generated names",
    "has_www": "a conventional www prefix",
    "double_slash_in_path": "a doubled slash used to confuse parsers",
    "hyphen_ratio_label": "share of hyphens in the domain name",
}


def extract_url_features(url: str) -> dict[str, float]:
    """Compute the feature dictionary for one URL."""
    raw = str(url or "").strip()
    candidate = raw if re.match(r"^[a-z][a-z0-9+.\-]*://", raw, re.IGNORECASE) else "http://" + raw

    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower()
        path = parts.path or ""
        query = parts.query or ""
        netloc = parts.netloc or ""
        scheme = (parts.scheme or "").lower()
        port = parts.port
    except ValueError:
        host, path, query, netloc, scheme, port = "", "", "", "", "http", None

    rd = registrable_domain(host)
    label = domain_label(host)
    suffix = public_suffix(host)
    subdomain = host[: -(len(rd) + 1)] if rd and host.endswith(rd) and host != rd else ""
    lowered = candidate.lower()
    path_query = (path + "?" + query).lower()

    digits_host = sum(ch.isdigit() for ch in host)
    params = parse_qsl(query, keep_blank_values=True)
    param_keys = [k.lower() for k, _ in params]
    tokens = re.split(r"[^A-Za-z0-9]+", lowered)

    flat_label = re.sub(r"[^a-z0-9]", "", label)
    brand_distance, _ = _nearest_brand_distance(label)
    is_official = rd in OFFICIAL_DOMAINS
    brand_in_label = 0.0 if is_official else float(any(b in flat_label for b in BRAND_LABELS if len(b) >= 4))
    brand_in_subdomain = 0.0 if is_official else float(
        any(b in re.sub(r"[^a-z0-9]", "", subdomain) for b in BRAND_LABELS if len(b) >= 4)
    )
    brand_in_path = 0.0 if is_official else float(
        any(b in path_query for b in BRAND_LABELS if len(b) >= 4)
    )

    ext_match = re.search(r"\.([A-Za-z0-9]{2,5})(?:$|[?#])", path)
    extension = ext_match.group(1).lower() if ext_match else ""

    features = {
        "url_length": float(len(candidate)),
        "host_length": float(len(host)),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "label_length": float(len(label)),
        "num_dots_host": float(host.count(".")),
        "num_hyphens_host": float(host.count("-")),
        "num_subdomains": float(max(0, len(subdomain.split(".")) if subdomain else 0)),
        "num_path_segments": float(len([s for s in path.split("/") if s])),
        "num_params": float(len(params)),
        "num_digits_host": float(digits_host),
        "digit_ratio_host": round(digits_host / len(host), 4) if host else 0.0,
        "num_digits_url": float(sum(ch.isdigit() for ch in candidate)),
        "count_at": float(netloc.count("@") + path.count("@")),
        "count_percent": float(candidate.count("%")),
        "count_equals": float(candidate.count("=")),
        "count_ampersand": float(candidate.count("&")),
        "count_underscore": float(candidate.count("_")),
        "num_special_chars": float(sum(candidate.count(c) for c in "@%=&~+,;$!*'()")),
        "is_https": float(scheme == "https"),
        "has_port": float(bool(port) and port not in (80, 443)),
        "is_ip_host": float(bool(IP_RE.match(host))),
        "has_punycode": float("xn--" in host),
        "non_ascii_count": float(sum(1 for ch in host if ord(ch) > 127)),
        "host_entropy": round(_entropy(host), 4),
        "path_entropy": round(_entropy(path), 4),
        "tld_suspicious": float(suffix in SUSPICIOUS_TLDS),
        "tld_common": float(suffix in COMMON_TLDS),
        "tld_length": float(len(suffix)),
        "is_shortener": float(rd in URL_SHORTENERS or host in URL_SHORTENERS),
        "is_free_hosting": float(any(host == s or host.endswith("." + s) for s in FREE_HOSTING_SUFFIXES)),
        "is_official_domain": float(is_official),
        "brand_in_label": brand_in_label,
        "brand_in_subdomain": brand_in_subdomain,
        "brand_in_path": brand_in_path,
        "nearest_brand_distance": float(min(brand_distance, 4)),
        "typosquat_flag": float(not is_official and 1 <= brand_distance <= 2),
        "credential_word_count": float(sum(1 for w in CREDENTIAL_URL_WORDS if w in path_query or w in host)),
        "credential_word_in_host": float(any(w in host for w in CREDENTIAL_URL_WORDS)),
        "has_redirect_param": float(
            any(k in REDIRECT_PARAMS for k in param_keys)
            and bool(re.search(r"https?(?::|%3a)", query, re.IGNORECASE))
        ),
        "has_identity_param": float(any(k in IDENTITY_PARAMS for k in param_keys)),
        "has_executable_ext": float(extension in EXECUTABLE_EXTENSIONS),
        "has_archive_or_html_ext": float(extension in ARCHIVE_WEB_EXTENSIONS),
        "has_base64_blob": float(bool(BASE64_RE.search(query or path))),
        "num_encoded_chars": float(len(ENCODED_RE.findall(candidate))),
        "longest_token_length": float(max((len(t) for t in tokens), default=0)),
        "vowel_ratio_label": round(sum(1 for c in flat_label if c in VOWELS) / len(flat_label), 4) if flat_label else 0.0,
        "max_consonant_run": float(_max_consonant_run(flat_label)),
        "has_www": float(host.startswith("www.") or (parts.hostname or "").lower().startswith("www.")),
        "double_slash_in_path": float("//" in path),
        "hyphen_ratio_label": round(label.count("-") / len(label), 4) if label else 0.0,
    }
    return features


def featurize_urls(urls: list[str]) -> np.ndarray:
    """Feature matrix in ``URL_FEATURE_NAMES`` order."""
    rows = [extract_url_features(u) for u in urls]
    return np.array([[row[name] for name in URL_FEATURE_NAMES] for row in rows], dtype=np.float64)
