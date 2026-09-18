"""
Model loading, prediction and explanation.

Explanations are exact, not approximated. Both served models are linear, so a
prediction decomposes cleanly:

    logit = intercept + sum_i (coefficient_i * value_i)

Each ``coefficient_i * value_i`` term is one token (message model) or one
engineered feature (URL model), which is what ``top_indicators`` returns. No
SHAP/LIME sampling, no surrogate model, nothing that could disagree with the
number actually used for the decision.
"""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from . import __version__
from .config import (
    ARTIFACT_DIR,
    DECISION_THRESHOLD,
    MESSAGE_MODEL_PATH,
    TOP_FEATURES,
    URL_MODEL_PATH,
)
from .features.text import normalize_text, text_statistics
from .features.url import FEATURE_DESCRIPTIONS, URL_FEATURE_NAMES, extract_url_features

_LOCK = threading.Lock()
_STATE: dict[str, Any] = {"message": None, "url": None, "thresholds": None, "loaded_at": None}

# Marker tokens produced by ``normalize_text`` get a human phrasing so the
# explanation never shows raw internals like "<url_shortener>".
MARKER_PHRASES = {
    "<url>": "contains a link",
    "<url_insecure>": "link does not use HTTPS",
    "<url_shortener>": "shortened link that hides its destination",
    "<url_ip_host>": "link points at a raw IP address",
    "<url_risky_tld>": "link uses a domain ending known for abuse",
    "<url_free_hosting>": "link is hosted on a free publishing platform",
    "<url_deep_subdomain>": "link uses a long chain of subdomains",
    "<url_punycode>": "link uses look-alike (punycode) characters",
    "<url_userinfo>": "link hides its real destination before an @",
    "<url_official_domain>": "link uses a verified official domain",
    "<url_brand_lookalike>": "link imitates a known brand",
    "<url_credential_path>": "link path is about logging in or verifying",
    "<url_long>": "unusually long web address",
    "<email>": "contains an e-mail address",
    "<email_freemail>": "sender uses a free webmail address",
    "<email_disposable>": "sender uses a disposable mailbox",
    "<email_official>": "sender uses an official brand address",
    "<email_risky_tld>": "sender domain uses a high-abuse ending",
    "<money>": "mentions a money amount",
    "<phone>": "contains a phone number",
    "<code>": "contains a numeric code",
    "<num>": "contains a number",
    "<leet>": "letters replaced with digits to dodge filters",
    "<spaced_letters>": "words broken up with spaces or dots",
    "<shouting>": "large amount of text in capitals",
    "<many_bangs>": "excessive exclamation marks",
    "<punct_run>": "repeated punctuation",
}


def _phrase(token: str) -> str:
    """Readable description for a TF-IDF feature name."""
    name = token.split("__", 1)[-1]
    if name in MARKER_PHRASES:
        return MARKER_PHRASES[name]
    parts = [MARKER_PHRASES.get(p, p) for p in name.split()]
    return " ".join(parts)


def load_models(force: bool = False) -> dict[str, Any]:
    """Load artifacts once, lazily, and cache them."""
    with _LOCK:
        if not force and _STATE["loaded_at"] is not None:
            return _STATE

        _STATE["message"] = joblib.load(MESSAGE_MODEL_PATH) if MESSAGE_MODEL_PATH.exists() else None
        _STATE["url"] = joblib.load(URL_MODEL_PATH) if URL_MODEL_PATH.exists() else None

        thresholds_path: Path = ARTIFACT_DIR / "thresholds.json"
        threshold = DECISION_THRESHOLD
        source = "config"
        if thresholds_path.exists():
            try:
                data = json.loads(thresholds_path.read_text(encoding="utf-8"))
                threshold = float(data.get("chosen_threshold", threshold))
                source = "thresholds.json (tuned on the gold set)"
            except (ValueError, OSError):
                pass
        _STATE["thresholds"] = {"message": threshold, "url": 0.5, "source": source}
        _STATE["loaded_at"] = time.time()
        return _STATE


def models_ready() -> dict[str, bool]:
    state = load_models()
    return {"message_model": state["message"] is not None, "url_model": state["url"] is not None}


# --------------------------------------------------------------------------- #
# Message prediction
# --------------------------------------------------------------------------- #
def predict_message(text: str, top_k: int = TOP_FEATURES) -> dict[str, Any]:
    state = load_models()
    bundle = state["message"]
    if bundle is None:
        raise RuntimeError("message model not trained; run training/train_message_model.py")

    started = time.perf_counter()
    normalized = normalize_text(text)
    pipeline = bundle["pipeline"]
    probability = float(pipeline.predict_proba([normalized])[0, 1])

    vector = pipeline.named_steps["features"].transform([normalized])
    coefficients = bundle["coefficients"]
    feature_names = bundle["feature_names"]

    # Exact per-term contribution to the logit.
    row = vector.tocoo()
    contributions = [(int(col), float(value * coefficients[col])) for col, value in zip(row.col, row.data)]

    # Word features carry readable names; char n-grams are accurate but noisy to
    # display, so they inform the score and are summarised rather than listed.
    word_terms = [
        (feature_names[idx], weight)
        for idx, weight in contributions
        if str(feature_names[idx]).startswith("word__")
    ]
    word_terms.sort(key=lambda item: abs(item[1]), reverse=True)

    seen: set[str] = set()
    indicators: list[dict[str, Any]] = []
    for name, weight in word_terms:
        phrase = _phrase(str(name))
        if phrase in seen:
            continue
        seen.add(phrase)
        indicators.append({
            "token": str(name).split("__", 1)[-1],
            "description": phrase,
            "contribution": round(weight, 4),
            "direction": "phishing" if weight > 0 else "legitimate",
        })
        if len(indicators) >= top_k:
            break

    char_total = sum(w for idx, w in contributions if str(feature_names[idx]).startswith("char__"))
    threshold = state["thresholds"]["message"]

    return {
        "model": "message",
        "probability": round(probability, 4),
        "label": "phishing" if probability >= threshold else "legitimate",
        "threshold": threshold,
        "risk_contribution": round(probability * 100, 1),
        "top_indicators": indicators,
        "character_ngram_contribution": round(float(char_total), 4),
        "normalized_text": normalized[:1000],
        "statistics": text_statistics(text),
        "latency_ms": round((time.perf_counter() - started) * 1000, 2),
        "model_version": bundle["metadata"].get("version", "unknown"),
    }


# --------------------------------------------------------------------------- #
# URL prediction
# --------------------------------------------------------------------------- #
def predict_url(url: str, top_k: int = TOP_FEATURES) -> dict[str, Any]:
    state = load_models()
    bundle = state["url"]
    if bundle is None:
        raise RuntimeError("url model not trained; run training/train_url_model.py")

    started = time.perf_counter()
    features = extract_url_features(url)
    vector = np.array([[features[name] for name in URL_FEATURE_NAMES]], dtype=np.float64)
    probability = float(bundle["pipeline"].predict_proba(vector)[0, 1])

    means = bundle["feature_means"]
    scales = bundle["feature_scales"]
    coefficients = bundle["coefficients"]
    standardized = (vector[0] - means) / np.where(scales == 0, 1, scales)
    contributions = standardized * coefficients

    order = np.argsort(np.abs(contributions))[::-1][:top_k]
    indicators = [
        {
            "feature": URL_FEATURE_NAMES[int(i)],
            "description": FEATURE_DESCRIPTIONS.get(URL_FEATURE_NAMES[int(i)], URL_FEATURE_NAMES[int(i)]),
            "value": round(float(vector[0][int(i)]), 4),
            "contribution": round(float(contributions[int(i)]), 4),
            "direction": "phishing" if contributions[int(i)] > 0 else "legitimate",
        }
        for i in order
        if abs(float(contributions[int(i)])) > 1e-6
    ]

    return {
        "model": "url",
        "url": url,
        "probability": round(probability, 4),
        "label": "phishing" if probability >= state["thresholds"]["url"] else "legitimate",
        "threshold": state["thresholds"]["url"],
        "risk_contribution": round(probability * 100, 1),
        "top_indicators": indicators,
        "features": {k: round(v, 4) for k, v in features.items()},
        "latency_ms": round((time.perf_counter() - started) * 1000, 2),
        "model_version": bundle["metadata"].get("version", "unknown"),
    }


def model_info() -> dict[str, Any]:
    state = load_models()
    gold_path = ARTIFACT_DIR / "gold_metrics.json"
    gold = {}
    if gold_path.exists():
        try:
            gold = json.loads(gold_path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            gold = {}

    return {
        "service_version": __version__,
        "thresholds": state["thresholds"],
        "message_model": state["message"]["metadata"] if state["message"] else None,
        "url_model": state["url"]["metadata"] if state["url"] else None,
        "gold_set_metrics": {
            "message": gold.get("message_gold"),
            "url": gold.get("url_gold"),
            "note": "gold-eval.csv / gold-urls.csv are hand written and out-of-distribution; "
                    "in-distribution splits of the generated corpus score ~1.000 and are not informative",
        },
    }
