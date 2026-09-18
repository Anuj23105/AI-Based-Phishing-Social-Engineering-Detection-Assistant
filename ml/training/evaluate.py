"""
Honest evaluation of the trained models.

Two very different numbers are reported and the difference between them is the
point of this script:

1. **In-distribution** — a held-out split of the generated corpus. This is
   almost always near 1.000 and is close to meaningless on its own: the train and
   test rows come from the same template banks, so the task is trivially
   separable. It is reported only to confirm the pipeline fits at all.

2. **Out-of-distribution (gold set)** — ``datasets/gold-eval.csv`` and
   ``datasets/gold-urls.csv``, both written by hand, independently of the
   templates, and containing hard negatives on purpose (genuine OTP alerts,
   genuine blocked-sign-in notices, genuine failed-payment mail). This is the
   number that indicates whether the model generalises, and it is the number the
   README quotes.

The same gold files are used by the Node rule-engine evaluation, so the two
tiers are measured on identical data and can be compared directly.

Usage
-----
    python training/evaluate.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joblib  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from app.config import ARTIFACT_DIR, MESSAGE_MODEL_PATH, URL_MODEL_PATH  # noqa: E402
from app.features.text import normalize_text  # noqa: E402
from app.features.url import featurize_urls  # noqa: E402

GOLD_DIR = Path(__file__).resolve().parent.parent.parent / "datasets"


def _metrics(y_true, y_prob, threshold: float = 0.5) -> dict:
    y_pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "samples": int(len(y_true)),
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, y_prob)), 4) if len(set(y_true)) > 1 else None,
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "false_negative_rate": round(float(fn / (fn + tp)) if (fn + tp) else 0.0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "threshold": threshold,
    }


def _print_block(title: str, metrics: dict) -> None:
    print(f"\n{title}")
    print("-" * len(title))
    print(f"  samples             : {metrics['samples']}")
    print(f"  accuracy            : {metrics['accuracy']:.4f}")
    print(f"  precision           : {metrics['precision']:.4f}")
    print(f"  recall              : {metrics['recall']:.4f}")
    print(f"  f1                  : {metrics['f1']:.4f}")
    if metrics["roc_auc"] is not None:
        print(f"  roc auc             : {metrics['roc_auc']:.4f}")
    print(f"  false positive rate : {metrics['false_positive_rate']:.4f}")
    print(f"  false negative rate : {metrics['false_negative_rate']:.4f}")
    print(f"  confusion matrix    : {metrics['confusion_matrix']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate PhishGuard models on the gold sets")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--show-errors", type=int, default=10, help="how many misclassified samples to print")
    args = parser.parse_args()

    report: dict = {"threshold": args.threshold}

    # ------------------------------------------------------------------ #
    # Message model
    # ------------------------------------------------------------------ #
    if not MESSAGE_MODEL_PATH.exists():
        raise SystemExit(f"missing model: {MESSAGE_MODEL_PATH}\nRun: python training/train_message_model.py")

    message_bundle = joblib.load(MESSAGE_MODEL_PATH)
    report["message_in_distribution"] = message_bundle["metadata"]["metrics"]
    _print_block("MESSAGE MODEL - in-distribution (held-out split of generated corpus)",
                 {**message_bundle["metadata"]["metrics"], "samples": message_bundle["metadata"]["test_rows"],
                  "threshold": 0.5})
    print("  note                : same templates as training, so ~1.000 is expected and not informative")

    gold_path = GOLD_DIR / "gold-eval.csv"
    if gold_path.exists():
        gold = pd.read_csv(gold_path)
        probs = message_bundle["pipeline"].predict_proba(
            gold["text"].astype(str).map(normalize_text).to_numpy()
        )[:, 1]
        gold_metrics = _metrics(gold["label"].to_numpy(), probs, args.threshold)
        report["message_gold"] = gold_metrics
        _print_block("MESSAGE MODEL - gold set (hand written, out-of-distribution)", gold_metrics)

        gold = gold.assign(prob=probs.round(3), pred=(probs >= args.threshold).astype(int))
        errors = gold[gold["pred"] != gold["label"]]
        report["message_gold_errors"] = [
            {"id": r.id, "label": int(r.label), "prob": float(r.prob), "tactic": r.tactic,
             "text": r.text[:150]}
            for r in errors.itertuples()
        ]
        if len(errors):
            print(f"\n  misclassified ({len(errors)}):")
            for row in errors.head(args.show_errors).itertuples():
                kind = "FALSE POSITIVE" if row.label == 0 else "MISSED PHISH  "
                print(f"    {kind} {row.id}  p={row.prob:.3f}  {row.text[:96]}")

        by_hardness = gold[gold["tactic"] == "hard-negative"]
        if len(by_hardness):
            flagged = int((by_hardness["pred"] == 1).sum())
            print(f"\n  hard negatives (genuine but alarming): {len(by_hardness) - flagged}/{len(by_hardness)} correctly cleared")
            report["message_hard_negatives"] = {"total": int(len(by_hardness)), "flagged": flagged}
    else:
        print(f"\n  gold set not found at {gold_path}")

    # ------------------------------------------------------------------ #
    # URL model
    # ------------------------------------------------------------------ #
    if URL_MODEL_PATH.exists():
        url_bundle = joblib.load(URL_MODEL_PATH)
        report["url_in_distribution"] = url_bundle["metadata"]["metrics"]
        _print_block("URL MODEL - in-distribution (held-out split of generated corpus)",
                     {**url_bundle["metadata"]["metrics"], "samples": url_bundle["metadata"]["rows"] // 5,
                      "threshold": 0.5})

        gold_urls_path = GOLD_DIR / "gold-urls.csv"
        if gold_urls_path.exists():
            gold_urls = pd.read_csv(gold_urls_path)
            probs = url_bundle["pipeline"].predict_proba(featurize_urls(gold_urls["url"].astype(str).tolist()))[:, 1]
            url_metrics = _metrics(gold_urls["label"].to_numpy(), probs, args.threshold)
            report["url_gold"] = url_metrics
            _print_block("URL MODEL - gold set (hand written, out-of-distribution)", url_metrics)

            gold_urls = gold_urls.assign(prob=probs.round(3), pred=(probs >= args.threshold).astype(int))
            errors = gold_urls[gold_urls["pred"] != gold_urls["label"]]
            report["url_gold_errors"] = [
                {"id": r.id, "label": int(r.label), "prob": float(r.prob), "url": r.url}
                for r in errors.itertuples()
            ]
            if len(errors):
                print(f"\n  misclassified ({len(errors)}):")
                for row in errors.head(args.show_errors).itertuples():
                    kind = "FALSE POSITIVE" if row.label == 0 else "MISSED PHISH  "
                    print(f"    {kind} {row.id}  p={row.prob:.3f}  {row.url[:90]}")
    else:
        print(f"\nURL model not trained yet ({URL_MODEL_PATH})")

    out = ARTIFACT_DIR / "gold_metrics.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
