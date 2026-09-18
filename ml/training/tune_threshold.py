"""
Select the decision threshold for the message model, and report *out-of-sample*
metrics for the chosen operating point.

Why a separate step
-------------------
The trained model separates the gold set perfectly by ranking (ROC-AUC 1.000)
but the default 0.5 cut sits too high for real-world phrasing, so genuine
phishing lands at p=0.12 and is waved through. Moving the threshold is the
correct fix, but tuning and reporting on the same 120 rows would be circular.

So the gold set is split repeatedly (stratified, 50/50). Each repeat picks the
threshold on one half — the largest recall subject to a false-positive rate at
or below ``--max-fpr`` — then scores the untouched half. The reported figures are
the means of those held-out halves, and the shipped threshold is the median of
the picks.

Usage
-----
    python training/tune_threshold.py
    python training/tune_threshold.py --repeats 400 --max-fpr 0.05
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.model_selection import StratifiedShuffleSplit  # noqa: E402

from app.config import ARTIFACT_DIR, MESSAGE_MODEL_PATH  # noqa: E402
from app.features.text import normalize_text  # noqa: E402

GOLD_DIR = Path(__file__).resolve().parent.parent.parent / "datasets"
CANDIDATES = np.round(np.arange(0.02, 0.96, 0.01), 2)


def _rates(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> tuple[float, float, float]:
    pred = (y_prob >= threshold).astype(int)
    tp = int(((pred == 1) & (y_true == 1)).sum())
    fp = int(((pred == 1) & (y_true == 0)).sum())
    tn = int(((pred == 0) & (y_true == 0)).sum())
    fn = int(((pred == 0) & (y_true == 1)).sum())
    accuracy = (tp + tn) / max(1, len(y_true))
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    return accuracy, recall, fpr


def _pick_threshold(y_true: np.ndarray, y_prob: np.ndarray, max_fpr: float) -> float:
    """
    Highest recall whose false-positive rate stays within budget.

    When the classes separate cleanly, a wide band of thresholds ties on both
    recall and FPR. Taking the first of those puts the cut hard against the edge
    of the band, where a single unusual sample flips the verdict. The midpoint of
    the tied band is picked instead, which is the most robust point available.
    """
    plateau: list[float] = []
    best_recall = -1.0
    for threshold in CANDIDATES:
        _, recall, fpr = _rates(y_true, y_prob, float(threshold))
        if fpr > max_fpr:
            continue
        if recall > best_recall:
            best_recall = recall
            plateau = [float(threshold)]
        elif recall == best_recall:
            plateau.append(float(threshold))
    if not plateau:
        return 0.5
    return float(statistics.median(plateau))


def main() -> None:
    parser = argparse.ArgumentParser(description="Tune the message-model decision threshold")
    parser.add_argument("--repeats", type=int, default=300)
    parser.add_argument("--max-fpr", type=float, default=0.10, help="false-positive budget (product target: <0.10)")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if not MESSAGE_MODEL_PATH.exists():
        raise SystemExit(f"missing model: {MESSAGE_MODEL_PATH}")
    gold_path = GOLD_DIR / "gold-eval.csv"
    if not gold_path.exists():
        raise SystemExit(f"missing gold set: {gold_path}")

    bundle = joblib.load(MESSAGE_MODEL_PATH)
    gold = pd.read_csv(gold_path)
    y = gold["label"].to_numpy()
    probs = bundle["pipeline"].predict_proba(gold["text"].astype(str).map(normalize_text).to_numpy())[:, 1]

    splitter = StratifiedShuffleSplit(n_splits=args.repeats, test_size=0.5, random_state=args.seed)
    picks: list[float] = []
    accuracies: list[float] = []
    recalls: list[float] = []
    fprs: list[float] = []

    for tune_idx, test_idx in splitter.split(probs.reshape(-1, 1), y):
        threshold = _pick_threshold(y[tune_idx], probs[tune_idx], args.max_fpr)
        accuracy, recall, fpr = _rates(y[test_idx], probs[test_idx], threshold)
        picks.append(threshold)
        accuracies.append(accuracy)
        recalls.append(recall)
        fprs.append(fpr)

    chosen = round(float(statistics.median(picks)), 2)
    full_accuracy, full_recall, full_fpr = _rates(y, probs, chosen)
    default_accuracy, default_recall, default_fpr = _rates(y, probs, 0.5)

    result = {
        "repeats": args.repeats,
        "max_fpr_budget": args.max_fpr,
        "chosen_threshold": chosen,
        "threshold_spread": {
            "min": round(min(picks), 2),
            "median": chosen,
            "max": round(max(picks), 2),
            "stdev": round(statistics.pstdev(picks), 3),
        },
        "held_out_mean": {
            "accuracy": round(statistics.mean(accuracies), 4),
            "recall": round(statistics.mean(recalls), 4),
            "false_positive_rate": round(statistics.mean(fprs), 4),
        },
        "held_out_worst": {
            "accuracy": round(min(accuracies), 4),
            "recall": round(min(recalls), 4),
            "false_positive_rate": round(max(fprs), 4),
        },
        "full_gold_at_chosen_threshold": {
            "accuracy": round(full_accuracy, 4),
            "recall": round(full_recall, 4),
            "false_positive_rate": round(full_fpr, 4),
        },
        "full_gold_at_default_0.5": {
            "accuracy": round(default_accuracy, 4),
            "recall": round(default_recall, 4),
            "false_positive_rate": round(default_fpr, 4),
        },
    }

    out = ARTIFACT_DIR / "thresholds.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"repeated 50/50 stratified splits of the gold set: {args.repeats}")
    print(f"false-positive budget                          : {args.max_fpr}")
    print(f"\nthreshold picked per split : min={result['threshold_spread']['min']} "
          f"median={chosen} max={result['threshold_spread']['max']} sd={result['threshold_spread']['stdev']}")
    print("\nHELD-OUT halves (the honest numbers)")
    print(f"  accuracy            : {result['held_out_mean']['accuracy']:.4f}  (worst split {result['held_out_worst']['accuracy']:.4f})")
    print(f"  recall              : {result['held_out_mean']['recall']:.4f}  (worst split {result['held_out_worst']['recall']:.4f})")
    print(f"  false positive rate : {result['held_out_mean']['false_positive_rate']:.4f}  (worst split {result['held_out_worst']['false_positive_rate']:.4f})")
    print(f"\nwhole gold set at threshold {chosen}")
    print(f"  accuracy={full_accuracy:.4f} recall={full_recall:.4f} fpr={full_fpr:.4f}")
    print(f"whole gold set at default 0.5")
    print(f"  accuracy={default_accuracy:.4f} recall={default_recall:.4f} fpr={default_fpr:.4f}")
    print(f"\nwrote {out}")
    print(f"set ML_DECISION_THRESHOLD={chosen} (or leave it: the service reads thresholds.json)")


if __name__ == "__main__":
    main()
