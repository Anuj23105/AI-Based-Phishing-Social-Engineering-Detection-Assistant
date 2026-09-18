"""
Train the URL classifier.

Model
-----
    50 engineered lexical features -> StandardScaler -> LogisticRegression

A logistic model on standardised features is chosen over a stronger tree
ensemble on purpose: the contribution of every feature to a single prediction is
exactly ``coefficient x standardised_value``, so the API can say *"the domain is
one character away from a real brand, which pushed this to 0.94"* instead of
handing back an unexplained probability. A RandomForest is trained alongside as
a benchmark and its score is recorded in the metrics file for comparison; it is
not the served model.

Usage
-----
    python training/train_url_model.py
    python training/train_url_model.py --data path/to/real_urls.csv --url-col url --label-col label
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split  # noqa: E402
from sklearn.pipeline import Pipeline  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

from app.config import DATA_DIR, RANDOM_SEED, URL_METRICS_PATH, URL_MODEL_PATH  # noqa: E402
from app.features.url import URL_FEATURE_NAMES, featurize_urls  # noqa: E402


def evaluate(y_true, y_pred, y_prob) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, y_prob)), 4),
        "average_precision": round(float(average_precision_score(y_true, y_prob)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "false_negative_rate": round(float(fn / (fn + tp)) if (fn + tp) else 0.0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the PhishGuard URL classifier")
    parser.add_argument("--data", type=Path, default=DATA_DIR / "urls.csv")
    parser.add_argument("--url-col", default="url")
    parser.add_argument("--label-col", default="label")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    parser.add_argument("--out", type=Path, default=URL_MODEL_PATH)
    args = parser.parse_args()

    if not args.data.exists():
        raise SystemExit(f"dataset not found: {args.data}\nRun: python training/generate_corpus.py")

    frame = pd.read_csv(args.data).dropna(subset=[args.url_col, args.label_col])
    y = frame[args.label_col].astype(int).to_numpy()
    print(f"loaded {len(frame)} urls from {args.data}")
    print(f"class balance: {dict(pd.Series(y).value_counts())}")

    print("extracting features ...")
    started = time.perf_counter()
    X = featurize_urls(frame[args.url_col].astype(str).tolist())
    print(f"  {X.shape[1]} features for {X.shape[0]} urls in {time.perf_counter() - started:.1f}s")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )

    pipeline = Pipeline(
        [
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(C=1.0, max_iter=4000, class_weight="balanced", random_state=args.seed)),
        ]
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=args.seed)
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="f1")
    print(f"cross-validated f1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    pipeline.fit(X_train, y_train)
    y_prob = pipeline.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)
    metrics = evaluate(y_test, y_pred, y_prob)

    forest = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=args.seed, n_jobs=-1)
    forest.fit(X_train, y_train)
    forest_prob = forest.predict_proba(X_test)[:, 1]
    forest_metrics = evaluate(y_test, (forest_prob >= 0.5).astype(int), forest_prob)

    scaler = pipeline.named_steps["scaler"]
    coefficients = pipeline.named_steps["clf"].coef_[0]

    bundle = {
        "pipeline": pipeline,
        "feature_names": list(URL_FEATURE_NAMES),
        "coefficients": coefficients,
        "feature_means": scaler.mean_,
        "feature_scales": scaler.scale_,
        "metadata": {
            "model": "engineered lexical features + StandardScaler + LogisticRegression",
            "version": "1.0.0",
            "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "dataset": str(args.data),
            "rows": int(len(frame)),
            "features": len(URL_FEATURE_NAMES),
            "seed": args.seed,
            "metrics": metrics,
            "cross_validation": {"mean_f1": round(float(cv_scores.mean()), 4), "std_f1": round(float(cv_scores.std()), 4)},
            "benchmark_random_forest": forest_metrics,
        },
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, args.out, compress=3)
    URL_METRICS_PATH.write_text(json.dumps(bundle["metadata"], indent=2), encoding="utf-8")

    print("\n=== held-out test set ===")
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"], digits=4))
    print(f"accuracy            : {metrics['accuracy']:.4f}")
    print(f"roc auc             : {metrics['roc_auc']:.4f}")
    print(f"false positive rate : {metrics['false_positive_rate']:.4f}")
    print(f"confusion matrix    : {metrics['confusion_matrix']}")
    print(f"\nbenchmark RandomForest: acc={forest_metrics['accuracy']:.4f} f1={forest_metrics['f1']:.4f} auc={forest_metrics['roc_auc']:.4f}")
    print(f"saved model         : {args.out}")

    order = np.argsort(coefficients)
    print("\ntop features pushing towards PHISHING:")
    for idx in order[::-1][:12]:
        print(f"  +{coefficients[idx]:6.3f}  {URL_FEATURE_NAMES[idx]}")
    print("\ntop features pushing towards LEGITIMATE:")
    for idx in order[:8]:
        print(f"  {coefficients[idx]:7.3f}  {URL_FEATURE_NAMES[idx]}")


if __name__ == "__main__":
    main()
