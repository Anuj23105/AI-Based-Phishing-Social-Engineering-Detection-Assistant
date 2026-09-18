"""
Train the message classifier (phishing / social-engineering text detection).

Model
-----
    normalize_text  ->  TF-IDF (word 1-2 grams  +  char_wb 3-5 grams)
                    ->  LogisticRegression (balanced, liblinear)

Why this and not a transformer? Three reasons that matter for this product:

* **Explainability is a hard requirement.** A linear model over TF-IDF gives an
  exact per-token contribution (coefficient x tf-idf value), which is what the
  API returns as ``top_indicators``. Nothing has to be approximated.
* **Latency budget.** Inference is ~1 ms on CPU, leaving the 5 s end-to-end
  target almost entirely unused. A fine-tuned BERT needs a GPU or ~200 ms+ CPU.
* **The interface is model-agnostic.** ``app/inference.py`` only needs
  ``predict_proba``. Swapping in a fine-tuned DistilBERT later means replacing
  the artifact and the loader, not the API or the frontend.

Character n-grams matter more than they look: they are what survives
obfuscation like "veriffy", "p4ssword" and "acc-ount".

Usage
-----
    python training/train_message_model.py
    python training/train_message_model.py --data path/to/real.csv --text-col body --label-col is_phishing
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
from sklearn.calibration import CalibratedClassifierCV  # noqa: E402
from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: E402
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
from sklearn.pipeline import FeatureUnion, Pipeline  # noqa: E402
from sklearn.svm import LinearSVC  # noqa: E402

from app.config import DATA_DIR, MESSAGE_METRICS_PATH, MESSAGE_MODEL_PATH, RANDOM_SEED  # noqa: E402
from app.features.text import normalize_text  # noqa: E402

# Keeps ``<url_shortener>`` style markers as single tokens instead of letting the
# default pattern shred them.
WORD_TOKEN_PATTERN = r"(?u)<[a-z_]+>|[a-z0-9]{2,}|[!?]"


def build_pipeline(seed: int) -> Pipeline:
    return Pipeline(
        [
            (
                "features",
                FeatureUnion(
                    [
                        (
                            "word",
                            TfidfVectorizer(
                                analyzer="word",
                                token_pattern=WORD_TOKEN_PATTERN,
                                ngram_range=(1, 2),
                                min_df=2,
                                max_df=0.9,
                                sublinear_tf=True,
                                lowercase=False,
                            ),
                        ),
                        (
                            "char",
                            TfidfVectorizer(
                                analyzer="char_wb",
                                ngram_range=(3, 5),
                                min_df=3,
                                max_features=60000,
                                sublinear_tf=True,
                                lowercase=False,
                            ),
                        ),
                    ]
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    C=6.0,
                    max_iter=3000,
                    class_weight="balanced",
                    solver="liblinear",
                    random_state=seed,
                ),
            ),
        ]
    )


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
    parser = argparse.ArgumentParser(description="Train the PhishGuard message classifier")
    parser.add_argument("--data", type=Path, default=DATA_DIR / "messages.csv")
    parser.add_argument("--text-col", default="text")
    parser.add_argument("--label-col", default="label")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    parser.add_argument("--no-cv", action="store_true", help="skip cross-validation (faster)")
    parser.add_argument("--out", type=Path, default=MESSAGE_MODEL_PATH)
    args = parser.parse_args()

    if not args.data.exists():
        raise SystemExit(f"dataset not found: {args.data}\nRun: python training/generate_corpus.py")

    frame = pd.read_csv(args.data)
    if args.text_col not in frame or args.label_col not in frame:
        raise SystemExit(f"columns {args.text_col!r}/{args.label_col!r} not in {list(frame.columns)}")

    frame = frame.dropna(subset=[args.text_col, args.label_col])
    frame["_label"] = frame[args.label_col].astype(int)
    print(f"loaded {len(frame)} rows from {args.data}")
    print(f"class balance: {frame['_label'].value_counts().to_dict()}")

    print("normalising text ...")
    started = time.perf_counter()
    X = frame[args.text_col].astype(str).map(normalize_text).to_numpy()
    y = frame["_label"].to_numpy()
    print(f"  normalised in {time.perf_counter() - started:.1f}s")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )

    pipeline = build_pipeline(args.seed)

    if not args.no_cv:
        print("cross-validating (5-fold) ...")
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=args.seed)
        cv_scores = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="f1", n_jobs=1)
        print(f"  f1 per fold: {[round(float(s), 4) for s in cv_scores]}")
        print(f"  mean f1    : {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        cv_summary = {"folds": [round(float(s), 4) for s in cv_scores],
                      "mean_f1": round(float(cv_scores.mean()), 4),
                      "std_f1": round(float(cv_scores.std()), 4)}
    else:
        cv_summary = None

    print("fitting final model ...")
    started = time.perf_counter()
    pipeline.fit(X_train, y_train)
    fit_seconds = round(time.perf_counter() - started, 2)

    y_prob = pipeline.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)
    metrics = evaluate(y_test, y_pred, y_prob)

    # Benchmark reference only: a linear SVM usually edges out logistic
    # regression on TF-IDF, but it does not give calibrated probabilities, and
    # probabilities are what the fusion layer in the Node service consumes.
    svm = Pipeline([("features", build_pipeline(args.seed).named_steps["features"]),
                    ("clf", CalibratedClassifierCV(LinearSVC(C=1.0, class_weight="balanced",
                                                             random_state=args.seed), cv=3))])
    svm.fit(X_train, y_train)
    svm_prob = svm.predict_proba(X_test)[:, 1]
    svm_metrics = evaluate(y_test, (svm_prob >= 0.5).astype(int), svm_prob)

    vectorizer = pipeline.named_steps["features"]
    feature_names = vectorizer.get_feature_names_out()
    coefficients = pipeline.named_steps["clf"].coef_[0]

    bundle = {
        "pipeline": pipeline,
        "feature_names": np.asarray(feature_names),
        "coefficients": coefficients,
        "metadata": {
            "model": "tfidf(word 1-2 + char_wb 3-5) + LogisticRegression",
            "version": "1.0.0",
            "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "dataset": str(args.data),
            "rows": int(len(frame)),
            "train_rows": int(len(X_train)),
            "test_rows": int(len(X_test)),
            "features": int(len(feature_names)),
            "fit_seconds": fit_seconds,
            "seed": args.seed,
            "metrics": metrics,
            "cross_validation": cv_summary,
            "benchmark_linear_svc": svm_metrics,
        },
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, args.out, compress=3)
    MESSAGE_METRICS_PATH.write_text(json.dumps(bundle["metadata"], indent=2), encoding="utf-8")

    print("\n=== held-out test set ===")
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"], digits=4))
    print(f"accuracy            : {metrics['accuracy']:.4f}")
    print(f"roc auc             : {metrics['roc_auc']:.4f}")
    print(f"false positive rate : {metrics['false_positive_rate']:.4f}")
    print(f"false negative rate : {metrics['false_negative_rate']:.4f}")
    print(f"confusion matrix    : {metrics['confusion_matrix']}")
    print(f"\nbenchmark LinearSVC : acc={svm_metrics['accuracy']:.4f} f1={svm_metrics['f1']:.4f} auc={svm_metrics['roc_auc']:.4f}")
    print(f"vocabulary          : {len(feature_names)} features")
    print(f"saved model         : {args.out}")
    print(f"saved metrics       : {MESSAGE_METRICS_PATH}")

    order = np.argsort(coefficients)
    print("\nstrongest phishing indicators learned:")
    for idx in order[::-1][:15]:
        name = feature_names[idx]
        if name.startswith("word__"):
            print(f"  +{coefficients[idx]:.3f}  {name[6:]}")
    print("\nstrongest legitimate indicators learned:")
    for idx in order[:15]:
        name = feature_names[idx]
        if name.startswith("word__"):
            print(f"  {coefficients[idx]:.3f}  {name[6:]}")


if __name__ == "__main__":
    main()
