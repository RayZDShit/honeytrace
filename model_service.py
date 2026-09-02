"""Train, evaluate, save, and apply the behavioral classifier."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np

from config import MODEL_MAX_CLASS_SAMPLES, MODEL_MIN_CLASS_SAMPLES, MODEL_PATH, ensure_directories
from db import connect, init_db
from feature_engineering import FEATURE_COLUMNS, feature_vector
from labeling import THREAT_LEVELS


RANDOM_STATE = 42


def _load_dataset():
    conn = connect(readonly=True)
    rows = conn.execute(
        """SELECT s.id,s.source_name,s.src_ip,s.rule_label,f.feature_json
           FROM sessions s JOIN session_features f ON f.session_id=s.id
           WHERE s.rule_label != 'unknown' ORDER BY s.id"""
    ).fetchall()
    conn.close()
    records = []
    for row in rows:
        features = json.loads(row["feature_json"])
        records.append({
            "id": int(row["id"]),
            "label": row["rule_label"],
            "group": f"{row['source_name']}|{row['src_ip']}",
            "vector": feature_vector(features),
        })
    return records


def _balanced_sample(records: list[dict]) -> list[dict]:
    counts = Counter(record["label"] for record in records)
    group_counts = {
        label: len({record["group"] for record in records if record["label"] == label})
        for label in counts
    }
    supported = {
        label for label, count in counts.items()
        if count >= MODEL_MIN_CLASS_SAMPLES and group_counts[label] >= 3
    }
    if len(supported) < 2:
        detail = ", ".join(f"{label}={count}" for label, count in counts.most_common())
        raise RuntimeError(
            f"At least two labels need {MODEL_MIN_CLASS_SAMPLES} sessions from 3 attacker groups. "
            f"Current support: {detail or 'none'}"
        )
    rng = np.random.default_rng(RANDOM_STATE)
    selected: list[dict] = []
    for label in sorted(supported):
        class_rows = [record for record in records if record["label"] == label]
        if len(class_rows) > MODEL_MAX_CLASS_SAMPLES:
            indexes = rng.choice(len(class_rows), size=MODEL_MAX_CLASS_SAMPLES, replace=False)
            class_rows = [class_rows[int(index)] for index in indexes]
        selected.extend(class_rows)
    rng.shuffle(selected)
    return selected


def _make_holdout(X, y, groups):
    from sklearn.model_selection import StratifiedGroupKFold

    class_group_counts = []
    for label in np.unique(y):
        class_group_counts.append(len(set(groups[y == label])))
    splits = min(5, min(class_group_counts)) if class_group_counts else 2
    splits = max(2, splits)
    splitter = StratifiedGroupKFold(n_splits=splits, shuffle=True, random_state=RANDOM_STATE)
    train_idx, test_idx = next(splitter.split(X, y, groups))
    return train_idx, test_idx, splits


def _candidate_models():
    from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier

    return {
        "ExtraTrees": ExtraTreesClassifier(
            n_estimators=240, max_features=0.75, min_samples_leaf=1,
            class_weight="balanced", n_jobs=-1, random_state=RANDOM_STATE,
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=240, max_features="sqrt", min_samples_leaf=1,
            class_weight="balanced_subsample", n_jobs=-1, random_state=RANDOM_STATE,
        ),
    }


def train_model(progress=print) -> dict:
    from sklearn.base import clone
    from sklearn.metrics import (
        accuracy_score,
        balanced_accuracy_score,
        classification_report,
        confusion_matrix,
        f1_score,
    )
    from sklearn.model_selection import StratifiedGroupKFold, cross_val_score

    init_db()
    ensure_directories()
    records = _balanced_sample(_load_dataset())
    X = np.asarray([record["vector"] for record in records], dtype=np.float64)
    y = np.asarray([record["label"] for record in records])
    groups = np.asarray([record["group"] for record in records])
    train_idx, test_idx, holdout_splits = _make_holdout(X, y, groups)
    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    groups_train = groups[train_idx]

    progress(f"Training candidates on {len(train_idx):,} sessions; protected holdout: {len(test_idx):,}")
    inner_group_counts = [len(set(groups_train[y_train == label])) for label in np.unique(y_train)]
    inner_splits = max(2, min(3, min(inner_group_counts)))
    inner_cv = StratifiedGroupKFold(n_splits=inner_splits, shuffle=True, random_state=RANDOM_STATE + 1)
    candidate_scores = {}
    candidates = _candidate_models()
    for name, candidate in candidates.items():
        scores = cross_val_score(
            candidate, X_train, y_train, groups=groups_train, cv=inner_cv,
            scoring="f1_macro", n_jobs=1,
        )
        candidate_scores[name] = {
            "macro_f1_mean": float(np.mean(scores)),
            "macro_f1_std": float(np.std(scores)),
        }
        progress(f"{name}: cross-validated macro-F1 {np.mean(scores):.4f} ± {np.std(scores):.4f}")

    best_name = max(candidate_scores, key=lambda name: candidate_scores[name]["macro_f1_mean"])
    model = clone(candidates[best_name])
    model.fit(X_train, y_train)
    predicted = model.predict(X_test)
    labels = sorted(set(y_test) | set(predicted))

    version = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    artifact = {
        "version": version,
        "model": model,
        "feature_columns": FEATURE_COLUMNS,
        "classes": list(model.classes_),
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(artifact, MODEL_PATH)

    report = classification_report(y_test, predicted, labels=labels, output_dict=True, zero_division=0)
    metrics = {
        "accuracy": float(accuracy_score(y_test, predicted)),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, predicted)),
        "macro_f1": float(f1_score(y_test, predicted, average="macro")),
        "weighted_f1": float(f1_score(y_test, predicted, average="weighted")),
        "classification_report": report,
        "confusion_matrix": confusion_matrix(y_test, predicted, labels=labels).tolist(),
        "labels": labels,
        "candidate_scores": candidate_scores,
        "holdout_group_folds": holdout_splits,
        "inner_group_folds": inner_splits,
        "class_support": dict(Counter(y.tolist())),
        "evaluation_name": "Pseudo-label agreement on attacker-group holdout",
        "disclaimer": (
            "Labels are generated by documented behavioral rules from Cowrie telemetry. "
            "These metrics measure agreement with those pseudo-labels, not independently verified real-world ground truth."
        ),
    }
    importance = dict(sorted(
        zip(FEATURE_COLUMNS, model.feature_importances_.tolist()),
        key=lambda item: item[1], reverse=True,
    ))
    fingerprint_text = "|".join(f"{record['id']}:{record['label']}" for record in records)
    fingerprint = hashlib.sha256(fingerprint_text.encode()).hexdigest()

    conn = connect()
    conn.execute(
        """INSERT INTO model_runs(model_version,created_at,algorithm,artifact_path,
           feature_columns_json,classes_json,metrics_json,feature_importance_json,
           train_samples,test_samples,dataset_fingerprint,label_provenance)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            version, artifact["trained_at"], best_name, str(MODEL_PATH),
            json.dumps(FEATURE_COLUMNS), json.dumps(list(model.classes_)),
            json.dumps(metrics), json.dumps(importance), len(train_idx), len(test_idx),
            fingerprint, "Auditable behavioral pseudo-label rules in labeling.py",
        ),
    )
    conn.commit()
    conn.close()
    apply_model(progress=progress)
    result = {"version": version, "algorithm": best_name, **metrics}
    progress(
        f"Saved {best_name} model {version}: balanced accuracy {metrics['balanced_accuracy']:.2%}, "
        f"macro-F1 {metrics['macro_f1']:.2%}"
    )
    return result


def load_artifact(path: str | Path = MODEL_PATH):
    path = Path(path)
    if not path.exists():
        return None
    return joblib.load(path)


def apply_model(*, progress=print, session_ids: list[int] | None = None) -> int:
    artifact = load_artifact()
    if artifact is None:
        raise FileNotFoundError(f"No trained model found at {MODEL_PATH}")
    model = artifact["model"]
    conn = connect()
    if session_ids:
        placeholders = ",".join("?" for _ in session_ids)
        conn.execute(
            f"""UPDATE sessions SET predicted_label=NULL,prediction_confidence=NULL,
                final_label='unknown',threat_level='low',model_version=NULL
                WHERE rule_label='unknown' AND id IN ({placeholders})""",
            session_ids,
        )
        rows = conn.execute(
            f"""SELECT s.id,s.rule_label,f.feature_json FROM sessions s
                JOIN session_features f ON f.session_id=s.id
                WHERE s.rule_label!='unknown' AND s.id IN ({placeholders}) ORDER BY s.id""",
            session_ids,
        ).fetchall()
    else:
        conn.execute(
            """UPDATE sessions SET predicted_label=NULL,prediction_confidence=NULL,
               final_label='unknown',threat_level='low',model_version=NULL
               WHERE rule_label='unknown'"""
        )
        rows = conn.execute(
            """SELECT s.id,s.rule_label,f.feature_json FROM sessions s
               JOIN session_features f ON f.session_id=s.id
               WHERE s.rule_label!='unknown' ORDER BY s.id"""
        ).fetchall()
    updated = 0
    for start in range(0, len(rows), 2000):
        chunk = rows[start:start + 2000]
        X = np.asarray([feature_vector(json.loads(row["feature_json"])) for row in chunk])
        probabilities = model.predict_proba(X)
        indexes = np.argmax(probabilities, axis=1)
        predictions = model.classes_[indexes]
        confidences = probabilities[np.arange(len(chunk)), indexes]
        updates = []
        for row, prediction, confidence in zip(chunk, predictions, confidences):
            rule_label = row["rule_label"]
            final_label = str(prediction) if confidence >= 0.55 else rule_label
            updates.append((str(prediction), float(confidence), final_label,
                            THREAT_LEVELS.get(final_label, "low"), artifact["version"], int(row["id"])))
        conn.executemany(
            """UPDATE sessions SET predicted_label=?,prediction_confidence=?,final_label=?,
               threat_level=?,model_version=? WHERE id=?""",
            updates,
        )
        conn.commit()
        updated += len(chunk)
        progress(f"Applied model to {updated:,}/{len(rows):,} sessions")
    conn.close()
    return updated
