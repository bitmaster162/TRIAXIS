import collections
import hashlib
import json
import math
import pathlib
import random

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.neighbors import NearestNeighbors

ROOT = pathlib.Path("extracted/bench-release")
POOL = [
    "DeepHermes-3-Llama-3-8B-Preview",
    "DeepSeek-R1-0528-Qwen3-8B",
    "DeepSeek-R1-Distill-Qwen-7B",
    "Fin-R1",
    "GLM-Z1-9B-0414",
    "Intern-S1-mini",
    "Llama-3.1-8B-Instruct",
    "Llama-3.1-8B-UltraMedical",
    "Llama-3.1-Nemotron-Nano-8B-v1",
    "MiMo-7B-RL-0530",
    "MiniCPM4.1-8B",
    "NVIDIA-Nemotron-Nano-9B-v2",
    "OpenThinker3-7B",
    "Qwen2.5-Coder-7B-Instruct",
    "Qwen3-8B",
    "cogito-v1-preview-llama-8B",
    "gemma-2-9b-it",
    "glm-4-9b-chat",
    "granite-3.3-8b-instruct",
    "internlm3-8b-instruct",
]


def norm(value):
    return str(value).strip().lower()


POOL_BY_NORM = {norm(model): model for model in POOL}


def stable(value):
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return repr(value)


def record_id(record, index):
    for key in ("id", "task_id", "problem_id", "question_id", "sample_id", "data_id", "index", "idx"):
        if key in record and record[key] is not None:
            return f"{key}:{stable(record[key])}"
    for key in ("origin_query", "prompt", "question", "input", "messages"):
        if key in record and record[key] is not None:
            digest = hashlib.sha256(stable(record[key]).encode()).hexdigest()
            return f"{key}:{digest}"
    return f"index:{index}"


def score_of(record):
    for key in ("score", "reward", "accuracy", "correct", "pass", "success"):
        if key not in record:
            continue
        value = record[key]
        if isinstance(value, bool):
            return float(value)
        if isinstance(value, (int, float)) and math.isfinite(float(value)):
            return float(value)
        if isinstance(value, dict):
            for nested in ("score", "reward", "accuracy", "value"):
                nested_value = value.get(nested)
                if isinstance(nested_value, bool):
                    return float(nested_value)
                if isinstance(nested_value, (int, float)) and math.isfinite(float(nested_value)):
                    return float(nested_value)
    return None


def text_of(record):
    for key in ("origin_query", "prompt", "question", "input", "messages"):
        if key in record and record[key] is not None:
            return stable(record[key])
    return ""


def load_rows():
    table = collections.defaultdict(dict)
    for path in ROOT.rglob("*.json"):
        try:
            obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        raw_model = obj.get("model_name")
        if norm(raw_model) not in POOL_BY_NORM:
            continue
        model = POOL_BY_NORM[norm(raw_model)]
        if str(obj.get("split", "")).lower() != "test":
            continue
        dataset = str(obj.get("dataset_name") or path.parts[-4]).strip().lower()
        records = obj.get("records")
        if not isinstance(records, list):
            continue
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            score = score_of(record)
            if score is None:
                continue
            rid = record_id(record, index)
            row = table[dataset].setdefault(rid, {"scores": {}, "text": text_of(record)})
            row["scores"][model] = score
            if not row["text"]:
                row["text"] = text_of(record)
    matched = {
        dataset: {rid: row for rid, row in rows.items() if all(model in row["scores"] for model in POOL)}
        for dataset, rows in table.items()
    }
    return {dataset: rows for dataset, rows in matched.items() if rows}


def is_train(dataset, rid):
    digest = int(hashlib.sha256((dataset + "\0" + rid).encode()).hexdigest()[:16], 16)
    return digest % 10 < 7


def split_rows(matched):
    train, test = [], []
    for dataset, rows in matched.items():
        for rid, row in rows.items():
            (train if is_train(dataset, rid) else test).append((dataset, rid, row))
    assert len(train) == 9210, len(train)
    assert len(test) == 4002, len(test)
    return train, test


def best_single_and_dataset(train, matched):
    def macro_score(model):
        per_dataset = collections.defaultdict(list)
        for dataset, _, row in train:
            per_dataset[dataset].append(row["scores"][model])
        return sum(sum(values) / len(values) for values in per_dataset.values()) / len(per_dataset)

    best_single = max(POOL, key=lambda model: (macro_score(model), model))
    dataset_choice = {}
    for dataset in matched:
        rows = [item for item in train if item[0] == dataset]
        dataset_choice[dataset] = max(
            POOL,
            key=lambda model: (sum(item[2]["scores"][model] for item in rows) / len(rows), model),
        )
    return best_single, dataset_choice


def fit_knn(train, test, matched):
    choices = {}
    for dataset in sorted(matched):
        train_ds = [item for item in train if item[0] == dataset]
        test_ds = [item for item in test if item[0] == dataset]
        if not train_ds or not test_ds:
            continue
        vectorizer = TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            min_df=2,
            max_features=30000,
            sublinear_tf=True,
            dtype=np.float32,
        )
        x_train = vectorizer.fit_transform([item[2]["text"] for item in train_ds])
        x_test = vectorizer.transform([item[2]["text"] for item in test_ds])
        k = min(5, len(train_ds))
        nn = NearestNeighbors(n_neighbors=k, metric="cosine", algorithm="brute", n_jobs=-1)
        nn.fit(x_train)
        _, indices = nn.kneighbors(x_test, return_distance=True)
        for test_index, (_, rid, _) in enumerate(test_ds):
            neighbors = [train_ds[index] for index in indices[test_index]]
            choices[(dataset, rid)] = max(
                POOL,
                key=lambda model: (
                    sum(neighbor[2]["scores"][model] for neighbor in neighbors) / len(neighbors),
                    model,
                ),
            )
    return choices


def fit_linear(train, test):
    train_text = [f"__DATASET_{dataset}__ {row['text']}" for dataset, _, row in train]
    test_text = [f"__DATASET_{dataset}__ {row['text']}" for dataset, _, row in test]
    labels = [max(POOL, key=lambda model: (row["scores"][model], model)) for _, _, row in train]
    vectorizer = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        min_df=2,
        max_features=50000,
        sublinear_tf=True,
        dtype=np.float32,
    )
    x_train = vectorizer.fit_transform(train_text)
    x_test = vectorizer.transform(test_text)
    classifier = SGDClassifier(
        loss="log_loss",
        alpha=1e-5,
        max_iter=2000,
        tol=1e-4,
        random_state=20260813,
        shuffle=True,
    )
    classifier.fit(x_train, labels)
    predictions = classifier.predict(x_test)
    return {(dataset, rid): str(model) for (dataset, rid, _), model in zip(test, predictions)}


def evaluate(rows, chooser):
    per_dataset = collections.defaultdict(list)
    flat, recall, choices = [], [], []
    for dataset, rid, row in rows:
        model = chooser(dataset, rid, row)
        score = row["scores"][model]
        per_dataset[dataset].append(score)
        flat.append(score)
        choices.append(model)
        recall.append(float(score >= max(row["scores"].values()) - 1e-12))
    return {
        "macro": sum(sum(values) / len(values) for values in per_dataset.values()) / len(per_dataset),
        "weighted": sum(flat) / len(flat),
        "model_recall": sum(recall) / len(recall),
        "model_choice_counts": dict(collections.Counter(choices)),
        "per_dataset": {dataset: sum(values) / len(values) for dataset, values in sorted(per_dataset.items())},
    }


def paired_delta(test, challenger, baseline):
    values = []
    for dataset, rid, row in test:
        values.append(row["scores"][challenger(dataset, rid, row)] - row["scores"][baseline(dataset, rid, row)])
    observed = sum(values) / len(values)
    rng = random.Random(20260813)
    bootstrap = []
    for _ in range(3000):
        bootstrap.append(sum(values[rng.randrange(len(values))] for __ in range(len(values))) / len(values))
    bootstrap.sort()
    return {
        "delta": observed,
        "bootstrap95": [bootstrap[int(0.025 * len(bootstrap))], bootstrap[int(0.975 * len(bootstrap)) - 1]],
    }


def main():
    matched = load_rows()
    train, test = split_rows(matched)
    best_single, dataset_choice = best_single_and_dataset(train, matched)
    knn_choice = fit_knn(train, test, matched)
    linear_choice = fit_linear(train, test)

    choose_best = lambda dataset, rid, row: best_single
    choose_dataset = lambda dataset, rid, row: dataset_choice[dataset]
    choose_knn = lambda dataset, rid, row: knn_choice[(dataset, rid)]
    choose_linear = lambda dataset, rid, row: linear_choice[(dataset, rid)]
    choose_oracle = lambda dataset, rid, row: max(POOL, key=lambda model: (row["scores"][model], model))

    evaluations = {
        "best_single": evaluate(test, choose_best),
        "dataset_router": evaluate(test, choose_dataset),
        "tfidf_5nn": evaluate(test, choose_knn),
        "tfidf_linear": evaluate(test, choose_linear),
        "instance_oracle": evaluate(test, choose_oracle),
    }
    contrasts = {
        "knn_minus_dataset": paired_delta(test, choose_knn, choose_dataset),
        "linear_minus_dataset": paired_delta(test, choose_linear, choose_dataset),
    }
    survivors = [
        name
        for name, contrast in contrasts.items()
        if contrast["delta"] > 0 and contrast["bootstrap95"][0] > 0
    ]
    output = {
        "schema": "triaxis.r8d.simple_query_router_challengers/v1",
        "evidence_class": "EXPLORATORY_OFFLINE_HELDOUT",
        "source": {
            "llmrouterbench_commit": "c77cb0506949d8f959e97967d2fefca0e8ff1b05",
            "archive_sha256": "b79f8cde1a6f029c2efa663a3a3b6f7748defb22341fe59f328cebef6648c8f1",
            "sklearn": "1.7.1",
        },
        "train_rows": len(train),
        "test_rows": len(test),
        "datasets": sorted(matched),
        "best_single_model": best_single,
        "evaluations": evaluations,
        "contrasts": contrasts,
        "survivors": survivors,
        "verdict": "QUERY_LEVEL_SURVIVOR_FOUND" if survivors else "COLLAPSE_SIGNAL_QUERY_LEVEL_SIMPLE_ROUTERS_FAIL_DATASET_ROUTER",
        "claim_boundary": [
            "R8-D challengers do not alter or rerun rejected F0.",
            "All fitting uses train only; held-out outcomes are scoring only.",
            "No live model calls, no secrets, no official leaderboard claim.",
        ],
    }
    pathlib.Path("R8D_SIMPLE_QUERY_ROUTER_RESULT.json").write_text(
        json.dumps(output, indent=2, sort_keys=True), encoding="utf-8"
    )
    print("===R8D_RESULT_BEGIN===")
    print(json.dumps(output, indent=2, sort_keys=True))
    print("===R8D_RESULT_END===")


if __name__ == "__main__":
    main()
