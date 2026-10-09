import collections
import hashlib
import json
import math
import pathlib
import random

import numpy as np
import onnxruntime as ort
from sklearn.cluster import KMeans
from tokenizers import Tokenizer

ROOT = pathlib.Path("extracted/bench-release")
EMBED_ROOT = pathlib.Path("embedding_model")
POOL = [
    "DeepHermes-3-Llama-3-8B-Preview", "DeepSeek-R1-0528-Qwen3-8B",
    "DeepSeek-R1-Distill-Qwen-7B", "Fin-R1", "GLM-Z1-9B-0414", "Intern-S1-mini",
    "Llama-3.1-8B-Instruct", "Llama-3.1-8B-UltraMedical",
    "Llama-3.1-Nemotron-Nano-8B-v1", "MiMo-7B-RL-0530", "MiniCPM4.1-8B",
    "NVIDIA-Nemotron-Nano-9B-v2", "OpenThinker3-7B", "Qwen2.5-Coder-7B-Instruct",
    "Qwen3-8B", "cogito-v1-preview-llama-8B", "gemma-2-9b-it", "glm-4-9b-chat",
    "granite-3.3-8b-instruct", "internlm3-8b-instruct",
]
MODEL_ID = "sentence-transformers/all-MiniLM-L6-v2"
MODEL_REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
N_CLUSTERS = 30
SEED = 42


def norm(value): return str(value).strip().lower()
POOL_BY_NORM = {norm(model): model for model in POOL}


def stable(value):
    try: return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    except Exception: return repr(value)


def record_id(record, index):
    for key in ("id", "task_id", "problem_id", "question_id", "sample_id", "data_id", "index", "idx"):
        if key in record and record[key] is not None: return f"{key}:{stable(record[key])}"
    for key in ("origin_query", "prompt", "question", "input", "messages"):
        if key in record and record[key] is not None:
            return f"{key}:{hashlib.sha256(stable(record[key]).encode()).hexdigest()}"
    return f"index:{index}"


def score_of(record):
    for key in ("score", "reward", "accuracy", "correct", "pass", "success"):
        if key not in record: continue
        value = record[key]
        if isinstance(value, bool): return float(value)
        if isinstance(value, (int, float)) and math.isfinite(float(value)): return float(value)
        if isinstance(value, dict):
            for nested in ("score", "reward", "accuracy", "value"):
                nested_value = value.get(nested)
                if isinstance(nested_value, bool): return float(nested_value)
                if isinstance(nested_value, (int, float)) and math.isfinite(float(nested_value)): return float(nested_value)
    return None


def text_of(record):
    for key in ("origin_query", "prompt", "question", "input", "messages"):
        if key in record and record[key] is not None: return stable(record[key])
    return ""


def load_rows():
    table = collections.defaultdict(dict)
    for path in ROOT.rglob("*.json"):
        try: obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception: continue
        if not isinstance(obj, dict): continue
        raw_model = obj.get("model_name")
        if norm(raw_model) not in POOL_BY_NORM: continue
        model = POOL_BY_NORM[norm(raw_model)]
        if str(obj.get("split", "")).lower() != "test": continue
        dataset = str(obj.get("dataset_name") or path.parts[-4]).strip().lower()
        records = obj.get("records")
        if not isinstance(records, list): continue
        for index, record in enumerate(records):
            if not isinstance(record, dict): continue
            score = score_of(record)
            if score is None: continue
            rid = record_id(record, index)
            row = table[dataset].setdefault(rid, {"scores": {}, "text": text_of(record)})
            row["scores"][model] = score
            if not row["text"]: row["text"] = text_of(record)
    matched = {
        dataset: {rid: row for rid, row in rows.items() if all(model in row["scores"] for model in POOL)}
        for dataset, rows in table.items()
    }
    return {dataset: rows for dataset, rows in matched.items() if rows}


def is_train(dataset, rid):
    digest = int(hashlib.sha256((dataset + "\0" + rid).encode()).hexdigest()[:16], 16)
    return digest % 10 < 7


class OnnxSentenceEncoder:
    def __init__(self):
        pooling = json.loads((EMBED_ROOT / "pooling.json").read_text())
        sentence_cfg = json.loads((EMBED_ROOT / "sentence_bert_config.json").read_text())
        assert pooling.get("pooling_mode_mean_tokens") is True, pooling
        assert not pooling.get("pooling_mode_cls_token", False), pooling
        self.max_length = int(sentence_cfg.get("max_seq_length", 256))
        self.tokenizer = Tokenizer.from_file(str(EMBED_ROOT / "tokenizer.json"))
        self.tokenizer.enable_truncation(max_length=self.max_length)
        pad_id = self.tokenizer.token_to_id("[PAD]")
        assert pad_id is not None
        self.tokenizer.enable_padding(pad_id=pad_id, pad_token="[PAD]")
        self.session = ort.InferenceSession(
            str(EMBED_ROOT / "model.onnx"), providers=["CPUExecutionProvider"]
        )
        self.input_names = {item.name for item in self.session.get_inputs()}

    def encode(self, texts, batch_size=128):
        result = []
        for start in range(0, len(texts), batch_size):
            batch = texts[start:start + batch_size]
            encoded = self.tokenizer.encode_batch(batch)
            ids = np.asarray([item.ids for item in encoded], dtype=np.int64)
            mask = np.asarray([item.attention_mask for item in encoded], dtype=np.int64)
            type_ids = np.asarray([item.type_ids for item in encoded], dtype=np.int64)
            feed = {}
            if "input_ids" in self.input_names: feed["input_ids"] = ids
            if "attention_mask" in self.input_names: feed["attention_mask"] = mask
            if "token_type_ids" in self.input_names: feed["token_type_ids"] = type_ids
            outputs = self.session.run(None, feed)
            hidden = next((out for out in outputs if getattr(out, "ndim", 0) == 3), None)
            if hidden is None:
                pooled = next((out for out in outputs if getattr(out, "ndim", 0) == 2), None)
                if pooled is None: raise RuntimeError("No suitable ONNX embedding output")
            else:
                weights = mask.astype(np.float32)[..., None]
                pooled = (hidden * weights).sum(axis=1) / np.clip(weights.sum(axis=1), 1e-9, None)
            pooled = pooled.astype(np.float32)
            pooled /= np.clip(np.linalg.norm(pooled, axis=1, keepdims=True), 1e-12, None)
            result.append(pooled)
        return np.vstack(result)


def evaluate(rows, chooser):
    per_dataset = collections.defaultdict(list)
    flat, recall = [], []
    for dataset, rid, row in rows:
        model = chooser(dataset, rid, row)
        score = row["scores"][model]
        per_dataset[dataset].append(score)
        flat.append(score)
        recall.append(float(score >= max(row["scores"].values()) - 1e-12))
    return {
        "macro": sum(sum(v) / len(v) for v in per_dataset.values()) / len(per_dataset),
        "weighted": sum(flat) / len(flat),
        "model_recall": sum(recall) / len(recall),
        "per_dataset": {d: sum(v) / len(v) for d, v in sorted(per_dataset.items())},
    }


def paired_delta(test, challenger, baseline):
    values = [row["scores"][challenger(ds, rid, row)] - row["scores"][baseline(ds, rid, row)] for ds, rid, row in test]
    observed = sum(values) / len(values)
    rng = random.Random(20260813)
    bootstrap = []
    for _ in range(3000):
        bootstrap.append(sum(values[rng.randrange(len(values))] for __ in range(len(values))) / len(values))
    bootstrap.sort()
    return {"delta": observed, "bootstrap95": [bootstrap[75], bootstrap[2924]]}


def main():
    matched = load_rows()
    train, test = [], []
    for dataset, rows in matched.items():
        for rid, row in rows.items():
            (train if is_train(dataset, rid) else test).append((dataset, rid, row))
    assert len(train) == 9210, len(train)
    assert len(test) == 4002, len(test)

    def macro_model_score(model):
        per = collections.defaultdict(list)
        for dataset, _, row in train: per[dataset].append(row["scores"][model])
        return sum(sum(v) / len(v) for v in per.values()) / len(per)

    best_single = max(POOL, key=lambda m: (macro_model_score(m), m))
    dataset_choice = {}
    for dataset in matched:
        rows = [item for item in train if item[0] == dataset]
        dataset_choice[dataset] = max(POOL, key=lambda m: (sum(item[2]["scores"][m] for item in rows) / len(rows), m))

    encoder = OnnxSentenceEncoder()
    train_embeddings = encoder.encode([row["text"] for _, _, row in train])
    test_embeddings = encoder.encode([row["text"] for _, _, row in test])

    kmeans = KMeans(n_clusters=N_CLUSTERS, random_state=SEED, n_init=10)
    train_cluster = kmeans.fit_predict(train_embeddings)
    test_cluster = kmeans.predict(test_embeddings)

    cluster_model_scores = collections.defaultdict(lambda: collections.defaultdict(list))
    for cluster, (_, _, row) in zip(train_cluster, train):
        for model in POOL: cluster_model_scores[int(cluster)][model].append(row["scores"][model])
    cluster_choice = {
        cluster: max(POOL, key=lambda m: (sum(by_model[m]) / len(by_model[m]), m))
        for cluster, by_model in cluster_model_scores.items()
    }
    semantic_choice = {(dataset, rid): cluster_choice[int(cluster)] for cluster, (dataset, rid, _) in zip(test_cluster, test)}

    choose_best = lambda dataset, rid, row: best_single
    choose_dataset = lambda dataset, rid, row: dataset_choice[dataset]
    choose_semantic = lambda dataset, rid, row: semantic_choice[(dataset, rid)]
    choose_oracle = lambda dataset, rid, row: max(POOL, key=lambda m: (row["scores"][m], m))

    evaluations = {
        "best_single": evaluate(test, choose_best),
        "dataset_router": evaluate(test, choose_dataset),
        "semantic_cluster_emulation": evaluate(test, choose_semantic),
        "instance_oracle": evaluate(test, choose_oracle),
    }
    contrast = paired_delta(test, choose_semantic, choose_dataset)
    survivor = contrast["delta"] > 0 and contrast["bootstrap95"][0] > 0
    output = {
        "schema": "triaxis.r8e.semantic_cluster_emulation/v2",
        "evidence_class": "MECHANISM_EMULATION_EXPLORATORY_OFFLINE_HELDOUT",
        "source": {
            "llmrouterbench_commit": "c77cb0506949d8f959e97967d2fefca0e8ff1b05",
            "archive_sha256": "b79f8cde1a6f029c2efa663a3a3b6f7748defb22341fe59f328cebef6648c8f1",
            "mechanism_prior_art": "Avengers/Avengers-Pro semantic embedding + clustering",
            "official_avengers_config_n_clusters": 30,
            "official_avengers_top_k": 1,
            "embedding_substitution": {
                "official_provider": "external OpenAI-compatible endpoint",
                "used_local_model": MODEL_ID,
                "revision": MODEL_REVISION,
                "execution_backend": "quantized ONNX + official mean pooling"
            },
            "repair_from_v1": "PyTorch install failed ENOSPC; algorithm and frozen cluster parameters unchanged"
        },
        "train_rows": len(train), "test_rows": len(test), "n_clusters": N_CLUSTERS,
        "evaluations": evaluations,
        "semantic_minus_dataset": contrast,
        "survivor": survivor,
        "verdict": "SEMANTIC_CLUSTER_CANDIDATE_LIFT" if survivor else "SEMANTIC_CLUSTER_FAILS_DATASET_ROUTER",
        "claim_boundary": [
            "This is NOT an official Avengers or Avengers-Pro reproduction.",
            "The routing mechanism is emulated with a pinned public local embedding model.",
            "All fitting uses train only; held-out outcomes are scoring only.",
            "No live LLM model calls and no test-time tuning."
        ]
    }
    pathlib.Path("R8E_SEMANTIC_CLUSTER_RESULT.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print("===R8E_RESULT_BEGIN===")
    print(json.dumps(output, indent=2, sort_keys=True))
    print("===R8E_RESULT_END===")


if __name__ == "__main__": main()
