"""Prepare a pinned twenty-row schedule locally; never run a model or repository."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.evaluation.benchmark_manifest import (
    DATASET_REVISION, build_benchmark_manifest, canonical_bytes, model_input,
)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key.")
        result[key] = value
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows-json", type=Path, required=True, help="Private canonical rows from the pinned dataset")
    parser.add_argument("--expected-sha256", required=True, help="Externally verified input bytes SHA256")
    parser.add_argument("--output", type=Path, required=True, help="Fresh private output directory; contains evaluator data")
    parser.add_argument("--dataset-revision", default=DATASET_REVISION)
    parser.add_argument("--seed", default="swe-unhinted-20-v1")
    args = parser.parse_args(argv)
    try:
        if args.rows_json.is_symlink() or not re.fullmatch(r"[0-9a-f]{64}", args.expected_sha256):
            raise ValueError("Ordinary pinned JSON input is required.")
        with args.rows_json.open("rb") as stream:
            data = stream.read(20 * 1024 * 1024 + 1)
        if len(data) > 20 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != args.expected_sha256:
            raise ValueError("Input identity or size differs from the external pin.")
        rows = json.loads(data.decode("utf-8"), object_pairs_hook=_unique)
        manifest = build_benchmark_manifest(rows, dataset_revision=args.dataset_revision, seed=args.seed)
        models = {task["instance_id"]: model_input(manifest, task["instance_id"]) for task in manifest["tasks"]}
        schedule = {key: value for key, value in manifest.items() if key not in ("evaluator_rows", "manifest_digest")}
        schedule.update(kind="UNHINTED_LITE_PUBLIC_SCHEDULE", private_manifest_digest=manifest["manifest_digest"],
                        source_json_sha256=args.expected_sha256)
        args.output.mkdir(parents=True, exist_ok=False)
        for name, value in (("manifest.private.json", manifest), ("schedule.json", schedule), ("model_inputs.json", models)):
            with (args.output / name).open("xb") as stream:
                stream.write(canonical_bytes(value))
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({"status": "REJECTED", "error_type": type(error).__name__}))
        return 2
    print(json.dumps({"status": "PREPARED", "scheduled": 20, "total_budget_cny": "4",
                      "execution_admitted": False, "model_requests": 0,
                      "manifest_digest": manifest["manifest_digest"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
