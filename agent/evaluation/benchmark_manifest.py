"""Deterministic preregistration; metadata never admits repository execution."""

import hashlib
import json
import re
from types import MappingProxyType

DATASET_REVISION = "6ec7bb89b9342f664a54a6e0a6ea6501d3437cc2"
SEEN_INSTANCE_IDS = ("sympy__sympy-20590",)
DEFAULT_POLICY = MappingProxyType({
    "model": "deepseek-flash", "guard_id": "settled-cny-v1",
    "max_requests": 20, "max_output_tokens": 2048, "max_body_bytes": 16384,
    "context_policy": "unhinted-bounded-tools-v1", "budget_microcny": 200000,
    "automatic_retry": False, "automatic_resume": False,
})


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _validate_row(row: object) -> dict:
    if (type(row) is not dict or not 1 <= len(row) <= 32
            or not all(type(k) is str and type(v) is str for k, v in row.items())
            or len(canonical_bytes(row)) > 2 * 1024 * 1024):
        raise ValueError("A bounded official string-valued row is required.")
    required = ("instance_id", "repo", "base_commit", "problem_statement", "patch", "test_patch", "FAIL_TO_PASS", "PASS_TO_PASS")
    if any(key not in row for key in required):
        raise ValueError("Official evaluator fields are missing.")
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", row["repo"])
            or any(part in (".", "..") for part in row["repo"].split("/"))):
        raise ValueError("Invalid repository identity.")
    if not re.fullmatch(re.escape(row["repo"].replace("/", "__")) + r"-[1-9][0-9]*", row["instance_id"]):
        raise ValueError("Instance identity does not match repository.")
    if not re.fullmatch(r"[0-9a-f]{40}", row["base_commit"]):
        raise ValueError("A full base commit is required.")
    if not row["problem_statement"].strip() or "\x00" in row["problem_statement"]:
        raise ValueError("A nonempty problem statement is required.")
    rosters = []
    for key in ("FAIL_TO_PASS", "PASS_TO_PASS"):
        roster = json.loads(row[key])
        if (type(roster) is not list or len(roster) > 10000
                or any(type(case) is not str or not case.strip() or case != case.strip()
                       or len(case) > 4096 or any(ord(c) < 32 for c in case) for case in roster)
                or len(roster) != len(set(roster))):
            raise ValueError("Invalid exact test roster.")
        rosters.append(set(roster))
    if not rosters[0] or rosters[0] & rosters[1]:
        raise ValueError("F2P must be nonempty and disjoint from P2P.")
    return dict(row)


def build_benchmark_manifest(rows, *, dataset_revision: str, policy: dict | None = None,
                             seed: str = "swe-unhinted-20-v1") -> dict:
    """Freeze twenty holdout rows, using only repo/instance identity for ranking.

    Full evaluator rows stay private. Call ``model_input`` for model visibility.
    This fixed Lite profile exercises unhinted location, not multifile gold.
    No model, network, Docker, repository code or credential is accessed here.
    """
    if dataset_revision != DATASET_REVISION:
        raise ValueError("Dataset revision differs from the pinned Lite revision.")
    if type(seed) is not str or not 1 <= len(seed) <= 128:
        raise ValueError("A bounded preregistered seed is required.")
    if type(rows) not in (list, tuple) or not 20 <= len(rows) <= 10000:
        raise ValueError("Expected a bounded collection with at least twenty rows.")
    selected_policy = dict(DEFAULT_POLICY if policy is None else policy)
    if selected_policy != DEFAULT_POLICY:
        raise ValueError("This profile requires its frozen four-CNY policy.")
    checked, total_bytes = [], 0
    for row in rows:
        validated = _validate_row(row)
        total_bytes += len(canonical_bytes(validated))
        if total_bytes > 20 * 1024 * 1024:
            raise ValueError("Metadata collection exceeds the twenty-MiB input limit.")
        checked.append(validated)
    if len({row["instance_id"] for row in checked}) != len(checked):
        raise ValueError("Duplicate instance identity is ambiguous.")
    seen_bases = {(r["repo"], r["base_commit"]) for r in checked if r["instance_id"] in SEEN_INSTANCE_IDS}
    buckets = {}
    for row in checked:
        if row["instance_id"] not in SEEN_INSTANCE_IDS and (row["repo"], row["base_commit"]) not in seen_bases:
            buckets.setdefault(row["repo"], []).append(row)
    for bucket in buckets.values():
        bucket.sort(key=lambda r: _sha([seed, r["instance_id"]]))
    repositories = sorted(buckets, key=lambda repo: _sha([seed, repo]))
    if len(repositories) < 5:
        raise ValueError("The preregistered multirepository profile requires at least five repositories.")
    chosen, used_bases = [], set()
    while len(chosen) < 20:
        progressed = False
        for repo in repositories:
            while buckets[repo]:
                row = buckets[repo].pop(0)
                identity = (repo, row["base_commit"])
                if identity not in used_bases:
                    used_bases.add(identity)
                    chosen.append(row)
                    progressed = True
                    break
            if len(chosen) == 20:
                break
        if not progressed:
            raise ValueError("Insufficient distinct unseen repository revisions for twenty trials.")
    manifest = {
        "schema_version": 1, "kind": "UNHINTED_LITE_PREREGISTRATION", "dataset_revision": dataset_revision,
        "dataset": "princeton-nlp/SWE-bench_Lite", "split": "test", "seed": seed,
        "scheduled": 20, "attempts_per_task": 1, "total_budget_microcny": 4000000,
        "policy": selected_policy, "policy_digest": _sha(selected_policy),
        "seen_instance_ids": list(SEEN_INSTANCE_IDS), "execution_admitted": False,
        "model_admitted": False, "resource_status": "NOT_CHECKED",
        "task_environment_status": "NOT_CHECKED", "pricing_status": "MUST_VERIFY_AT_PAID_ADMISSION",
        "fresh_run_id_required": True, "input_rows_digest": _sha(sorted(checked, key=lambda r: r["instance_id"])),
        "coverage": "Lite unhinted single-file-gold subset; not multifile or full leaderboard",
        "tasks": [{"instance_id": r["instance_id"], "repo": r["repo"], "base_commit": r["base_commit"],
                   "problem_statement": r["problem_statement"], "row_sha256": _sha(r),
                   "cohort": "holdout", "budget_microcny": 200000, "status": "NOT_STARTED"} for r in chosen],
        "evaluator_rows": {r["instance_id"]: r for r in chosen},
    }
    manifest["manifest_digest"] = _sha(manifest)
    return manifest


def model_input(manifest: dict, instance_id: str) -> dict[str, str]:
    """Return only problem/repo/base; never file hints, gold or evaluator tests."""
    unsigned = {k: v for k, v in manifest.items() if k != "manifest_digest"}
    if manifest.get("manifest_digest") != _sha(unsigned):
        raise ValueError("Preregistered manifest changed.")
    for task in manifest["tasks"]:
        if task["instance_id"] == instance_id:
            return {key: task[key] for key in ("repo", "base_commit", "problem_statement")}
    raise ValueError("Instance is not in the frozen schedule.")
