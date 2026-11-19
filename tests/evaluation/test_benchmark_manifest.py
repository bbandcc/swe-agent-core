import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


def rows():
    return [{"instance_id": f"org{i % 8}__repo-{i + 1}", "repo": f"org{i % 8}/repo",
             "base_commit": f"{i + 1:040x}", "problem_statement": f"Repair behavior {i}",
             "patch": "GOLD_CANARY", "test_patch": "ORACLE_CANARY", "hints_text": "HINT_CANARY",
             "FAIL_TO_PASS": '["test_failure"]', "PASS_TO_PASS": '["test_existing"]'} for i in range(48)]


class BenchmarkManifestTests(unittest.TestCase):
    def test_twenty_stratified_frozen_rows_have_unhinted_model_views(self):
        from agent.evaluation.benchmark_manifest import build_benchmark_manifest, model_input, DATASET_REVISION
        first = build_benchmark_manifest(rows(), dataset_revision=DATASET_REVISION, seed="fixed")
        second = build_benchmark_manifest(list(reversed(rows())), dataset_revision=DATASET_REVISION, seed="fixed")
        self.assertEqual(first, second)
        self.assertEqual(len(first["tasks"]), 20)
        self.assertEqual(len({task["repo"] for task in first["tasks"]}), 8)
        self.assertEqual(sum(task["budget_microcny"] for task in first["tasks"]), 4000000)
        for task in first["tasks"]:
            view = model_input(first, task["instance_id"])
            self.assertEqual(set(view), {"repo", "base_commit", "problem_statement"})
            self.assertNotIn("CANARY", str(view))
            self.assertEqual(task["cohort"], "holdout")

    def test_seen_instance_and_same_revision_never_enter_holdout(self):
        from agent.evaluation.benchmark_manifest import build_benchmark_manifest, DATASET_REVISION
        supplied = rows()
        known = {**supplied[0], "repo": "sympy/sympy", "instance_id": "sympy__sympy-20590"}
        supplied += [known, {**known, "instance_id": "sympy__sympy-20591"}]
        manifest = build_benchmark_manifest(supplied, dataset_revision=DATASET_REVISION)
        self.assertFalse(any(task["repo"] == "sympy/sympy" for task in manifest["tasks"]))
        self.assertFalse(manifest["execution_admitted"])
        self.assertTrue(manifest["fresh_run_id_required"])

    def test_invalid_rows_revision_policy_and_duplicate_ids_are_rejected(self):
        from agent.evaluation.benchmark_manifest import build_benchmark_manifest, DATASET_REVISION, DEFAULT_POLICY
        with self.assertRaises(ValueError):
            build_benchmark_manifest(rows(), dataset_revision="0" * 40)
        with self.assertRaises(ValueError):
            build_benchmark_manifest(rows(), dataset_revision=DATASET_REVISION,
                                     policy={**DEFAULT_POLICY, "budget_microcny": 1000000})
        with self.assertRaises(ValueError):
            build_benchmark_manifest(rows() + [rows()[0]], dataset_revision=DATASET_REVISION)
        for key, value in (("base_commit", "main"), ("repo", "../escape"),
                           ("problem_statement", ""), ("FAIL_TO_PASS", "[]"),
                           ("PASS_TO_PASS", '["test_failure"]')):
            invalid = rows()
            invalid[0][key] = value
            with self.assertRaises(ValueError, msg=key):
                build_benchmark_manifest(invalid, dataset_revision=DATASET_REVISION)

    def test_insufficient_unseen_revisions_rejected_and_modified_manifest_not_rendered(self):
        from agent.evaluation.benchmark_manifest import build_benchmark_manifest, model_input, DATASET_REVISION
        supplied = rows()
        for row in supplied:
            row["base_commit"] = "1" * 40
        with self.assertRaises(ValueError):
            build_benchmark_manifest(supplied, dataset_revision=DATASET_REVISION)
        manifest = build_benchmark_manifest(rows(), dataset_revision=DATASET_REVISION)
        changed = copy.deepcopy(manifest)
        changed["tasks"][0]["problem_statement"] += " modified"
        with self.assertRaises(ValueError):
            model_input(changed, changed["tasks"][0]["instance_id"])
        with self.assertRaises(ValueError):
            model_input(manifest, "unknown")

    def test_cli_prepares_only_fresh_directory_after_external_pin_validation(self):
        script = Path(__file__).resolve().parents[2] / "scripts/prepare_benchmark.py"
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "rows.json", Path(directory) / "prepared"
            data = json.dumps(rows()).encode()
            source.write_bytes(data)
            command = [sys.executable, str(script), "--rows-json", str(source), "--output", str(output),
                       "--expected-sha256"]
            invalid = subprocess.run(command + ["0" * 64], capture_output=True, text=True, timeout=20)
            self.assertEqual(invalid.returncode, 2)
            self.assertFalse(output.exists())
            valid = subprocess.run(command + [hashlib.sha256(data).hexdigest()], capture_output=True, text=True, timeout=20)
            self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
            schedule = json.loads((output / "schedule.json").read_text(encoding="utf-8"))
            self.assertNotIn("CANARY", json.dumps(schedule))
            self.assertNotIn("evaluator_rows", schedule)
            self.assertFalse(schedule["execution_admitted"])
            self.assertEqual(len(json.loads((output / "model_inputs.json").read_text(encoding="utf-8"))), 20)
            repeated = subprocess.run(command + [hashlib.sha256(data).hexdigest()], capture_output=True, text=True, timeout=20)
            self.assertEqual(repeated.returncode, 2)

    def test_ambiguous_repository_segments_and_single_repository_profile_are_rejected(self):
        from agent.evaluation.benchmark_manifest import build_benchmark_manifest, DATASET_REVISION
        for repository in ("../repo", "org/..", "./repo", "org/."):
            invalid = rows()
            invalid[0].update(repo=repository, instance_id=repository.replace("/", "__") + "-1")
            with self.assertRaises(ValueError):
                build_benchmark_manifest(invalid, dataset_revision=DATASET_REVISION)
        invalid = rows()
        for index, row in enumerate(invalid):
            row.update(repo="org/repo", instance_id=f"org__repo-{index + 1}")
        with self.assertRaises(ValueError):
            build_benchmark_manifest(invalid, dataset_revision=DATASET_REVISION)
