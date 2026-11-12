"""Data-only tests; never import or execute the pinned foreign repository."""

import copy
import hashlib
import json
import unittest
from pathlib import Path

from agent.evaluation.swebench_instance import admit_swebench_instance, grade_swebench_instance
from agent.verification.contracts import (
    REPORT_SCHEMA,
    VerificationCase,
    VerificationCaseStatus,
    VerificationReport,
)


ASSET = Path(__file__).resolve().parents[2] / "evals/swebench/sympy__sympy-20590.json"
EDITABLE = ("sympy/core/_print_helpers.py",)
ORACLE = ("sympy/core/tests/test_basic.py",)
PINNED_ROW_SHA256 = "feb99cda40e77a4391d300261f7a511072080217fef21c94afdd58c0000e9382"


def pinned_digest(row):
    encoded = (json.dumps(row, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
    return hashlib.sha256(encoded).hexdigest()


class SwebenchAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.asset = json.loads(ASSET.read_text(encoding="utf-8-sig"))
        self.row = copy.deepcopy(self.asset["row"])

    def admit(self, row=None, *, expected=None, editable=EDITABLE, oracle=ORACLE):
        return admit_swebench_instance(
            self.row if row is None else row,
            expected_sha256=expected or PINNED_ROW_SHA256,
            editable_paths=editable,
            oracle_paths=oracle,
        )

    def test_official_pinned_row_has_workspace_task_and_exact_case_ids(self):
        self.assertEqual(self.asset["provenance"]["canonical_row_sha256"], PINNED_ROW_SHA256)
        self.assertEqual(self.asset["provenance"]["dataset_revision"], "6ec7bb89b9342f664a54a6e0a6ea6501d3437cc2")
        result = self.admit()
        self.assertTrue(result.valid, result.issues)
        instance = result.instance
        self.assertEqual(instance.instance_id, "sympy__sympy-20590")
        self.assertEqual(instance.repository, "sympy/sympy")
        self.assertEqual(instance.fail_to_pass, ("test_immutable",))
        self.assertEqual(len(instance.pass_to_pass), 21)
        self.assertEqual(instance.gold_patch_sha256, self.asset["provenance"]["patch_sha256"])
        self.assertEqual(instance.test_patch_sha256, self.asset["provenance"]["test_patch_sha256"])
        self.assertFalse(hasattr(instance, "hints_text"))
        self.assertFalse(hasattr(instance, "patch"))
        self.assertFalse(hasattr(instance, "test_patch"))
        task = instance.workspace_task()
        self.assertEqual(task["target"]["revision"], self.row["base_commit"])
        self.assertEqual(task["allowed_edit_scope"], [{"path": EDITABLE[0], "operation": "modify"}])
        self.assertEqual(task["oracle"]["test_files"], [{"path": ORACLE[0]}])
        self.assertFalse(result.execution_admitted)

    def test_patch_paths_must_match_trusted_scope_and_protect_oracle(self):
        for editable, oracle in ((ORACLE, ORACLE), (EDITABLE, EDITABLE),
                                 (("sympy/core",), ORACLE),
                                 (("sympy\\core\\_print_helpers.py",), ORACLE)):
            with self.subTest(editable=editable, oracle=oracle):
                result = self.admit(editable=editable, oracle=oracle)
                self.assertFalse(result.valid)
                self.assertIsNone(result.instance)

    def test_malformed_or_unpinned_rows_are_structured_rejections(self):
        changed = copy.deepcopy(self.row)
        changed["base_commit"] = "0" * 40
        self.assertEqual(self.admit(changed).issues[0].code, "row_identity")
        for field, value in (("repo", "other/repository"), ("base_commit", "HEAD"),
                             ("instance_id", "sympy__sympy-invalid"),
                             ("problem_statement", ""), ("patch", None),
                             ("FAIL_TO_PASS", "[]"), ("PASS_TO_PASS", '["test_immutable"]'),
                             ("FAIL_TO_PASS", '["test_immutable", "test_immutable"]'),
                             ("PASS_TO_PASS", "__import__('os')")):
            with self.subTest(field=field, value=value):
                row = copy.deepcopy(self.row)
                row[field] = value
                result = self.admit(row, expected=pinned_digest(row))
                self.assertFalse(result.valid)
                self.assertIsNone(result.instance)
        for malformed in (None, [], {"x": float("nan")}):
            with self.subTest(malformed=malformed):
                self.assertFalse(admit_swebench_instance(
                    malformed, expected_sha256="0" * 64,
                    editable_paths=EDITABLE, oracle_paths=ORACLE,
                ).valid)
        huge = copy.deepcopy(self.row)
        huge["problem_statement"] = "x" * (2 * 1024 * 1024)
        self.assertFalse(self.admit(huge, expected=pinned_digest(huge)).valid)

    def test_ordinary_file_creation_is_distinct_from_modification(self):
        row = copy.deepcopy(self.row)
        row["patch"] = ("diff --git a/sympy/core/new.py b/sympy/core/new.py\n"
                        "new file mode 100644\n--- /dev/null\n+++ b/sympy/core/new.py\n"
                        "@@ -0,0 +1 @@\n+answer = 42\n")
        result = self.admit(row, expected=pinned_digest(row), editable=("sympy/core/new.py",))
        self.assertTrue(result.valid, result.issues)
        self.assertEqual(result.instance.editable_scope, (("sympy/core/new.py", "create"),))

    def test_patch_grammar_rejects_unsupported_or_inconsistent_edits(self):
        patch = self.row["patch"]
        bad_patches = [
            patch.replace("@@ -17,6 +17,11 @@", "@@ -0,6 +17,11 @@"),
            patch.replace("@@ -17,6 +17,11 @@", "@@ -17,999 +17,11 @@"),
            patch.replace("--- a/", "old mode 100644\nnew mode 100755\n--- a/"),
            patch.replace("--- a/", "rename from old.py\nrename to new.py\n--- a/"),
            patch.replace("--- a/", "GIT binary patch\n--- a/"),
            patch.replace("b/sympy/core/_print_helpers.py", "b/sympy/core/other.py", 1),
            patch.replace("sympy/core/_print_helpers.py", "../outside.py"),
            patch.replace("sympy/core/_print_helpers.py", "C:/outside.py"),
            patch.replace("--- a/sympy/core/_print_helpers.py", "--- /dev/null"),
            patch.replace("+++ b/sympy/core/_print_helpers.py", "+++ /dev/null"),
            patch + patch,
            patch[:-2],
            "diff --git a/x b/x\nnew file mode 120000\n--- /dev/null\n+++ b/x\n@@ -0,0 +1 @@\n+target\n",
        ]
        for bad in bad_patches:
            with self.subTest(patch=bad[:90]):
                row = copy.deepcopy(self.row)
                row["patch"] = bad
                self.assertFalse(self.admit(row, expected=pinned_digest(row)).valid)


class SwebenchStrictGradingTests(unittest.TestCase):
    def setUp(self):
        self.asset = json.loads(ASSET.read_text(encoding="utf-8-sig"))
        self.instance = admit_swebench_instance(
            self.asset["row"],
            expected_sha256=PINNED_ROW_SHA256,
            editable_paths=EDITABLE, oracle_paths=ORACLE,
        ).instance

    def reports(self, *, instance=None, mapping=None):
        instance = instance or self.instance
        mapping = mapping or {}
        baseline = tuple(VerificationCase("official", mapping.get(case_id, case_id),
                         VerificationCaseStatus.FAIL if case_id in instance.fail_to_pass else VerificationCaseStatus.PASS)
                         for case_id in instance.fail_to_pass + instance.pass_to_pass)
        post = tuple(VerificationCase("official", case.case_id, VerificationCaseStatus.PASS) for case in baseline)
        return baseline, post

    def test_exact_f2p_and_p2p_evidence_passes(self):
        baseline, post = self.reports()
        result = grade_swebench_instance(
            self.instance,
            VerificationReport("official", REPORT_SCHEMA, baseline),
            VerificationReport("official", REPORT_SCHEMA, post),
        )
        self.assertTrue(result.resolved, result.issues)
        self.assertTrue(result.fail_to_pass_passed)
        self.assertIs(result.pass_to_pass_passed, True)

    def test_missing_duplicate_or_different_report_identity_is_rejected(self):
        baseline, post = self.reports()
        wrong_check = tuple(VerificationCase("other-check", case.case_id, case.status) for case in post)
        for before, after in ((None, post), (baseline, None),
                              (baseline[1:], post), (baseline, post[1:]),
                              (baseline + baseline[:1], post),
                              (baseline, post + post[:1]),
                              (baseline, wrong_check),
                              (baseline, post + (VerificationCase("official", "unexpected", VerificationCaseStatus.PASS),))):
            with self.subTest(before=before is None, after=after is None):
                result = grade_swebench_instance(self.instance, before, after)
                self.assertFalse(result.resolved)
                self.assertTrue(result.issues)

    def test_bad_transitions_skip_and_error_never_pass(self):
        baseline, post = self.reports()
        for index in (0, 1):
            for status in VerificationCaseStatus:
                before = list(baseline)
                before[index] = VerificationCase("official", before[index].case_id, status)
                if status != baseline[index].status:
                    self.assertFalse(grade_swebench_instance(self.instance, before, post).resolved)
                after = list(post)
                after[index] = VerificationCase("official", after[index].case_id, status)
                if status != VerificationCaseStatus.PASS:
                    self.assertFalse(grade_swebench_instance(self.instance, baseline, after).resolved)

    def test_explicit_mapping_is_bijective_and_prefixes_are_not_guessed(self):
        mapping = {case: f"sympy.core.tests.test_basic::{case}" for case in self.instance.fail_to_pass + self.instance.pass_to_pass}
        baseline, post = self.reports(mapping=mapping)
        self.assertFalse(grade_swebench_instance(self.instance, baseline, post).resolved)
        self.assertTrue(grade_swebench_instance(self.instance, baseline, post, case_id_mapping=mapping).resolved)
        incomplete = dict(mapping)
        del incomplete[self.instance.pass_to_pass[-1]]
        duplicate = {case: "same-case" for case in mapping}
        for bad_mapping in (incomplete, duplicate, {**mapping, "untrusted-extra": "extra"}):
            result = grade_swebench_instance(self.instance, baseline, post, case_id_mapping=bad_mapping)
            self.assertFalse(result.resolved)

    def test_empty_p2p_is_not_applicable_instead_of_100_percent(self):
        row = copy.deepcopy(self.asset["row"])
        row["PASS_TO_PASS"] = "[]"
        instance = admit_swebench_instance(row, expected_sha256=pinned_digest(row), editable_paths=EDITABLE, oracle_paths=ORACLE).instance
        baseline, post = self.reports(instance=instance)
        result = grade_swebench_instance(instance, baseline, post)
        self.assertTrue(result.resolved)
        self.assertIsNone(result.pass_to_pass_passed)


if __name__ == "__main__":
    unittest.main()
