import hashlib
import json
import unittest

from agent.evaluation.benchmark_manifest import canonical_bytes


def row(repo="psf/requests", version="2.10", path="tests/test_requests.py"):
    return {"repo": repo, "instance_id": repo.replace("/", "__") + "-123",
            "base_commit": "1" * 40, "version": version, "problem_statement": "Repair behavior",
            "test_patch": f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n",
            "FAIL_TO_PASS": '["test_fail"]', "PASS_TO_PASS": '["test_keep"]'}


def digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


class NativeTaskSpecTests(unittest.TestCase):
    def test_requests_native_metadata_keeps_install_and_parser_contract(self):
        from agent.evaluation.native_task_spec import prepare_native_task
        value = row()
        spec = prepare_native_task(value, expected_row_sha256=digest(value))
        self.assertEqual(spec.test_argv, ("pytest", "-rA", "tests/test_requests.py"))
        self.assertEqual(spec.parser_id, "pytest-options")
        self.assertEqual(spec.environment.python_version, "3.9")
        self.assertEqual(spec.environment.install_argv, ("python", "-m", "pip", "install", "."))
        self.assertEqual(spec.fail_to_pass, ("test_fail",))
        self.assertEqual(spec.test_patch_sha256, hashlib.sha256(value["test_patch"].encode()).hexdigest())

    def test_native_commands_and_special_environment_remain_distinct(self):
        from agent.evaluation.native_task_spec import prepare_native_task
        django = row("django/django", "3.2", "tests/backends/base/test_creation.py")
        spec = prepare_native_task(django, expected_row_sha256=digest(django))
        self.assertEqual(spec.directives, ("backends.base.test_creation",))
        self.assertEqual(spec.test_argv[:2], ("./tests/runtests.py", "--verbosity"))
        self.assertIn("upstream-eval-writes:/etc/locale.gen", spec.environment.extra_state)
        self.assertEqual(dict(spec.test_environment)["LC_ALL"], "en_US.UTF-8")
        for repo, version, entry, parser in (("sympy/sympy", "1.6", "bin/test", "sympy"),
                                             ("sphinx-doc/sphinx", "3.4", "tox", "pytest-v2"),
                                             ("matplotlib/matplotlib", "3.6", "pytest", "matplotlib")):
            value = row(repo, version)
            spec = prepare_native_task(value, expected_row_sha256=digest(value))
            self.assertEqual(spec.test_argv[0], entry)
            self.assertEqual(spec.parser_id, parser)
        value = row("astropy/astropy", "1.3")
        spec = prepare_native_task(value, expected_row_sha256=digest(value))
        self.assertIn("console_output_style=classic", spec.test_argv)
        self.assertEqual(spec.environment.python_version, "3.6")

    def test_externally_pinned_identity_supported_versions_and_roster_are_required(self):
        from agent.evaluation.native_task_spec import prepare_native_task
        value = row()
        with self.assertRaises(ValueError):
            prepare_native_task(value, expected_row_sha256="0" * 64)
        with self.assertRaises(ValueError):
            prepare_native_task(value, expected_row_sha256=digest(value), harness_commit="main")
        for key, changed in (("version", "unknown"), ("base_commit", "main"), ("FAIL_TO_PASS", "[]"),
                             ("PASS_TO_PASS", '["test_fail"]'), ("PASS_TO_PASS", '["test_keep","test_keep"]')):
            invalid = {**value, key: changed}
            with self.assertRaises(ValueError, msg=key):
                prepare_native_task(invalid, expected_row_sha256=digest(invalid))
        for key in ("test_patch", "FAIL_TO_PASS", "version"):
            invalid = {k: v for k, v in value.items() if k != key}
            with self.assertRaises(ValueError, msg=key):
                prepare_native_task(invalid, expected_row_sha256=digest(invalid))

    def test_test_patch_paths_reject_escaping_duplicate_rename_and_nonportable_forms(self):
        from agent.evaluation.native_task_spec import prepare_native_task
        for path in ("../outside.py", "/outside.py", "C:/outside.py", "tests/./bad.py", "tests//bad.py", ".git/a.py", ".GIT/a.py", "tests/CON.py", "-bad.py"):
            value = row(path=path)
            with self.assertRaises(ValueError, msg=path):
                prepare_native_task(value, expected_row_sha256=digest(value))
        value = row()
        for patch in (value["test_patch"] * 2,
                      value["test_patch"].replace("b/tests/test_requests.py", "b/tests/other.py"),
                      value["test_patch"].replace("@@ -1 +1 @@", "@@ -1,8 +1,8 @@"),
                      value["test_patch"].replace("index ", "new file mode ") + "GIT binary patch\n"):
            invalid = {**value, "test_patch": patch}
            with self.assertRaises(ValueError):
                prepare_native_task(invalid, expected_row_sha256=digest(invalid))
