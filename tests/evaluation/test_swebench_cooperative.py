"""Public adapter contracts; repository execution stays opt-in and in Docker."""

import json
from pathlib import Path
import tempfile
import unittest
from dataclasses import replace
import os
import sys
from unittest.mock import patch

from agent.evaluation.swebench_cooperative import (
    CooperativeRunner, cleanup_cooperative_lease, cooperative_verification_spec,
)
from agent.verification.contracts import VerificationCase, VerificationCaseStatus, VerificationCheckStatus, VerificationReport, VerificationResult, REPORT_SCHEMA
from agent.verification.runner import VerificationRunner


class CooperativeContractTests(unittest.TestCase):
    def test_fixed_pytest_command_uses_only_author_reviewed_observer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            spec = cooperative_verification_spec(root)
            self.assertIn(str(root / "test_observer.py"), spec.argv)
            self.assertIn("--noconftest", spec.argv)
            self.assertIn(str(root / "pytest.ini"), spec.argv)
            self.assertEqual(spec.report_path, "report.xml")
            self.assertEqual(spec.name, "sympy-cooperative")

    def test_timeout_must_be_finite_and_leave_room_for_parent_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            for timeout in (0, -1, True, float("nan"), float("inf"), 15, 181):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    cooperative_verification_spec(directory, timeout_seconds=timeout)

    def test_no_lease_is_a_no_resource_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(cleanup_cooperative_lease(Path(directory)))

    def test_lease_cannot_target_other_containers_or_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for value in (
                {}, {"container_name": "user-container", "snapshot": str(root / "snapshots" / "attempt")},
                {"container_name": "swe-cooperative-" + "a" * 32, "snapshot": str(root.parent)},
            ):
                with self.subTest(value=value):
                    (root / "lease.json").write_text(json.dumps(value), encoding="utf-8")
                    self.assertFalse(cleanup_cooperative_lease(root))


class CooperativeRunnerTests(unittest.TestCase):
    def fixture(self):
        from agent.evaluation.swebench_instance import admit_swebench_instance
        from agent.evaluation.swebench_observer import SOURCE, TEST, assemble_cooperative_workspace
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        asset = Path(__file__).resolve().parents[2] / "evals/swebench/sympy__sympy-20590.json"
        row = json.loads(asset.read_text(encoding="utf-8-sig"))["row"]
        instance = admit_swebench_instance(row,
            expected_sha256="feb99cda40e77a4391d300261f7a511072080217fef21c94afdd58c0000e9382",
            editable_paths=(SOURCE,), oracle_paths=(TEST,)).instance
        setup = assemble_cooperative_workspace(root / "setup", instance=instance,
            source_files={SOURCE: b"# inert author fixture\n"},
            dependency_files={"mpmath.py": b"raise RuntimeError('not a host import')\n"},
            source_test_bytes=b"raise RuntimeError('not a host import')\n")
        environment = patch.dict(os.environ, {"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_ADDOPTS": "", "PYTEST_PLUGINS": "",
            "PYTHONPATH": "", "PYTHONHOME": ""})
        environment.start()
        self.addCleanup(environment.stop)
        return setup, CooperativeRunner(setup, runtime_root=root / "runtime")

    def response(self, setup, runner, spec, *, malformed=None):
        control = json.loads(setup.control_path.read_text())
        receipt = {"receipt_id": control["attempt_id"], "source_hash": control["source_hash"],
            "image": runner.image, "status": "completed", "cleanup_complete": True}
        setup.receipt_path.write_text(json.dumps(receipt if malformed is None else malformed))
        cases = tuple(VerificationCase(spec.name, f"test_observer::test_case[{case}]", VerificationCaseStatus.PASS)
                      for case in setup.instance.fail_to_pass + setup.instance.pass_to_pass)
        return VerificationResult.create(name=spec.name, argv=spec.argv, cwd=spec.cwd,
            status=VerificationCheckStatus.PASS, exit_code=0,
            report=VerificationReport(spec.name, REPORT_SCHEMA, cases))

    def test_public_spec_mutation_cannot_admit_another_host_command(self):
        setup, runner = self.fixture()
        changed = replace(runner.spec, argv=(sys.executable, "-c", "print('inert')"), report_path=None)
        self.assertFalse(runner.permits(changed, setup.generation_root))
        runner.spec = changed
        self.assertFalse(runner.permits(changed, setup.generation_root))

    def test_non_object_receipts_are_structured_execution_errors(self):
        for malformed in ([], ["invalid"], "invalid"):
            with self.subTest(malformed=malformed):
                setup, runner = self.fixture()
                with patch.object(CooperativeRunner, "cleanup", return_value=True), patch.object(
                    VerificationRunner, "run", lambda _, spec: self.response(setup, runner, spec, malformed=malformed)):
                    result = runner.run(runner.spec)
                self.assertEqual(result.status, VerificationCheckStatus.EXECUTION_ERROR)
                self.assertEqual(runner.receipts, [])

    def test_disappearing_source_after_admission_is_an_execution_error(self):
        from agent.evaluation import swebench_observer as observer
        setup, runner = self.fixture()
        read = observer.candidate_source
        def disappearing(value):
            content = read(value)
            (setup.generation_root / observer.SOURCE).unlink()
            return content
        with patch.object(observer, "candidate_source", disappearing):
            result = runner.run(runner.spec)
        self.assertEqual(result.status, VerificationCheckStatus.EXECUTION_ERROR)

    def test_observer_drift_is_refused_without_dispatch(self):
        setup, runner = self.fixture()
        (setup.observer_root / "test_observer.py").write_text("raise RuntimeError('never execute')\n")
        result = runner.run(runner.spec)
        self.assertEqual(result.status, VerificationCheckStatus.EXECUTION_ERROR)

    def test_unconfirmed_parent_cleanup_cannot_be_a_pass(self):
        setup, runner = self.fixture()
        with patch.object(CooperativeRunner, "cleanup", lambda item: not item.lease_path.exists()), patch.object(
            VerificationRunner, "run", lambda _, spec: self.response(setup, runner, spec)):
            result = runner.run(runner.spec)
        self.assertEqual(result.status, VerificationCheckStatus.EXECUTION_ERROR)
        self.assertEqual(runner.receipts, [])

    def test_worker_timeout_remains_timeout_without_a_complete_receipt(self):
        _, runner = self.fixture()
        def timed_out(_, spec):
            return VerificationResult.create(name=spec.name, argv=spec.argv, cwd=spec.cwd,
                status=VerificationCheckStatus.TIMEOUT, exit_code=None, stdout="private partial diagnostics")
        with patch.object(CooperativeRunner, "cleanup", return_value=True), patch.object(VerificationRunner, "run", timed_out):
            result = runner.run(runner.spec)
        self.assertEqual(result.status, VerificationCheckStatus.TIMEOUT)
        self.assertNotIn("private", result.stdout + result.stderr + result.message)

    def test_specific_research_admission_reaches_core_baseline_dispatch(self):
        from agent.evaluation.swebench_cooperative import CooperativeAdmission
        from agent.graph import AgentState
        from agent.verification.workflow import VerificationController
        setup, runner = self.fixture()
        controller = VerificationController((runner.spec,), runner, setup.generation_root,
            reviewed_inputs=CooperativeAdmission(runner))
        with patch.object(CooperativeRunner, "cleanup", return_value=True), patch.object(
            VerificationRunner, "run", lambda _, spec: self.response(setup, runner, spec)):
            state = controller.run_baseline(AgentState())
        self.assertEqual(state["baseline_verification"][0].status, VerificationCheckStatus.PASS)


if __name__ == "__main__":
    unittest.main()
