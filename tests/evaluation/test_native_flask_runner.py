"""Concrete Flask admission must reject before resource creation."""
import unittest
from pathlib import Path
import shutil
import tempfile
import json
import time
from types import SimpleNamespace
from unittest.mock import patch
from agent.evaluation.native_runner import NativeAdmission
from tests.evaluation import test_native_result as fixtures


class NativeFlaskRunnerTests(unittest.TestCase):
    def test_foreign_task_is_rejected_before_paths_or_docker(self):
        from agent.evaluation.native_flask_runner import NativeFlaskRunner
        fixture = fixtures.NativeResultTests(); fixture.setUp()
        with patch('pathlib.Path.mkdir', side_effect=AssertionError('no filesystem work')):
            with self.assertRaisesRegex(ValueError, 'Fixed Flask spec'):
                NativeFlaskRunner(fixture.spec, None, baseline_root='unused', generation_root='unused',
                    control_root='unused', runtime_root='unused', wheels={}, test_patch=b'',
                    lease={}, owner_root='unused')

    def test_native_admission_does_not_accept_flask_shaped_foreign_runner(self):
        class Foreign:
            def permits(self, *args): return True
            def bind_attempt(self, attempt): return True
        with self.assertRaises(ValueError): NativeAdmission(Foreign())

    def test_fixed_materials_require_active_owner_and_current_wheel_bytes(self):
        from tests.evaluation.test_native_flask_candidate import NativeFlaskCandidateTests
        from agent.evaluation.native_flask_runner import NativeFlaskRunner
        from agent.evaluation.native_flask import ownership
        from agent.runtime import RunIdentity, WorkspaceIdentity
        from agent.verification.contracts import VerificationCheckStatus, VerificationAttempt, VerificationResult
        from agent.runtime.revision import detect_workspace_revision
        fixture = NativeFlaskCandidateTests()
        baseline, task, test_patch, source_wheels = fixture.fixed_materials()
        with tempfile.TemporaryDirectory() as temporary, patch.object(ownership, 'command',
                side_effect=AssertionError('Admission must not execute Docker')):
            root = Path(temporary); generation = root / 'G'; shutil.copytree(baseline, generation)
            wheels = {}
            for name, source in source_wheels.items():
                wheels[name] = root / name; shutil.copyfile(source, wheels[name])
            identity = RunIdentity('flask-admission-run', 'flask-admission-thread', task.instance_id,
                WorkspaceIdentity.from_root(generation))
            with ownership.lease_owner(root / 'owner') as lease:
                runner = NativeFlaskRunner(task, identity, baseline_root=baseline, generation_root=generation,
                    control_root=root / 'control', runtime_root=root / 'runtime', wheels=wheels,
                    test_patch=test_patch, lease=lease, owner_root=root / 'owner')
                admission = NativeAdmission(runner)
                self.assertTrue(admission.permits(runner.spec, runner, generation))
                self.assertEqual(runner.run(runner.spec).status, VerificationCheckStatus.EXECUTION_ERROR)
                path = next(iter(wheels.values())); saved = path.read_bytes()
                path.write_bytes(saved[:-1] + bytes([saved[-1] ^ 1]))
                self.assertFalse(admission.permits(runner.spec, runner, generation))
                path.write_bytes(saved)
                self.assertTrue(admission.permits(runner.spec, runner, generation))
                attempt = VerificationAttempt.started(run_id=identity.run_id, task_id=task.instance_id,
                    phase='baseline', repair_attempt=0, spec_index=0, spec=runner.spec,
                    attempt_ordinal=0, workspace_revision=detect_workspace_revision(generation))
                self.assertTrue(runner.bind_attempt(attempt))
                now = [time.monotonic()]
                def observed(prepared, lease, **kwargs):
                    guest = {'phase':'completed', 'candidate_sha256':prepared.candidate_sha256,
                        'environment_sha256':prepared.environment_sha256, 'native_log':'', 'exit_code':0}
                    (prepared.directory/'guest-result.json').write_text(json.dumps(guest),encoding='utf-8')
                    return {'status':'OBSERVED','cleanup_complete':True,'creation_unknown':False,'gate_released':True}
                def late_observer(*args, **kwargs):
                    now[0] += 151
                    return SimpleNamespace(verification=VerificationResult.create(name=runner.spec.name,
                        argv=runner.spec.argv,cwd=runner.spec.cwd,status=VerificationCheckStatus.PASS,exit_code=0))
                with patch('agent.evaluation.native_flask_runner.time.monotonic',side_effect=lambda:now[0]), \
                        patch('agent.evaluation.native_flask_runner.container.observe',side_effect=observed), \
                        patch('agent.evaluation.native_flask_runner.observe_native_result',side_effect=late_observer):
                    self.assertEqual(runner.run(runner.spec).status,VerificationCheckStatus.EXECUTION_ERROR)
                self.assertEqual(runner.receipts,[])
                self.assertFalse(runner.bind_attempt(attempt))
            self.assertFalse(admission.permits(runner.spec, runner, generation))


if __name__ == '__main__': unittest.main()
