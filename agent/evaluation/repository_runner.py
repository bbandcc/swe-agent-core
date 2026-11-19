"""Concrete cooperative repository runner; only its fixed host observer runs."""
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import uuid

from agent.evaluation.attempt_receipts import bind_attempt_receipts
from agent.evaluation.repository_candidate import CandidatePolicy, freeze_candidate
from agent.evaluation.repository_observer import RepositoryObserverSetup, capture_tree, digest, validate_setup
from agent.evaluation.repository_container import parse_cases
from agent.evaluation.swebench_cooperative import cleanup_cooperative_lease
from agent.verification.contracts import VerificationCheckStatus, VerificationResult, VerificationSpec, VerificationSummary
from agent.verification.runner import VerificationRunner
from agent.workspace import has_single_regular_file_link


class RepositoryObserverRunner:
    """Independent JSON-case profile; not arbitrary repository execution support."""
    def __init__(self, setup, *, runtime_root, policy=None, timeout_seconds=150.0):
        if type(setup) is not RepositoryObserverSetup or not validate_setup(setup):
            raise ValueError('Fixed observer inputs required')
        if type(timeout_seconds) not in (int, float) or not 30 <= timeout_seconds <= 180:
            raise ValueError('Finite check deadline required')
        self.setup = self._setup = setup
        if (os.environ.get('PYTEST_DISABLE_PLUGIN_AUTOLOAD') != '1'
                or os.environ.get('PYTHONDONTWRITEBYTECODE') != '1'
                or any(os.environ.get(k) for k in ('PYTEST_ADDOPTS','PYTEST_PLUGINS','PYTHONPATH','PYTHONHOME'))):
            raise ValueError('Fixed plugin-free observer environment required')
        self.generation_root, self.execution_root = setup.generation_root, setup.observer_root
        self.runtime_root = Path(runtime_root).resolve()
        if any(self.runtime_root == r or r in self.runtime_root.parents or self.runtime_root in r.parents
               for r in (setup.baseline_root, setup.generation_root, setup.dependency_root, setup.observer_root)):
            raise ValueError('Runtime must not overlap executable inputs')
        self.policy = self._policy = policy or CandidatePolicy()
        if type(self.policy) is not CandidatePolicy: raise ValueError('Concrete source policy required')
        self.spec = VerificationSpec('repository-cooperative', (sys.executable, '-m', 'pytest', '-q',
            '-p', 'no:cacheprovider', '--assert=plain', '--noconftest', f'--confcutdir={self.execution_root}',
            '-c', str(self.execution_root/'pytest.ini'), f'--rootdir={self.execution_root}',
            str(self.execution_root/'test_observer.py'), '--junitxml=report.xml'),
            timeout_seconds=timeout_seconds, report_path='report.xml')
        self._spec, self._environment = self.spec, dict(os.environ)
        self._runner = self._fixed_runner = VerificationRunner(self.execution_root, runtime_root=self.runtime_root)
        self._boundary = (self.generation_root, self.execution_root, self.runtime_root)
        self._run = self.run
        self.receipts = []

    def cleanup(self):
        return cleanup_cooperative_lease(self.setup.root)

    def permits(self, spec, workspace_root):
        try:
            return (self.setup is self._setup and self.policy == self._policy
                and self._boundary == (self.generation_root, self.execution_root, self.runtime_root)
                and self.run == self._run and type(self._runner) is VerificationRunner and self._runner is self._fixed_runner
                and self._runner.execution_root == self.execution_root and dict(os.environ) == self._environment
                and type(spec) is VerificationSpec and self.spec == self._spec
                and 0 < spec.timeout_seconds <= self._spec.timeout_seconds
                and replace(spec, timeout_seconds=self._spec.timeout_seconds) == self._spec
                and Path(workspace_root).resolve(strict=True) == self.generation_root
                and validate_setup(self.setup))
        except (OSError, TypeError, ValueError): return False

    def _freeze(self, target):
        result = freeze_candidate(self.setup.baseline_root, self.generation_root, self.policy, target)
        if not result.ok: raise ValueError('Candidate rejected: ' + result.error_code)
        manifest = capture_tree(result.snapshot.root)[1]
        if digest(manifest) != result.snapshot.tree_sha256: raise ValueError('Snapshot identity differs')
        return manifest

    def _source(self):
        path = self.setup.root/('.inspect-' + uuid.uuid4().hex)
        try: return self._freeze(path)
        finally:
            if (path.exists() and not path.is_symlink() and not path.is_junction()
                    and path.resolve().parent == self._setup.root.resolve()): shutil.rmtree(path)

    def _write(self, path, value):
        if path.exists() and not has_single_regular_file_link(path): raise ValueError('Unsafe control path')
        temp = self.setup.root/('control-' + uuid.uuid4().hex)
        with temp.open('x', encoding='utf-8') as stream: json.dump(value, stream)
        temp.replace(path)

    def run(self, spec):
        if not self.permits(spec, self.generation_root): return self._error(self._spec, 'Repository inputs changed')
        root = self.setup.root
        attempt = uuid.uuid4().hex
        started = time.monotonic()
        receipt_path = root/'receipt.json'
        try:
            if not self.cleanup(): raise ValueError('Unresolved parent lease')
            snapshots = root/'snapshots'
            if snapshots.is_symlink() or snapshots.is_junction(): raise ValueError('Unsafe snapshots')
            snapshots.mkdir(exist_ok=True)
            snapshot = snapshots/attempt
            name = 'swe-cooperative-' + attempt
            self._write(root/'lease.json', {'container_name':name,'snapshot':str(snapshot)})
            manifest = self._freeze(snapshot)
            tree_hash = digest(manifest)
            if receipt_path.exists():
                if not has_single_regular_file_link(receipt_path): raise ValueError('Unsafe receipt')
                receipt_path.unlink()
            remaining = spec.timeout_seconds - (time.monotonic()-started) - 15
            if remaining < 1: raise ValueError('Snapshot exhausted deadline')
            self._write(root/'control.json', {'snapshot':str(snapshot),'source_hash':tree_hash,
                'attempt_id':attempt,'container_name':name,'timeout_seconds':min(120,remaining)})
            result = self._runner.run(replace(spec, timeout_seconds=remaining))
            if not self.cleanup(): raise ValueError('Parent could not confirm removal')
            if result.status in (VerificationCheckStatus.TIMEOUT, VerificationCheckStatus.EXECUTION_ERROR):
                return replace(result, stdout='', stderr='', message='Repository observer did not complete')
            if not has_single_regular_file_link(receipt_path) or receipt_path.stat().st_size > 256*1024:
                raise ValueError('Missing/big receipt')
            receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
            if (receipt.get('receipt_id') != attempt or receipt.get('source_hash') != tree_hash
                    or receipt.get('task_digest') != self.setup.task_digest or receipt.get('image') != self.setup.task.image
                    or receipt.get('cleanup_complete') is not True or result.report is None
                    or len(result.report.cases) != len(self.setup.task.case_ids)):
                raise ValueError('Wrong receipt/report identity')
            parse_cases(receipt['execution'], self.setup.task.case_ids)
            if self._source() != manifest or not self.permits(spec, self.generation_root):
                raise ValueError('Inputs changed during execution')
            result = replace(result, stdout='Cooperative repository cases completed; not adversarial proof.',
                stderr='', message='repository_receipt=' + attempt)
            receipt.update(cooperative_only=True, adversarial_proof=False,
                result_digest=hashlib.sha256(json.dumps(asdict(VerificationSummary.from_result(result)),
                    sort_keys=True, default=str).encode()).hexdigest())
            self.receipts.append(receipt)
            return result
        except (OSError, ValueError, TypeError, KeyError) as error:
            return self._error(spec, str(error))
        finally: self.cleanup()

    def bind_attempts(self, result, *, runtime_root):
        return bind_attempt_receipts(result, runtime_root=runtime_root, configured_runtime_root=self.runtime_root,
            generation_root=self.generation_root, receipts=self.receipts, source_reader=self._source,
            receipt_prefix='repository_receipt=')

    @staticmethod
    def _error(spec, message):
        return VerificationResult.create(name=spec.name, argv=spec.argv, cwd=spec.cwd,
            status=VerificationCheckStatus.EXECUTION_ERROR, exit_code=None, message=message,
            allowed_failure_case_ids=spec.allowed_failure_case_ids)


class RepositoryAdmission:
    """Only the concrete fixed repository observer, never a boolean trust switch."""
    def __init__(self, runner):
        if type(runner) is not RepositoryObserverRunner: raise ValueError('Concrete repository runner required')
        self.runner = runner

    def permits(self, spec, runner, workspace_root):
        return runner is self.runner and type(runner) is RepositoryObserverRunner and runner.permits(spec, workspace_root)
