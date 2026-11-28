"""Concrete cooperative Flask4045 execution, original graph and native audit."""
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import time
import uuid

from agent.evaluation.native_flask import candidate, container, ownership, profile
from agent.evaluation.native_observer import native_observer_spec, observe_native_result
from agent.evaluation.native_receipts import bind_native_receipts
from agent.evaluation.native_result import NativeAttemptIdentity
from agent.evaluation.native_task_spec import NativeTaskSpec
from agent.evaluation.repository_candidate import freeze_candidate
from agent.evaluation.repository_observer import capture_tree, tree_fingerprint
from agent.verification.contracts import (
    VerificationAttempt, VerificationAttemptStatus, VerificationCheckStatus,
    VerificationResult, VerificationSummary, verification_spec_digest,
)
from agent.workspace import has_single_regular_file_link


def _digest(value):
    return hashlib.sha256(profile.encoded(value)).hexdigest()


class NativeFlaskRunner:
    """Caller holds the fixed Flask owner lock until graph and cleanup finish.

    Only this reviewed task, source view and two offline wheels are supported.
    Native logs share the candidate's process and are not adversarial evidence.
    """

    def __init__(self, task, identity, *, baseline_root, generation_root,
                 control_root, runtime_root, wheels, test_patch, lease, owner_root):
        if type(task) is not NativeTaskSpec or _digest(asdict(task)) != profile.SPEC:
            raise ValueError('Fixed Flask spec required')
        roots = tuple(ownership.ordinary(p) for p in
            (baseline_root, generation_root, control_root, runtime_root, owner_root))
        if any(a == b or a in b.parents or b in a.parents
               for i, a in enumerate(roots) for b in roots[i + 1:]):
            raise ValueError('Native Flask roots overlap')
        self.baseline_root, self.generation_root, self.root, self.runtime_root, self.owner_root = roots
        if (identity.task_id != task.instance_id
                or identity.workspace.canonical_root != str(self.generation_root)
                or tree_fingerprint(self.baseline_root) != profile.BASELINE
                or tree_fingerprint(self.generation_root) != profile.BASELINE):
            raise ValueError('Native Flask source/identity mismatch')
        if (ownership.ordinary(lease['directory']) != self.owner_root
                or not lease.get('_active') or lease['closed']
                or ownership.recover_flask(self.owner_root)['status'] != 'OWNER_ACTIVE'):
            raise ValueError('Active Flask owner lease required')
        if type(test_patch) is not bytes or profile.sha(test_patch) != profile.TEST_PATCH:
            raise ValueError('Fixed Flask test patch required')
        if type(wheels) is not dict or set(wheels) != set(profile.PINS):
            raise ValueError('Fixed Flask wheels required')
        self.wheels = {name: ownership.ordinary(path) for name, path in wheels.items()}
        self._wheel_bytes = {}
        for name, path in self.wheels.items():
            size, sha = profile.PINS[name]
            if not has_single_regular_file_link(path) or path.stat().st_size != size:
                raise ValueError('Fixed Flask wheel identity required')
            data = path.read_bytes()
            if profile.sha(data) != sha:
                raise ValueError('Fixed Flask wheel identity required')
            self._wheel_bytes[name] = data
        self.root.mkdir(exist_ok=False)
        self.task, self.identity, self.lease = task, identity, lease
        self.policy = candidate.fixed_policy()
        self.test_patch = test_patch
        self.execution_root = self.root / 'observer'
        self.spec = native_observer_spec(self.execution_root, timeout_seconds=150)
        self._spec, self._run = self.spec, self.run
        self._roots = roots
        self._owner = lease['owner']
        self._code = candidate.host_identity()
        self._pending = None
        self._seen = set()
        self.receipts, self.native_attempts, self.case_mapping = [], [], ()
        self.environment_sha = None

    def permits(self, spec, workspace_root):
        try:
            return (self.spec == self._spec and replace(spec, timeout_seconds=150) == self._spec
                and 0 < spec.timeout_seconds <= 150 and self.run == self._run
                and Path(workspace_root).resolve() == self.generation_root
                and self._roots == (self.baseline_root, self.generation_root, self.root,
                    self.runtime_root, self.owner_root)
                and _digest(asdict(self.task)) == profile.SPEC
                and self.policy == candidate.fixed_policy()
                and profile.sha(self.test_patch) == profile.TEST_PATCH
                and candidate.host_identity() == self._code
                and tree_fingerprint(self.baseline_root) == profile.BASELINE
                and set(self.wheels) == set(profile.PINS)
                and all(has_single_regular_file_link(p) and p.read_bytes() == self._wheel_bytes[n]
                        for n, p in self.wheels.items())
                and self.lease.get('_active') and not self.lease['closed']
                and self.lease['owner'] == self._owner
                and ownership.ordinary(self.lease['directory']) == self.owner_root
                and not self.lease['creation_unknown'] and not self.lease['creation_in_flight']
                and time.monotonic() < self.lease['deadline']
                and ownership.recover_flask(self.owner_root)['status'] == 'OWNER_ACTIVE')
        except (OSError, ValueError, TypeError, KeyError):
            return False

    def bind_attempt(self, attempt):
        if (type(attempt) is not VerificationAttempt
                or attempt.status is not VerificationAttemptStatus.STARTED
                or attempt.run_id != self.identity.run_id or attempt.task_id != self.task.instance_id
                or attempt.spec_digest != verification_spec_digest(self.spec)
                or attempt.spec_index != 0 or attempt.attempt_ordinal != 0
                or not 0 <= attempt.repair_attempt <= 2
                or attempt.phase == 'baseline' and attempt.repair_attempt != 0
                or attempt.attempt_id in self._seen or self._pending is not None):
            return False
        self._pending = attempt
        return True

    def _source(self):
        return capture_tree(self.generation_root)[1]

    def run(self, spec):
        started = time.monotonic()
        attempt, self._pending = self._pending, None
        if attempt is None or not self.permits(spec, self.generation_root):
            return self._error(spec)
        self._seen.add(attempt.attempt_id)
        deadline = min(started + spec.timeout_seconds, self.lease['deadline'])
        receipt = uuid.uuid4().hex
        case = self.root / receipt[:12]
        try:
            case.mkdir(exist_ok=False)
            frozen = freeze_candidate(self.baseline_root, self.generation_root, self.policy, case / 'snapshot')
            if not frozen.ok:
                raise ValueError('Flask candidate rejected')
            prepared = candidate.prepare_candidate(frozen.snapshot, self.policy,
                baseline_root=self.baseline_root, task=self.task, test_patch=self.test_patch,
                wheels=self.wheels, directory=case / 'prepared')
            if self.environment_sha is None:
                self.environment_sha = prepared.environment_sha256
            elif self.environment_sha != prepared.environment_sha256:
                raise ValueError('Flask baseline/post environment changed')
            remaining = deadline - time.monotonic()
            if remaining <= 20:
                raise ValueError('Flask preparation exhausted deadline')
            observed = container.observe(prepared, self.lease, timeout_seconds=min(120, remaining - 20))
            if (observed.get('status') != 'OBSERVED' or not observed.get('cleanup_complete')
                    or observed.get('creation_unknown') or not observed.get('gate_released')):
                raise ValueError('Flask execution incomplete')
            guest = json.loads((prepared.directory / 'guest-result.json').read_text(encoding='utf-8'))
            source_sha = frozen.snapshot.tree_sha256
            if (guest.get('candidate_sha256') != source_sha
                    or guest.get('environment_sha256') != self.environment_sha):
                raise ValueError('Flask observation identity changed')
            native_identity = NativeAttemptIdentity(self.task.instance_id, self.task.row_sha256,
                profile.IMAGE, self.environment_sha, source_sha, receipt,
                attempt.phase, attempt.repair_attempt)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('Flask check deadline exhausted')
            result = observe_native_result(self.task, native_identity, expected_identity=native_identity,
                log=guest['native_log'], exit_code=guest.get('exit_code'),
                completed=guest.get('phase') == 'completed', cleanup_complete=observed['cleanup_complete'],
                directory=self.execution_root, runtime_root=self.runtime_root,
                timeout_seconds=min(30, remaining))
            if result.verification.status is VerificationCheckStatus.EXECUTION_ERROR:
                return result.verification
            if profile.sha(self._source()) != source_sha:
                raise ValueError('Flask final source changed')
            if time.monotonic() >= deadline:
                raise ValueError('Flask observer/source audit exhausted deadline')
            self.case_mapping = result.case_mapping
            self.native_attempts.append(result.native)
            self.receipts.append({'receipt_id': receipt, 'source_hash': source_sha,
                'result_digest': hashlib.sha256(json.dumps(asdict(
                    VerificationSummary.from_result(result.verification)), sort_keys=True, default=str).encode()).hexdigest()})
            return result.verification
        except (OSError, ValueError, TypeError, KeyError):
            return self._error(spec)

    def bind_attempts(self, result, *, runtime_root):
        if (not self.lease.get('cleanup_complete') or not self.lease['closed']
                or self.lease.get('creation_unknown')
                or ownership.recover_flask(self.owner_root)['status'] != 'CLEANED'):
            raise ValueError('Global Flask cleanup incomplete')
        return bind_native_receipts(result, spec=self.task, runtime_root=runtime_root,
            configured_runtime_root=self.runtime_root, generation_root=self.generation_root,
            receipts=self.receipts, native_attempts=tuple(self.native_attempts), source_reader=self._source,
            receipt_prefix='native_receipt=', case_mapping=self.case_mapping,
            expected_image=profile.IMAGE, expected_environment_sha256=self.environment_sha)

    @staticmethod
    def _error(spec):
        return VerificationResult.create(name=spec.name, argv=spec.argv, cwd=spec.cwd,
            status=VerificationCheckStatus.EXECUTION_ERROR, exit_code=None,
            message='Native Flask execution could not be verified')
