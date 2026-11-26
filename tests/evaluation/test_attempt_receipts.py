"""Original audit binding must be a bijection, not a matching row count."""
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from agent.evaluation.attempt_receipts import bind_attempt_receipts
from agent.runtime import AuditStatus, RunRecord, write_run_record
from agent.runtime.durable import DurableRunResult, DurableRunStatus
from agent.runtime.identity import RunIdentity, WorkspaceIdentity
from agent.runtime.revision import WorkspaceRevision, WorkspaceRevisionReason
from agent.verification.contracts import (
    VerificationAttempt, VerificationResult, VerificationSpec, VerificationSummary,
    VerificationCheckStatus,
)
from agent.verification.evaluation import AcceptanceReason, AcceptanceResult


class AttemptReceiptTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        # Match the concrete runners' canonical roots, including Windows 8.3 TEMP.
        self.root = Path(temporary.name).resolve(strict=True)
        self.generation = self.root/'G'; self.generation.mkdir()
        self.runtime = self.root/'runtime'; self.runtime.mkdir()
        self.source = b'fixed final source manifest'
        identity = RunIdentity('receipt-run', 'receipt-thread', 'receipt-task',
            WorkspaceIdentity.from_root(self.generation))
        spec = VerificationSpec('observer', ('fixed-host-observer',))
        attempts, receipts = [], []
        for index, phase in enumerate(('baseline', 'post')):
            rid = str(index+1)*32
            checked = VerificationResult.create(name=spec.name, argv=spec.argv, cwd=spec.cwd,
                status=VerificationCheckStatus.PASS, exit_code=0, message='native_receipt='+rid)
            summary = VerificationSummary.from_result(checked)
            attempt = VerificationAttempt.started(run_id=identity.run_id, task_id=identity.task_id,
                phase=phase, repair_attempt=0, spec_index=0, spec=spec, attempt_ordinal=0,
                workspace_revision=WorkspaceRevision.unknown(WorkspaceRevisionReason.NOT_GIT)).with_result(summary)
            attempts.append(attempt)
            receipts.append({'receipt_id':rid,'source_hash':hashlib.sha256(self.source).hexdigest(),
                'result_digest':hashlib.sha256(json.dumps(asdict(summary),sort_keys=True,default=str).encode()).hexdigest()})
        record = RunRecord(schema_version=1, run_id=identity.run_id, thread_id=identity.thread_id,
            task_id=identity.task_id, workspace_root=identity.workspace.canonical_root,
            workspace_root_digest=identity.workspace.root_digest, run_config_digest='a'*64,
            runtime_status='completed', workflow_outcome='completed', verification_status='verified',
            error_code=None, budget=None, started_at=1, finished_at=2, last_event_sequence=None,
            audit_status=AuditStatus.COMPLETE, agent_revision={})
        saved = write_run_record(self.runtime, record)
        self.assertTrue(saved.success)
        self.result = DurableRunResult(DurableRunStatus.COMPLETED, run_id=identity.run_id,
            record_ref=saved.record_ref, state={'run_identity':identity,'verification_attempts':tuple(attempts),
                'acceptance':AcceptanceResult(True, AcceptanceReason.ACCEPTED)})
        self.receipts = receipts

    def bind(self, receipts=None, result=None):
        return bind_attempt_receipts(result or self.result, runtime_root=self.runtime,
            configured_runtime_root=self.runtime, generation_root=self.generation,
            receipts=self.receipts if receipts is None else receipts,
            source_reader=lambda:self.source, receipt_prefix='native_receipt=')

    def test_exact_independent_receipts_bind_both_original_attempts(self):
        self.assertEqual([v['attempt_id'] for v in self.bind()],
            [a.attempt_id for a in self.result.state['verification_attempts']])

    def test_lexical_record_root_alias_uses_the_configured_canonical_identity(self):
        bound = bind_attempt_receipts(self.result,runtime_root=self.runtime/'..'/'runtime',
            configured_runtime_root=self.runtime,generation_root=self.generation,
            receipts=self.receipts,source_reader=lambda:self.source,receipt_prefix='native_receipt=')
        self.assertEqual(len(bound),2)

    def test_duplicate_post_receipt_cannot_replace_missing_baseline(self):
        with self.assertRaises(ValueError):
            self.bind([self.receipts[1], dict(self.receipts[1])])

    def test_duplicate_checkpoint_attempts_are_rejected(self):
        attempts = self.result.state['verification_attempts']
        changed = replace(self.result, state={**self.result.state,'verification_attempts':(attempts[1],attempts[1])})
        with self.assertRaises(ValueError): self.bind(result=changed)

    def test_reused_receipt_with_changed_result_digest_is_rejected(self):
        receipts = [dict(v) for v in self.receipts]
        receipts[1]['receipt_id'] = receipts[0]['receipt_id']
        with self.assertRaises(ValueError): self.bind(receipts)

    def test_empty_receipts_and_attempts_do_not_create_complete_audit(self):
        changed = replace(self.result, state={**self.result.state,'verification_attempts':(), 'acceptance':None})
        with self.assertRaises(ValueError): self.bind([], changed)


if __name__ == '__main__': unittest.main()
