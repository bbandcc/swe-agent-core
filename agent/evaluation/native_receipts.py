"""Bind native observations to original durable audit data; never admit execution.

Only a concrete controller can establish the observations, pins and case mapping.
This module does not run a candidate, query SQLite, or authenticate foreign logs.
"""
from dataclasses import dataclass
import json
import re

from agent.evaluation.attempt_receipts import bind_attempt_receipts
from agent.evaluation.native_result import NativeAttemptResult, grade_native_attempts
from agent.evaluation.native_task_spec import NativeTaskSpec
from agent.outcome import WorkflowOutcome
from agent.runtime.durable import DurableRunStatus
from agent.runtime.trajectory import RunRecord
from agent.verification.contracts import VerificationCheckStatus, VerificationStatus
from agent.verification.evaluation import AcceptanceResult, classify_verification, evaluate_acceptance
from agent.workspace import WorkspacePathResolver, has_single_regular_file_link


@dataclass(frozen=True, slots=True)
class NativeBoundReceipt:
    receipt_id: str
    attempt_id: str
    phase: str
    repair_attempt: int
    source_sha256: str


@dataclass(frozen=True, slots=True)
class NativeReceiptAudit:
    resolved: bool
    issues: tuple[str, ...]
    bindings: tuple[NativeBoundReceipt, ...] = ()


def bind_native_receipts(result, *, spec, runtime_root, configured_runtime_root,
                         generation_root, receipts, native_attempts, source_reader,
                         receipt_prefix, case_mapping, expected_image,
                         expected_environment_sha256) -> NativeReceiptAudit:
    """Require agreement of native data, original summaries, RunRecord and source.

    The caller supplies original checkpoint state and independently obtained pins.
    Receipt UUIDs remain distinct from original SHA attempt IDs. A true return is
    a data audit, not a replacement for the runner/SQLite integration control.
    """
    try:
        if (type(spec) is not NativeTaskSpec or type(native_attempts) is not tuple
                or not 2 <= len(native_attempts) <= 4
                or any(type(a) is not NativeAttemptResult for a in native_attempts)
                or type(expected_environment_sha256) is not str
                or not re.fullmatch('[a-f0-9]{64}',expected_environment_sha256)):
            return NativeReceiptAudit(False,('native_audit_inputs_invalid',))
        roster = spec.fail_to_pass+spec.pass_to_pass
        if (type(case_mapping) is not tuple or len(case_mapping)!=len(roster)
                or any(type(v) is not tuple or len(v)!=2
                    or any(type(s) is not str or not s for s in v) for v in case_mapping)):
            return NativeReceiptAudit(False,('case_mapping_invalid',))
        mapping = dict(case_mapping)
        if (len(mapping)!=len(case_mapping) or set(mapping)!=set(roster)
                or len(set(mapping.values()))!=len(mapping)):
            return NativeReceiptAudit(False,('case_mapping_invalid',))
        state = result.state or {}
        acceptance = state.get('acceptance')
        if (result.status is not DurableRunStatus.COMPLETED
                or state.get('outcome') is not WorkflowOutcome.COMPLETED
                or state.get('verification_status') not in (VerificationStatus.IMPROVED,VerificationStatus.VERIFIED)
                or type(acceptance) is not AcceptanceResult or acceptance.accepted is not True):
            return NativeReceiptAudit(False,('graph_outcome_not_accepted',))
        original = bind_attempt_receipts(result,runtime_root=runtime_root,
            configured_runtime_root=configured_runtime_root,generation_root=generation_root,
            receipts=receipts,source_reader=source_reader,receipt_prefix=receipt_prefix)
        record_path = WorkspacePathResolver(runtime_root).resolve_file(result.record_ref)
        if (not record_path.ok or not has_single_regular_file_link(record_path.path)
                or record_path.path.stat().st_size>256*1024):
            return NativeReceiptAudit(False,('original_record_unavailable',))
        record = RunRecord.from_dict(json.loads(record_path.path.read_text(encoding='utf-8')))
        if (record.workflow_outcome!=state['outcome'].value
                or record.verification_status!=state['verification_status'].value
                or record.error_code is not None or result.error_code is not None):
            return NativeReceiptAudit(False,('original_record_outcome_mismatch',))
        observed = {a.identity.attempt_id:a for a in native_attempts}
        if (len(observed)!=len(native_attempts)
                or set(observed)!={v['receipt']['receipt_id'] for v in original}):
            return NativeReceiptAudit(False,('native_receipt_set_mismatch',))
        by_id = {a.attempt_id:a for a in state['verification_attempts']}
        ordered = sorted(original,key=lambda v:(v['phase']!='baseline',v['repair_attempt']))
        repair_count = state.get('repair_attempts')
        if (type(repair_count) is not int or not 0 <= repair_count <= 2
                or repair_count != ordered[-1]['repair_attempt']):
            return NativeReceiptAudit(False,('original_repair_count_mismatch',))
        bindings, evidence, summaries = [], [], []
        for item in ordered:
            receipt = item['receipt']; native = observed[receipt['receipt_id']]
            identity = native.identity; summary = by_id[item['attempt_id']].result
            if (identity.task_id!=spec.instance_id or item['task_id']!=spec.instance_id
                    or identity.row_sha256!=spec.row_sha256
                    or identity.image!=expected_image
                    or identity.environment_sha256!=expected_environment_sha256
                    or identity.phase!=item['phase'] or identity.repair_attempt!=item['repair_attempt']
                    or identity.source_sha256!=receipt['source_hash']):
                return NativeReceiptAudit(False,('original_native_identity_mismatch',))
            expected_status = VerificationCheckStatus.PASS if native.exit_code==0 else VerificationCheckStatus.FAIL
            if (summary is None or summary.report is None or summary.status is not expected_status
                    or summary.exit_code!=native.exit_code
                    or set(summary.report.case_map)!=set(mapping.values())
                    or any(summary.report.case_map[mapping[c]].status.value!=
                        ('pass' if status=='PASSED' else 'fail') for c,status in native.parsed.cases)):
                return NativeReceiptAudit(False,('original_native_cases_mismatch',))
            bindings.append(NativeBoundReceipt(identity.attempt_id,item['attempt_id'],
                item['phase'],item['repair_attempt'],identity.source_sha256))
            evidence.append(native)
            summaries.append(summary)
        baseline, post = (summaries[0],), (summaries[-1],)
        if any(classify_verification(baseline,(summary,)) is not VerificationStatus.REGRESSION
               for summary in summaries[1:-1]):
            return NativeReceiptAudit(False,('illegal_repair_transition',))
        if (classify_verification(baseline,post) is not state['verification_status']
                or not evaluate_acceptance(baseline,post).accepted):
            return NativeReceiptAudit(False,('original_acceptance_policy_mismatch',))
        grade = grade_native_attempts(spec,tuple(evidence))
        return NativeReceiptAudit(grade.resolved,grade.issues,tuple(bindings))
    except (OSError,ValueError,TypeError,KeyError,AttributeError):
        return NativeReceiptAudit(False,('original_audit_binding_invalid',))
