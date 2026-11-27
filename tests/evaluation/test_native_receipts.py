"""Bind native data to original audit/report identities, without execution admission."""
from dataclasses import asdict, replace
import hashlib
import json
import unittest

from tests.evaluation import test_attempt_receipts as original_fixtures
from tests.evaluation import test_native_result as native_fixtures
from agent.evaluation.native_receipts import bind_native_receipts
from agent.outcome import WorkflowOutcome
from agent.runtime import RunRecord, write_run_record
from agent.verification.contracts import (
    REPORT_SCHEMA, VerificationCase, VerificationCaseStatus, VerificationReport,
    VerificationCheckStatus, VerificationStatus, VerificationSpec, VerificationAttempt,
)


class NativeReceiptTests(unittest.TestCase):
    def setUp(self):
        original_fixtures.AttemptReceiptTests.setUp(self)
        data = native_fixtures.NativeResultTests(); data.setUp()
        self.spec = replace(data.spec,instance_id='receipt-task')
        self.identities = (replace(data.before, task_id='receipt-task',
            source_sha256=hashlib.sha256(b'old manifest').hexdigest()),
            replace(data.after,task_id='receipt-task',source_sha256=hashlib.sha256(self.source).hexdigest()))
        from agent.evaluation.native_result import validate_native_attempt
        self.native = tuple(validate_native_attempt(self.spec,i,expected_identity=i,
            log=('FAILED f2p\nPASSED p2p\n' if index==0 else 'PASSED f2p\nPASSED p2p\n'),
            exit_code=1-index,completed=True,cleanup_complete=True)
            for index,i in enumerate(self.identities))
        self.mapping = (('f2p','observer::case_0'),('p2p','observer::case_1'))
        approved = VerificationSpec('observer',('python','-m','pytest','--junitxml=report.xml'),
            report_path='report.xml')
        attempts = []
        for index, original in enumerate(self.result.state['verification_attempts']):
            report = VerificationReport('observer',REPORT_SCHEMA,tuple(VerificationCase('observer',target,
                VerificationCaseStatus.FAIL if index==0 and source=='f2p' else VerificationCaseStatus.PASS)
                for source,target in self.mapping))
            summary = replace(original.result, status=VerificationCheckStatus.FAIL if index==0 else VerificationCheckStatus.PASS,
                exit_code=1-index,report=report,argv=approved.argv,
                allowed_failure_case_ids=approved.allowed_failure_case_ids)
            attempts.append(VerificationAttempt.started(run_id=original.run_id,task_id=original.task_id,
                phase=original.phase,repair_attempt=original.repair_attempt,spec_index=original.spec_index,
                spec=approved,attempt_ordinal=original.attempt_ordinal,
                workspace_revision=original.workspace_revision).with_result(summary))
            self.receipts[index].update(source_hash=self.identities[index].source_sha256,
                result_digest=hashlib.sha256(json.dumps(asdict(summary),sort_keys=True,default=str).encode()).hexdigest())
        self.result = replace(self.result,state={**self.result.state,'verification_attempts':tuple(attempts),
            'outcome':WorkflowOutcome.COMPLETED,'verification_status':VerificationStatus.IMPROVED,
            'repair_attempts':0})
        path=self.runtime/self.result.record_ref
        record=RunRecord.from_dict(json.loads(path.read_text(encoding='utf-8')))
        saved=write_run_record(self.runtime,replace(record,verification_status='improved'))
        self.assertTrue(saved.success)

    def bind(self, *, native=None, receipts=None, result=None, mapping=None):
        return bind_native_receipts(result or self.result,spec=self.spec,
            runtime_root=self.runtime, configured_runtime_root=self.runtime,
            generation_root=self.generation, receipts=self.receipts if receipts is None else receipts,
            native_attempts=self.native if native is None else native, source_reader=lambda:self.source,
            receipt_prefix='native_receipt=',case_mapping=self.mapping if mapping is None else mapping,
            expected_image=self.identities[0].image,
            expected_environment_sha256=self.identities[0].environment_sha256)

    def test_complete_original_reports_bind_without_conflating_uuid_and_attempt_sha(self):
        result=self.bind()
        self.assertTrue(result.resolved,result)
        self.assertEqual(len(result.bindings),2)
        for value in result.bindings:
            self.assertEqual(len(value.receipt_id),32)
            self.assertEqual(len(value.attempt_id),64)

    def test_duplicate_missing_or_extra_native_observations_are_rejected(self):
        for values in (self.native[:1],(self.native[1],self.native[1]),(*self.native,self.native[0])):
            with self.subTest(values=len(values)):
                self.assertFalse(self.bind(native=values).resolved)

    def test_phase_and_repair_are_compared_to_original_attempts(self):
        for change in ({'phase':'baseline'}, {'repair_attempt':1}):
            altered=replace(self.native[1],identity=replace(self.identities[1],**change))
            self.assertFalse(self.bind(native=(self.native[0],altered)).resolved)

    def test_native_source_environment_or_task_cannot_replace_independent_pins(self):
        for change in ({'source_sha256':'9'*64},{'environment_sha256':'9'*64},
                {'image':'other/image@sha256:'+'9'*64},{'task_id':'other-task'}):
            altered=replace(self.native[1],identity=replace(self.identities[1],**change))
            self.assertFalse(self.bind(native=(self.native[0],altered)).resolved)

    def test_prepared_native_task_cannot_replace_original_run_task(self):
        self.spec=replace(self.spec,instance_id='other-task')
        observations=tuple(replace(a,identity=replace(a.identity,task_id='other-task')) for a in self.native)
        self.assertFalse(self.bind(native=observations).resolved)

    def test_raw_native_cases_cannot_disagree_with_original_junit(self):
        from agent.evaluation.native_result import validate_native_attempt
        identity=self.identities[1]
        altered=validate_native_attempt(self.spec,identity,expected_identity=identity,
            log='FAILED f2p\nPASSED p2p\n',exit_code=1,completed=True,cleanup_complete=True)
        self.assertFalse(self.bind(native=(self.native[0],altered)).resolved)

    def test_non_bijective_case_mapping_is_rejected(self):
        for mapping in (self.mapping[:1],(self.mapping[0],self.mapping[0]),
                (('f2p','observer::case_0'),('p2p','observer::case_0'))):
            self.assertFalse(self.bind(mapping=mapping).resolved)

    def test_claimed_acceptance_cannot_override_original_check_policy(self):
        attempts=[]
        for index,original in enumerate(self.result.state['verification_attempts']):
            summary=replace(original.result,allowed_failure_case_ids=('observer::case_0','observer::case_1'))
            attempts.append(original.with_result(summary))
            self.receipts[index]['result_digest']=hashlib.sha256(
                json.dumps(asdict(summary),sort_keys=True,default=str).encode()).hexdigest()
        changed=replace(self.result,state={**self.result.state,'verification_attempts':tuple(attempts)})
        self.assertFalse(self.bind(result=changed).resolved)

    def test_graph_business_outcome_and_original_record_must_agree(self):
        changed=replace(self.result,state={**self.result.state,'outcome':WorkflowOutcome.FAILED})
        self.assertFalse(self.bind(result=changed).resolved)
        path=self.runtime/self.result.record_ref
        record=RunRecord.from_dict(json.loads(path.read_text(encoding='utf-8')))
        self.assertTrue(write_run_record(self.runtime,replace(record,workflow_outcome='failed')).success)
        self.assertFalse(self.bind().resolved)

    def test_audit_failure_or_final_source_drift_cannot_resolve(self):
        self.assertFalse(self.bind(result=replace(self.result,audit_incomplete=True)).resolved)
        self.source=b'changed after verification'
        self.assertFalse(self.bind().resolved)

    def repair_chain(self,kind):
        from agent.evaluation.native_result import validate_native_attempt
        original=self.result.state['verification_attempts'];post=original[1]
        cases=tuple(replace(c,status=VerificationCaseStatus.FAIL)
            if kind=='regression' or kind=='unfixed' and c.case_id=='observer::case_0' else c
            for c in post.result.report.cases)
        summary=replace(post.result,report=replace(post.result.report,cases=cases),
            status=VerificationCheckStatus.PASS if kind=='passed' else VerificationCheckStatus.FAIL,
            exit_code=0 if kind=='passed' else 1)
        middle_id=replace(self.identities[1],source_sha256=hashlib.sha256(b'intermediate').hexdigest())
        log=''.join(('PASSED' if c.status is VerificationCaseStatus.PASS else 'FAILED')+' '+source+'\n'
            for (source,_),c in zip(self.mapping,cases))
        middle=validate_native_attempt(self.spec,middle_id,expected_identity=middle_id,
            log=log,exit_code=summary.exit_code,completed=True,cleanup_complete=True)
        last_id=replace(self.identities[1],attempt_id='3'*32,repair_attempt=1)
        last=replace(self.native[1],identity=last_id)
        final_summary=replace(post.result,message='native_receipt='+'3'*32)
        approved=VerificationSpec('observer',('python','-m','pytest','--junitxml=report.xml'),report_path='report.xml')
        final=VerificationAttempt.started(run_id=post.run_id,task_id=post.task_id,phase='post',
            repair_attempt=1,spec_index=0,spec=approved,attempt_ordinal=0,
            workspace_revision=post.workspace_revision).with_result(final_summary)
        receipts=[dict(self.receipts[0])]
        for value,checked in ((middle,summary),(last,final_summary)):
            receipts.append({'receipt_id':value.identity.attempt_id,'source_hash':value.identity.source_sha256,
                'result_digest':hashlib.sha256(json.dumps(asdict(checked),sort_keys=True,default=str).encode()).hexdigest()})
        result=replace(self.result,state={**self.result.state,'verification_attempts':
            (original[0],post.with_result(summary),final),'repair_attempts':1})
        return result,receipts,(self.native[0],middle,last)

    def test_original_regression_then_bounded_repair_can_resolve(self):
        result,receipts,native=self.repair_chain('regression')
        audit=self.bind(result=result,receipts=receipts,native=native)
        self.assertTrue(audit.resolved,audit)

    def test_illegal_original_retry_is_rejected_even_with_complete_receipt_set(self):
        for kind in ('unfixed','passed'):
            with self.subTest(kind=kind):
                result,receipts,native=self.repair_chain(kind)
                self.assertFalse(self.bind(result=result,receipts=receipts,native=native).resolved)

    def test_checkpoint_repair_count_must_match_last_original_post(self):
        for value in (None,True,-1,1,2,3,'0'):
            with self.subTest(value=value):
                changed=replace(self.result,state={**self.result.state,'repair_attempts':value})
                self.assertFalse(self.bind(result=changed).resolved)

    def test_original_attempt_value_types_survive_real_sqlite_checkpoint_roundtrip(self):
        import sqlite3
        from contextlib import closing
        from langgraph.checkpoint.sqlite import SqliteSaver
        from langgraph.graph import StateGraph, START, END
        from agent.runtime.checkpointing import checkpoint_serializer
        graph = StateGraph(dict)
        graph.add_node('persist',lambda state:state)
        graph.add_edge(START,'persist'); graph.add_edge('persist',END)
        with closing(sqlite3.connect(self.runtime/'native-audit-checkpoint.sqlite',check_same_thread=False)) as connection:
            saver=SqliteSaver(connection,serde=checkpoint_serializer())
            compiled=graph.compile(checkpointer=saver)
            config={'configurable':{'thread_id':'native-audit-author-control'}}
            compiled.invoke(dict(self.result.state),config)
        with closing(sqlite3.connect(self.runtime/'native-audit-checkpoint.sqlite',check_same_thread=False)) as connection:
            reader=graph.compile(checkpointer=SqliteSaver(connection,serde=checkpoint_serializer()))
            restored=reader.get_state(config).values
        self.assertEqual(tuple(restored['verification_attempts']),self.result.state['verification_attempts'])
        self.assertTrue(self.bind(result=replace(self.result,state=restored)).resolved)


if __name__ == '__main__': unittest.main()
