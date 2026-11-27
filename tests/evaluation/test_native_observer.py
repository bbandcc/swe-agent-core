"""A native observation becomes JUnit only through real fixed host assertions."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests.evaluation import test_native_result as fixtures
from agent.evaluation.native_observer import observe_native_result,native_observer_spec
from agent.verification.contracts import VerificationCheckStatus


class NativeObserverTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve(strict=True)
        data=fixtures.NativeResultTests();data.setUp()
        self.task,self.identity=data.spec,data.before
        self.enterContext(patch.dict('os.environ',{'PYTEST_DISABLE_PLUGIN_AUTOLOAD':'1',
            'PYTHONDONTWRITEBYTECODE':'1','PYTEST_PLUGINS':'','PYTEST_ADDOPTS':'',
            'PYTHONPATH':'','PYTHONHOME':''}))

    def observe(self,identity=None,log='FAILED f2p\nPASSED p2p\n',exit_code=1,**kwargs):
        values=dict(expected_identity=identity or self.identity,log=log,exit_code=exit_code,
            completed=True,cleanup_complete=True,directory=self.root/'observer',runtime_root=self.root/'runtime')
        values.update(kwargs)
        return observe_native_result(self.task,identity or self.identity,**values)

    def test_real_pytest_reports_exact_baseline_cases_with_no_raw_case_names(self):
        result=self.observe()
        self.assertTrue(result.native.valid)
        self.assertEqual(result.verification.status,VerificationCheckStatus.FAIL,result.verification)
        self.assertEqual(result.verification.exit_code,1)
        self.assertEqual([(c.case_id,c.status.value) for c in result.verification.report.cases],
            [('test_observer::test_case[c0000]','fail'),('test_observer::test_case[c0001]','pass')])
        self.assertEqual(result.case_mapping,(('f2p','test_observer::test_case[c0000]'),
            ('p2p','test_observer::test_case[c0001]')))
        self.assertNotIn('f2p',result.verification.stdout+result.verification.stderr)
        self.assertIn('native_receipt='+self.identity.attempt_id,result.verification.message)

    def test_incomplete_log_rejects_without_creating_host_test_directory(self):
        result=self.observe(log='PASSED p2p\n')
        self.assertEqual(result.verification.status,VerificationCheckStatus.EXECUTION_ERROR)
        self.assertFalse((self.root/'observer').exists())

    def test_same_graph_spec_and_clean_directory_support_baseline_then_post(self):
        before=self.observe()
        self.assertFalse((self.root/'observer').exists())
        after=self.observe(replace(self.identity,phase='post',attempt_id='2'*32,source_sha256='e'*64),
            log='PASSED f2p\nPASSED p2p\n',exit_code=0)
        self.assertEqual(after.verification.status,VerificationCheckStatus.PASS,after.verification)
        self.assertEqual(before.verification.argv,after.verification.argv)
        self.assertEqual(after.verification.argv,native_observer_spec(self.root/'observer').argv)
        self.assertIsNotNone(after.inputs_sha256)

    def test_lifecycle_or_identity_failure_never_dispatches_host_pytest(self):
        for changes in ({'cleanup_complete':False},{'completed':False},
                {'expected_identity':replace(self.identity,attempt_id='3'*32)}):
            with self.subTest(changes=changes):
                result=self.observe(**changes)
                self.assertEqual(result.verification.status,VerificationCheckStatus.EXECUTION_ERROR)
                self.assertFalse((self.root/'observer').exists())

    def test_raw_log_python_canary_is_not_executable_host_input(self):
        canary=self.root/'not-created'
        text="__import__('pathlib').Path("+repr(str(canary))+ ").write_text('bad')\n"
        result=self.observe(log=text+'FAILED f2p\nPASSED p2p\n')
        self.assertEqual(result.verification.status,VerificationCheckStatus.FAIL,result.verification)
        self.assertFalse(canary.exists())

    def test_existing_or_overlapping_output_is_refused_and_preserved(self):
        (self.root/'observer').mkdir();(self.root/'observer/canary').write_bytes(b'keep')
        result=self.observe()
        self.assertEqual(result.verification.status,VerificationCheckStatus.EXECUTION_ERROR)
        self.assertEqual((self.root/'observer/canary').read_bytes(),b'keep')

    def test_plugin_injection_is_refused_before_host_directory_creation(self):
        with patch.dict('os.environ',{'PYTEST_PLUGINS':'unreviewed_plugin'}):
            self.assertEqual(self.observe().verification.status,VerificationCheckStatus.EXECUTION_ERROR)
        self.assertFalse((self.root/'observer').exists())


if __name__=='__main__':unittest.main()
