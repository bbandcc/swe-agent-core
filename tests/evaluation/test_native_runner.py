"""Concrete native admission rejects unknown runners and unreviewed profiles."""
import unittest
from agent.evaluation.native_runner import NativeAdmission,NativeRequestsRunner
from agent.evaluation.native_graph import native_graph_factory
from tests.evaluation import test_native_result as fixtures


class NativeAdmissionTests(unittest.TestCase):
    def test_general_boolean_or_duck_typed_runner_cannot_gain_native_admission(self):
        class Fake:
            def permits(self,*args):return True
            def run(self,*args):raise AssertionError('not run')
        for runner in (True,object(),Fake()):
            with self.subTest(runner=type(runner).__name__),self.assertRaises(ValueError):NativeAdmission(runner)

    def test_unreviewed_spec_is_rejected_before_any_native_path_or_resource_work(self):
        data=fixtures.NativeResultTests();data.setUp()
        with self.assertRaisesRegex(ValueError,'Fixed Requests spec'):
            NativeRequestsRunner(data.spec,None,baseline_root='unused',generation_root='unused',
                control_root='unused',runtime_root='unused',wheel_directory='unused',wheel_manifest='unused',
                test_patch=b'',lease={},owner_root='unused')

    def test_graph_factory_does_not_accept_the_old_or_generic_runner(self):
        with self.assertRaises(ValueError):native_graph_factory(object(),None,None,None)


if __name__=='__main__':unittest.main()
