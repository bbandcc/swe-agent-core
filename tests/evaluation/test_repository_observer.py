import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent.evaluation.repository_observer import RepositoryTaskSpec, prepare_repository_observer, tree_fingerprint
from agent.evaluation.repository_runner import RepositoryObserverRunner, RepositoryAdmission

IMAGE = 'python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b'


class RepositoryObserverTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict('os.environ', {'PYTEST_DISABLE_PLUGIN_AUTOLOAD':'1',
            'PYTHONDONTWRITEBYTECODE':'1','PYTEST_ADDOPTS':'','PYTEST_PLUGINS':'','PYTHONPATH':'','PYTHONHOME':''}))
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('B', 'G', 'D', 'oracle'): (self.root/name).mkdir()
        for name in ('B', 'G'):
            (self.root/name/'a.py').write_text('VALUE=0\n')
            (self.root/name/'b.py').write_text('VALUE=0\n')
        (self.root/'oracle'/'cases.py').write_text("import sys,json\nsys.path[:0]=['/repo','/deps']\nimport a,b\ncases=[{'id':'two-files','passed':a.VALUE==1 and b.VALUE==2}]\nprint(json.dumps({'cases':cases}))\nsys.exit(0 if cases[0]['passed'] else 1)\n")
        self.task = RepositoryTaskSpec('author-two-files', IMAGE, ('python','-I','-B','/trusted/oracle/cases.py'),
            ('two-files',), tree_fingerprint(self.root/'B'), tree_fingerprint(self.root/'D'), tree_fingerprint(self.root/'oracle'))

    def prepare(self):
        return prepare_repository_observer(self.root/'run', self.root/'B', self.root/'G',
            self.root/'D', self.root/'oracle', self.task)

    def test_prepares_fixed_host_inputs_and_refuses_template_or_dependency_drift(self):
        setup = self.prepare()
        compile((setup.observer_root/'test_observer.py').read_bytes(), 'fixed-observer', 'exec')
        runner = RepositoryObserverRunner(setup, runtime_root=self.root/'runtime')
        self.assertTrue(RepositoryAdmission(runner).permits(runner.spec, runner, setup.generation_root))
        (setup.observer_root/'test_observer.py').write_text('raise RuntimeError("modified")')
        self.assertFalse(runner.permits(runner.spec, setup.generation_root))

    def test_parser_rejects_missing_duplicate_wrong_and_exit_inconsistent_cases(self):
        from agent.evaluation.repository_container import parse_cases
        valid = {'status':'completed','cleanup':True,'exit_code':0,'stdout':json.dumps({'cases':[{'id':'two-files','passed':True}]})}
        self.assertTrue(parse_cases(valid, ('two-files',))[0]['passed'])
        for changes in ({'stdout':'{}'}, {'stdout':'{"cases":[],"cases":[]}'}, {'exit_code':1}, {'status':'timeout'}, {'cleanup':False}):
            with self.assertRaises(ValueError): parse_cases({**valid,**changes}, ('two-files',))

    def test_fixed_spec_runner_and_resealed_config_mutations_are_refused(self):
        from dataclasses import replace
        setup = self.prepare(); runner = RepositoryObserverRunner(setup, runtime_root=self.root/'runtime')
        original_spec = runner.spec
        altered = replace(runner.spec, argv=('unreviewed-host-command',))
        self.assertFalse(runner.permits(altered, setup.generation_root))
        runner.spec = altered
        self.assertFalse(runner.permits(altered, setup.generation_root))
        runner.spec = original_spec
        path = setup.observer_root/'config.json'
        config = json.loads(path.read_text()); config['argv'] = ['unreviewed-guest-command']
        path.write_text(json.dumps(config))
        changed = replace(setup, frozen_digest=tree_fingerprint(setup.observer_root))
        with self.assertRaises(ValueError): RepositoryObserverRunner(changed, runtime_root=self.root/'other')

    def test_dependency_and_dispatch_method_drift_are_refused(self):
        setup = self.prepare(); runner = RepositoryObserverRunner(setup, runtime_root=self.root/'runtime')
        dispatch = runner.run
        runner.run = lambda _: None
        self.assertFalse(runner.permits(runner.spec, setup.generation_root))
        runner.run = dispatch
        (setup.dependency_root/'unreviewed.py').write_text('raise RuntimeError()')
        self.assertFalse(runner.permits(runner.spec, setup.generation_root))

    def test_core_controller_accepts_only_this_concrete_reviewed_observer(self):
        from agent.graph import AgentState
        from agent.verification.workflow import VerificationController
        from agent.verification.runner import VerificationRunner
        setup = self.prepare()
        runner = RepositoryObserverRunner(setup, runtime_root=self.root/'runtime')
        class DispatchObserved(Exception): pass
        controller = VerificationController((runner.spec,), runner, setup.generation_root,
            reviewed_inputs=RepositoryAdmission(runner))
        with patch.object(VerificationRunner, 'run', side_effect=DispatchObserved), patch.object(
                RepositoryObserverRunner, 'cleanup', return_value=True):
            with self.assertRaises(DispatchObserved):
                controller.run_baseline(AgentState())

    def test_actual_docker_two_file_baseline_post_control(self):
        import os
        if os.environ.get('SWE_REPOSITORY_DOCKER_CONTROL') != '1': self.skipTest('Explicit opt-in Docker control')
        setup = self.prepare(); runner = RepositoryObserverRunner(setup, runtime_root=self.root/'runtime')
        before = runner.run(runner.spec)
        self.assertEqual(before.status.value, 'fail', before)
        (setup.generation_root/'a.py').write_text('VALUE=1\n')
        (setup.generation_root/'b.py').write_text('VALUE=2\n')
        after = runner.run(runner.spec)
        self.assertEqual(after.status.value, 'pass', after)
        self.assertEqual(len(runner.receipts), 2)
        self.assertNotEqual(runner.receipts[0]['source_hash'], runner.receipts[1]['source_hash'])
        self.assertTrue(runner.cleanup())

    def test_actual_timeout_remains_timeout_and_parent_cleans_lease(self):
        import os
        if os.environ.get('SWE_REPOSITORY_DOCKER_CONTROL') != '1': self.skipTest('Explicit opt-in Docker control')
        from dataclasses import replace
        (self.root/'oracle'/'cases.py').write_text('import time\ntime.sleep(240)\n')
        self.task = replace(self.task, oracle_sha256=tree_fingerprint(self.root/'oracle'))
        setup = self.prepare()
        runner = RepositoryObserverRunner(setup, runtime_root=self.root/'runtime', timeout_seconds=30)
        result = runner.run(runner.spec)
        self.assertEqual(result.status.value, 'timeout', result)
        self.assertFalse((setup.root/'lease.json').exists())
        self.assertTrue(runner.cleanup())
