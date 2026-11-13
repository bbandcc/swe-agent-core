"""Data-only public contracts and trusted-template tests; no Docker/model."""
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

from agent.evaluation.swebench_instance import admit_swebench_instance
from agent.evaluation.swebench_observer import (
    SOURCE, TEST, assemble_cooperative_workspace, candidate_source,
    load_cooperative_workspace, observer_files_for, parse_cooperative_execution,
    prepare_cooperative_workspace, validate_frozen_inputs,
)


class SwebenchObserverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        asset = Path(__file__).resolve().parents[2] / 'evals/swebench/sympy__sympy-20590.json'
        row = json.loads(asset.read_text(encoding='utf-8-sig'))['row']
        self.instance = admit_swebench_instance(row,
            expected_sha256='feb99cda40e77a4391d300261f7a511072080217fef21c94afdd58c0000e9382',
            editable_paths=(SOURCE,), oracle_paths=(TEST,)).instance
        self.counter = 0
        self.setup = self.workspace()

    def workspace(self):
        self.counter += 1
        return assemble_cooperative_workspace(self.root / str(self.counter), instance=self.instance,
            source_files={SOURCE: b'# author fixture\n', 'sympy/other.py': b'raise RuntimeError("never import")\n'},
            dependency_files={'mpmath/__init__.py': b'raise RuntimeError("never import")\n'},
            source_test_bytes=b'raise RuntimeError("never host import")\n')

    def record(self, failed=False):
        cases = [{'id': name, 'passed': True} for name in self.instance.fail_to_pass + self.instance.pass_to_pass]
        if failed:
            cases[0].update(passed=False, error='AssertionError', traceback='test_immutable assertion')
        return {'status': 'completed', 'cleanup': True, 'exit_code': int(failed),
                'stdout': json.dumps({'python': '3.9.25', 'cases': cases}), 'stderr': ''}

    def test_author_workspace_is_separate_without_official_source_claim(self):
        setup = self.setup
        self.assertIs(setup.manifest['source_verified'], False)
        self.assertEqual(candidate_source(setup), b'# author fixture\n')
        self.assertFalse((setup.generation_root / TEST).exists())
        self.assertEqual({p.name for p in setup.root.iterdir()}, {'B', 'D', 'G', 'O', 'workspace.json'})
        validate_frozen_inputs(setup)
        self.assertEqual(load_cooperative_workspace(setup.root).manifest, setup.manifest)

    def test_only_one_bounded_utf8_regular_source_can_change(self):
        target = self.setup.generation_root / SOURCE
        target.write_bytes(b'# changed\n')
        self.assertEqual(candidate_source(self.setup), b'# changed\n')
        self.assertEqual(candidate_source(load_cooperative_workspace(self.setup.root)), b'# changed\n')
        for invalid in (b'\xff', b'x' * 32769):
            with self.subTest(kind=invalid[:10]):
                target.write_bytes(invalid)
                with self.assertRaises(ValueError): candidate_source(self.setup)
        target.unlink()
        with self.assertRaises(ValueError): candidate_source(self.setup)

    def test_generation_additions_deletions_and_protected_paths_are_rejected(self):
        for relative in ('.git/config', TEST, 'new.py', 'empty-dir'):
            with self.subTest(relative=relative):
                setup = self.workspace()
                target = setup.generation_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.mkdir() if relative == 'empty-dir' else target.write_bytes(b'# added')
                with self.assertRaises(ValueError): candidate_source(setup)
        (self.setup.generation_root / 'sympy/other.py').unlink()
        with self.assertRaises(ValueError): candidate_source(self.setup)

    def test_frozen_tree_drift_is_rejected(self):
        for field in ('baseline_root', 'dependency_root', 'observer_root'):
            with self.subTest(field=field):
                setup = self.workspace()
                target = next(p for p in getattr(setup, field).rglob('*') if p.is_file())
                target.write_bytes(b'# tampered')
                with self.assertRaises(ValueError): validate_frozen_inputs(setup)

    def test_templates_cannot_be_replaced_with_matching_caller_hash(self):
        setup = self.setup
        (setup.observer_root / 'test_observer.py').write_text('def test_forged(): pass\n')
        setup.manifest['observer_hash'] = 'caller-controlled'
        with self.assertRaises(ValueError): validate_frozen_inputs(setup)
        with self.assertRaises(ValueError):
            validate_frozen_inputs(replace(setup, observer_root=setup.generation_root))

    def test_manifest_field_tampering_is_rejected_on_reload(self):
        for key, value in (('case_ids', []), ('source_hash', '0' * 64), ('instance_id', 'invented'),
                           ('source_verified', True), ('schema', 100)):
            with self.subTest(key=key):
                setup = self.workspace()
                manifest = dict(setup.manifest)
                manifest[key] = value
                (setup.root / 'workspace.json').write_text(json.dumps(manifest))
                with self.assertRaises(ValueError): load_cooperative_workspace(setup.root)

    def test_source_hardlink_and_symlink_are_rejected(self):
        os.link(self.setup.generation_root / SOURCE, self.root / 'alias')
        with self.assertRaises(ValueError): candidate_source(self.setup)
        setup = self.workspace()
        source = setup.generation_root / SOURCE
        source.unlink()
        try:
            source.symlink_to(self.root / 'alias')
        except OSError:
            return  # Windows without symlink privilege still exercised the hardlink case.
        with self.assertRaises(ValueError): candidate_source(setup)

    def test_missing_fixed_inputs_and_escaped_author_paths_are_rejected(self):
        with self.assertRaises((ValueError, OSError)):
            prepare_cooperative_workspace(self.root / 'official', self.root / 'missing')
        with self.assertRaises(ValueError):
            assemble_cooperative_workspace(self.root / 'escaped', instance=self.instance,
                source_files={'../escape.py': b'# no'}, dependency_files={}, source_test_bytes=b'')

    def test_observer_files_bind_templates_paths_and_exact_roster(self):
        expected = observer_files_for(self.setup.root, self.instance, b'raise RuntimeError("never host import")\n')
        self.assertEqual({p.name for p in self.setup.observer_root.iterdir()}, set(expected))
        for name, data in expected.items():
            self.assertEqual((self.setup.observer_root / name).read_bytes(), data)
        compile(expected['test_observer.py'], 'trusted_observer', 'exec')
        compile(expected['run_roster.py'], 'trusted_roster', 'exec')
        self.assertIn(b'container_name: str', expected['control_runtime.py'])
        self.assertIn(b'python_files = test_observer.py', expected['pytest.ini'])

    def test_valid_results_preserve_assertion_failures_and_cooperative_limit(self):
        ids = self.instance.fail_to_pass + self.instance.pass_to_pass
        for failed in (False, True):
            with self.subTest(failed=failed):
                parsed = parse_cooperative_execution(self.record(failed), ids)
                self.assertEqual(len(parsed['cases']), 22)
                self.assertIs(parsed['cases'][0]['passed'], not failed)
        # Perfectly valid forged JSON is indistinguishable here: documented cooperative limit.

    def test_invalid_container_results_are_execution_errors(self):
        changes = ('missing', 'duplicate', 'unknown', 'non-json', 'duplicate-key', 'error',
                   'bad-boolean', 'timeout', 'cleanup', 'exit', 'extra')
        for change in changes:
            with self.subTest(change=change):
                result = self.record()
                payload = json.loads(result['stdout'])
                if change == 'missing': payload['cases'].pop()
                if change == 'duplicate': payload['cases'][-1] = payload['cases'][0]
                if change == 'unknown': payload['cases'][-1]['id'] = 'invented'
                if change == 'error': payload['cases'][0].update(passed=False, error='ImportError', traceback='bad import')
                if change == 'bad-boolean': payload['cases'][0]['passed'] = 1
                if change == 'extra': payload['unexpected'] = True
                result['stdout'] = json.dumps(payload)
                if change == 'non-json': result['stdout'] = 'PASS'
                if change == 'duplicate-key': result['stdout'] = '{"python":"3.9.25","python":"3.9.25","cases":[]}'
                if change == 'timeout': result['status'] = 'timeout'
                if change == 'cleanup': result['cleanup'] = False
                if change == 'exit': result['exit_code'] = 2
                with self.assertRaises(ValueError):
                    parse_cooperative_execution(result, self.instance.fail_to_pass + self.instance.pass_to_pass)

    def _host_template_run(self, result):
        setup = self.setup
        snapshot = setup.root / 'snapshots' / 'attempt'
        snapshot.parent.mkdir()
        shutil.copytree(setup.baseline_root, snapshot)
        import hashlib
        setup.control_path.write_text(json.dumps({'snapshot_repo': str(snapshot),
            'source_hash': hashlib.sha256((snapshot / SOURCE).read_bytes()).hexdigest(),
            'attempt_id': 'a' * 32, 'container_name': 'swe-cooperative-' + 'a' * 32,
            'receipt_path': str(setup.receipt_path)}))
        counter = setup.root / 'executions.json'
        # Author-controlled transport stub: never executes candidate/foreign code.
        stub = ('import json\nfrom pathlib import Path\nIMAGE=' + repr(setup.image) + '\n'
            'def execute(*args,**kwargs):\n'
            '    p=Path(' + repr(str(counter)) + ')\n'
            '    p.write_text(str(int(p.read_text())+1) if p.exists() else "1")\n'
            '    return ' + repr(result) + '\n')
        (setup.observer_root / 'control_runtime.py').write_text(stub)
        junit = setup.root / 'junit.xml'
        process = subprocess.run([sys.executable, '-I', '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
            '-c', str(setup.observer_root / 'pytest.ini'), str(setup.observer_root / 'test_observer.py'),
            '--junitxml', str(junit)], capture_output=True, timeout=30, cwd=setup.root,
            env={'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}, shell=False)
        self.assertEqual(counter.read_text(), '1', process.stdout.decode(errors='replace'))
        self.assertEqual(process.returncode, 1)
        return ET.parse(junit).getroot(), json.loads(setup.receipt_path.read_text())

    def test_host_pytest_runs_once_and_emits_twenty_two_cases(self):
        junit, receipt = self._host_template_run(self.record(failed=True))
        self.assertEqual(len(junit.findall('.//testcase')), 22)
        self.assertEqual(len(junit.findall('.//failure')), 1)
        self.assertEqual(len(junit.findall('.//error')), 0)
        self.assertEqual(receipt['status'], 'completed')
        self.assertEqual(receipt['receipt_id'], 'a' * 32)
        self.assertEqual(len(receipt['observed']['cases']), 22)

    def test_host_pytest_transport_error_produces_errors_not_baseline_failures(self):
        broken = self.record()
        broken['stdout'] = 'printed PASS'
        junit, receipt = self._host_template_run(broken)
        self.assertEqual(len(junit.findall('.//error')), 22)
        self.assertEqual(len(junit.findall('.//failure')), 0)
        self.assertEqual(receipt['status'], 'execution_error')
        self.assertIs(receipt['cleanup_complete'], True)
        self.assertIsNone(receipt['observed'])


if __name__ == '__main__':
    unittest.main()
