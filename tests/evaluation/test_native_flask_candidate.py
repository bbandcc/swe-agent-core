"""Public fixed material seams; never Docker, target imports or model requests."""
import unittest
from dataclasses import asdict,replace
import json
from pathlib import Path
import shutil
import tempfile
from unittest.mock import patch

from agent.evaluation.repository_candidate import CandidatePolicy,freeze_candidate
from agent.evaluation.native_task_spec import prepare_native_task
from agent.evaluation.native_flask import prepare_candidate,fixed_policy,validate_candidate_inputs
from agent.evaluation.native_flask.candidate import host_identity


class NativeFlaskCandidateTests(unittest.TestCase):
    def test_target_whitelist_cannot_replace_complete_fixed_policy(self):
        with self.assertRaisesRegex(ValueError,'complete_fixed_policy_required'):
            prepare_candidate(None,CandidatePolicy(editable_prefixes=('src/flask',)),
                baseline_root=None,task=None,test_patch=None,wheels=None,directory=None)

    def test_fixed_policy_contains_the_complete_public_default_contract(self):
        policy=fixed_policy()
        self.assertEqual(policy.editable_prefixes,('.',))
        self.assertEqual(policy.immutable_paths,())
        self.assertIn('tests',policy.protected_paths)
        self.assertEqual(set(asdict(policy)),{'editable_prefixes','protected_paths','immutable_paths',
            'max_entries','max_total_bytes','max_changed_bytes'})

    def test_malformed_public_snapshot_and_prepared_object_are_refused(self):
        with self.assertRaisesRegex(ValueError,'public_frozen_snapshot_required'):
            prepare_candidate(None,fixed_policy(),baseline_root=None,task=None,test_patch=None,wheels=None,directory=None)
        with self.assertRaisesRegex(ValueError,'public_prepared_candidate_required'):
            validate_candidate_inputs({'inputs':'arbitrary'})

    def test_unbound_task_cannot_use_an_otherwise_public_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);base=root/'b';generation=root/'g';base.mkdir();generation.mkdir()
            for path in (base,generation):(path/'a.py').write_bytes(b'x=1\n')
            frozen=freeze_candidate(base,generation,fixed_policy(),root/'s')
            self.assertTrue(frozen.ok,frozen)
            with self.assertRaisesRegex(ValueError,'fixed_task_spec_required'):
                prepare_candidate(frozen.snapshot,fixed_policy(),baseline_root=base,task=None,
                    test_patch=b'',wheels={},directory=root/'u')

    def fixed_materials(self):
        project=Path(__file__).resolve().parents[2]
        base=project/'.research-cache/flask4045-consumer-c8f6e2223a7d47538c147773ba8c3edb/model-base'
        manifest=project/'.research-cache/benchmark-20-20261119/prepared/manifest.private.json'
        wheels={'Werkzeug-2.0.3-py3-none-any.whl':project/'.research-cache/flask4045-wheel-a6a3d28c2d434d35ba768da83a3f0813/Werkzeug-2.0.3-py3-none-any.whl',
            'setuptools-65.5.1-py3-none-any.whl':project/'.research-cache/flask-setuptools-material-b982243379814459aec12fc83d7f0cdf/setuptools-65.5.1-py3-none-any.whl'}
        if not base.is_dir() or not manifest.is_file() or not all(p.is_file() for p in wheels.values()):
            self.skipTest('Local pinned Flask data unavailable; no network or Docker fallback')
        data=json.loads(manifest.read_text(encoding='utf-8'))
        item=next(t for t in data['tasks'] if t['instance_id']=='pallets__flask-4045')
        row=data['evaluator_rows'][item['instance_id']]
        return base,prepare_native_task(row,expected_row_sha256=item['row_sha256']),row['test_patch'].encode(),wheels

    def test_fixed_materials_publish_full_candidate_and_reject_later_drift_without_execution(self):
        base,task,test_patch,wheels=self.fixed_materials()
        with tempfile.TemporaryDirectory() as temporary,patch('subprocess.Popen',
                side_effect=AssertionError('Material preparation must never execute')):
            root=Path(temporary);generation=root/'g';shutil.copytree(base,generation)
            readme=generation/'README.rst';readme.write_bytes(readme.read_bytes()+b'\nNon-target source edit.\n')
            frozen=freeze_candidate(base,generation,fixed_policy(),root/'s')
            self.assertTrue(frozen.ok,frozen)
            prepared=prepare_candidate(frozen.snapshot,fixed_policy(),baseline_root=base,task=task,
                test_patch=test_patch,wheels=wheels,directory=root/'u')
            self.assertIsNone(validate_candidate_inputs(prepared))
            self.assertTrue((prepared.inputs/'candidate/examples/tutorial/flaskr/__init__.py').is_file())
            self.assertFalse((prepared.inputs/'candidate/tests').exists())
            self.assertTrue((prepared.inputs/'candidate/README.rst').read_bytes().endswith(b'Non-target source edit.\n'))
            self.assertEqual(set(p.name for p in prepared.inputs.iterdir()),
                {'guest.py','fixed_profile.py','fixed_runtime.py','config.json','candidate','test.patch','wheels'})
            self.assertTrue({'native_flask/candidate.py','native_flask/ownership.py','native_flask/container.py',
                'native_flask_runner.py','native_graph.py'}<=set(host_identity()))
            for field,reason in (('host_code_sha256','host_implementation_changed'),
                    ('candidate_sha256','candidate_snapshot_changed'),('environment_sha256','prepared_configuration_changed')):
                with self.subTest(field=field),self.assertRaisesRegex(ValueError,reason):
                    validate_candidate_inputs(replace(prepared,**{field:'0'*64}))
            path=prepared.inputs/'wheels/setuptools-65.5.1-py3-none-any.whl';data=bytearray(path.read_bytes())
            data[-1]^=1;path.write_bytes(data)
            with self.assertRaisesRegex(ValueError,'prepared_inputs_changed'):validate_candidate_inputs(prepared)

    def test_extra_test_tree_and_frozen_source_drift_are_refused_before_publication(self):
        base,task,test_patch,wheels=self.fixed_materials()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for label in ('extra','drift'):
                generation=root/label;shutil.copytree(base,generation)
                if label=='extra':
                    path=generation/'examples/tests/unexpected.py';path.parent.mkdir()
                    path.write_bytes(b'raise AssertionError("must never execute")\n')
                frozen=freeze_candidate(base,generation,fixed_policy(),root/('s-'+label))
                self.assertTrue(frozen.ok,frozen)
                if label=='drift':
                    path=frozen.snapshot.root/'README.rst';path.write_bytes(path.read_bytes()+b'\nAfter freeze.\n')
                reason='protected_candidate_path' if label=='extra' else 'candidate_snapshot_changed'
                with self.assertRaisesRegex(ValueError,reason):
                    prepare_candidate(frozen.snapshot,fixed_policy(),baseline_root=base,task=task,
                        test_patch=test_patch,wheels=wheels,directory=root/('u-'+label))
                self.assertFalse((root/('u-'+label)).exists())

    def test_fixed_test_patch_and_wheel_set_are_required_before_publication(self):
        base,task,test_patch,wheels=self.fixed_materials()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);generation=root/'g';shutil.copytree(base,generation)
            frozen=freeze_candidate(base,generation,fixed_policy(),root/'s')
            self.assertTrue(frozen.ok,frozen)
            for label,patch_bytes,wheel_paths,reason in (
                    ('patch',test_patch+b'\n',wheels,'test_patch_identity'),
                    ('wheels',test_patch,{},'fixed_wheel_set_required')):
                with self.subTest(label=label),self.assertRaisesRegex(ValueError,reason):
                    prepare_candidate(frozen.snapshot,fixed_policy(),baseline_root=base,task=task,
                        test_patch=patch_bytes,wheels=wheel_paths,directory=root/label)
                self.assertFalse((root/label).exists())

    def test_added_conftest_and_changed_test_configuration_are_refused(self):
        base,task,test_patch,wheels=self.fixed_materials()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for label,reason in (('conftest','additional_test_file'),('config','trusted_test_configuration_changed')):
                generation=root/label;shutil.copytree(base,generation)
                if label=='conftest':(generation/'conftest.py').write_bytes(b'raise AssertionError("must not import")\n')
                else:
                    path=generation/'setup.cfg';path.write_bytes(path.read_bytes()+b'\n# modified test configuration\n')
                frozen=freeze_candidate(base,generation,fixed_policy(),root/('s-'+label))
                self.assertTrue(frozen.ok,frozen)
                with self.assertRaisesRegex(ValueError,reason):
                    prepare_candidate(frozen.snapshot,fixed_policy(),baseline_root=base,task=task,
                        test_patch=test_patch,wheels=wheels,directory=root/('u-'+label))
                self.assertFalse((root/('u-'+label)).exists())


if __name__=='__main__':unittest.main()
