"""Public fixed-container contract; all Docker responses are offline fixtures."""
import json
import io
import re
from pathlib import Path
import tempfile
from types import SimpleNamespace, ModuleType
import unittest
from unittest.mock import patch

from agent.evaluation.native_flask import container, ownership


def expected(inputs,owner):
    return {'Id':'c'*64,'Name':'/swe-flask-candidate-'+'d'*32,'Created':'2026-11-28T00:00:00Z',
        'Image':'sha256:'+'b'*64,'Config':{'Image':ownership.IMAGE,'User':'65534:65534','WorkingDir':'/',
            'Entrypoint':[ownership.PYTHON],'Cmd':['-I','-S','-B','/trusted/shim.py'],
            'Labels':{'org.opencontainers.image.version':'22.04',ownership.LABEL:owner}},
        'Mounts':[{'Type':'bind','RW':False,'Source':str(inputs.resolve()),'Destination':'/trusted','Propagation':'rprivate'}],
        'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,'PidMode':'','IpcMode':'private',
            'PidsLimit':64,'Memory':536870912,'MemorySwap':536870912,'NanoCpus':1000000000,
            'Tmpfs':{'/tmp':'rw,nosuid,nodev,noexec,size=256m'},'LogConfig':{'Type':'none'},
            'SecurityOpt':['no-new-privileges'],'CapDrop':['ALL'],'CapAdd':None,'GroupAdd':None,'Devices':[],'DeviceRequests':None}}


class FlaskContainerTests(unittest.TestCase):
    def test_failed_journal_and_artifact_finalization_stays_structured_unknown(self):
        candidate=ModuleType('agent.evaluation.native_flask.candidate');candidate.PreparedFlaskCandidate=SimpleNamespace
        candidate.validate_candidate_inputs=lambda value:None
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);directory=root/'candidate';(directory/'inputs').mkdir(parents=True)
            (directory/'consume.started').write_text('old')
            prepared=SimpleNamespace(directory=directory,inputs=directory/'inputs',candidate_sha256='a'*64,environment_sha256='e'*64)
            with ownership.lease_owner(root/'owner',timeout_seconds=30) as lease:
                with patch.dict('sys.modules',{'agent.evaluation.native_flask.candidate':candidate}),\
                        patch.object(ownership,'save_lease',side_effect=OSError('disk unavailable')),\
                        patch.object(ownership,'command',side_effect=AssertionError('no Docker')):
                    result=container.observe(prepared,lease,timeout_seconds=20)
                self.assertEqual(result['status'],'ERROR');self.assertFalse(result['cleanup_complete'])
                self.assertTrue(result['creation_unknown']);self.assertEqual(result['journal_error'],'OSError')

    def test_existing_started_marker_preserves_old_evidence_and_unknown_without_replay(self):
        candidate=ModuleType('agent.evaluation.native_flask.candidate');candidate.PreparedFlaskCandidate=SimpleNamespace
        candidate.validate_candidate_inputs=lambda value:None
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);directory=root/'candidate';(directory/'inputs').mkdir(parents=True)
            (directory/'consume.started').write_text('previous owner')
            (directory/'observation.json').write_text('old evidence')
            prepared=SimpleNamespace(directory=directory,inputs=directory/'inputs',candidate_sha256='a'*64,environment_sha256='e'*64)
            with ownership.lease_owner(root/'owner',timeout_seconds=30) as lease:
                with patch.dict('sys.modules',{'agent.evaluation.native_flask.candidate':candidate}),\
                        patch.object(ownership,'command',side_effect=AssertionError('no replay')):
                    result=container.observe(prepared,lease,timeout_seconds=20)
                self.assertEqual((directory/'observation.json').read_text(),'old evidence')
                self.assertFalse(result['cleanup_complete']);self.assertTrue(result['creation_unknown'])
                self.assertTrue(lease['closed'])

    def test_public_success_and_failed_proc_gate_preserve_original_materials(self):
        for denied in (False,True):
            with self.subTest(denied=denied),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);directory=root/'candidate';inputs=directory/'inputs';inputs.mkdir(parents=True)
                (inputs/'guest.py').write_text('pass')
                prepared=SimpleNamespace(directory=directory,inputs=inputs,candidate_sha256='a'*64,environment_sha256='e'*64)
                candidate=ModuleType('agent.evaluation.native_flask.candidate');candidate.PreparedFlaskCandidate=SimpleNamespace
                candidate.validate_candidate_inputs=lambda value:None
                runtime=ModuleType('agent.evaluation.native_flask.runtime');runtime.validate_status=lambda text:not denied
                with ownership.lease_owner(root/'owner',timeout_seconds=60) as lease:
                    present=[True];identity={};processes=[]
                    def docker(*args,**kwargs):
                        if args[:2]==('image','inspect'):
                            data=json.dumps([{'Id':'sha256:'+'b'*64,'RepoDigests':[ownership.IMAGE],'Os':'linux','Architecture':'amd64'}]).encode()
                        elif args[0]=='create':
                            row=lease['containers'][-1];identity.update(expected(Path(row['inputs']),lease['owner']))
                            identity['Name']='/'+row['name'];data=b'c'*64
                        elif args[0]=='inspect':data=json.dumps([identity]).encode()
                        elif args[0]=='exec':data=(ownership.PYTHON+'\0-I\0-S\0-B\0/trusted/shim.py\0').encode() if args[-1].endswith('cmdline') else b'fixed status'
                        elif args[0]=='rm':present[0]=False;data=b''
                        else:data=b'c'*64 if present[0] else b''
                        return SimpleNamespace(returncode=0,stdout=data,stderr=b'')
                    def start(*args,**kwargs):
                        copied=Path(lease['containers'][-1]['inputs']);shim=(copied/'shim.py').read_text()
                        token=re.search('READY:([a-f0-9]{32})',shim).group(1)
                        guest={'phase':'completed','candidate_import_verified':True,'cleanup_children':True,'source_unchanged':True,
                            'candidate_sha256':'a'*64,'environment_sha256':'e'*64,'exit_code':0,'native_log':'fixture only'}
                        process=SimpleNamespace(stdin=io.BytesIO(),stdout=io.BytesIO(('READY:'+token+'\n'+json.dumps(guest)).encode()),
                            stderr=io.BytesIO(),returncode=0,poll=lambda:0)
                        processes.append(process);return process
                    with patch.dict('sys.modules',{'agent.evaluation.native_flask.candidate':candidate,'agent.evaluation.native_flask.runtime':runtime}),\
                            patch.object(ownership,'command',side_effect=docker),patch.object(container.subprocess,'Popen',side_effect=start):
                        result=container.observe(prepared,lease,timeout_seconds=30)
                    self.assertEqual(result['gate_released'],not denied)
                    self.assertEqual(result['status'],'ERROR' if denied else 'OBSERVED')
                    self.assertTrue(result['cleanup_complete']);self.assertFalse(result['creation_unknown'])
                    self.assertFalse((inputs/'shim.py').exists());self.assertFalse(lease['closed'])
                    if not denied:self.assertEqual(json.loads((directory/'guest-result.json').read_text())['native_log'],'fixture only')
                    with patch.object(ownership,'command',side_effect=docker):ownership.cleanup_flask(lease,final=True)

    def test_resource_gate_accepts_exact_profile_and_rejects_each_drift(self):
        inputs=Path('fixed-inputs');value=expected(inputs,'a'*32)
        self.assertTrue(container.expected_container(value,inputs,'a'*32,'sha256:'+'b'*64))
        for group,key,bad in [('HostConfig','NetworkMode','host'),('HostConfig','Memory',0),
                ('Config','Cmd',['/bin/sh']),('Config','User','0:0')]:
            drift=json.loads(json.dumps(value));drift[group][key]=bad
            self.assertFalse(container.expected_container(drift,inputs,'a'*32,'sha256:'+'b'*64))
        value['Mounts'].append(dict(value['Mounts'][0]))
        self.assertFalse(container.expected_container(value,inputs,'a'*32,'sha256:'+'b'*64))

    def test_rejects_inactive_owner_before_materials_or_docker(self):
        with patch.object(ownership,'command',side_effect=AssertionError('must not execute')):
            with self.assertRaises(ValueError):container.observe(object(),{})

    def test_creation_intent_is_durable_before_unknown_create_and_forbids_replay(self):
        candidate=ModuleType('agent.evaluation.native_flask.candidate')
        candidate.PreparedFlaskCandidate=SimpleNamespace
        candidate.validate_candidate_inputs=lambda value:None
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);directory=root/'candidate';(directory/'inputs').mkdir(parents=True)
            (directory/'inputs'/'guest.py').write_text('pass')
            prepared=SimpleNamespace(directory=directory,inputs=directory/'inputs',candidate_sha256='a'*64,environment_sha256='e'*64)
            with ownership.lease_owner(root/'owner',timeout_seconds=30) as lease:
                def docker(*args,**kwargs):
                    if args[:2]==('image','inspect'):
                        data=[{'Id':'sha256:'+'b'*64,'RepoDigests':[ownership.IMAGE],'Os':'linux','Architecture':'amd64'}]
                        return SimpleNamespace(returncode=0,stdout=json.dumps(data).encode(),stderr=b'')
                    if args[0]=='create':
                        journal=json.loads((root/'owner'/'lease.json').read_text())
                        self.assertTrue(journal['creation_in_flight']);self.assertIsNone(journal['containers'][0]['id'])
                        raise TimeoutError('creation reply lost')
                    raise AssertionError('must never delete by guessed name')
                with patch.dict('sys.modules',{'agent.evaluation.native_flask.candidate':candidate}),patch.object(ownership,'command',side_effect=docker):
                    result=container.observe(prepared,lease,timeout_seconds=20)
                    self.assertFalse(result['cleanup_complete']);self.assertTrue(result['creation_unknown'])
                    self.assertFalse(result['gate_released']);self.assertEqual(result['status'],'ERROR')
                    with self.assertRaises(ValueError):container.observe(prepared,lease,timeout_seconds=20)
                self.assertTrue(lease['closed'])

    def test_material_validation_time_consumes_original_case_deadline(self):
        candidate=ModuleType('agent.evaluation.native_flask.candidate');candidate.PreparedFlaskCandidate=SimpleNamespace
        clock=[100.0]
        candidate.validate_candidate_inputs=lambda value:clock.__setitem__(0,121.0)
        with tempfile.TemporaryDirectory() as temporary,patch.object(container.time,'monotonic',side_effect=lambda:clock[0]):
            root=Path(temporary);directory=root/'candidate';(directory/'inputs').mkdir(parents=True)
            prepared=SimpleNamespace(directory=directory,inputs=directory/'inputs',candidate_sha256='a'*64,environment_sha256='e'*64)
            with ownership.lease_owner(root/'owner',timeout_seconds=60) as lease:
                with patch.dict('sys.modules',{'agent.evaluation.native_flask.candidate':candidate}),patch.object(ownership,'command',side_effect=AssertionError('deadline before Docker')):
                    result=container.observe(prepared,lease,timeout_seconds=20)
                self.assertFalse(result['gate_released']);self.assertTrue(result['cleanup_complete'])
                self.assertEqual(result['error_message'],'flask_case_deadline')
