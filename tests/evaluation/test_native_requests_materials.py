"""Public data-contract checks; real Docker evidence is recorded separately."""
import math
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from agent.evaluation.native_requests.tls import (IMAGE, IMAGE_LABELS, LABEL, PYTHON,
    container_is_expected, deadline_timeout, fixed_tls_materials, invoke, volume_is_owned)


class FixedTLSContracts(unittest.TestCase):
    def test_volume_identity_requires_exact_owned_local_volume(self):
        lease = {'volume': 'swe-fixed-tls-'+'a'*32, 'owner': 'a'*32,
                 'created_at': '2026-11-26T00:00:00Z'}
        value = {'Name': lease['volume'], 'Driver': 'local', 'Options': {},
                 'Labels': {'swe.fixed-tls.owner': lease['owner']},
                 'CreatedAt': lease['created_at']}
        self.assertTrue(volume_is_owned(value, lease))
        for key, change in [('Name', 'other'), ('Driver', 'nfs'),
                            ('Options', {'device': '/host'}), ('Labels', {}),
                            ('CreatedAt', 'different')]:
            with self.subTest(key=key):
                self.assertFalse(volume_is_owned({**value, key: change}, lease))
        self.assertFalse(volume_is_owned({}, lease))

    def test_deadlines_are_finite_positive_and_cannot_be_extended(self):
        self.assertEqual(deadline_timeout(110, 20, 100), 10)
        self.assertEqual(deadline_timeout(110, 3, 100), 3)
        for args in [(100, 3, 100), (99, 3, 100), (110, 0, 100),
                     (math.inf, 3, 100), (110, math.nan, 100)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                deadline_timeout(*args)

    def test_container_rejects_entrypoint_directory_or_propagation_drift(self):
        lease = {'owner': 'a'*32, 'volume': 'swe-fixed-tls-'+'a'*32}
        inputs = Path('inputs')
        value = {'HostConfig': {'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,
            'PidMode':'','IpcMode':'private','PidsLimit':32,'Memory':268435456,
            'MemorySwap':268435456,'NanoCpus':1000000000,'Tmpfs':{'/tmp':'rw,nosuid,nodev,noexec,size=16m'},
            'LogConfig':{'Type':'none'},'CapDrop':['ALL'],'CapAdd':[], 'SecurityOpt':['no-new-privileges']},
            'Config': {'User':'65534:65534','Image':IMAGE,'Entrypoint':[PYTHON],'WorkingDir':'/',
                'Cmd':['-I','-B','/trusted/guest.py','consumer',lease['owner']],
                'Labels':{**IMAGE_LABELS,LABEL:lease['owner']}},
            'Mounts':[{'Type':'bind','Source':str(inputs.resolve()),'Destination':'/trusted','RW':False,'Propagation':'rprivate'},
                {'Type':'volume','Name':lease['volume'],'Destination':'/fixed-tls','Driver':'local','RW':False}]}
        self.assertTrue(container_is_expected(value,lease,inputs,'consumer'))
        for key, changed in [('Entrypoint',['/bin/sh']),('WorkingDir','/testbed')]:
            with self.subTest(key=key):
                invalid={**value,'Config':{**value['Config'],key:changed}}
                self.assertFalse(container_is_expected(invalid,lease,inputs,'consumer'))
        value['Mounts'][0]['Propagation']='shared'
        self.assertFalse(container_is_expected(value,lease,inputs,'consumer'))

    def test_create_rpc_timeout_never_reports_cleanup_complete(self):
        for visible in (True,False):
            with self.subTest(volume_visible=visible), tempfile.TemporaryDirectory() as temp:
                state={'volume':None,'present':False}
                def docker(*args,**kwargs):
                    if args[:2]==('volume','create'):
                        state.update(volume=args[-1],present=True)
                        raise subprocess.TimeoutExpired(['docker',*args],1)
                    if args[:2]==('volume','ls'):
                        return subprocess.CompletedProcess(args,0,
                            (state['volume'] or '').encode() if state['present'] and visible else b'',b'')
                    if args[:2]==('volume','inspect'):
                        owner=state['volume'].removeprefix('swe-fixed-tls-')
                        value={'Name':state['volume'],'Driver':'local','Options':None,
                            'Labels':{LABEL:owner},'CreatedAt':'2026-11-26T00:00:00Z'}
                        return subprocess.CompletedProcess(args,0,json.dumps([value]).encode(),b'')
                    if args[:2]==('volume','rm'):
                        state['present']=False
                        return subprocess.CompletedProcess(args,0,b'',b'')
                    raise AssertionError('unexpected operation')
                directory=Path(temp)/'run'
                with patch('agent.evaluation.native_requests.tls.command',side_effect=docker):
                    with self.assertRaisesRegex(RuntimeError,'cleanup_unknown'):
                        with fixed_tls_materials(directory):
                            self.fail('timed-out create must not yield materials')
                lease=json.loads((directory/'lease.json').read_text())
                self.assertTrue(lease['creation_unknown'])
                self.assertFalse(lease['cleanup_complete'])
                self.assertIn('creation_rpc_outcome_unknown',lease['cleanup_errors'])
                self.assertEqual(state['present'],not visible)

    def test_nonzero_or_malformed_create_receipts_remain_unknown(self):
        for code, payload in ((1,b''),(0,b'not-the-requested-volume')):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as temp:
                lease={'volume':'swe-fixed-tls-'+'a'*32,'deadline':time.monotonic()+10,
                    'cleanup_deadline':time.monotonic()+20,'creation_unknown':False,
                    'file':str(Path(temp)/'lease.json')}
                result=subprocess.CompletedProcess([],code,payload,b'')
                with patch('agent.evaluation.native_requests.tls.command',return_value=result):
                    with self.assertRaisesRegex(ValueError,'creation_rpc_outcome_unknown'):
                        invoke(lease,'volume','create',lease['volume'])
                persisted=json.loads(Path(lease['file']).read_text())
                self.assertTrue(persisted['creation_unknown'])
                self.assertTrue(persisted['creation_in_flight'])


if __name__ == '__main__':
    unittest.main()
