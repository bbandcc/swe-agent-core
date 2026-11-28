"""Fixed Flask lease data and process ownership, without a Docker daemon."""
import json
import tempfile
import unittest
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

from agent.evaluation.native_flask.ownership import IMAGE, TASK, lease_owner, recover_flask


class FlaskLeaseTests(unittest.TestCase):
    def test_confirmed_absence_does_not_repeat_docker_after_case_cleanup(self):
        from agent.evaluation.native_flask import ownership
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'owner'
            with patch.object(ownership,'command',side_effect=AssertionError('no repeated Docker query')):
                with lease_owner(root,timeout_seconds=30) as lease:
                    ownership.begin_container(lease,'swe-flask-candidate-'+'a'*32,root,'sha256:'+'b'*64)
                    value={'Id':'c'*64,'Name':'/swe-flask-candidate-'+'a'*32,'Image':'sha256:'+'b'*64,'Created':'now',
                        'Config':{'Image':IMAGE,'Labels':{'org.opencontainers.image.version':'22.04',ownership.LABEL:lease['owner']}}}
                    ownership.confirm_container(lease,'swe-flask-candidate-'+'a'*32,value)
                    with patch.object(ownership,'command',return_value=SimpleNamespace(returncode=0,stdout=b'',stderr=b'')):
                        self.assertTrue(ownership.cleanup_flask(lease)['cleanup_complete'])
                self.assertTrue(lease['cleanup_complete'])

    def test_hard_parent_exit_releases_os_lock_for_independent_exact_cleanup(self):
        from agent.evaluation.native_flask import ownership
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'owner'
            script="""import os,sys
from agent.evaluation.native_flask.ownership import *
with lease_owner(sys.argv[1],timeout_seconds=30) as lease:
 name='swe-flask-candidate-'+'a'*32
 begin_container(lease,name,sys.argv[1],'sha256:'+'b'*64)
 value={'Id':'c'*64,'Name':'/'+name,'Image':'sha256:'+'b'*64,'Created':'now','Config':{'Image':IMAGE,'Labels':{'org.opencontainers.image.version':'22.04',LABEL:lease['owner']}}}
 confirm_container(lease,name,value)
 os._exit(7)
"""
            child=subprocess.run([sys.executable,'-c',script,str(root)],capture_output=True,timeout=15,shell=False)
            self.assertEqual(child.returncode,7,child.stderr.decode(errors='replace'))
            saved=json.loads((root/'lease.json').read_text());row=saved['containers'][0];present=[True];removed=[]
            value={'Id':row['id'],'Name':'/'+row['name'],'Image':row['image_id'],'Created':row['created_at'],
                'Config':{'Image':IMAGE,'Labels':{'org.opencontainers.image.version':'22.04',ownership.LABEL:saved['owner']}}}
            def command(*args,**kwargs):
                if args[0]=='inspect':data=json.dumps([value]).encode()
                elif args[0]=='rm':removed.append(args[-1]);present[0]=False;data=b''
                else:data=row['id'].encode() if present[0] else b''
                return SimpleNamespace(returncode=0,stdout=data,stderr=b'')
            with patch.object(ownership,'command',side_effect=command):report=recover_flask(root)
            self.assertTrue(report['cleanup_complete']);self.assertEqual(removed,[row['id']])
            self.assertFalse(report['restart_permitted']);self.assertTrue(json.loads((root/'lease.json').read_text())['closed'])

    def test_per_case_cleanup_preserves_live_owner_for_next_case(self):
        from agent.evaluation.native_flask import ownership
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'owner'
            with lease_owner(root,timeout_seconds=30) as lease:
                report=ownership.cleanup_flask(lease)
                self.assertTrue(report['cleanup_complete']);self.assertFalse(lease['closed'])
                name='swe-flask-candidate-'+'a'*32
                ownership.begin_container(lease,name,root,'sha256:'+'b'*64)
                saved=json.loads((root/'lease.json').read_text())
                self.assertTrue(saved['creation_in_flight']);self.assertIsNone(saved['containers'][0]['id'])
            self.assertTrue(lease['creation_unknown']);self.assertFalse(lease['cleanup_complete'])

    def test_recovery_deletes_only_exact_confirmed_id_and_rejects_foreign_labels(self):
        from agent.evaluation.native_flask import ownership
        for foreign in (False,True):
            with self.subTest(foreign=foreign),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)/'owner';name='swe-flask-candidate-'+'a'*32;cid='c'*64
                present=[True];removed=[]
                with lease_owner(root,timeout_seconds=30) as lease:
                    ownership.begin_container(lease,name,root,'sha256:'+'b'*64)
                    value={'Id':cid,'Name':'/'+name,'Image':'sha256:'+'b'*64,'Created':'2026-11-28T00:00:00Z',
                        'Config':{'Image':IMAGE,'Labels':{'org.opencontainers.image.version':'22.04',ownership.LABEL:lease['owner']}}}
                    ownership.confirm_container(lease,name,value)
                    if foreign:value['Config']['Labels'][ownership.LABEL]='foreign'
                    def command(*args,**kwargs):
                        if args[0]=='inspect':data=json.dumps([value]).encode()
                        elif args[0]=='rm':removed.append(args[-1]);present[0]=False;data=b''
                        else:data=cid.encode() if present[0] else b''
                        return SimpleNamespace(returncode=0,stdout=data,stderr=b'')
                    with patch.object(ownership,'command',side_effect=command):
                        report=ownership.cleanup_flask(lease)
                        self.assertEqual(report['cleanup_complete'],not foreign)
                    # Context exit/recovery do not need a daemon in this test.
                    lease['containers']=[]
                self.assertEqual(removed,[] if foreign else [cid])

    def test_active_owner_blocks_recovery_and_empty_closed_lease_is_clean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'owner'
            with lease_owner(root,timeout_seconds=30) as lease:
                saved=json.loads((root/'lease.json').read_text())
                self.assertEqual((saved['task_id'],saved['image']),(TASK,IMAGE))
                with patch('agent.evaluation.native_flask.ownership.command',side_effect=AssertionError('no Docker while owner active')):
                    self.assertEqual(recover_flask(root)['status'],'OWNER_ACTIVE')
            self.assertTrue(lease['cleanup_complete'])
            report=recover_flask(root)
            self.assertEqual(report['status'],'CLEANED');self.assertFalse(report['restart_permitted'])

    def test_malformed_or_wrong_profile_never_touches_docker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'owner'
            with lease_owner(root,timeout_seconds=30):pass
            saved=json.loads((root/'lease.json').read_text())
            for field,value in (('image','another/image'),('task_id','another-task'),('owner','../escape')):
                damaged=dict(saved);damaged[field]=value;(root/'lease.json').write_text(json.dumps(damaged))
                with patch('agent.evaluation.native_flask.ownership.command',side_effect=AssertionError('no Docker for bad pins')):
                    report=recover_flask(root)
                self.assertEqual(report['status'],'UNKNOWN');self.assertFalse(report['cleanup_complete'])

    def test_creation_in_flight_never_becomes_restart_permission_when_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'owner'
            with lease_owner(root,timeout_seconds=30):pass
            saved=json.loads((root/'lease.json').read_text())
            saved.update(creation_unknown=True,creation_in_flight=True,closed=False,cleanup_complete=False)
            (root/'lease.json').write_text(json.dumps(saved))
            report=recover_flask(root)
            self.assertEqual(report['status'],'UNKNOWN');self.assertFalse(report['restart_permitted'])
            self.assertTrue(json.loads((root/'lease.json').read_text())['creation_unknown'])

    def test_recovery_timeout_is_finite_bounded_and_not_a_task_extension(self):
        for seconds in (0,-1,True,float('nan'),float('inf'),61):
            with self.subTest(seconds=seconds),self.assertRaises(ValueError):
                recover_flask(Path('unused'),timeout_seconds=seconds)
