"""Manual continuation of the same financial authorization, never rerun a trial."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import httpx

from agent.evaluation.benchmark_budget import BenchmarkBatchAllowance
from tests.evaluation.test_benchmark_budget import manifest


class BatchResumeTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)/'budget';self.manifest=manifest()

    def create(self):
        batch=BenchmarkBatchAllowance(self.manifest,self.manifest['manifest_digest'],self.root)
        self.addCleanup(batch.close);return batch

    def reopen(self):
        batch=BenchmarkBatchAllowance.open_existing(self.manifest,self.manifest['manifest_digest'],self.root)
        self.addCleanup(batch.close);return batch

    def test_manual_release_preserves_consumed_slot_and_settled_cost(self):
        batch=self.create();task=self.manifest['tasks'][0]['instance_id']
        cap=batch.open_trial(task,httpx.MockTransport(lambda _:httpx.Response(200,json={
            'model':'deepseek-flash','usage':{'prompt_tokens':1,'completion_tokens':1,'total_tokens':2}})))
        with httpx.Client(transport=cap) as client:
            client.post('https://api.deepseek.com/chat/completions',json={'model':'deepseek-flash',
                'messages':[{'role':'user','content':'Task'}],'max_tokens':2048,'stream':False,
                'thinking':{'type':'disabled'}})
        batch.finish_trial(task,reported_outcome='FAILED');batch.release()
        resumed=self.reopen()
        self.assertEqual(resumed.summary()['claimed'],1)
        self.assertEqual(resumed.summary()['finished_known_microcny'],10)
        with self.assertRaises(ValueError):resumed.open_trial(task,httpx.MockTransport(lambda _:None))
        resumed.open_trial(self.manifest['tasks'][1]['instance_id'],httpx.MockTransport(lambda _:None))
        resumed.finish_trial(self.manifest['tasks'][1]['instance_id'],reported_outcome='NOT_STARTED')
        resumed.release();again=self.reopen()
        self.assertEqual(again.summary()['allocated_microcny'],400000)

    def test_live_owner_or_terminal_close_cannot_be_reopened(self):
        batch=self.create()
        with self.assertRaises(ValueError):self.reopen()
        batch.close()
        with self.assertRaises(ValueError):self.reopen()

    def test_active_or_unknown_claim_cannot_be_released(self):
        batch=self.create();task=self.manifest['tasks'][0]['instance_id']
        cap=batch.open_trial(task,httpx.MockTransport(lambda _:httpx.Response(500)))
        with self.assertRaises(ValueError):batch.release()
        with httpx.Client(transport=cap) as client:
            with self.assertRaises(httpx.TransportError):
                client.post('https://api.deepseek.com/chat/completions',json={'model':'deepseek-flash',
                    'messages':[{'role':'user','content':'Task'}],'max_tokens':2048,'stream':False,
                    'thinking':{'type':'disabled'}})
        batch.finish_trial(task,reported_outcome='FAILED')
        with self.assertRaises(ValueError):batch.release()
        batch.close()
        with self.assertRaises(ValueError):self.reopen()

    def test_failed_release_fsync_cannot_become_a_recoverable_release(self):
        import os
        batch=self.create();original=os.fsync
        def fail(fd):
            if '"event":"RELEASED"' in (self.root/'batch.jsonl').read_text():raise OSError('disk failure')
            return original(fd)
        with patch('os.fsync',side_effect=fail),self.assertRaises(OSError):batch.release()
        batch.close()
        with self.assertRaises(ValueError):self.reopen()

    def test_changed_child_ledger_or_corrupt_parent_never_reopens(self):
        batch=self.create();task=self.manifest['tasks'][0]['instance_id']
        batch.open_trial(task,httpx.MockTransport(lambda _:None))
        batch.finish_trial(task,reported_outcome='NOT_STARTED');batch.release()
        (self.root/task/'trial.jsonl').write_text('changed',encoding='utf-8')
        with self.assertRaises(ValueError):self.reopen()

    def test_changed_manifest_cannot_reuse_original_authorization(self):
        batch=self.create();batch.release()
        changed=dict(self.manifest);changed['manifest_digest']='0'*64
        with self.assertRaises(ValueError):BenchmarkBatchAllowance.open_existing(changed,'0'*64,self.root)

    def test_parent_settlement_change_cannot_reuse_unchanged_child_seal(self):
        batch=self.create();task=self.manifest['tasks'][0]['instance_id']
        batch.open_trial(task,httpx.MockTransport(lambda _:None))
        batch.finish_trial(task,reported_outcome='NOT_STARTED');batch.release()
        path=self.root/'batch.jsonl';records=[json.loads(line) for line in path.read_text().splitlines()]
        finished=next(r for r in records if r['event']=='FINISHED')
        finished['spend'].update(known_microcny=1,upper_microcny=1)
        path.write_text(''.join(json.dumps(r)+'\n' for r in records),encoding='utf-8')
        with self.assertRaises(ValueError):self.reopen()

    def test_copied_released_ledger_is_not_a_second_authorization(self):
        import shutil
        batch=self.create();batch.release()
        copied=self.root.with_name('copied-budget');shutil.copytree(self.root,copied)
        with self.assertRaises(ValueError):BenchmarkBatchAllowance.open_existing(self.manifest,self.manifest['manifest_digest'],copied)

    def test_incomplete_parent_record_is_not_truncated_and_reused(self):
        batch=self.create();batch.release()
        with (self.root/'batch.jsonl').open('ab') as stream:stream.write(b'{"event":')
        with self.assertRaises(ValueError):self.reopen()
        self.assertTrue((self.root/'batch.jsonl').read_bytes().endswith(b'{"event":'))

    def test_real_process_owner_death_does_not_release_unfinished_authorization(self):
        import subprocess,sys,time
        source="""import sys,time,httpx
from pathlib import Path
from tests.evaluation.test_benchmark_budget import manifest
from agent.evaluation.benchmark_budget import BenchmarkBatchAllowance
m=manifest();b=BenchmarkBatchAllowance(m,m['manifest_digest'],Path(sys.argv[1]))
b.open_trial(m['tasks'][0]['instance_id'],httpx.MockTransport(lambda _:None))
(Path(sys.argv[1])/'ready').write_bytes(b'1')
time.sleep(60)
"""
        process=subprocess.Popen([sys.executable,'-c',source,str(self.root)],stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,shell=False,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        try:
            deadline=time.monotonic()+25
            while not (self.root/'ready').exists() and time.monotonic()<deadline and process.poll() is None:
                time.sleep(.05)
            self.assertTrue((self.root/'ready').exists())
            with self.assertRaises(ValueError):self.reopen()
            process.kill();process.wait(timeout=10)
            with self.assertRaises(ValueError):self.reopen()
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=10)

    def test_twenty_original_slots_remain_exactly_four_cny_across_manual_releases(self):
        batch=self.create()
        for index,task in enumerate(self.manifest['tasks']):
            batch.open_trial(task['instance_id'],httpx.MockTransport(lambda _:None))
            batch.finish_trial(task['instance_id'],reported_outcome='NOT_STARTED')
            if index in (6,13):batch.release();batch=self.reopen()
        self.assertEqual(batch.summary()['claimed'],20)
        self.assertEqual(batch.summary()['allocated_microcny'],4000000)
        self.assertEqual(batch.summary()['remaining'],0)


if __name__=='__main__':unittest.main()
