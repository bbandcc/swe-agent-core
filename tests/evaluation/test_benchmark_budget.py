import tempfile
from pathlib import Path
import unittest
import httpx
from agent.evaluation.benchmark_manifest import build_benchmark_manifest, DATASET_REVISION
from agent.evaluation.benchmark_budget import BenchmarkBatchAllowance


def manifest():
    rows=[{'instance_id':f'org__repo{i%5}-{i+1}','repo':f'org/repo{i%5}','base_commit':f'{i:040x}',
           'problem_statement':'Fix the behavior','patch':'private','test_patch':'private',
           'FAIL_TO_PASS':'["f"]','PASS_TO_PASS':'["p"]'} for i in range(20)]
    return build_benchmark_manifest(rows,dataset_revision=DATASET_REVISION)


class BenchmarkBudgetTests(unittest.TestCase):
    def test_twenty_slots_are_once_only_and_sum_to_exactly_four_cny(self):
        m=manifest()
        with tempfile.TemporaryDirectory() as d:
            batch=BenchmarkBatchAllowance(m,m['manifest_digest'],Path(d)/'batch')
            try:
                for task in m['tasks']:
                    identity=task['instance_id']
                    batch.open_trial(identity,httpx.MockTransport(lambda _: self.fail('No request')))
                    with self.assertRaises(ValueError):
                        batch.open_trial(identity,httpx.MockTransport(lambda _: self.fail('No request')))
                    batch.finish_trial(identity,reported_outcome='NOT_STARTED')
                self.assertEqual(batch.summary()['allocated_microcny'],4000000)
                self.assertEqual(batch.summary()['remaining'],0)
                self.assertFalse(batch.summary()['halted'])
            finally:batch.close()
            with self.assertRaises(FileExistsError):
                BenchmarkBatchAllowance(m,m['manifest_digest'],Path(d)/'batch')

    def test_unknown_dispatch_stops_all_remaining_slots(self):
        m=manifest()
        with tempfile.TemporaryDirectory() as d:
            batch=BenchmarkBatchAllowance(m,m['manifest_digest'],Path(d)/'batch')
            try:
                task=m['tasks'][0]['instance_id']
                cap=batch.open_trial(task,httpx.MockTransport(lambda _: httpx.Response(500)))
                with httpx.Client(transport=cap) as client:
                    with self.assertRaises(httpx.TransportError):
                        client.post('https://api.deepseek.com/chat/completions',json={
                            'model':'deepseek-flash','messages':[{'role':'user','content':'Task'}],
                            'max_tokens':2048,'stream':False,'thinking':{'type':'disabled'}})
                batch.finish_trial(task,reported_outcome='FAILED')
                self.assertTrue(batch.summary()['halted'])
                with self.assertRaises(ValueError):
                    batch.open_trial(m['tasks'][1]['instance_id'],httpx.MockTransport(lambda _: self.fail('No request')))
            finally:batch.close()

    def test_wrong_frozen_manifest_is_rejected_before_creating_directory(self):
        m=manifest();m['tasks'][0]['budget_microcny']=1000000
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'batch'
            with self.assertRaises(ValueError):
                BenchmarkBatchAllowance(m,m['manifest_digest'],path)
            self.assertFalse(path.exists())

    def test_failed_finish_audit_cannot_be_retried_to_clear_unknown(self):
        import os
        from unittest.mock import patch
        m=manifest()
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'batch'
            batch=BenchmarkBatchAllowance(m,m['manifest_digest'],path)
            task=m['tasks'][0]['instance_id']
            batch.open_trial(task,httpx.MockTransport(lambda _: self.fail('No request')))
            original=os.fsync
            def disk_error(fd):
                if '"event":"FINISHED"' in (path/'batch.jsonl').read_text():
                    raise OSError('Injected disk error')
                return original(fd)
            try:
                with patch('os.fsync',side_effect=disk_error):
                    with self.assertRaises(OSError):
                        batch.finish_trial(task,reported_outcome='NOT_STARTED')
                with self.assertRaises(ValueError):
                    batch.finish_trial(task,reported_outcome='NOT_STARTED')
                with self.assertRaises(ValueError):
                    batch.open_trial(m['tasks'][1]['instance_id'],httpx.MockTransport(lambda _: self.fail('No request')))
                self.assertTrue(batch.summary()['halted'])
            finally:batch.close()

    def test_parallel_claims_cannot_open_two_live_transports(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        m=manifest();barrier=threading.Barrier(2)
        with tempfile.TemporaryDirectory() as d:
            batch=BenchmarkBatchAllowance(m,m['manifest_digest'],Path(d)/'batch')
            def claim(task):
                barrier.wait(5)
                try:
                    batch.open_trial(task,httpx.MockTransport(lambda _: self.fail('No request')))
                    return task
                except ValueError:return None
            try:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    claimed=list(pool.map(claim,[t['instance_id'] for t in m['tasks'][:2]]))
                winners=[task for task in claimed if task is not None]
                self.assertEqual(len(winners),1)
                self.assertEqual(batch.summary()['allocated_microcny'],200000)
                batch.finish_trial(winners[0],reported_outcome='NOT_STARTED')
            finally:batch.close()

    def test_closing_active_claim_is_not_a_finished_or_recoverable_trial(self):
        m=manifest()
        with tempfile.TemporaryDirectory() as d:
            batch=BenchmarkBatchAllowance(m,m['manifest_digest'],Path(d)/'batch')
            task=m['tasks'][0]['instance_id']
            batch.open_trial(task,httpx.MockTransport(lambda _: self.fail('No request')))
            batch.close()
            self.assertTrue(batch.summary()['halted'])
            self.assertTrue(batch.summary()['active'])
            self.assertTrue(batch.summary()['closed'])
            with self.assertRaises(ValueError):batch.finish_trial(task,reported_outcome='NOT_STARTED')
