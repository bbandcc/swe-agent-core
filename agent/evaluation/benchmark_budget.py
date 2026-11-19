"""Once-only allocation of twenty 0.2-CNY trials; not execution admission."""
import json
import os
import re
import threading
from pathlib import Path

from agent.evaluation.benchmark_manifest import DEFAULT_POLICY, model_input
from agent.evaluation.trial_spend import SettledTrialTransport, TRIAL_LIMIT_MICROCNY


class BenchmarkBatchAllowance:
    """Serial financial allocation, separate from repository safety and grading.

    Never resume an existing directory. A claim is consumed even on failure.
    Only the owned live transport supplies spend totals; an unknown stops all
    remaining claims. Outcomes are caller reports, not acceptance proofs.
    """

    def __init__(self, manifest: dict, expected_digest: str, directory: Path):
        if (manifest.get('manifest_digest') != expected_digest
                or manifest.get('policy') != DEFAULT_POLICY
                or manifest.get('scheduled') != 20
                or manifest.get('total_budget_microcny') != 4000000):
            raise ValueError('Frozen four-CNY manifest required')
        tasks = [task['instance_id'] for task in manifest['tasks']]
        if (len(tasks) != 20 or len(set(tasks)) != 20
                or any(not re.fullmatch(r'[A-Za-z0-9_.-]+__[A-Za-z0-9_.-]+-[1-9][0-9]*', t) for t in tasks)):
            raise ValueError('Twenty distinct allocation slots required')
        for task in tasks:
            model_input(manifest, task)  # Verifies the complete frozen manifest.
        self._tasks = frozenset(tasks)
        self._lock = threading.RLock()
        self._used = set()
        self._active = None
        self._halted = self._closed = False
        self._known = 0
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self._writer = (self.directory/'batch.jsonl').open('x', encoding='utf-8')
        try:
            self._record('POLICY', manifest_digest=expected_digest, slots=20,
                         allocation_microcny=TRIAL_LIMIT_MICROCNY, total_microcny=4000000)
        except BaseException:
            self._writer.close()
            raise

    def _record(self, event, **data):
        self._writer.write(json.dumps({'event':event, **data}, separators=(',', ':'))+'\n')
        self._writer.flush()
        os.fsync(self._writer.fileno())

    def open_trial(self, task_id: str, inner) -> SettledTrialTransport:
        with self._lock:
            return self._open_trial(task_id, inner)

    def _open_trial(self, task_id, inner):
        if (self._closed or self._halted or self._active is not None
                or task_id not in self._tasks or task_id in self._used):
            raise ValueError('Batch claim refused')
        self._used.add(task_id)
        try:
            self._record('CLAIMED', task_id=task_id, allocation_microcny=TRIAL_LIMIT_MICROCNY)
            cap = SettledTrialTransport(inner, self.directory/task_id)
            self._active = (task_id, cap)
            return cap
        except BaseException:
            self._halted = True
            raise

    def finish_trial(self, task_id: str, *, reported_outcome: str):
        with self._lock:
            self._finish_trial(task_id, reported_outcome=reported_outcome)

    def _finish_trial(self, task_id, *, reported_outcome):
        if self._closed or self._halted or self._active is None or self._active[0] != task_id:
            raise ValueError('No matching active trial')
        if reported_outcome not in {'RESOLVED','UNRESOLVED','FAILED','NOT_STARTED'}:
            raise ValueError('Explicit terminal outcome required')
        _, cap = self._active
        # Closing waits for an active dispatch and prevents spending after seal.
        try:
            cap.close()
            summary = cap.summary()
            if summary['upper_microcny'] > TRIAL_LIMIT_MICROCNY:
                raise ValueError('Trial allowance invariant failed')
            self._halted = summary['unknown']
            self._record('FINISHED', task_id=task_id, reported_outcome=reported_outcome,
                         spend=summary)
            self._known += summary['known_microcny']
            self._active = None
        except BaseException:
            self._halted = True
            raise

    def summary(self):
        return {'scheduled':20, 'claimed':len(self._used), 'remaining':20-len(self._used),
                'allocated_microcny':len(self._used)*TRIAL_LIMIT_MICROCNY,
                'limit_microcny':4000000, 'finished_known_microcny':self._known,
                'halted':self._halted, 'active':self._active is not None,
                'closed':self._closed,
                'automatic_resume':False}

    def close(self):
        with self._lock:
            self._close()

    def _close(self):
        if not self._closed:
            self._closed = True
            try:
                if self._active is not None:
                    self._halted = True
                    self._active[1].close()
            finally:
                self._writer.close()
