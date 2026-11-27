"""Bounded journal reconciliation and OS ownership for manual batch release."""
import hashlib
import json
import os
from pathlib import Path
import re

from agent.workspace import has_single_regular_file_link,canonical_path_key


def directory_identity(directory):
    return hashlib.sha256(canonical_path_key(Path(directory).resolve(strict=True)).encode('utf-8')).hexdigest()


class BatchJournalLock:
    def __init__(self,directory,*,create):
        self.directory=Path(directory).absolute()
        if any(p.is_symlink() or p.is_junction() for p in (self.directory,*self.directory.parents)):
            raise ValueError('Linked financial directory')
        path=self.directory/'batch-owner.lock'
        if not create and not has_single_regular_file_link(path):raise ValueError('Missing financial owner lock')
        self.stream=path.open('x+b' if create else 'r+b');self.locked=False
        try:
            if create:self.stream.write(b'1');self.stream.flush();os.fsync(self.stream.fileno())
            self.stream.seek(0)
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(self.stream.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.locked=True
        except BaseException:
            self.stream.close();raise ValueError('Financial batch owner active') from None

    def close(self):
        if self.stream.closed:return
        try:
            if self.locked:
                self.stream.seek(0)
                if os.name=='nt':
                    import msvcrt
                    msvcrt.locking(self.stream.fileno(),msvcrt.LK_UNLCK,1)
                else:
                    import fcntl
                    fcntl.flock(self.stream.fileno(),fcntl.LOCK_UN)
        finally:self.locked=False;self.stream.close()


def trial_seal(directory,spend):
    directory=Path(directory)
    if directory.is_symlink() or directory.is_junction() or not directory.is_dir():raise ValueError('Invalid trial directory')
    entries=list(directory.iterdir())
    if not 1<=len(entries)<=21:raise ValueError('Invalid trial ledger set')
    rows=[]
    for path in sorted(entries):
        if (not has_single_regular_file_link(path) or not re.fullmatch(r'(trial|request-\d{3})\.jsonl',path.name)
                or path.stat().st_size>1024*1024):raise ValueError('Invalid child receipt')
        rows.append((path.name,hashlib.sha256(path.read_bytes()).hexdigest()))
    if 'trial.jsonl' not in {p.name for p in entries}:raise ValueError('Missing child ledger')
    return hashlib.sha256(json.dumps({'files':rows,'spend':spend},sort_keys=True,separators=(',',':')).encode()).hexdigest()


def _object(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise ValueError('Duplicate journal field')
        value[key]=item
    return value


def read_released(directory,expected_digest,tasks):
    directory=Path(directory);path=directory/'batch.jsonl'
    if (directory/'write-in-progress').exists() or not has_single_regular_file_link(path) or path.stat().st_size>4*1024*1024:
        raise ValueError('Financial journal uncertain')
    raw=path.read_bytes()
    if not raw.endswith(b'\n'):raise ValueError('Incomplete financial record')
    lines=raw.splitlines()
    if not 1<=len(lines)<=4096:raise ValueError('Financial record limit')
    records=[json.loads(line,object_pairs_hook=_object) for line in lines]
    policy={'event':'POLICY','manifest_digest':expected_digest,'slots':20,'allocation_microcny':200000,
            'total_microcny':4000000,'journal_version':2,'directory_sha256':directory_identity(directory)}
    if records[0]!=policy:raise ValueError('Financial policy mismatch')
    used=set();known=0;active=None;released=halted=closed=False
    for value in records[1:]:
        if type(value) is not dict:raise ValueError('Invalid financial record shape')
        event=value.get('event')
        if closed:raise ValueError('Record follows terminal close')
        if event=='CLAIMED':
            task=value.get('task_id')
            if (set(value)!={'event','task_id','allocation_microcny'} or released or halted or active is not None
                    or task not in tasks or task in used or type(value['allocation_microcny']) is not int
                    or value['allocation_microcny']!=200000):raise ValueError('Invalid financial claim')
            used.add(task);active=task
        elif event=='FINISHED':
            if (set(value)!={'event','task_id','reported_outcome','spend','trial_sha256'} or released or halted
                    or active is None or value['task_id']!=active
                    or value['reported_outcome'] not in {'RESOLVED','UNRESOLVED','FAILED','NOT_STARTED'}):
                raise ValueError('Invalid finished claim')
            spend=value['spend']
            if (type(spend) is not dict or type(spend.get('unknown')) is not bool
                    or type(spend.get('known_microcny')) is not int or not 0<=spend['known_microcny']<=200000
                    or type(spend.get('held_microcny')) is not int or not 0<=spend['held_microcny']<=200000
                    or type(spend.get('upper_microcny')) is not int
                    or spend['upper_microcny']!=spend['known_microcny']+spend['held_microcny']
                    or spend['upper_microcny']>200000 or spend.get('limit_microcny')!=200000
                    or spend.get('currency')!='CNY' or spend.get('policy_id')!='settled-cny-v1'
                    or type(spend.get('requests')) is not int or not 0<=spend['requests']<=20
                    or not spend['unknown'] and spend['held_microcny']!=0
                    or value['trial_sha256']!=trial_seal(directory/active,spend)):
                raise ValueError('Child financial settlement mismatch')
            known+=spend['known_microcny'];halted=spend['unknown'];active=None
        elif event=='RELEASED':
            if value!={'event':'RELEASED'} or released or halted or active is not None:
                raise ValueError('Unsafe financial release')
            released=True
        elif event=='ACQUIRED':
            if value!={'event':'ACQUIRED'} or not released or halted or active is not None:
                raise ValueError('Invalid financial reacquisition')
            released=False
        elif event=='CLOSED':closed=True;released=False
        else:raise ValueError('Unknown financial event')
    if not released or active is not None or halted or closed or known>4000000:
        raise ValueError('Only explicitly released known batches can continue')
    return used,known
