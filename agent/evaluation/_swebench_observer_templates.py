"""Fixed cooperative worker templates; candidate packages only load in Docker."""

ROSTER_SOURCE = '''import json,runpy,sys,traceback,platform
sys.path[:0]=['/repo','/deps']
ns=runpy.run_path('/trusted/test_basic.py')
records=[]
for name in CASE_IDS:
    try:
        ns[name]()
        records.append({'id':name,'passed':True})
    except Exception as error:
        records.append({'id':name,'passed':False,'error':type(error).__name__,
                        'traceback':traceback.format_exc(limit=5)})
print(json.dumps({'python':platform.python_version(),'cases':records},sort_keys=True))
sys.exit(0 if all(r['passed'] for r in records) else 1)
'''

HOST_SOURCE = '''import hashlib,json,re,sys
sys.dont_write_bytecode=True
from pathlib import Path
import pytest
from observer_contract import parse_cooperative_execution
from control_runtime import execute,IMAGE
CASE_IDS = IDS_LITERAL
def load_json(path):
    def unique(pairs):
        value=dict(pairs)
        if len(value)!=len(pairs):
            raise ValueError('Duplicate JSON key')
        return value
    with Path(path).open('rb') as stream:
        data=stream.read(65537)
    if len(data)>65536:
        raise ValueError('Control exceeds bound')
    return json.loads(data,object_pairs_hook=unique)
@pytest.fixture(scope='session')
def observed():
    config=load_json(Path(__file__).parent/'config.json')
    receipt={'receipt_id':None,'source_hash':None,'image':IMAGE,'status':'execution_error',
             'cleanup_complete':False,'execution':None,'observed':None}
    try:
        control=load_json(config['control_path'])
        receipt.update(receipt_id=control.get('attempt_id'),source_hash=control.get('source_hash'))
        if (not re.fullmatch(r'[a-f0-9]{32}',control['attempt_id'])
                or not re.fullmatch(r'swe-cooperative-[a-f0-9]{32}',control['container_name'])
                or not re.fullmatch(r'[a-f0-9]{64}',control['source_hash'])
                or control.get('receipt_path',config['receipt_path']) != config['receipt_path']):
            raise ValueError('Invalid parent control identity')
        snapshot=Path(control['snapshot_repo'])
        root=Path(config['root'])
        if (not snapshot.is_absolute() or not snapshot.resolve().is_relative_to(root)
                or any(part.is_symlink() or part.is_junction() for part in (snapshot,*snapshot.parents))
                or any(snapshot==root/name or root/name in snapshot.parents or snapshot in (root/name).parents
                       for name in ('B','D','G','O'))):
            raise ValueError('Snapshot escaped the run root')
        source_path=snapshot.joinpath('sympy/core/_print_helpers.py')
        if source_path.is_symlink() or source_path.stat().st_nlink!=1:
            raise ValueError('Snapshot source is not a single regular file')
        with source_path.open('rb') as stream:
            source=stream.read(32769)
        if len(source)>32768 or hashlib.sha256(source).hexdigest()!=control['source_hash']:
            raise ValueError('Snapshot source identity changed')
        execution=execute(snapshot,Path(config['dependency_root']),Path(__file__).parent,
            ['python','-I','-S','-B','/trusted/run_roster.py'],container_name=control['container_name'])
        receipt.update(execution=execution,cleanup_complete=execution['cleanup'])
        value=parse_cooperative_execution(execution,tuple(CASE_IDS))
        receipt.update(status='completed',observed=value)
    finally:
        Path(config['receipt_path']).write_text(json.dumps(receipt,sort_keys=True),encoding='utf-8')
    return {case['id']:case for case in value['cases']}
@pytest.mark.parametrize('case_id',CASE_IDS,ids=CASE_IDS)
def test_case(case_id,observed):
    case=observed[case_id]
    if not case['passed']:
        pytest.fail(case.get('traceback','Assertion failed'),pytrace=False)
'''
