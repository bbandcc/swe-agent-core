"""Fixed host assertions for validated native data; never native execution admission."""
from dataclasses import dataclass, replace
import json
import hashlib
import math
import os
from pathlib import Path
import sys

from agent.evaluation.native_result import NativeAttemptResult, validate_native_attempt
from agent.verification.contracts import VerificationCheckStatus, VerificationResult, VerificationSpec
from agent.verification.runner import VerificationRunner
from agent.workspace import has_single_regular_file_link

HOST = '''import json
from pathlib import Path
import pytest
TOKEN = {token}
IDS = {ids}
@pytest.fixture(scope='session')
def observations():
    path=Path(__file__).with_name('observation.json')
    assert path.stat().st_size<=65536
    data=json.loads(path.read_text(encoding='utf-8'))
    assert set(data)=={{'token','cases'}} and data['token']==TOKEN
    assert type(data['cases']) is list and len(data['cases'])==len(IDS)
    assert all(type(v) is bool for v in data['cases'])
    return data['cases']
@pytest.mark.parametrize('index',range(len(IDS)),ids=IDS)
def test_case(index,observations):
    if not observations[index]:pytest.fail('Native assertion failed',pytrace=False)
'''
INI = b'[pytest]\naddopts =\npython_files = test_observer.py\n'


@dataclass(frozen=True, slots=True)
class NativeObserverResult:
    native: NativeAttemptResult | None
    verification: VerificationResult
    case_mapping: tuple[tuple[str, str], ...] = ()
    inputs_sha256: str | None = None


def native_observer_spec(directory: Path, *, timeout_seconds: float = 30) -> VerificationSpec:
    """Stable graph check identity, even while the ephemeral observer is absent."""
    root=Path(directory).resolve()
    return VerificationSpec('native-observer',(sys.executable,'-m','pytest','-q',
        '-p','no:cacheprovider','--assert=plain','--noconftest',f'--confcutdir={root}',
        '-c',str(root/'pytest.ini'),f'--rootdir={root}',str(root/'test_observer.py'),
        '--junitxml=report.xml'),timeout_seconds=timeout_seconds,report_path='report.xml')


def observe_native_result(task, observed_identity, *, expected_identity, log: str,
                          exit_code: int | None, completed: bool, cleanup_complete: bool,
                          directory: Path, runtime_root: Path,
                          timeout_seconds: float = 30) -> NativeObserverResult:
    """Execute only authored pytest; foreign names/log text never enter its code.

    Caller owns both disjoint directories and excludes concurrent host writers.
    Lifecycle facts/identity are caller-supplied, independently obtained evidence;
    generating JUnit does not authenticate them or run any candidate code.
    """
    native = None
    spec = VerificationSpec('native-observer',(sys.executable,'-m','pytest',
        '--junitxml=report.xml'),report_path='report.xml')
    def error(message):
        return NativeObserverResult(native,VerificationResult.create(name=spec.name,argv=spec.argv,
            cwd=spec.cwd,status=VerificationCheckStatus.EXECUTION_ERROR,exit_code=None,message=message))
    try:
        if (type(timeout_seconds) not in (int,float) or not math.isfinite(timeout_seconds)
                or not 0<timeout_seconds<=60):return error('Invalid native observer deadline')
        native=validate_native_attempt(task,observed_identity,expected_identity=expected_identity,
            log=log,exit_code=exit_code,completed=completed,cleanup_complete=cleanup_complete)
        if not native.valid:return error('Native observation rejected')
        if (os.environ.get('PYTEST_DISABLE_PLUGIN_AUTOLOAD')!='1'
                or os.environ.get('PYTHONDONTWRITEBYTECODE')!='1'
                or any(os.environ.get(k) for k in ('PYTEST_ADDOPTS','PYTEST_PLUGINS','PYTHONPATH','PYTHONHOME'))):
            return error('Fixed plugin-free host environment required')
        directory,runtime_root=Path(directory).absolute(),Path(runtime_root).absolute()
        if any(p.is_symlink() or p.is_junction() for root in (directory,runtime_root) for p in (root,*root.parents)):
            return error('Linked native observer roots')
        directory,runtime_root=directory.resolve(),runtime_root.resolve()
        if (directory.exists() or not directory.parent.is_dir() or directory==runtime_root
                or directory in runtime_root.parents or runtime_root in directory.parents):
            return error('Fresh disjoint native observer root required')
        if not 1<=len(native.parsed.cases)<=4096:return error('Native case limit')
        ids=[f'c{i:04d}' for i in range(len(native.parsed.cases))]
        mapping=tuple((case,'test_observer::test_case['+ids[i]+']') for i,(case,_) in enumerate(native.parsed.cases))
        data={'token':expected_identity.attempt_id,'cases':[s=='PASSED' for _,s in native.parsed.cases]}
        files={'test_observer.py':HOST.format(token=repr(expected_identity.attempt_id),ids=repr(ids)).encode(),
            'pytest.ini':INI,'observation.json':json.dumps(data,separators=(',',':')).encode()}
        directory.mkdir()
        for name,content in files.items():
            with (directory/name).open('xb') as stream:stream.write(content)
        spec=native_observer_spec(directory,timeout_seconds=timeout_seconds)
        result=VerificationRunner(directory,runtime_root=runtime_root).run(spec)
        if any(not has_single_regular_file_link(directory/name)
                or (directory/name).read_bytes()!=content for name,content in files.items()):
            return error('Native observer inputs changed')
        expected_status=VerificationCheckStatus.PASS if exit_code==0 else VerificationCheckStatus.FAIL
        expected_cases={target:status for (_,target),(_,status) in zip(mapping,native.parsed.cases)}
        if (result.status is not expected_status or result.exit_code!=exit_code or result.report is None
                or set(result.report.case_map)!=set(expected_cases)
                or any(c.status.value!=('pass' if expected_cases[c.case_id]=='PASSED' else 'fail')
                    for c in result.report.cases)):
            return error('Native host assertion/report mismatch')
        result=replace(result,stdout='Fixed native assertions completed.',stderr='',
            message='native_receipt='+expected_identity.attempt_id)
        inputs_sha=hashlib.sha256(json.dumps([[name,len(content),hashlib.sha256(content).hexdigest()]
            for name,content in sorted(files.items())],separators=(',',':')).encode()).hexdigest()
        # Own fresh folder only; preserve any changed/extra input as evidence.
        if {p.name for p in directory.iterdir()}!=set(files):return error('Native observer cleanup unknown')
        for name in files:(directory/name).unlink()
        directory.rmdir()
        return NativeObserverResult(native,result,mapping,inputs_sha)
    except (OSError,ValueError,TypeError,KeyError,AttributeError):
        return error('Native observer unavailable')
