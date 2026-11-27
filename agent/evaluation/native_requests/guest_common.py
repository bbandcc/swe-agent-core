"""Fixed cooperative Requests controller, entered only after the parent privilege gate."""
import hashlib
from contextlib import ExitStack
import json
import os
from pathlib import Path
import resource
import signal
import stat
import shutil
import subprocess
import sys
import time

BASE = '36453b95b13079296776d11b09cab2567ea3e703'
SOURCE = '2005cc0a544f4de6962df341319dad5e70e91eab8ac2495f18f13b451dd1cd4e'
LIMIT = 4 * 1024 * 1024
CAPS = ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')
PROFILE_COUNTS = {'san-runtime-v1': 10, 'historical-compat-v1': 16}


def validate_status(text):
    facts = dict(line.split(':', 1) for line in text.splitlines() if ':' in line)
    if not (all(facts[k].split() == ['65534'] * 4 for k in ('Uid', 'Gid'))
            and not facts['Groups'].strip() and facts['NoNewPrivs'].strip() == '1'
            and all(int(facts[k], 16) == 0 for k in CAPS)):
        raise ValueError('entry_privilege_rejected')
    return {k: facts[k].strip() for k in ('Uid', 'Gid', 'Groups', 'NoNewPrivs', *CAPS)}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hash(root):
    rows, total = [], 0
    for parent, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != '.git')
        if any((Path(parent)/d).is_symlink() for d in dirs):
            raise ValueError('source_symlink')
        for name in sorted(files):
            path = Path(parent)/name
            if path.is_symlink() or not path.is_file(): raise ValueError('source_not_regular')
            total += path.stat().st_size
            if total > 64*1024*1024 or len(rows) >= 4096: raise ValueError('source_limit')
            rows.append([path.relative_to(root).as_posix(), path.stat().st_size, sha(path)])
    return hashlib.sha256(json.dumps(sorted(rows), separators=(',', ':')).encode()).hexdigest()


def run(argv, cwd, log, timeout, stderr_log=None):
    """Bound one process group; parent still verifies destruction of the whole container."""
    with ExitStack() as stack:
        output = stack.enter_context(Path(log).open('wb'))
        diagnostic = stack.enter_context(Path(stderr_log).open('wb')) if stderr_log else subprocess.STDOUT
        process = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
            stdout=output, stderr=diagnostic, start_new_session=True, shell=False)
        try:
            code = process.wait(timeout=timeout)
        finally:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait(timeout=3)
            deadline = time.monotonic() + 1
            while True:
                try: os.killpg(process.pid, 0)
                except ProcessLookupError: break
                if time.monotonic() >= deadline: raise RuntimeError('child_group_cleanup_unknown')
                time.sleep(.01)
    if Path(log).stat().st_size >= LIMIT: raise ValueError('log_limit')
    if stderr_log and Path(stderr_log).stat().st_size >= LIMIT: raise ValueError('diagnostic_limit')
    return code


def certificates(record, profile='san-runtime-v1', fixed=None):
    certdir = Path('/tmp/site/pytest_httpbin/certs')
    record['original_cert_sha256'] = {n: sha(certdir/n) for n in ('cacert.pem', 'cert.pem', 'key.pem')}
    if fixed is not None:
        if profile != 'historical-compat-v1' or set(fixed) != {'owner', 'sha256'}:
            raise ValueError('fixed_tls_configuration')
        root = Path('/fixed-tls')
        if (sorted(p.name for p in root.iterdir()) != ['cacert.pem','cert.pem','key.pem','manifest.json']
                or (root/'manifest.json').is_symlink() or not (root/'manifest.json').is_file()
                or (root/'manifest.json').stat().st_size > 65536):
            raise ValueError('fixed_tls_manifest_file')
        manifest = json.loads((root/'manifest.json').read_text())
        if manifest != fixed or set(fixed['sha256']) != {'cacert.pem', 'cert.pem', 'key.pem'}:
            raise ValueError('fixed_tls_manifest_changed')
        for name in ('cacert.pem', 'cert.pem', 'key.pem'):
            path = root/name
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size < 65536:
                    raise ValueError('fixed_tls_file')
                with os.fdopen(fd, 'rb', closefd=False) as stream: data = stream.read(65536)
                if hashlib.sha256(data).hexdigest() != fixed['sha256'][name]:
                    raise ValueError('fixed_tls_hash_changed')
                (certdir/name).write_bytes(data)
                if sha(certdir/name) != fixed['sha256'][name]: raise ValueError('fixed_tls_copy_changed')
            finally: os.close(fd)
        record['derived_cert_sha256'] = dict(fixed['sha256'])
        record['certificate_adaptation'] = 'Same private RO volume materials; historical CN-only fixture; no verification bypass'
        return
    raise ValueError('fixed_tls_materials_required')


INVOCATION = r'''
import hashlib,json,os,sys
from pathlib import Path
sys.path[:0]=['/tmp/candidate','/tmp/site']
import requests,requests.utils
origin=Path(requests.utils.__file__).resolve()
if not origin.is_relative_to(Path('/tmp/candidate')):raise RuntimeError('wrong_candidate_origin')
if origin.read_bytes()!=Path('/tmp/work/requests/utils.py').read_bytes():raise RuntimeError('wrong_candidate_bytes')
Path('/tmp/origin.json').write_text(json.dumps({'module':'requests.utils','origin':str(origin),
    'candidate_sha256':hashlib.sha256(origin.read_bytes()).hexdigest()}))
import pytest
os.chdir('/tmp/work')
args=['-p','pytest_httpbin.plugin','-rA','tests/test_requests.py']
if sys.argv[1]=='historical-compat-v1':
    if pytest.__version__!='3.10.1' or not Path(pytest.__file__).resolve().is_relative_to(Path('/tmp/site')):
        raise RuntimeError('wrong_compat_pytest_origin_or_version')
    args[:0]=['-v','--assert=plain','-p','pytest_mock']
sys.exit(pytest.main(args))
'''
