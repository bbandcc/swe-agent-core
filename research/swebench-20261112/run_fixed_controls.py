"""Research-only SymPy controls. No arbitrary candidates, model, or host imports.

The three reviewed inputs share immutable official tests. Results are cooperative
test evidence, not an adversarial Python sandbox or an official leaderboard run.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / '.research-cache/swebench-official-research'
IMAGE = 'python@sha256:2d97f6910b16bd338d3060f261f53f144965f755599aab1acda1e13cf1731b1b'
BASE = 'cffd4e0f86fefd4802349a9f9b19ed70934ea354'
SOURCE = 'sympy/core/_print_helpers.py'
TEST = 'sympy/core/tests/test_basic.py'
PINS = {
    'sympy-base.tar.gz': '932ba79e0521f1076e0e14ff134ea1a93d970b3a839b867f11039b4f0a6babda',
    'mpmath-1.3.0-py3-none-any.whl': 'a0b2b9fe80bbcd81a6647ff13108738cfb482d481d826cc0e02f5b35e5c88d2c',
    'sympy__sympy-20590.row.json': 'feb99cda40e77a4391d300261f7a511072080217fef21c94afdd58c0000e9382',
}
LIMIT = 65_536


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def relative(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or any(p in ('..', '') or ':' in p for p in path.parts) or '\\' in name:
        raise ValueError('Unsafe archive member')
    return path


def materialize(repo: Path, deps: Path) -> None:
    """Extract only ordinary, bounded data; never execute archive/wheel code."""
    total = count = 0
    prefix = 'sympy-' + BASE
    with tarfile.open(CACHE / 'sympy-base.tar.gz', 'r:gz') as archive:
        for member in archive:
            path = relative(member.name)
            if path.parts[0] != prefix:
                raise ValueError('Archive root changed')
            if member.isdir():
                continue
            if not member.isfile() or member.size > 8 * 1024 * 1024:
                raise ValueError('Unsupported archive entry')
            total += member.size
            count += 1
            if count > 3000 or total > 64 * 1024 * 1024:
                raise ValueError('Archive bound exceeded')
            target = repo.joinpath(*path.parts[1:])
            if target.exists():
                raise ValueError('Duplicate archive entry')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.extractfile(member).read())
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
    if (count, total) != (1828, 32985401):
        raise ValueError('Unexpected archive inventory')
    total = 0
    with zipfile.ZipFile(CACHE / 'mpmath-1.3.0-py3-none-any.whl') as wheel:
        for item in wheel.infolist():
            path = relative(item.filename)
            if path.parts[0] != 'mpmath' or item.is_dir():
                continue
            if (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('Wheel symlink rejected')
            total += item.file_size
            if total > 8 * 1024 * 1024 or item.file_size > 2 * 1024 * 1024:
                raise ValueError('Wheel bound exceeded')
            target = deps.joinpath(*path.parts)
            if target.exists():
                raise ValueError('Duplicate wheel entry')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(wheel.read(item))


def apply_fixed_patch(repo: Path, patch: str, expected_path: str, *, wrong: bool = False) -> dict:
    """Only the pinned, one-hunk patches are admitted through the public seam."""
    sys.path.insert(0, str(ROOT))
    from agent.editing.models import EditOperation, EditProposal, EditStatus
    from agent.editing.workspace import WorkspaceEditor
    from agent.workspace.policy import WorkspaceAccessPolicy
    lines = patch.splitlines(keepends=True)
    if (lines[0] != f'diff --git a/{expected_path} b/{expected_path}\n'
            or sum(line.startswith('@@ ') for line in lines) != 1):
        raise ValueError('Unexpected fixed patch shape')
    start = next(i for i, line in enumerate(lines) if line.startswith('@@ ')) + 1
    old = ''.join(line[1:] for line in lines[start:] if line.startswith((' ', '-')))
    new = ''.join(line[1:] for line in lines[start:] if line.startswith((' ', '+')))
    if wrong:
        if new.count('__slots__ = ()') != 1:
            raise ValueError('Unexpected gold source')
        new = new.replace('__slots__ = ()', "__slots__ = ('__dict__',)")
    editor = WorkspaceEditor(repo, access_policy=WorkspaceAccessPolicy())
    before = editor.snapshot(expected_path)
    result = editor.apply(EditProposal('sympy__sympy-20590', expected_path,
        EditOperation.EDIT, new, base_hash=before.content_hash, old_text=old))
    if result.status != EditStatus.APPLIED:
        raise ValueError(f'Fixed edit rejected: {result.error_code}')
    return {'path': expected_path, 'before': result.before_hash, 'after': result.after_hash}


def tree_hash(root: Path) -> str:
    entries = [(p.relative_to(root).as_posix(), digest(p.read_bytes()))
               for p in sorted(root.rglob('*')) if p.is_file()]
    return digest(json.dumps(entries, separators=(',', ':')).encode())


def command(argv: list[str], timeout: float = 15) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, timeout=timeout,
                          stdin=subprocess.DEVNULL, shell=False, check=False)


def execute(repo: Path, deps: Path, trusted: Path, argv: list[str]) -> dict:
    """One fixed container; inspect before execution and always prove removal."""
    name = 'swe-sympy-control-' + uuid.uuid4().hex
    started = time.monotonic()
    record = {'container': name, 'argv': argv, 'status': 'execution_error', 'cleanup': False}
    process = None
    threads: list[threading.Thread] = []
    output = [bytearray(), bytearray()]
    overflow = threading.Event()
    capture_error = threading.Event()
    create = ['docker', 'create', '--pull', 'never', '--name', name, '--network', 'none',
        '--read-only', '--user', '65534:65534', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--pids-limit', '64',
        '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
        '--ulimit', 'nofile=128:128', '--log-driver', 'none',
        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m', '--workdir', '/repo']
    for path, target in ((repo, '/repo'), (deps, '/deps'), (trusted, '/trusted')):
        create += ['--mount', f'type=bind,source={path},target={target},readonly']
    for value in ('PYTHONPATH=/deps', 'PYTHONDONTWRITEBYTECODE=1', 'PYTHONHASHSEED=0',
                  'PYTHONWARNINGS=ignore::UserWarning,ignore::SyntaxWarning', 'SYMPY_USE_CACHE=no'):
        create += ['--env', value]
    try:
        created = command(create + [IMAGE] + argv)
        if created.returncode:
            raise RuntimeError(created.stderr.decode(errors='replace')[:1000])
        inspected = command(['docker', 'inspect', name])
        if inspected.returncode:
            raise RuntimeError('Inspect failed')
        details = json.loads(inspected.stdout)[0]
        host, config = details['HostConfig'], details['Config']
        record['inspect'] = {'Image': details['Image'], 'HostConfig': host,
                             'User': config['User'], 'Mounts': details['Mounts']}
        if not (host['NetworkMode'] == 'none' and host['ReadonlyRootfs']
            and config['User'] == '65534:65534' and host['PidsLimit'] == 64
            and host['Memory'] == host['MemorySwap'] == 536870912
            and host['NanoCpus'] == 1000000000 and 'ALL' in host['CapDrop']
            and 'no-new-privileges' in host['SecurityOpt'] and not host['Privileged']
            and {m['Destination'] for m in details['Mounts'] if m['Type'] == 'bind'} == {'/repo', '/deps', '/trusted'}
            and all(not m['RW'] for m in details['Mounts'] if m['Type'] == 'bind')
            and '/tmp' in host['Tmpfs'] and config['Image'] == IMAGE):
            raise RuntimeError('Actual Docker isolation differed from the fixed contract')
        process = subprocess.Popen(['docker', 'start', '--attach', name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, shell=False)

        def capture(stream, sink):
            try:
                while chunk := stream.read(4096):
                    room = LIMIT - len(sink)
                    sink.extend(chunk[:room])
                    if len(chunk) > room:
                        overflow.set()
                        break
            except OSError:
                capture_error.set()
            finally:
                stream.close()

        for stream, sink in zip((process.stdout, process.stderr), output):
            thread = threading.Thread(target=capture, args=(stream, sink), daemon=True)
            thread.start()
            threads.append(thread)
        deadline = started + 120
        while process.poll() is None and not overflow.is_set() and time.monotonic() < deadline:
            time.sleep(0.02)
        if overflow.is_set():
            record['status'] = 'output_limit'
        elif process.poll() is None:
            record['status'] = 'timeout'
        else:
            record['status'] = 'completed'
            record['exit_code'] = process.returncode
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError, AssertionError) as error:
        record['error'] = str(error)[:1000]
    finally:
        if process and process.poll() is None:
            try:
                process.kill()
                process.wait(timeout=5)
            except (OSError, subprocess.SubprocessError) as error:
                record['client_stop_error'] = type(error).__name__
                capture_error.set()
        try:
            removed = command(['docker', 'rm', '--force', name])
            absent = command(['docker', 'ps', '--all', '--filter', f'name=^/{name}$', '--format', '{{.ID}}'])
            record['cleanup'] = removed.returncode == 0 and absent.returncode == 0 and not absent.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            record['cleanup'] = False
        for thread in threads:
            thread.join(timeout=2)
        record.update(stdout=output[0].decode(errors='replace'), stderr=output[1].decode(errors='replace'),
                      elapsed_seconds=round(time.monotonic() - started, 3))
        if any(t.is_alive() for t in threads) or overflow.is_set() or capture_error.is_set():
            record['status'] = 'capture_error'
        if not record['cleanup']:
            record['status'] = 'cleanup_error'
    return record


def main() -> None:
    if sys.argv[1:] != ['--run']:
        raise SystemExit('Explicit --run required; no candidate/path/image options exist.')
    for name, expected in PINS.items():
        if digest((CACHE / name).read_bytes()) != expected:
            raise ValueError(f'Pinned artifact mismatch: {name}')
    row = json.loads((CACHE / 'sympy__sympy-20590.row.json').read_text(encoding='utf-8'))
    ids = json.loads(row['FAIL_TO_PASS']) + json.loads(row['PASS_TO_PASS'])
    if row['base_commit'] != BASE or len(ids) != 22 or len(set(ids)) != 22:
        raise ValueError('Fixed row identity or exact scoring roster changed')
    run = CACHE / ('controls-' + uuid.uuid4().hex)
    run.mkdir()
    base, deps, trusted = run / 'base', run / 'deps', run / 'trusted'
    trusted.mkdir()
    materialize(base, deps)
    test_edit = apply_fixed_patch(base, row['test_patch'], TEST)
    (trusted / 'test_basic.py').write_bytes((base / TEST).read_bytes())
    runner = '''import json,runpy,sys,traceback,platform
sys.path[:0]=['/repo','/deps']
ns=runpy.run_path('/trusted/test_basic.py')
ids=IDS
records=[]
for name in ids:
    try:
        ns[name]()
        records.append({'id':name,'passed':True})
    except Exception as error:
        records.append({'id':name,'passed':False,'error':type(error).__name__,
                        'traceback':traceback.format_exc(limit=5)})
print(json.dumps({'python':platform.python_version(),'cases':records},sort_keys=True))
sys.exit(0 if all(r['passed'] for r in records) else 1)
'''.replace('IDS', repr(ids))
    (trusted / 'roster.py').write_text(runner, encoding='utf-8')
    receipt = {'instance_id': row['instance_id'], 'base_commit': BASE, 'image': IMAGE,
        'script_sha256': digest(Path(__file__).read_bytes()), 'inputs': PINS,
        'test_edit': test_edit, 'trusted_tree_sha256': tree_hash(trusted),
        'dependency_tree_sha256': tree_hash(deps), 'controls': {},
        'limitation': 'Only three reviewed fixed inputs; cooperative stdout evidence, not adversarial proof or leaderboard score.'}
    for kind in ('original', 'gold', 'wrong'):
        repo = run / kind
        shutil.copytree(base, repo)
        edit = None if kind == 'original' else apply_fixed_patch(repo, row['patch'], SOURCE, wrong=kind == 'wrong')
        before = tree_hash(repo)
        official = execute(repo, deps, trusted, ['python', '-B', 'bin/test', '-C', '--verbose', TEST])
        roster = execute(repo, deps, trusted, ['python', '-I', '-S', '-B', '/trusted/roster.py'])
        receipt['controls'][kind] = {'edit': edit, 'repo_tree_sha256': before,
            'source_sha256': digest((repo / SOURCE).read_bytes()), 'official_style': official,
            'exact_roster': roster, 'control_ok': False}
        (run / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
        cases = json.loads(roster['stdout']) if roster['status'] == 'completed' else None
        if not cases or [case['id'] for case in cases['cases']] != ids:
            raise ValueError('Exact scoring roster results are missing or changed')
        if cases['python'] != '3.9.25' or not all(type(case['passed']) is bool for case in cases['cases']):
            raise ValueError('Unexpected interpreter or non-boolean case result')
        expected = {name: kind == 'gold' or name != 'test_immutable' for name in ids}
        matched = {case['id']: case['passed'] for case in cases['cases']} == expected
        official_rows = re.findall(r'^(test_\w+) +(ok|F)(?:\s|$)', official['stdout'], re.MULTILINE)
        official_cases = {name: status == 'ok' for name, status in official_rows}
        official_expected = {**expected, 'test_replace_exceptions': True}
        official_matched = (len(official_rows) == len(official_cases) == 23
            and official_cases == official_expected and f'{TEST}[23]' in official['stdout'])
        failures = [case for case in cases['cases'] if not case['passed']]
        valid_failure = all(case.get('error') == 'AssertionError' and 'test_immutable' in case['traceback'] for case in failures)
        control_ok = (matched and official_matched and valid_failure and before == tree_hash(repo)
            and official['status'] == roster['status'] == 'completed'
            and official['cleanup'] and roster['cleanup']
            and official.get('exit_code') == roster.get('exit_code') == (0 if kind == 'gold' else 1))
        receipt['controls'][kind] = {'edit': edit, 'repo_tree_sha256': before,
            'source_sha256': digest((repo / SOURCE).read_bytes()), 'official_style': official,
            'exact_roster': roster, 'observed': cases, 'official_cases': official_cases,
            'official_test_count': len(official_cases), 'control_ok': control_ok}
        (run / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
        print(kind, control_ok, flush=True)
    receipt['all_controls_ok'] = all(c['control_ok'] for c in receipt['controls'].values())
    receipt['immutable_inputs_unchanged'] = (tree_hash(trusted) == receipt['trusted_tree_sha256']
        and tree_hash(deps) == receipt['dependency_tree_sha256'])
    (run / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(str(run / 'receipt.json'), flush=True)
    if not receipt['all_controls_ok'] or not receipt['immutable_inputs_unchanged']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
