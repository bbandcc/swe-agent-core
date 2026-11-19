"""Restricted cooperative JSON-case container execution; no host payload import."""
import json
from pathlib import Path
import re
import subprocess
import threading
import time

LIMIT = 65536


def parse_cases(record, case_ids):
    def unique(pairs):
        value = dict(pairs)
        if len(value) != len(pairs): raise ValueError('Duplicate JSON key')
        return value
    if (type(record) is not dict or not case_ids or len(set(case_ids)) != len(case_ids)
            or record.get('status') != 'completed' or record.get('cleanup') is not True
            or type(record.get('exit_code')) is not int or record['exit_code'] not in (0, 1)
            or type(record.get('stdout')) is not str or len(record['stdout'].encode()) > LIMIT):
        raise ValueError('Container did not complete cleanly')
    value = json.loads(record['stdout'], object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != {'cases'} or type(value['cases']) is not list
            or len(value['cases']) != len(case_ids)):
        raise ValueError('Wrong case schema')
    for case, identity in zip(value['cases'], case_ids):
        if (type(case) is not dict or set(case) != {'id', 'passed'}
                or case['id'] != identity or type(case['passed']) is not bool):
            raise ValueError('Wrong case identity/status')
    if record['exit_code'] != int(not all(c['passed'] for c in value['cases'])):
        raise ValueError('Exit status differs from cases')
    return value['cases']


def execute(repo, deps, trusted, image, argv, name, timeout_seconds):
    """One parent-leased instance with fixed resources and read-only mounts."""
    if (not re.fullmatch(r'python@sha256:[a-f0-9]{64}', image)
            or not re.fullmatch(r'swe-cooperative-[a-f0-9]{32}', name)
            or type(timeout_seconds) not in (int, float) or not 1 <= timeout_seconds <= 150):
        raise ValueError('Invalid fixed execution identity')
    result = {'status': 'execution_error', 'cleanup': False, 'stdout': '', 'stderr': '', 'exit_code': None}
    process, threads = None, []
    output = [bytearray(), bytearray()]
    failed = threading.Event()
    started = time.monotonic()

    def command(arguments):
        return subprocess.run(['docker', *arguments], stdin=subprocess.DEVNULL,
            capture_output=True, timeout=5, shell=False, check=False)

    try:
        create = ['create', '--pull', 'never', '--name', name, '--network', 'none', '--read-only',
            '--user', '65534:65534', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--pids-limit', '64', '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
            '--log-driver', 'none', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m', '--workdir', '/repo',
            '--env', 'PYTHONDONTWRITEBYTECODE=1', '--env', 'PYTHONHASHSEED=0']
        sources = {target: str(Path(path).resolve(strict=True)) for path, target in
                   ((repo, '/repo'), (deps, '/deps'), (trusted, '/trusted'))}
        for target, path in sources.items():
            if ',' in path: raise ValueError('Mount path contains Docker delimiter')
            create += ['--mount', f'type=bind,source={path},target={target},readonly']
        if command(create + [image, *argv]).returncode: raise ValueError('Create failed')
        inspection = command(['inspect', name])
        if inspection.returncode: raise ValueError('Inspect failed')
        observed = json.loads(inspection.stdout)[0]
        host, config = observed['HostConfig'], observed['Config']
        mounts = observed['Mounts']
        if not (host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] and not host['Privileged']
                and config['User'] == '65534:65534' and config['Image'] == image
                and host['PidsLimit'] == 64 and host['Memory'] == host['MemorySwap'] == 536870912
                and host['NanoCpus'] == 1000000000 and 'ALL' in host['CapDrop']
                and 'no-new-privileges' in host['SecurityOpt'] and '/tmp' in host['Tmpfs']
                and not host.get('Devices') and not host.get('DeviceRequests')
                and len(mounts) == 3 and all(m['Type'] == 'bind' for m in mounts)
                and len([m for m in mounts if m['Type'] == 'bind']) == 3
                and {m['Destination'] for m in mounts if m['Type'] == 'bind'} == set(sources)
                and all(not m['RW'] for m in mounts if m['Type'] == 'bind')):
            raise ValueError('Actual isolation differs from reviewed policy')
        result['inspection'] = {'image_id': observed['Image'], 'user': config['User'],
                                'network': host['NetworkMode'], 'readonly': host['ReadonlyRootfs']}
        process = subprocess.Popen(['docker', 'start', '--attach', name], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

        def capture(stream, sink):
            try:
                while chunk := stream.read(4096):
                    room = LIMIT - len(sink)
                    sink.extend(chunk[:room])
                    if len(chunk) > room: failed.set(); break
            except OSError: failed.set()
            finally: stream.close()

        for stream, sink in zip((process.stdout, process.stderr), output):
            thread = threading.Thread(target=capture, args=(stream, sink), daemon=True)
            thread.start(); threads.append(thread)
        while process.poll() is None and not failed.is_set() and time.monotonic() - started < timeout_seconds:
            time.sleep(.02)
        if failed.is_set(): result['status'] = 'output_limit'
        elif process.poll() is None: result['status'] = 'timeout'
        else: result.update(status='completed', exit_code=process.returncode)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        result['status'] = 'execution_error'
    finally:
        if process is not None and process.poll() is None:
            try: process.kill(); process.wait(timeout=5)
            except (OSError, subprocess.SubprocessError): failed.set()
        try:
            command(['rm', '--force', name])
            absent = command(['container', 'ls', '--all', '--filter', f'name=^/{name}$', '--format', '{{.ID}}'])
            result['cleanup'] = absent.returncode == 0 and not absent.stdout.strip()
        except (OSError, subprocess.SubprocessError): result['cleanup'] = False
        for thread in threads: thread.join(timeout=2)
        result.update(stdout=output[0].decode('utf-8', errors='replace'),
                      stderr=output[1].decode('utf-8', errors='replace'))
        if failed.is_set() or any(t.is_alive() for t in threads): result['status'] = 'capture_error'
        if not result['cleanup']: result['status'] = 'cleanup_error'
    return result
