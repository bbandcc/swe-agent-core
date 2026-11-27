"""Independent recovery of one guarded research lease, never task resumption."""
from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import re
import time
import uuid

from agent.workspace import has_single_regular_file_link
from .tls import IMAGE, IMAGE_LABELS, LABEL, volume_is_owned
from .constants import command


def _ordinary(path):
    path = Path(path).absolute()
    if any(p.is_symlink() or p.is_junction() for p in (path, *path.parents)):
        raise ValueError('linked_recovery_path')
    return path


@contextmanager
def _lock(path, *, create=False):
    """The OS releases this byte lock on hard parent death, including Windows."""
    path = _ordinary(path)
    if not create and not has_single_regular_file_link(path):
        raise ValueError('missing_owner_lock')
    with path.open('x+b' if create else 'r+b') as stream:
        if create:
            stream.write(b'1'); stream.flush(); os.fsync(stream.fileno())
        acquired = False
        try:
            stream.seek(0)
            if os.name == 'nt':
                import msvcrt
                try: msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError: raise BlockingIOError('owner_active') from None
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
            yield
        finally:
            if acquired:
                stream.seek(0)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


@contextmanager
def lease_owner(directory):
    """Hold throughout all creation RPCs and cleanup, before creating materials."""
    directory = _ordinary(directory)
    directory.mkdir(exist_ok=False)
    with _lock(directory / 'lease-owner.lock', create=True):
        yield directory


def _read_lease(directory):
    path = _ordinary(directory / 'materials/lease.json')
    if not has_single_regular_file_link(path) or path.stat().st_size > 256*1024:
        raise ValueError('invalid_lease')
    lease = json.loads(path.read_text(encoding='utf-8'))
    owner = lease.get('owner')
    names, ids = lease.get('containers'), lease.get('container_ids', {})
    if (type(owner) is not str or not re.fullmatch('[a-f0-9]{32}', owner)
            or lease.get('image') != IMAGE or lease.get('volume') != 'swe-fixed-tls-'+owner
            or type(lease.get('volume_attempted')) is not bool
            or type(lease.get('creation_unknown')) is not bool
            or type(lease.get('creation_in_flight', False)) is not bool
            or type(names) is not list or len(names)>64 or len(set(names))!=len(names)
            or any(type(n) is not str or not re.fullmatch('swe-(?:fixed-tls|gated-requests)-[a-f0-9]{32}', n) for n in names)
            or type(ids) is not dict or not set(ids).issubset(names)
            or any(type(v) is not str or not re.fullmatch('[a-f0-9]{64}', v) for v in ids.values())
            or lease.get('created_at') is not None and (type(lease['created_at']) is not str
                or not re.fullmatch(r'\d{4}-\d\d-\d\dT[0-9:.]+(?:Z|[+-]\d\d:\d\d)', lease['created_at']))):
        raise ValueError('invalid_lease')
    return lease


def recover_fixed_tls(directory, *, timeout_seconds=30):
    """Confirm known resources removed; unknown creation remains UNKNOWN forever.

    A fresh bounded recovery deadline does not refresh any execution/model budget.
    No task is resumed and no label-wide prune or host volume path access occurs.
    The caller owns this control directory and excludes malicious host writers.
    """
    if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 60):
        raise ValueError('bounded_recovery_timeout_required')
    result = {'status': 'UNKNOWN', 'cleanup_complete': False, 'restart_permitted': False,
              'issues': [], 'removed_containers': [], 'removed_volume': False}
    deadline = time.monotonic()+timeout_seconds

    def docker(*args):
        remaining = deadline-time.monotonic()
        if remaining <= 0: raise ValueError('recovery_deadline_exhausted')
        value = command(*args, timeout=min(10, remaining))
        if value.returncode or len(value.stdout)>256*1024 or len(value.stderr)>65536:
            raise ValueError('recovery_docker_operation_failed')
        return value.stdout

    def present(kind, name):
        field = '{{.ID}}' if kind == 'container' else '{{.Name}}'
        return bool(docker(kind, 'ls', *(['--all'] if kind=='container' else []),
            '--filter', 'name=^'+('/' if kind=='container' else '')+name+'$', '--format', field).strip())

    try:
        directory = _ordinary(directory)
        with _lock(directory/'lease-owner.lock'):
            lease = _read_lease(directory)
            # Persisted before RPC dispatch. Absence on one query cannot close it.
            unknown = lease['creation_unknown'] or lease.get('creation_in_flight', False)
            if unknown: result['issues'].append('creation_rpc_outcome_unknown')
            for name in lease['containers']:
                if not present('container', name): continue
                value = json.loads(docker('inspect', name))[0]
                expected_id = lease['container_ids'].get(name)
                if (not expected_id or value['Id'] != expected_id
                        or value['Config']['Image'] != IMAGE
                        or value['Config']['Labels'] != {**IMAGE_LABELS, LABEL:lease['owner']}):
                    raise ValueError('container_identity_unknown')
                docker('rm', '--force', expected_id)
                if present('container', name): raise ValueError('container_removal_unconfirmed')
                result['removed_containers'].append(expected_id)
            if lease['volume_attempted'] and present('volume', lease['volume']):
                value = json.loads(docker('volume', 'inspect', lease['volume']))[0]
                if not lease['created_at'] or not volume_is_owned(value, lease):
                    raise ValueError('volume_identity_unknown')
                # Docker refuses removal while ANY other container holds the volume.
                docker('volume', 'rm', lease['volume'])
                if present('volume', lease['volume']): raise ValueError('volume_removal_unconfirmed')
                result['removed_volume'] = True
            if not result['issues']:
                result.update(status='CLEANED', cleanup_complete=True)
    except BlockingIOError:
        result.update(status='OWNER_ACTIVE', issues=['owner_active'])
    except Exception as error:
        message = str(error) if isinstance(error, ValueError) else type(error).__name__
        result['issues'].append(message[:120])
    return result
