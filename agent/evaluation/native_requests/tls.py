"""One owned TLS volume for cooperative research; never production admission."""
from contextlib import contextmanager
import hashlib
import json
import math
from pathlib import Path
import re
import time
import uuid

from .constants import IMAGE, command

LABEL = 'swe.fixed-tls.owner'
IMAGE_LABELS = {'org.opencontainers.image.version': '22.04'}
PYTHON = '/opt/miniconda3/envs/testbed/bin/python'
FILES = ('cacert.pem', 'cert.pem', 'key.pem')
GUEST = r'''
import hashlib,json,os,resource,ssl,subprocess,sys,threading
from pathlib import Path
role,owner=sys.argv[1:3]
root=Path('/fixed-tls')
resource.setrlimit(resource.RLIMIT_FSIZE,(65536,65536));os.umask(0o077)
facts=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
uid='0' if role=='init' else '65534'
assert all(facts[k].split()==[uid]*4 for k in ('Uid','Gid'))
assert facts['Groups'].split() in ([],[uid]), 'unexpected_group_profile'
assert facts['NoNewPrivs'].strip()=='1'
assert all(int(facts[k],16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
def digest(path):
    assert path.is_file() and not path.is_symlink() and path.stat().st_size<65536
    return hashlib.sha256(path.read_bytes()).hexdigest()
def tools(args):
    result=subprocess.run(['/usr/bin/openssl']+args,stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15,shell=False)
    if result.returncode:raise RuntimeError('openssl_failed')
if role=='init':
    assert not list(root.iterdir());os.chmod(root,0o1777)
    result={'initialized':True}
elif role=='author':
    assert not list(root.iterdir())
    assert hashlib.sha256(Path('/usr/bin/openssl').read_bytes()).hexdigest()=='a55e3085b6a1df8887722f6cee7fc32c861d11d5fb584a63837d32d29602c65b'
    work=Path('/tmp/tls');work.mkdir()
    ext=work/'ext';ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    tools(['req','-x509','-newkey','rsa:2048','-sha256','-days','2','-nodes',
        '-subj','/CN=SWE fixed historical fixture CA','-addext','basicConstraints=critical,CA:TRUE',
        '-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',str(work/'ca.key'),'-out',str(root/'cacert.pem')])
    tools(['req','-new','-newkey','rsa:2048','-sha256','-nodes','-subj','/CN=127.0.0.1',
        '-keyout',str(root/'key.pem'),'-out',str(work/'server.csr')])
    tools(['x509','-req','-in',str(work/'server.csr'),'-CA',str(root/'cacert.pem'),
        '-CAkey',str(work/'ca.key'),'-set_serial','1','-days','2','-sha256',
        '-extfile',str(ext),'-out',str(root/'cert.pem')])
    for name in ('cacert.pem','cert.pem','key.pem'):os.chmod(root/name,0o400)
    hashes={n:digest(root/n) for n in ('cacert.pem','cert.pem','key.pem')}
    (root/'manifest.json').write_text(json.dumps({'owner':owner,'sha256':hashes}))
    os.chmod(root/'manifest.json',0o400)
    result={'materials':hashes,'openssl_sha256':hashlib.sha256(Path('/usr/bin/openssl').read_bytes()).hexdigest()}
elif role=='consumer':
    import http.server
    assert sorted(p.name for p in root.iterdir())==['cacert.pem','cert.pem','key.pem','manifest.json']
    manifest=json.loads((root/'manifest.json').read_text());assert manifest['owner']==owner
    before={n:digest(root/n) for n in ('cacert.pem','cert.pem','key.pem')}
    assert before==manifest['sha256']
    try:
        (root/'write-canary').write_bytes(b'owned-control')
    except OSError as error:
        import errno
        assert error.errno in (errno.EROFS,errno.EACCES)
    else:raise RuntimeError('read_only_volume_write_succeeded')
    sys.path.insert(0,'/testbed')
    import requests,requests.utils
    origin=Path(requests.utils.__file__).resolve()
    assert origin.is_relative_to(Path('/testbed/requests'))
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200);self.end_headers();self.wfile.write(b'fixed-tls-ok')
        def log_message(self,*args):pass
    server=http.server.HTTPServer(('127.0.0.1',0),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(root/'cert.pem'),str(root/'key.pem'))
    server.socket=context.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    session=requests.Session();session.trust_env=False
    try:
        port=str(server.server_address[1]);url='https://127.0.0.1:'+port+'/'
        import warnings
        with warnings.catch_warnings(record=True) as emitted:
            warnings.simplefilter('always')
            assert session.get(url,verify=str(root/'cacert.pem'),timeout=3).content==b'fixed-tls-ok'
        assert any(w.category.__name__=='SubjectAltNameWarning' for w in emitted)
        wrong_ca='/etc/ssl/certs/ca-certificates.crt';assert Path(wrong_ca).is_file()
        for target,ca in ((url,wrong_ca),('https://localhost:'+port+'/',str(root/'cacert.pem'))):
            negative=requests.Session();negative.trust_env=False
            try:
                try:negative.get(target,verify=ca,timeout=3)
                except requests.exceptions.SSLError:pass
                else:raise RuntimeError('negative_tls_verification_accepted')
            finally:negative.close()
    finally:
        session.close();server.shutdown();server.server_close();thread.join(3)
    assert not thread.is_alive()
    assert {n:digest(root/n) for n in before}==before
    result={'materials':before,'read_only_write_rejected':True,'correct_ca_cn_accepted':True,
        'wrong_ca_rejected':True,'wrong_hostname_rejected':True,'source_unchanged':True,
        'subject_alt_name_warning_observed':True,
        'requests_version':requests.__version__,'requests_utils_sha256':digest(origin),
        'requests_utils_origin':str(origin)}
else:raise ValueError('unknown_role')
result['profile_facts']={k:facts[k].strip() for k in ('Uid','Gid','Groups','NoNewPrivs','CapInh','CapPrm','CapEff','CapBnd','CapAmb')}
print(json.dumps(dict(result,role=role,owner=owner,cap0_nonroot=role!='init')))
'''


def deadline_timeout(deadline, limit, now):
    if not all(math.isfinite(v) for v in (deadline, limit, now)) or limit <= 0 or deadline <= now:
        raise ValueError('deadline_or_limit_invalid')
    return min(limit, deadline-now)


def volume_is_owned(value, lease):
    return (value.get('Name') == lease['volume'] and value.get('Driver') == 'local'
        and not value.get('Options') and value.get('Labels') == {LABEL: lease['owner']}
        and (not lease.get('created_at') or value.get('CreatedAt') == lease['created_at']))


def container_is_expected(value, lease, inputs, role):
    h, c, mounts = value['HostConfig'], value['Config'], value['Mounts']
    expected = {m['Destination']: m for m in mounts}
    bind, volume = expected.get('/trusted', {}), expected.get('/fixed-tls', {})
    return (h['NetworkMode'] == 'none' and h['ReadonlyRootfs'] and not h['Privileged']
        and not h['PidMode'] and h['IpcMode'] == 'private' and h['PidsLimit'] == 32
        and h['Memory'] == h['MemorySwap'] == 268435456 and h['NanoCpus'] == 1000000000
        and h['Tmpfs'] == {'/tmp': 'rw,nosuid,nodev,noexec,size=16m'}
        and h['LogConfig']['Type'] == 'none' and not h.get('Devices') and not h.get('DeviceRequests')
        and {v.removeprefix('CAP_') for v in h['CapDrop']} == {'ALL'} and not h.get('CapAdd')
        and not h.get('GroupAdd') and 'no-new-privileges' in h['SecurityOpt']
        and c['User'] == ('0:0' if role == 'init' else '65534:65534') and c['Image'] == IMAGE
        and c['Entrypoint'] == [PYTHON] and c['WorkingDir'] == '/'
        and c['Cmd'] == ['-I', '-B', '/trusted/guest.py', role, lease['owner']]
        and c['Labels'] == {**IMAGE_LABELS, LABEL: lease['owner']} and len(mounts) == 2
        and bind.get('Type') == 'bind' and bind.get('Source') == str(inputs.resolve()) and not bind.get('RW')
        and bind.get('Propagation') == 'rprivate'
        and volume.get('Type') == 'volume' and volume.get('Name') == lease['volume']
        and volume.get('Driver') == 'local' and volume.get('RW') == (role != 'consumer'))


def invoke(lease, *args, limit=15, cleanup=False):
    deadline = lease['cleanup_deadline'] if cleanup else lease['deadline']
    creating = args[0] == 'create' or args[:2] == ('volume', 'create')
    if creating:
        lease['creation_in_flight'] = True
        Path(lease['file']).write_text(json.dumps(lease, indent=2), encoding='utf-8')
    try:
        result = command(*args, timeout=deadline_timeout(deadline, limit, time.monotonic()))
        if len(result.stdout) > 65536 or len(result.stderr) > 65536:
            raise ValueError('docker_output_limit')
        if creating:
            receipt = result.stdout.strip().decode('ascii')
            valid = (bool(re.fullmatch('[a-f0-9]{64}', receipt)) if args[0] == 'create'
                else receipt == lease['volume'])
            if result.returncode or not valid:
                lease['creation_unknown'] = True
                raise ValueError('creation_rpc_outcome_unknown')
            lease['creation_in_flight'] = False
            if args[0] == 'create':
                lease.setdefault('container_ids', {})[args[args.index('--name')+1]] = receipt
            Path(lease['file']).write_text(json.dumps(lease, indent=2), encoding='utf-8')
    except Exception:
        if creating:
            lease['creation_unknown'] = True
            Path(lease['file']).write_text(json.dumps(lease, indent=2), encoding='utf-8')
        raise
    return result


def inspect_volume(lease, *, cleanup=False):
    result = invoke(lease, 'volume', 'inspect', lease['volume'], cleanup=cleanup)
    if result.returncode: raise ValueError('volume_inspection_failed')
    value = json.loads(result.stdout)[0]
    if not volume_is_owned(value, lease): raise ValueError('volume_ownership_changed')
    return value


def run_role(lease, inputs, role):
    inspect_volume(lease)
    name = 'swe-fixed-tls-'+uuid.uuid4().hex
    lease['containers'].append(name)
    Path(lease['file']).write_text(json.dumps(lease, indent=2), encoding='utf-8')
    argv = ['create', '--pull', 'never', '--name', name, '--label', LABEL+'='+lease['owner'],
        '--network', 'none', '--read-only', '--user', '0:0' if role == 'init' else '65534:65534',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '32',
        '--memory', '256m', '--memory-swap', '256m', '--cpus', '1', '--log-driver', 'none',
        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=16m', '--workdir', '/',
        '--mount', f'type=bind,source={inputs.resolve()},target=/trusted,readonly',
        '--mount', f'type=volume,source={lease["volume"]},target=/fixed-tls,volume-nocopy'+(',readonly' if role == 'consumer' else ''),
        '--entrypoint', PYTHON, IMAGE, '-I', '-B', '/trusted/guest.py', role, lease['owner']]
    if invoke(lease, *argv).returncode: raise ValueError('container_create_failed')
    inspected = invoke(lease, 'inspect', name)
    if inspected.returncode or not container_is_expected(json.loads(inspected.stdout)[0], lease, inputs, role):
        raise ValueError('container_isolation_changed')
    outcome = invoke(lease, 'start', '--attach', name, limit=50)
    if outcome.returncode:
        (inputs.parent/(role+'-stderr.log')).write_bytes(outcome.stderr)
        raise ValueError('author_control_failed_'+role)
    value = json.loads(outcome.stdout)
    if value.get('role') != role or value.get('owner') != lease['owner']:
        raise ValueError('guest_identity_changed')
    if invoke(lease, 'rm', name).returncode: raise ValueError('container_remove_failed')
    absent = invoke(lease, 'container', 'ls', '--all', '--filter', 'name=^/'+name+'$', '--format', '{{.ID}}')
    if absent.returncode or absent.stdout.strip(): raise ValueError('container_cleanup_unknown')
    return value


@contextmanager
def fixed_tls_materials(directory):
    """Yield one live owned volume; raising on unknown cleanup forbids success."""
    directory = Path(directory); directory.mkdir(exist_ok=False)
    inputs = directory/'inputs'; inputs.mkdir()
    (inputs/'guest.py').write_text(GUEST, encoding='utf-8', newline='\n')
    owner = uuid.uuid4().hex; start = time.monotonic()
    lease = {'owner': owner, 'volume': 'swe-fixed-tls-'+owner, 'created_at': None,
        'image': IMAGE, 'deadline': start+240, 'cleanup_deadline': start+270,
        'containers': [], 'file': str(directory/'lease.json'), 'cleanup_complete': False,
        'creation_unknown': False, 'volume_attempted': False}
    Path(lease['file']).write_text(json.dumps(lease, indent=2), encoding='utf-8')
    try:
        existing = invoke(lease, 'volume', 'ls', '--filter', 'name=^'+lease['volume']+'$', '--format', '{{.Name}}')
        if existing.returncode or existing.stdout.strip(): raise ValueError('volume_name_collision')
        lease['volume_attempted'] = True
        result = invoke(lease, 'volume', 'create', '--driver', 'local', '--label', LABEL+'='+owner, lease['volume'])
        if result.returncode: raise ValueError('volume_create_failed')
        lease['created_at'] = inspect_volume(lease)['CreatedAt']
        lease['initializer'] = run_role(lease, inputs, 'init')
        lease['author'] = run_role(lease, inputs, 'author')
        Path(lease['file']).write_text(json.dumps(lease, indent=2), encoding='utf-8')
        yield lease
    except Exception as error:
        lease['operation_error'] = type(error).__name__+':'+str(error)[:120]
        raise
    finally:
        errors = []
        for name in lease['containers']:
            try:
                remaining = invoke(lease, 'container', 'ls', '--all', '--filter', 'name=^/'+name+'$', '--format', '{{.ID}}', cleanup=True)
                if remaining.returncode: raise ValueError('container_query_failed')
                if remaining.stdout.strip():
                    value = json.loads(invoke(lease, 'inspect', name, cleanup=True).stdout)[0]
                    if value['Config']['Labels'] != {**IMAGE_LABELS, LABEL: owner} or value['Config']['Image'] != IMAGE:
                        raise ValueError('container_ownership_changed')
                    if name in lease.get('container_ids', {}) and value['Id'] != lease['container_ids'][name]:
                        raise ValueError('container_id_changed')
                    if invoke(lease, 'rm', '--force', name, cleanup=True).returncode:
                        raise ValueError('container_remove_failed')
                    after = invoke(lease, 'container', 'ls', '--all', '--filter', 'name=^/'+name+'$', '--format', '{{.ID}}', cleanup=True)
                    if after.returncode or after.stdout.strip(): raise ValueError('container_cleanup_unknown')
            except Exception as error: errors.append(type(error).__name__+':'+str(error)[:120])
        if lease['volume_attempted'] and not errors:
            try:
                present = invoke(lease, 'volume', 'ls', '--filter', 'name=^'+lease['volume']+'$', '--format', '{{.Name}}', cleanup=True)
                if present.returncode: raise ValueError('volume_query_failed')
                if present.stdout.strip():
                    inspect_volume(lease, cleanup=True)
                    if invoke(lease, 'volume', 'rm', lease['volume'], cleanup=True).returncode:
                        raise ValueError('volume_remove_failed')
                after = invoke(lease, 'volume', 'ls', '--filter', 'name=^'+lease['volume']+'$', '--format', '{{.Name}}', cleanup=True)
                if after.returncode or after.stdout.strip(): raise ValueError('volume_cleanup_unknown')
            except Exception as error: errors.append(type(error).__name__+':'+str(error)[:120])
        if lease['creation_unknown']: errors.append('creation_rpc_outcome_unknown')
        lease['cleanup_complete'] = not errors
        lease['cleanup_errors'] = errors
        Path(lease['file']).write_text(json.dumps(lease, indent=2), encoding='utf-8')
        if errors: raise RuntimeError('fixed_tls_cleanup_unknown')
