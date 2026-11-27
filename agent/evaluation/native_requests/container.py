"""Fixed candidate container observation; cooperative evidence, no admission."""
import hashlib
import json
from pathlib import Path
import queue
import re
import subprocess
import threading
import time
import uuid
from agent.evaluation.native_log import parse_native_log
from .constants import IMAGE, SOURCE, command
from .network import BOOTSTRAP, status_ok, routes_ok
from .tls import inspect_volume, invoke, IMAGE_LABELS, LABEL
LIMIT = 16 * 1024 * 1024

def sha(data): return hashlib.sha256(data).hexdigest()


def inspect_expected(value, inputs, tls=None):
    h, c, m = value['HostConfig'], value['Config'], value['Mounts']
    if tls is not None:
        volumes = [v for v in m if v['Destination'] == '/fixed-tls']
        if (len(m) != 2 or len(volumes) != 1 or volumes[0]['Type'] != 'volume'
                or volumes[0]['Name'] != tls['volume'] or volumes[0]['RW']
                or volumes[0]['Driver'] != 'local'
                or c['Labels'] != {**IMAGE_LABELS, LABEL: tls['owner']}): return False
        m = [v for v in m if v['Destination'] != '/fixed-tls']
    return (h['NetworkMode']=='none' and h['ReadonlyRootfs'] and not h['Privileged']
        and h['PidMode']=='' and h['IpcMode']=='private' and h['PidsLimit']==64
        and h['Memory']==h['MemorySwap']==536870912 and h['NanoCpus']==1000000000
        and h['Tmpfs']=={'/tmp':'rw,nosuid,nodev,noexec,size=128m'} and h['LogConfig']['Type']=='none'
        and 'no-new-privileges' in h['SecurityOpt'] and not h.get('Devices') and not h.get('DeviceRequests')
        and {v.removeprefix('CAP_') for v in h['CapDrop']}=={'ALL'}
        and {v.removeprefix('CAP_') for v in h['CapAdd']}=={'NET_ADMIN','SETUID','SETGID','SETPCAP'}
        and c['User']=='0:0' and c['Image']==IMAGE and c['Cmd']==['-I','-S','-B','/trusted/bootstrap.py']
        and c['Entrypoint']==['/opt/miniconda3/envs/testbed/bin/python'] and c['WorkingDir']=='/'
        and not h.get('GroupAdd')
        and len(m)==1 and m[0]['Type']=='bind' and not m[0]['RW'] and m[0]['Source']==str(inputs.resolve())
        and m[0]['Destination']=='/trusted' and m[0]['Propagation']=='rprivate')


def tree_digest(root):
    return sha(json.dumps([[p.relative_to(root).as_posix(),sha(p.read_bytes())]
        for p in sorted(root.rglob('*')) if p.is_file()],separators=(',',':')).encode())


def observe(directory, spec, tls):
    if type(tls) is not dict:
        raise ValueError("Live fixed TLS lease required")
    inputs = directory/'inputs'; token = uuid.uuid4().hex
    name = 'swe-gated-requests-'+uuid.uuid4().hex
    def docker(*args, timeout=15, cleanup=False):
        return invoke(tls, *args, limit=timeout, cleanup=cleanup) if tls is not None else command(*args, timeout=timeout)
    bootstrap = BOOTSTRAP.replace('/trusted/probe.py','/trusted/shim.py')
    shim = ("import os,select,sys\nprint('READY:"+token+"',flush=True)\n"
        + "if not select.select([sys.stdin],[],[],30)[0]:raise RuntimeError('gate timeout')\n"
        + "if sys.stdin.readline()!='GO:"+token+"\\n':raise RuntimeError('gate denied')\n"
        + "os.execve('/opt/miniconda3/envs/testbed/bin/python',['/opt/miniconda3/envs/testbed/bin/python','-I','-B','/trusted/guest.py'],"
          "{'PATH':'/usr/bin:/bin','HOME':'/tmp','PYTHONDONTWRITEBYTECODE':'1'})\n")
    (inputs/'bootstrap.py').write_text(bootstrap,encoding='utf-8',newline='\n')
    (inputs/'shim.py').write_text(shim,encoding='utf-8',newline='\n')
    frozen = tree_digest(inputs)
    configuration = json.loads((inputs/'config.json').read_text(encoding='utf-8'))
    expected_profile = configuration.get('profile', 'san-runtime-v1')
    record = {'variant':configuration['variant'],
              'gate_released':False,'cleanup_complete':False,'inputs_sha256':frozen}
    process, readers, output = None, [], [bytearray(),bytearray()]
    ready, failed = queue.Queue(), threading.Event()
    deadline = min(time.monotonic()+240, tls['deadline']) if tls is not None else time.monotonic()+240
    try:
        argv = ['create','--interactive','--pull','never','--name',name,'--network','none','--read-only',
            '--user','0:0','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64',
            '--memory','512m','--memory-swap','512m','--cpus','1','--log-driver','none',
            '--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=128m','--workdir','/',
            '--mount',f'type=bind,source={inputs.resolve()},target=/trusted,readonly',
            '--entrypoint','/opt/miniconda3/envs/testbed/bin/python']
        for cap in ('NET_ADMIN','SETUID','SETGID','SETPCAP'): argv += ['--cap-add',cap]
        if tls is not None:
            inspect_volume(tls)
            tls['containers'].append(name)
            Path(tls['file']).write_text(json.dumps(tls,indent=2),encoding='utf-8')
            argv += ['--label', LABEL+'='+tls['owner'], '--mount',
                f'type=volume,source={tls["volume"]},target=/fixed-tls,readonly,volume-nocopy']
        if docker(*argv,IMAGE,'-I','-S','-B','/trusted/bootstrap.py').returncode: raise ValueError('create_failed')
        inspection = docker('inspect',name); (directory/'inspection.json').write_bytes(inspection.stdout)
        if not inspect_expected(json.loads(inspection.stdout)[0],inputs,tls): raise ValueError('isolation_drift')
        process = subprocess.Popen(['docker','start','--attach','--interactive',name],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False)
        def drain(stream, sink, notify):
            first = True
            try:
                while chunk := stream.readline(65536):
                    if len(sink)+len(chunk)>LIMIT: failed.set(); break
                    sink.extend(chunk)
                    if notify and first: ready.put(chunk); first = False
            except OSError: failed.set()
            finally: stream.close()
        for index, stream in enumerate((process.stdout,process.stderr)):
            thread = threading.Thread(target=drain,args=(stream,output[index],index==0),daemon=True)
            thread.start(); readers.append(thread)
        if ready.get(timeout=12)!=('READY:'+token+'\n').encode(): raise ValueError('wrong_ready')
        facts = {}
        for key,path in (('status','/proc/1/status'),('cmdline','/proc/1/cmdline'),
                         ('route4','/proc/1/net/route'),('route6','/proc/1/net/ipv6_route')):
            result = docker('exec',name,'/bin/cat',path,timeout=4)
            if result.returncode or len(result.stdout)>8192: raise ValueError('parent_read_failed')
            facts[key] = result.stdout.decode(); (directory/('parent-'+key+'.log')).write_bytes(result.stdout)
        result = docker('exec',name,'/bin/ls','/sys/class/net',timeout=4)
        if result.returncode: raise ValueError('interface_read_failed')
        facts['interfaces'] = result.stdout.decode()
        record['parent_gate_passed'] = (status_ok(facts['status']) and routes_ok(facts['route4'],facts['route6'],facts['interfaces'])
            and facts['cmdline'].split('\0')==['/opt/miniconda3/envs/testbed/bin/python','-I','-S','-B','/trusted/shim.py',''])
        (directory/'parent-facts.json').write_text(json.dumps(facts,indent=2),encoding='utf-8')
        if not record['parent_gate_passed'] or failed.is_set(): raise ValueError('parent_gate_denied')
        process.stdin.write(('GO:'+token+'\n').encode()); process.stdin.flush(); process.stdin.close()
        record['gate_released'] = True
        task_deadline = min(deadline,time.monotonic()+200)
        while process.poll() is None and not failed.is_set() and time.monotonic()<task_deadline:
            time.sleep(.05)
        if process.poll() is None: raise ValueError('guest_timeout_or_output_limit')
        for thread in readers: thread.join(timeout=2)
        if failed.is_set() or any(t.is_alive() for t in readers) or process.returncode: raise ValueError('guest_failed')
        guest = json.loads(bytes(output[0]).split(b'\n',1)[1])
        (directory/'guest-result.json').write_text(json.dumps(guest,indent=2),encoding='utf-8')
        record.update({k:v for k,v in guest.items() if k not in ('native_log','install_log')})
        if (guest.get('phase')!='completed' or guest.get('candidate_import_verified') is not True
                or guest.get('profile')!=expected_profile
                or (tls is not None and guest.get('environment_materials_sha256') != configuration.get('environment_materials_sha256'))
                or guest.get('cleanup_children') is not True or guest.get('remaining_namespace_pids')!=[]
                or guest.get('source_snapshot_sha256')!=SOURCE or guest.get('test_patch_sha256')!=spec.test_patch_sha256
                or not re.fullmatch(r'[a-f0-9]{64}',guest.get('candidate_source_sha256',''))): raise ValueError('guest_identity_failed')
        parser_id = 'pytest-options-v2' if expected_profile == 'historical-compat-v1' else spec.parser_id
        parsed = parse_native_log(parser_id,guest['native_log'],spec.fail_to_pass+spec.pass_to_pass)
        cases = dict(parsed.cases)
        record.update(parser_id=parser_id,parser_complete=parsed.complete,parser_issues=parsed.issues,
            case_origin_sha256=sha(json.dumps(parsed.case_origins).encode()),strict_passed=parsed.strict_passed,
            f2p_statuses=[cases[c] for c in spec.fail_to_pass],p2p_passed=sum(cases[c]=='PASSED' for c in spec.pass_to_pass))
        if tree_digest(inputs)!=frozen: raise ValueError('inputs_changed')
    except (OSError,ValueError,KeyError,TypeError,queue.Empty,subprocess.SubprocessError) as error:
        record.update(controller_error=type(error).__name__,controller_message=str(error)[:200])
    finally:
        if process is not None and process.poll() is None:
            try:
                if process.stdin and not process.stdin.closed: process.stdin.close()
            except OSError: pass
            try: process.kill(); process.wait(timeout=3)
            except (OSError,subprocess.SubprocessError): pass
        try:
            if tls is not None:
                current = docker('container','ls','--all','--filter',f'name=^/{name}$','--format','{{.ID}}',cleanup=True)
                if current.returncode: raise ValueError('cleanup_query_unknown')
                if current.stdout.strip():
                    value = json.loads(docker('inspect',name,cleanup=True).stdout)[0]
                    if (value['Id'] != tls.get('container_ids',{}).get(name)
                            or value['Config']['Image'] != IMAGE
                            or value['Config']['Labels'] != {**IMAGE_LABELS,LABEL:tls['owner']}):
                        raise ValueError('cleanup_ownership_changed')
            docker('rm','--force',name,cleanup=True)
            absent = docker('container','ls','--all','--filter',f'name=^/{name}$','--format','{{.ID}}',cleanup=True)
            record['cleanup_complete'] = (absent.returncode==0 and not absent.stdout.strip()
                and not (tls is not None and tls.get('creation_unknown')))
        except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
            record['cleanup_message'] = type(error).__name__+':'+str(error)[:100]
        for thread in readers: thread.join(timeout=2)
        (directory/'stdout.log').write_bytes(output[0]); (directory/'stderr.log').write_bytes(output[1])
        (directory/'result.json').write_text(json.dumps(record,indent=2),encoding='utf-8')
    return record
