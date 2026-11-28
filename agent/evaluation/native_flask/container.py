"""One fixed, parent-gated Flask observation under a caller-owned durable lease."""
import json
import math
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import threading
import time
import uuid

from agent.evaluation.repository_observer import tree_fingerprint
from . import ownership
from .ownership import IMAGE, LABEL, PYTHON

LIMIT=12*1024*1024


def expected_container(value,inputs,owner,local_id):
    """Exact fixed profile, including the sole read-only candidate mount."""
    try:
        h,c,m=value['HostConfig'],value['Config'],value['Mounts']
        fields={'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,'PidMode':'',
            'IpcMode':'private','PidsLimit':64,'Memory':536870912,'MemorySwap':536870912,
            'NanoCpus':1000000000,'Tmpfs':{'/tmp':'rw,nosuid,nodev,noexec,size=256m'}}
        return (value['Image']==local_id and all(h.get(k)==v for k,v in fields.items())
            and not h.get('CapAdd') and not h.get('GroupAdd') and not h.get('Devices')
            and not h.get('DeviceRequests') and h['LogConfig']['Type']=='none'
            and h['SecurityOpt']==['no-new-privileges']
            and {v.removeprefix('CAP_') for v in h['CapDrop']}=={'ALL'}
            and c['Image']==IMAGE and c['User']=='65534:65534' and c['WorkingDir']=='/'
            and c['Entrypoint']==[PYTHON] and c['Cmd']==['-I','-S','-B','/trusted/shim.py']
            and c['Labels']=={'org.opencontainers.image.version':'22.04',LABEL:owner}
            and len(m)==1 and m[0]['Type']=='bind' and m[0]['RW'] is False
            and m[0]['Source']==str(inputs.resolve()) and m[0]['Destination']=='/trusted'
            and m[0]['Propagation']=='rprivate')
    except (KeyError,TypeError,AttributeError):return False


def observe(prepared,lease,*,timeout_seconds=150):
    """No replay: a durable intent precedes create; GO never renews the deadline."""
    entered=time.monotonic()
    if (type(timeout_seconds) not in (int,float) or not math.isfinite(timeout_seconds)
            or not 0<timeout_seconds<=150):raise ValueError('bounded_flask_case_timeout_required')
    if (not lease.get('_active') or lease.get('closed') or lease.get('creation_unknown')
            or lease.get('creation_in_flight')
            or lease.get('_deadlines')!=(lease.get('deadline'),lease.get('cleanup_deadline'))):
        raise ValueError('live_unspent_flask_owner_required')
    deadline=min(lease['deadline'],entered+timeout_seconds)
    cleanup_end=min(lease['cleanup_deadline'],entered+timeout_seconds+15)
    result={'status':'REJECTED','execution_admitted':False,'execution_started':False,'gate_released':False,
        'parent_gate_passed':False,'candidate_import_verified':False,'cleanup_complete':False,'creation_unknown':False}
    process=None;readers=[];output=[bytearray(),bytearray()];failed=threading.Event();directory=None;owns_case=False
    def remaining(limit):
        left=deadline-time.monotonic()
        if left<=0:raise ValueError('flask_case_deadline')
        return min(left,limit)
    def docker(*args,limit=10):
        value=ownership.command(*args,timeout=remaining(limit))
        if value.returncode or len(value.stdout)>262144 or len(value.stderr)>65536:
            raise ValueError('flask_docker_rpc_failed')
        remaining(10)
        return value.stdout
    try:
        from .candidate import PreparedFlaskCandidate,validate_candidate_inputs
        if type(prepared) is not PreparedFlaskCandidate:raise ValueError('public_prepared_flask_candidate_required')
        validate_candidate_inputs(prepared);remaining(10)
        directory=ownership.ordinary(prepared.directory)
        if (directory/'consume.started').exists() or (directory/'observation.json').exists():
            # Its original lease, not this new caller, owns any prior RPC outcome.
            lease.update(creation_unknown=True,closed=True,cleanup_complete=False)
            ownership.save_lease(lease)
            raise ValueError('flask_case_already_started_unknown_no_replay')
        # The exclusive marker is never removed, even if no create response arrives.
        with (directory/'consume.started').open('x',encoding='utf-8') as marker:
            json.dump({'owner':lease['owner'],'lease_directory':lease['directory']},marker)
            marker.flush();os.fsync(marker.fileno())
        owns_case=True
        case=ownership.ordinary(lease['directory'])/('case-'+uuid.uuid4().hex[:12]);case.mkdir()
        inputs=case/'inputs';shutil.copytree(prepared.inputs,inputs,symlinks=False)
        if tree_fingerprint(inputs)!=tree_fingerprint(prepared.inputs):raise ValueError('copied_materials_changed')
        validate_candidate_inputs(prepared);remaining(10)
        local=json.loads(docker('image','inspect',IMAGE))[0]
        if (IMAGE not in local['RepoDigests'] or local['Os']!='linux' or local['Architecture']!='amd64'
                or not re.fullmatch('sha256:[a-f0-9]{64}',local['Id'])):raise ValueError('fixed_image_identity')
        token=uuid.uuid4().hex;name='swe-flask-candidate-'+uuid.uuid4().hex
        shim=("import os,select,sys\nprint('READY:"+token+"',flush=True)\n"
            "if not select.select([sys.stdin],[],[],30)[0]:raise RuntimeError('gate timeout')\n"
            "if sys.stdin.readline()!='GO:"+token+"\\n':raise RuntimeError('gate denied')\n"
            "os.execve('"+PYTHON+"',['"+PYTHON+"','-I','-B','/trusted/guest.py'],"
            "{'PATH':'/usr/bin:/bin','HOME':'/tmp','PYTHONDONTWRITEBYTECODE':'1'})\n")
        (inputs/'shim.py').write_text(shim,encoding='utf-8',newline='\n')
        frozen=tree_fingerprint(inputs)
        result.update(inputs_sha256=frozen,candidate_sha256=prepared.candidate_sha256,
            environment_sha256=prepared.environment_sha256)
        remaining(10);ownership.begin_container(lease,name,inputs,local['Id'])
        response=docker('create','--interactive','--pull','never','--name',name,'--label',LABEL+'='+lease['owner'],
            '--network','none','--read-only','--user','65534:65534','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--pids-limit','64','--memory','512m',
            '--memory-swap','512m','--cpus','1','--log-driver','none','--workdir','/',
            '--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=256m','--mount',
            f'type=bind,source={inputs},target=/trusted,readonly',
            '--entrypoint',PYTHON,IMAGE,'-I','-S','-B','/trusted/shim.py').strip()
        if not re.fullmatch(b'[a-f0-9]{64}',response):raise ValueError('flask_creation_identity_unknown')
        cid=response.decode();inspected=docker('inspect',cid);value=json.loads(inspected)[0]
        if value.get('Id')!=cid:raise ValueError('flask_creation_identity_unknown')
        ownership.confirm_container(lease,name,value)
        (directory/'inspection.json').write_bytes(inspected)
        if not expected_container(value,inputs,lease['owner'],local['Id']):raise ValueError('parent_isolation_changed')
        remaining(10)
        process=subprocess.Popen(['docker','start','--attach','--interactive',cid],stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False)
        result['execution_started']=True;ready=queue.Queue()
        def drain(stream,sink,notify):
            first=True
            try:
                while chunk:=stream.readline(65536):
                    if len(sink)+len(chunk)>LIMIT:failed.set();break
                    sink.extend(chunk)
                    if notify and first:ready.put(chunk);first=False
            except OSError:failed.set()
            finally:stream.close()
        for index,stream in enumerate((process.stdout,process.stderr)):
            thread=threading.Thread(target=drain,args=(stream,output[index],index==0),daemon=True)
            thread.start();readers.append(thread)
        if ready.get(timeout=remaining(12))!=('READY:'+token+'\n').encode():raise ValueError('wrong_parent_ready')
        from .runtime import validate_status
        facts={}
        for key,path in (('status','/proc/1/status'),('cmdline','/proc/1/cmdline')):
            data=docker('exec',cid,'/bin/cat',path,limit=4)
            if len(data)>8192:raise ValueError('parent_status_read_failed')
            facts[key]=data.decode()
        (directory/'parent-facts.json').write_text(json.dumps(facts),encoding='utf-8')
        validate_candidate_inputs(prepared)
        if (not validate_status(facts['status']) or facts['cmdline'].split('\0')!=[PYTHON,'-I','-S','-B','/trusted/shim.py','']
                or failed.is_set() or tree_fingerprint(inputs)!=frozen):raise ValueError('parent_gate_denied')
        remaining(10);result['parent_gate_passed']=True
        process.stdin.write(('GO:'+token+'\n').encode());process.stdin.flush();process.stdin.close()
        result['gate_released']=True
        while process.poll() is None and not failed.is_set():remaining(10);time.sleep(min(.05,remaining(.05)))
        for thread in readers:thread.join(timeout=remaining(2))
        if failed.is_set() or any(t.is_alive() for t in readers) or process.returncode:raise ValueError('consumer_process_failed')
        guest=json.loads(bytes(output[0]).split(b'\n',1)[1])
        (directory/'guest-result.json').write_text(json.dumps(guest),encoding='utf-8')
        if (guest.get('phase')!='completed' or guest.get('candidate_import_verified') is not True
                or guest.get('cleanup_children') is not True or guest.get('source_unchanged') is not True
                or guest.get('candidate_sha256')!=prepared.candidate_sha256
                or guest.get('environment_sha256')!=prepared.environment_sha256
                or type(guest.get('exit_code')) is not int):raise ValueError('guest_execution_incomplete')
        if tree_fingerprint(inputs)!=frozen:raise ValueError('inputs_changed_after_gate')
        remaining(10)
        result.update(status='OBSERVED',candidate_import_verified=True,phase=guest['phase'],tests_exit_code=guest['exit_code'])
    except Exception as error:
        result.update(status='ERROR' if result['execution_started'] or lease['creation_in_flight'] else 'REJECTED',
            error_type=type(error).__name__,error_message=str(error)[:200])
    finally:
        if process is not None and process.poll() is None:
            try:
                if not process.stdin.closed:process.stdin.close()
                process.kill();process.wait(timeout=max(.001,min(3,cleanup_end-time.monotonic())))
            except (OSError,subprocess.SubprocessError):result['attach_cleanup_error']=True
        try:
            cleanup=ownership.cleanup_flask(lease,deadline=cleanup_end)
            result.update(cleanup_complete=cleanup['cleanup_complete'],cleanup_issues=cleanup['issues'],
                creation_unknown=lease['creation_unknown'])
        except Exception as error:result.update(cleanup_complete=False,cleanup_error=type(error).__name__)
        result['creation_unknown']=bool(lease['creation_unknown'] or lease['creation_in_flight'])
        for thread in readers:thread.join(timeout=max(0,min(2,cleanup_end-time.monotonic())))
        if any(t.is_alive() for t in readers):result['cleanup_complete']=False
        if not result['cleanup_complete']:
            result['status']='ERROR';lease.update(closed=True,cleanup_complete=False)
            try:ownership.save_lease(lease)
            except Exception as error:result['journal_error']=type(error).__name__
        if directory is not None and owns_case:
            try:
                (directory/'stdout.log').write_bytes(output[0]);(directory/'stderr.log').write_bytes(output[1])
                (directory/'observation.json').write_text(json.dumps(result),encoding='utf-8')
            except OSError as error:result.update(status='ERROR',output_error=type(error).__name__)
    return result
