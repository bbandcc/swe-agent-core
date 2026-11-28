"""Fixed Flask container leases and independent cleanup, never task resumption."""
from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
from agent.workspace import has_single_regular_file_link

TASK='pallets__flask-4045'
IMAGE='swebench/sweb.eval.x86_64.pallets_1776_flask-4045@sha256:431573fcf066022cec6e296bdb1105b5135283a3ebdf13b9ad1bd1859580a7c0'
LABEL='swe.flask-candidate.owner'
PYTHON='/opt/miniconda3/envs/testbed/bin/python'


def command(*args,timeout=10):
    return subprocess.run(['docker',*args],stdin=subprocess.DEVNULL,capture_output=True,
        shell=False,timeout=timeout)


def ordinary(path):
    root=Path(path).absolute()
    if any(p.is_symlink() or p.is_junction() for p in (root,*root.parents)):
        raise ValueError('linked_flask_control_path')
    return root.resolve()


@contextmanager
def _lock(path,create=False):
    if not create and not has_single_regular_file_link(path):raise ValueError('missing_owner_lock')
    with path.open('x+b' if create else 'r+b') as stream:
        if create:stream.write(b'1');stream.flush();os.fsync(stream.fileno())
        held=False
        try:
            stream.seek(0)
            if os.name=='nt':
                import msvcrt
                try:msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
                except OSError:raise BlockingIOError('owner_active') from None
            else:
                import fcntl
                fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            held=True;yield
        finally:
            if held:
                stream.seek(0)
                if os.name=='nt':msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
                else:fcntl.flock(stream.fileno(),fcntl.LOCK_UN)


def save_lease(lease):
    """Flush intent before an RPC; partial writes make recovery UNKNOWN."""
    path=ordinary(lease['directory'])/'lease.json'
    if path.exists() and not has_single_regular_file_link(path):raise ValueError('unsafe_lease_journal')
    with path.open('w' if path.exists() else 'x',encoding='utf-8') as stream:
        json.dump({k:v for k,v in lease.items() if not k.startswith('_')},stream,sort_keys=True)
        stream.flush();os.fsync(stream.fileno())


def _read(directory):
    path=directory/'lease.json'
    if not has_single_regular_file_link(path) or path.stat().st_size>65536:raise ValueError('invalid_lease')
    value=json.loads(path.read_text(encoding='utf-8'));rows=value.get('containers')
    if (value.get('task_id')!=TASK or value.get('image')!=IMAGE
            or ordinary(value.get('directory',''))!=directory
            or not re.fullmatch('[a-f0-9]{32}',value.get('owner',''))
            or any(type(value.get(k)) is not bool for k in ('creation_unknown','creation_in_flight','closed','cleanup_complete'))
            or any(type(value.get(k)) not in (int,float) or not math.isfinite(value[k]) for k in ('deadline','cleanup_deadline'))
            or not value['deadline']<value['cleanup_deadline'] or type(rows) is not list or len(rows)>4):
        raise ValueError('invalid_lease')
    names=[];ids=[]
    for row in rows:
        name=row.get('name');names.append(name)
        if row.get('id') is not None:ids.append(row['id'])
        if (type(name) is not str or not re.fullmatch('swe-flask-candidate-[a-f0-9]{32}',name)
                or not re.fullmatch('sha256:[a-f0-9]{64}',row.get('image_id',''))
                or type(row.get('removed')) is not bool or type(row.get('inputs')) is not str
                or not ordinary(row['inputs']).is_relative_to(directory)
                or (row.get('id') is not None and not re.fullmatch('[a-f0-9]{64}',row['id']))
                or (row.get('id') is None and (row.get('removed') or not (value['creation_unknown'] or value['creation_in_flight'])))
                or (row.get('id') is not None and (type(row.get('created_at')) is not str or not 1<=len(row['created_at'])<=128))):
            raise ValueError('invalid_lease')
    if len(set(names))!=len(names) or len(set(ids))!=len(ids):raise ValueError('invalid_lease')
    return value


def begin_container(lease,name,inputs,image_id):
    if (not lease.get('_active') or lease['closed'] or lease['creation_unknown'] or lease['creation_in_flight']
            or lease.get('_deadlines')!=(lease['deadline'],lease['cleanup_deadline'])
            or time.monotonic()>=lease['deadline'] or len(lease['containers'])>=4
            or not re.fullmatch('swe-flask-candidate-[a-f0-9]{32}',name)
            or any(row['name']==name for row in lease['containers'])
            or not re.fullmatch('sha256:[a-f0-9]{64}',image_id)):
        raise ValueError('flask_creation_not_permitted')
    if not ordinary(inputs).is_relative_to(ordinary(lease['directory'])):raise ValueError('owned_flask_inputs_required')
    lease['containers'].append({'name':name,'id':None,'created_at':None,'image_id':image_id,
        'inputs':str(ordinary(inputs)),'removed':False})
    lease['creation_in_flight']=True;lease['cleanup_complete']=False;save_lease(lease)


def confirm_container(lease,name,value):
    row=next(r for r in lease['containers'] if r['name']==name)
    if (not lease.get('_active') or not lease['creation_in_flight'] or row['id'] is not None
            or not re.fullmatch('[a-f0-9]{64}',value.get('Id',''))
            or value.get('Name')!='/'+name or value.get('Image')!=row['image_id']
            or value['Config']['Image']!=IMAGE
            or value['Config']['Labels']!={'org.opencontainers.image.version':'22.04',LABEL:lease['owner']}
            or type(value.get('Created')) is not str or not 1<=len(value['Created'])<=128):
        raise ValueError('flask_creation_identity_unknown')
    row.update(id=value['Id'],created_at=value['Created'])
    lease['creation_in_flight']=False;save_lease(lease)


def _cleanup(lease,deadline,*,final=True):
    report={'status':'UNKNOWN','cleanup_complete':False,'restart_permitted':False,'removed':[],'issues':[]}
    def docker(*args):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise ValueError('cleanup_deadline')
        result=command(*args,timeout=min(10,remaining))
        if result.returncode or len(result.stdout)>262144 or len(result.stderr)>65536:raise ValueError('cleanup_rpc_failed')
        return result.stdout
    try:
        if lease['creation_unknown'] or lease['creation_in_flight']:
            report['issues'].append('creation_rpc_outcome_unknown')
        for row in lease['containers']:
            if row['id'] is None or row['removed']:continue
            present=docker('container','ls','--all','--filter','id='+row['id'],'--format','{{.ID}}').strip()
            if not present:row['removed']=True;continue
            value=json.loads(docker('inspect',row['id']))[0]
            if (value.get('Id')!=row['id'] or value.get('Name')!='/'+row['name']
                    or value.get('Image')!=row['image_id'] or value.get('Created')!=row['created_at']
                    or value['Config']['Image']!=IMAGE
                    or value['Config']['Labels']!={'org.opencontainers.image.version':'22.04',LABEL:lease['owner']}):
                raise ValueError('cleanup_identity_unknown')
            docker('rm','--force',row['id'])
            if docker('container','ls','--all','--filter','id='+row['id'],'--format','{{.ID}}').strip():
                raise ValueError('removal_not_confirmed')
            row['removed']=True;report['removed'].append(row['id'])
        if not report['issues']:report.update(status='CLEANED',cleanup_complete=True)
    except Exception as error:report['issues'].append(str(error)[:120] if isinstance(error,ValueError) else type(error).__name__)
    lease.update(closed=final or not report['cleanup_complete'],cleanup_complete=report['cleanup_complete'])
    if lease['creation_in_flight']:lease['creation_unknown']=True
    save_lease(lease)
    return report


def cleanup_flask(lease,*,final=False,deadline=None):
    """Clean confirmed case resources while the caller still holds the owner lock."""
    if not lease.get('_active'):raise ValueError('live_flask_owner_required')
    end=lease['_deadlines'][1]
    return _cleanup(lease,min(end,deadline) if deadline is not None else end,final=final)


@contextmanager
def lease_owner(directory,*,timeout_seconds=300):
    if type(timeout_seconds) not in (int,float) or not math.isfinite(timeout_seconds) or not 20<=timeout_seconds<=600:
        raise ValueError('bounded_flask_deadline_required')
    directory=ordinary(directory);directory.mkdir(exist_ok=False)
    with _lock(directory/'lease-owner.lock',create=True):
        end=time.monotonic()+timeout_seconds
        lease={'directory':str(directory),'task_id':TASK,'image':IMAGE,'owner':uuid.uuid4().hex,
            'deadline':end-15,'cleanup_deadline':end,'containers':[],'closed':False,
            'creation_unknown':False,'creation_in_flight':False,'cleanup_complete':False,'_active':True}
        lease['_deadlines']=(lease['deadline'],lease['cleanup_deadline'])
        save_lease(lease)
        try:yield lease
        finally:
            try:_cleanup(lease,lease['cleanup_deadline'])
            finally:lease['_active']=False


def recover_flask(directory,*,timeout_seconds=30):
    """A fresh cleanup horizon never renews execution or grants replay."""
    if type(timeout_seconds) not in (int,float) or not math.isfinite(timeout_seconds) or not 0<timeout_seconds<=60:
        raise ValueError('bounded_recovery_timeout_required')
    try:
        directory=ordinary(directory)
        with _lock(directory/'lease-owner.lock'):
            return _cleanup(_read(directory),time.monotonic()+timeout_seconds)
    except BlockingIOError:return {'status':'OWNER_ACTIVE','cleanup_complete':False,'restart_permitted':False,'issues':['owner_active']}
    except Exception as error:return {'status':'UNKNOWN','cleanup_complete':False,'restart_permitted':False,'issues':[type(error).__name__]}
