"""Portable process execution and exact imports, with no author inputs."""
import os
from pathlib import Path
import signal
import subprocess

LIMIT=4*1024*1024


def validate_status(text):
    facts=dict(line.split(':',1) for line in text.splitlines() if ':' in line)
    return (all(facts[k].split()==['65534']*4 for k in ('Uid','Gid'))
        and facts['Groups'].split() in ([],['65534']) and facts['NoNewPrivs'].strip()=='1'
        and all(int(facts[k],16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')))


def run(argv,name,timeout):
    with Path('/tmp/'+name+'.stdout').open('wb') as out,Path('/tmp/'+name+'.stderr').open('wb') as err:
        child=subprocess.Popen(argv,cwd='/tmp/work',stdin=subprocess.DEVNULL,stdout=out,
            stderr=err,start_new_session=True,shell=False)
        try:return child.wait(timeout=timeout)
        finally:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            child.wait(timeout=3)


INVOCATION=r'''
import hashlib,json,os,sys,zipfile
from pathlib import Path
sys.path[:0]=['/tmp/work/src','/tmp/deps'];os.chdir('/tmp/work')
import setuptools,pkg_resources,werkzeug,flask,pytest
assert setuptools.__version__=='65.5.1' and werkzeug.__version__=='2.0.3'
origin={}
for name,module,wheel_name in (
 ('setuptools',setuptools,'setuptools-65.5.1-py3-none-any.whl'),
 ('pkg_resources',pkg_resources,'setuptools-65.5.1-py3-none-any.whl'),
 ('werkzeug',werkzeug,'Werkzeug-2.0.3-py3-none-any.whl')):
 path=Path(module.__file__).resolve();assert path==Path('/tmp/deps')/name/'__init__.py'
 with zipfile.ZipFile('/trusted/wheels/'+wheel_name) as wheel:assert path.read_bytes()==wheel.read(name+'/__init__.py')
 origin[name]=str(path);origin[name+'_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
assert pkg_resources.get_distribution('setuptools').version=='65.5.1'
assert Path(flask.__file__).resolve()==Path('/tmp/work/src/flask/__init__.py')
assert Path(pytest.__file__).resolve().is_relative_to(Path(sys.prefix))
origin.update(flask=str(Path(flask.__file__).resolve()),flask_sha256=hashlib.sha256(Path(flask.__file__).read_bytes()).hexdigest(),
 pytest=str(Path(pytest.__file__).resolve()),pytest_version=pytest.__version__,
 setuptools_version=setuptools.__version__,werkzeug_version=werkzeug.__version__)
Path('/tmp/origin.json').write_text(json.dumps(origin))
code=pytest.main(['-p','no:cacheprovider','-rA','tests/test_basic.py','tests/test_blueprints.py'])
loaded={}
for name,module in list(sys.modules.items()):
 if name=='flask' or name.startswith('flask.'):
  if getattr(module,'__file__',None):
   path=Path(module.__file__).resolve();assert path.is_relative_to(Path('/tmp/work/src/flask'))
   loaded[name]={'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
origin['flask_modules']=loaded
Path('/tmp/origin.json').write_text(json.dumps(origin))
sys.exit(code)
'''
