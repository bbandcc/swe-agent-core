"""Candidate-only fixed Flask entry; all private tests come from the pinned image."""
import json
import os
from pathlib import Path
import resource
import shutil
import sys

sys.path.insert(0,'/trusted')
from fixed_profile import ARGV,BASE,BASELINE,PINS,POLICY,SOURCE,SPEC,TEST_PATCH,hidden,sha,tree
from fixed_runtime import INVOCATION,LIMIT,run,validate_status


def main():
    result={'phase':'entry','entry_kind':'flask-candidate-v1','candidate_import_verified':False,
        'execution_admitted':False,'cleanup_children':False}
    try:
        if not validate_status(Path('/proc/self/status').read_text()):raise ValueError('entry_profile')
        resource.setrlimit(resource.RLIMIT_FSIZE,(LIMIT,LIMIT));os.umask(0o077)
        root=Path('/trusted');expected={'guest.py','fixed_profile.py','fixed_runtime.py','shim.py','config.json','candidate','test.patch','wheels'}
        if {p.name for p in root.iterdir()}!=expected:raise ValueError('unexpected_consumer_input')
        config=json.loads((root/'config.json').read_text())
        keys={'entry_kind','base_commit','source_sha256','baseline_sha256','task_spec_sha256','policy',
            'candidate_sha256','test_patch_sha256','wheels','argv','environment_sha256','support_sha256'}
        if (set(config)!=keys or config['entry_kind']!='flask-candidate-v1' or config['base_commit']!=BASE
                or config['source_sha256']!=SOURCE or config['baseline_sha256']!=BASELINE
                or config['task_spec_sha256']!=SPEC or config['policy']!=POLICY
                or config['test_patch_sha256']!=TEST_PATCH or config['argv']!=ARGV
                or config['wheels']!={n:{'size':s,'sha256':h} for n,(s,h) in PINS.items()}):
            raise ValueError('fixed_consumer_configuration')
        for name,expected_sha in config['support_sha256'].items():
            if name not in ('guest.py','fixed_profile.py','fixed_runtime.py') or sha((root/name).read_bytes())!=expected_sha:
                raise ValueError('support_identity')
        if set(config['support_sha256'])!={'guest.py','fixed_profile.py','fixed_runtime.py'}:raise ValueError('support_identity')
        if sha((root/'test.patch').read_bytes())!=TEST_PATCH:raise ValueError('test_patch_identity')
        if {p.name for p in (root/'wheels').iterdir()}!=set(PINS):raise ValueError('wheel_layout')
        for name,(size,expected_sha) in PINS.items():
            data=(root/'wheels'/name).read_bytes()
            if len(data)!=size or sha(data)!=expected_sha:raise ValueError('wheel_identity')
        if tree(Path('/testbed'))[3]!=SOURCE:raise ValueError('image_source_changed')
        if tree(Path('/testbed'),model=True)[2]!=BASELINE:raise ValueError('image_model_view_changed')
        for path in (root/'candidate').rglob('*'):
            if hidden(path.relative_to(root/'candidate').as_posix()):raise ValueError('private_path_in_candidate')
        candidate,_,candidate_sha,_=tree(root/'candidate')
        if candidate_sha!=config['candidate_sha256']:raise ValueError('candidate_snapshot_changed')
        result.update(environment_sha256=config['environment_sha256'],candidate_sha256=candidate_sha,
            source_sha256=SOURCE,baseline_sha256=BASELINE,test_patch_sha256=TEST_PATCH)
        work=Path('/tmp/work');shutil.copytree('/testbed',work,ignore=shutil.ignore_patterns('.git'))
        for parent,dirs,names in os.walk(work,topdown=False):
            for name in dirs:
                if name in ('__pycache__','.pytest_cache','build','dist') or name.endswith('.egg-info'):
                    shutil.rmtree(Path(parent)/name)
        shutil.copytree(root/'candidate',work,dirs_exist_ok=True)
        if tree(work,model=True)[0]!=candidate:raise ValueError('candidate_overlay_changed')
        os.environ.update(HOME='/tmp',PYTHONDONTWRITEBYTECODE='1',PYTHONHASHSEED='0',
            PYTHONIOENCODING='utf-8',PYTEST_DISABLE_PLUGIN_AUTOLOAD='1',PIP_CONFIG_FILE='/dev/null',
            PIP_NO_INDEX='1',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_CONFIG_SYSTEM='/dev/null')
        os.environ.pop('PYTEST_ADDOPTS',None)
        result['phase']='prepare'
        if run(['git','apply','/trusted/test.patch'],'test-apply',15):raise ValueError('fixed_test_patch_apply')
        before=tree(work)[3];result['runtime_source_sha256']=before
        if run([sys.executable,'-I','-B','-m','pip','--isolated','install','--disable-pip-version-check',
                '--no-index','--no-deps','--no-compile','--target','/tmp/deps',
                *[str(root/'wheels'/n) for n in PINS]],'deps',30):raise ValueError('dependency_install_failed')
        result['phase']='test';result['exit_code']=run([sys.executable,'-I','-B','-c',INVOCATION],'native',90)
        result['native_log']=Path('/tmp/native.stdout').read_text(errors='replace')
        result['native_stderr']=Path('/tmp/native.stderr').read_text(errors='replace')
        result['origin']=json.loads(Path('/tmp/origin.json').read_text())
        result['candidate_import_verified']=True
        result['source_unchanged']=tree(work)[3]==before
        result['remaining_namespace_pids']=[int(p.name) for p in Path('/proc').iterdir() if p.name.isdigit() and int(p.name)!=os.getpid()]
        if result['remaining_namespace_pids'] or not result['source_unchanged']:raise ValueError('post_execution_state_changed')
        result.update(phase='completed',cleanup_children=True)
    except Exception as error:
        result.update(error_type=type(error).__name__,error_message=str(error)[:200])
        for field,name in (('native_log','native.stdout'),('native_stderr','native.stderr')):
            path=Path('/tmp')/name
            if path.is_file() and path.stat().st_size<=LIMIT:result[field]=path.read_text(errors='replace')
    print(json.dumps(result))


if __name__=='__main__':main()
