"""Candidate-only Requests entry; no gold artifact or control-variant branch."""
import json
import os
from pathlib import Path
import resource
import shutil
import sys

sys.path.insert(0,'/trusted')
from common import BASE, SOURCE, LIMIT, INVOCATION, certificates, run, sha, source_hash, validate_status


def main():
    record={'phase':'entry','execution_admitted':False,'cleanup_children':False,
            'candidate_import_verified':False,'entry_kind':'requests-candidate-v1'}
    try:
        record['entry']=validate_status(Path('/proc/self/status').read_text())
        extra=[]
        for name in os.listdir('/proc/self/fd'):
            if int(name)<=2: continue
            try: os.readlink('/proc/self/fd/'+name)
            except FileNotFoundError: continue
            extra.append(int(name))
        if extra: raise ValueError('extra_entry_file_descriptors')
        resource.setrlimit(resource.RLIMIT_FSIZE,(LIMIT,LIMIT));os.umask(0o077)
        root=Path('/trusted')
        allowed={'bootstrap.py','shim.py','guest.py','common.py','config.json','test.patch','wheels','candidate'}
        if {p.name for p in root.iterdir()}!=allowed: raise ValueError('unexpected_candidate_input')
        if (root/'config.json').stat().st_size>65536: raise ValueError('configuration_limit')
        config=json.loads((root/'config.json').read_text())
        keys={'entry_kind','instance_id','base_commit','variant','profile','expected_source_tree_sha256',
            'expected_candidate_tree_sha256','expected_wheels','test_patch_sha256','pytest_args',
            'fixed_tls','environment_materials_sha256'}
        if (set(config)!=keys or config['entry_kind']!='requests-candidate-v1'
                or config['variant']!='candidate' or config['profile']!='historical-compat-v1'
                or config['instance_id']!='psf__requests-3362' or config['base_commit']!=BASE
                or config['expected_source_tree_sha256']!=SOURCE
                or config['pytest_args']!=['-rA','/tmp/work/tests/test_requests.py']):
            raise ValueError('candidate_configuration')
        record.update(profile=config['profile'],variant='candidate',
            environment_materials_sha256=config['environment_materials_sha256'],
            test_patch_sha256=config['test_patch_sha256'])
        if sha(root/'test.patch')!=config['test_patch_sha256']: raise ValueError('test_patch_identity')
        record['source_snapshot_sha256']=source_hash(Path('/testbed'))
        if record['source_snapshot_sha256']!=SOURCE: raise ValueError('image_source_changed')
        record['candidate_input_sha256']=source_hash(root/'candidate')
        if record['candidate_input_sha256']!=config['expected_candidate_tree_sha256']:
            raise ValueError('candidate_snapshot_changed')
        if (root/'candidate/tests').exists(): raise ValueError('protected_tests_in_candidate')
        work=Path('/tmp/work')
        shutil.copytree('/testbed',work,ignore=shutil.ignore_patterns('.git'))
        shutil.copytree(root/'candidate',work,dirs_exist_ok=True)
        # A byte snapshot deliberately does not preserve source mtimes. Distutils
        # must not reuse image build/lib files that now appear newer than edits.
        for generated in (work/'build',work/'requests.egg-info'):
            if generated.exists():
                if generated.is_symlink() or not generated.is_dir(): raise ValueError('generated_cache_type')
                shutil.rmtree(generated)
        if run(['git','apply','/trusted/test.patch'],work,'/tmp/test.log',15): raise ValueError('test_apply')
        record['candidate_source_sha256']=source_hash(work)
        wheels=config['expected_wheels'];names=[w['filename'] for w in wheels]
        if (len(wheels)!=16 or len({n.casefold() for n in names})!=16
                or 'Flask-0.10.1-py3-none-any.whl' not in names): raise ValueError('wheel_count')
        for wheel in wheels:
            name=wheel['filename']
            if '/' in name or '\\' in name or not name.endswith('.whl'): raise ValueError('wheel_path')
            if sha(root/'wheels'/name)!=wheel['sha256']: raise ValueError('wheel_identity')
        os.environ.update(HOME='/tmp',PIP_CONFIG_FILE='/dev/null',PIP_NO_INDEX='1',
            PIP_DISABLE_PIP_VERSION_CHECK='1',PYTHONDONTWRITEBYTECODE='1',PYTHONHASHSEED='0',
            PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
        os.environ.pop('PYTEST_ADDOPTS',None)
        record['phase']='install'
        args=[sys.executable,'-m','pip','install','--no-index','--no-deps']
        if run(args+['--target','/tmp/site']+[str(root/'wheels'/n) for n in names],'/tmp','/tmp/deps.log',45):
            raise ValueError('dependency_install_failed')
        certificates(record,config['profile'],config['fixed_tls'])
        if run(args+['--no-build-isolation','--target','/tmp/candidate',str(work)],'/tmp','/tmp/install.log',45):
            raise ValueError('candidate_install_failed')
        record['phase']='test'
        record['tests_exit_code']=run([sys.executable,'-I','-B','-c',INVOCATION,config['profile']],
            '/tmp','/tmp/native.log',90,stderr_log='/tmp/native-stderr.log')
        record['native_log']=Path('/tmp/native.log').read_text(errors='replace')
        record['native_stderr']=Path('/tmp/native-stderr.log').read_text(errors='replace')
        if Path('/tmp/origin.json').is_file():
            record['origin']=json.loads(Path('/tmp/origin.json').read_text())
            record['candidate_import_verified']=True
        record['remaining_namespace_pids']=sorted(int(p.name) for p in Path('/proc').iterdir()
            if p.name.isdigit() and int(p.name)!=os.getpid())
        if record['remaining_namespace_pids']: raise ValueError('namespace_children_cleanup_unknown')
        record.update(phase='completed',cleanup_children=True)
    except Exception as error:
        record.update(error_type=type(error).__name__,error_message=str(error)[:200])
    print(json.dumps(record))


if __name__=='__main__': main()
