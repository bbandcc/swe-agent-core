"""Fixed Flask candidate material data; no process creation or execution admission."""
from dataclasses import asdict,dataclass
import json
from pathlib import Path
import shutil

from agent.evaluation.repository_candidate import CandidatePolicy,RepositoryCandidateSnapshot,freeze_candidate
from agent.evaluation.repository_observer import capture_tree,tree_fingerprint
from agent.evaluation.native_task_spec import NativeTaskSpec
from agent.workspace import has_single_regular_file_link
from .profile import ARGV,BASE,BASELINE,IMAGE,PINS,POLICY,SOURCE,SPEC,TEST_PATCH,encoded,hidden,sha


@dataclass(frozen=True)
class PreparedFlaskCandidate:
    directory:Path
    baseline_root:Path
    task:NativeTaskSpec
    policy:CandidatePolicy
    candidate_sha256:str
    environment_sha256:str
    inputs_sha256:str
    host_code_sha256:str

    @property
    def inputs(self)->Path:return self.directory/'inputs'


def fixed_policy()->CandidatePolicy:
    return CandidatePolicy(editable_prefixes=tuple(POLICY['editable_prefixes']),
        protected_paths=tuple(POLICY['protected_paths']),immutable_paths=tuple(POLICY['immutable_paths']),
        max_entries=POLICY['max_entries'],max_total_bytes=POLICY['max_total_bytes'],
        max_changed_bytes=POLICY['max_changed_bytes'])


def host_identity()->dict[str,str]:
    """Bind actual package lifecycle plus shared native/freeze implementations."""
    package=Path(__file__).resolve().parent;evaluation=package.parent
    shared=('repository_candidate.py','repository_observer.py','native_task_spec.py','native_log.py',
        'native_result.py','native_observer.py','native_receipts.py','native_runner.py','native_flask_runner.py','native_graph.py')
    paths=sorted(set(package.rglob('*.py'))|{evaluation/name for name in shared})
    if len(paths)>100 or any(not has_single_regular_file_link(p) for p in paths):
        raise ValueError('unsafe_flask_implementation')
    return {p.relative_to(evaluation).as_posix():sha(p.read_bytes()) for p in paths}


def _support()->dict[str,bytes]:
    return {target:Path(__file__).with_name(source).read_bytes() for target,source in
        (('guest.py','guest.py'),('fixed_profile.py','profile.py'),('fixed_runtime.py','runtime.py'))}


def _configuration(candidate_sha,support,host_code):
    environment=sha(encoded({'image':IMAGE,'source':SOURCE,'baseline':BASELINE,'spec':SPEC,'policy':POLICY,
        'wheels':PINS,'test_patch':TEST_PATCH,'argv':ARGV,'support':support,'host_implementation':host_code}))
    return {'entry_kind':'flask-candidate-v1','base_commit':BASE,'source_sha256':SOURCE,'baseline_sha256':BASELINE,
        'task_spec_sha256':SPEC,'policy':POLICY,'candidate_sha256':candidate_sha,
        'test_patch_sha256':TEST_PATCH,'wheels':{n:{'size':s,'sha256':h} for n,(s,h) in PINS.items()},
        'argv':ARGV,'environment_sha256':environment,'support_sha256':support}


def prepare_candidate(snapshot,policy,*,baseline_root,task,test_patch,wheels,directory):
    """Publish exact source bytes and trusted materials; never execute target code."""
    if type(policy) is not CandidatePolicy or policy!=fixed_policy() or json.loads(encoded(asdict(policy)))!=POLICY:
        raise ValueError('complete_fixed_policy_required')
    if type(snapshot) is not RepositoryCandidateSnapshot:raise ValueError('public_frozen_snapshot_required')
    if type(task) is not NativeTaskSpec or sha(encoded(asdict(task)))!=SPEC:
        raise ValueError('fixed_task_spec_required')
    if type(test_patch) is not bytes or sha(test_patch)!=TEST_PATCH:raise ValueError('test_patch_identity')
    baseline_root=Path(baseline_root).absolute()
    if tree_fingerprint(baseline_root)!=BASELINE:raise ValueError('baseline_identity')
    for count,path in enumerate(snapshot.root.rglob('*')):
        if count>=4096 or hidden(path.relative_to(snapshot.root).as_posix()):raise ValueError('protected_candidate_path')
    files,manifest=capture_tree(snapshot.root)
    if sha(manifest)!=snapshot.tree_sha256 or manifest!=snapshot.manifest_bytes or sha(snapshot.patch)!=snapshot.patch_sha256:
        raise ValueError('candidate_snapshot_changed')
    baseline_files,_=capture_tree(baseline_root)
    for name in files.keys()-baseline_files.keys():
        basename=Path(name).name.casefold()
        if basename=='conftest.py' or basename.startswith('test_') or basename.endswith('_test.py'):
            raise ValueError('additional_test_file')
    for name in ('setup.cfg','pytest.ini','tox.ini','pyproject.toml','conftest.py'):
        if files.get(name)!=baseline_files.get(name):raise ValueError('trusted_test_configuration_changed')
    if type(wheels) is not dict or set(wheels)!=set(PINS):raise ValueError('fixed_wheel_set_required')
    wheel_bytes={}
    for name,(size,digest) in PINS.items():
        path=Path(wheels[name])
        if not has_single_regular_file_link(path) or path.stat().st_size!=size:raise ValueError('wheel_identity')
        data=path.read_bytes()
        if sha(data)!=digest:raise ValueError('wheel_identity')
        wheel_bytes[name]=data
    directory=Path(directory).absolute()
    if (directory.exists() or any(p.is_symlink() or p.is_junction() for p in (directory,*directory.parents))
            or any(a==directory or a in directory.parents or directory in a.parents for a in (baseline_root,snapshot.root))):
        raise ValueError('fresh_disjoint_consumer_directory_required')
    directory.mkdir()
    sealed=freeze_candidate(baseline_root,snapshot.root,policy,directory/'sealed')
    if not sealed.ok:raise ValueError('candidate_public_seal:'+str(sealed.error_code))
    if any(getattr(sealed.snapshot,n)!=getattr(snapshot,n) for n in ('manifest_bytes','entries','changes','patch')):
        raise ValueError('candidate_public_seal_identity')
    inputs=directory/'inputs';inputs.mkdir();(inputs/'wheels').mkdir()
    shutil.copytree(sealed.snapshot.root,inputs/'candidate')
    for name,data in wheel_bytes.items():(inputs/'wheels'/name).write_bytes(data)
    (inputs/'test.patch').write_bytes(test_patch)
    support=_support()
    for name,data in support.items():(inputs/name).write_bytes(data)
    host_code=host_identity();support_hash={n:sha(d) for n,d in support.items()}
    config=_configuration(snapshot.tree_sha256,support_hash,host_code)
    (inputs/'config.json').write_bytes(encoded(config))
    prepared=PreparedFlaskCandidate(directory,baseline_root,task,policy,snapshot.tree_sha256,
        config['environment_sha256'],tree_fingerprint(inputs),sha(encoded(host_code)))
    (directory/'prepared.json').write_bytes(encoded({'candidate_sha256':snapshot.tree_sha256,
        'environment_sha256':prepared.environment_sha256,'inputs_sha256':prepared.inputs_sha256,
        'host_implementation':host_code,'support_sha256':support_hash,'policy':POLICY,
        'input_paths':sorted(p.relative_to(inputs).as_posix() for p in inputs.rglob('*'))}))
    validate_candidate_inputs(prepared)
    return prepared


def validate_candidate_inputs(prepared)->None:
    """Reconcile published data with current code/materials; not execution admission."""
    if type(prepared) is not PreparedFlaskCandidate:raise ValueError('public_prepared_candidate_required')
    if any(p.is_symlink() or p.is_junction() for p in (prepared.directory,*prepared.directory.parents)):
        raise ValueError('linked_candidate_materials')
    if (prepared.policy!=fixed_policy() or type(prepared.task) is not NativeTaskSpec
            or sha(encoded(asdict(prepared.task)))!=SPEC):raise ValueError('fixed_preparation_changed')
    host_code=host_identity()
    if sha(encoded(host_code))!=prepared.host_code_sha256:raise ValueError('host_implementation_changed')
    if tree_fingerprint(prepared.baseline_root)!=BASELINE:raise ValueError('baseline_identity')
    inputs=prepared.inputs
    if {p.name for p in inputs.iterdir()}!={'guest.py','fixed_profile.py','fixed_runtime.py','config.json','candidate','test.patch','wheels'}:
        raise ValueError('unexpected_consumer_input')
    if tree_fingerprint(inputs)!=prepared.inputs_sha256:raise ValueError('prepared_inputs_changed')
    if tree_fingerprint(inputs/'candidate')!=prepared.candidate_sha256:raise ValueError('candidate_snapshot_changed')
    support_hash={n:sha(d) for n,d in _support().items()}
    config=_configuration(prepared.candidate_sha256,support_hash,host_code)
    if (json.loads((inputs/'config.json').read_bytes())!=config
            or prepared.environment_sha256!=config['environment_sha256']):raise ValueError('prepared_configuration_changed')
    if sha((inputs/'test.patch').read_bytes())!=TEST_PATCH:raise ValueError('test_patch_identity')
    for name,digest in support_hash.items():
        if sha((inputs/name).read_bytes())!=digest:raise ValueError('support_identity')
    if {p.name for p in (inputs/'wheels').iterdir()}!=set(PINS):raise ValueError('fixed_wheel_set_required')
    for name,(size,digest) in PINS.items():
        path=inputs/'wheels'/name
        if path.stat().st_size!=size or sha(path.read_bytes())!=digest:raise ValueError('wheel_identity')
