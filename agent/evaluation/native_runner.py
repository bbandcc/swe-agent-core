"""Concrete cooperative Requests runner. Candidate code executes only in Docker."""
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
import uuid

from agent.evaluation.native_observer import native_observer_spec, observe_native_result
from agent.evaluation import native_observer as observer_module
from agent.evaluation.native_receipts import bind_native_receipts
from agent.evaluation.native_result import NativeAttemptIdentity
from agent.evaluation.native_task_spec import NativeTaskSpec
from agent.evaluation.repository_candidate import CandidatePolicy,freeze_candidate
from agent.evaluation.repository_observer import capture_tree,tree_fingerprint
from agent.evaluation.native_requests import container,tls,ownership,constants
from agent.verification.contracts import (VerificationAttempt,VerificationAttemptStatus,
    VerificationCheckStatus,VerificationResult,VerificationSummary,verification_spec_digest)
from agent.workspace import has_single_regular_file_link

SPEC_SHA='3ae2d1ec45650c68b60a51bd7141071a61d8ffae8ce2e13968283435a10bfebe'
BASELINE_SHA='120d70045bb41111f8ab6771294eb4d6bee9b4eb5cc478caf19fd2d688bf30e6'
WHEELS_SHA='470c04710a0fee5c562d4325afe37f5a4c1016bbb8c5fed389b9bb62ea9c9710'


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


class NativeRequestsRunner:
    """Caller holds ownership.lease_owner through TLS creation, graph and cleanup.

    This is the fixed Requests historical profile, never arbitrary repository or
    adversarial execution admission. TLS is injected as data, not executable code.
    """
    def __init__(self,task,identity,*,baseline_root,generation_root,control_root,runtime_root,
                 wheel_directory,wheel_manifest,test_patch,lease,owner_root):
        if type(task) is not NativeTaskSpec:raise ValueError('Prepared native task required')
        task=replace(task,parser_id='pytest-options-v2')
        if digest(asdict(task))!=SPEC_SHA:raise ValueError('Fixed Requests spec required')
        self.task,self.identity=task,identity
        requested=tuple(Path(p).absolute() for p in (baseline_root,generation_root,control_root,runtime_root,owner_root))
        if any(p.is_symlink() or p.is_junction() for r in requested for p in (r,*r.parents)):
            raise ValueError('Linked native root')
        self.baseline_root=Path(baseline_root).resolve(strict=True)
        self.generation_root=Path(generation_root).resolve(strict=True)
        self.root=Path(control_root).resolve();self.runtime_root=Path(runtime_root).resolve()
        self.owner_root=Path(owner_root).resolve(strict=True);self.lease=lease
        roots=(self.baseline_root,self.generation_root,self.root,self.runtime_root,self.owner_root)
        if any(a==b or a in b.parents or b in a.parents for i,a in enumerate(roots) for b in roots[i+1:]):
            raise ValueError('Native roots overlap')
        if any(p.is_symlink() or p.is_junction() for r in roots for p in (r,*r.parents)):
            raise ValueError('Linked native root')
        if (identity.task_id!=task.instance_id or identity.workspace.canonical_root!=str(self.generation_root)
                or tree_fingerprint(self.baseline_root)!=BASELINE_SHA
                or tree_fingerprint(self.generation_root)!=BASELINE_SHA):raise ValueError('Native source/identity mismatch')
        if (Path(lease['file']).resolve()!=self.owner_root/'materials/lease.json'
                or ownership.recover_fixed_tls(self.owner_root)['status']!='OWNER_ACTIVE'):
            raise ValueError('Active owner lease required')
        self.root.mkdir(exist_ok=False);self.root=self.root.resolve()
        self.execution_root=self.root/'observer';self.spec=native_observer_spec(self.execution_root,timeout_seconds=150)
        raw=Path(wheel_manifest).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=WHEELS_SHA:raise ValueError('Reviewed wheel manifest required')
        self.wheels=[]
        for pin in json.loads(raw)['wheels']:
            name=pin['filename'];path=Path(wheel_directory)/name
            if (Path(name).name!=name or '/' in name or '\\' in name or not has_single_regular_file_link(path)
                    or path.stat().st_size>32*1024*1024):raise ValueError('Unsafe wheel')
            data=path.read_bytes()
            if hashlib.sha256(data).hexdigest()!=pin['sha256']:raise ValueError('Wheel changed')
            self.wheels.append(({'filename':name,'sha256':pin['sha256']},data))
        if len(self.wheels)!=16:raise ValueError('Sixteen reviewed wheels required')
        self.test_patch=bytes(test_patch)
        if hashlib.sha256(self.test_patch).hexdigest()!=task.test_patch_sha256:raise ValueError('Test patch changed')
        resource=Path(container.__file__).parent
        self.support={name:(resource/name).read_bytes() for name in ('guest.py','guest_common.py')}
        self._support=dict(self.support)
        self._package={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in resource.glob('*.py')}
        self._control_code={str(p):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (Path(__file__).resolve(),Path(observer_module.__file__).resolve())}
        self._materials=json.loads(json.dumps(lease['author']['materials']))
        self.wheels=tuple(self.wheels)
        self._wheel_identity=tuple((digest(p),hashlib.sha256(d).hexdigest()) for p,d in self.wheels)
        self.policy=CandidatePolicy(protected_paths=('.git','tests'))
        self.environment_sha=digest({'image':constants.IMAGE,'task':SPEC_SHA,'wheels':WHEELS_SHA,
            'tls':self._materials,'implementation':self._package,
            'control_code':self._control_code,'baseline':BASELINE_SHA,
            'guest':{k:hashlib.sha256(v).hexdigest() for k,v in self.support.items()}})
        self._lease_identity=(lease['owner'],lease['volume'],lease['created_at'],lease['file'])
        self._environment=dict(os.environ);self._spec=self.spec;self._pending=None;self._seen=set()
        self._run=self.run
        self._boundaries=(self.baseline_root,self.generation_root,self.root,self.runtime_root,self.owner_root)
        self.receipts=[];self.native_attempts=[];self.case_mapping=()

    def permits(self,spec,workspace_root):
        try:
            return (self.spec==self._spec and replace(spec,timeout_seconds=150)==self._spec
                and self.run==self._run and digest(asdict(self.task))==SPEC_SHA
                and self._boundaries==(self.baseline_root,self.generation_root,self.root,self.runtime_root,self.owner_root)
                and all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==sha for p,sha in self._control_code.items())
                and self.policy==CandidatePolicy(protected_paths=('.git','tests'))
                and self.support==self._support and self.lease['author']['materials']==self._materials
                and tuple((digest(p),hashlib.sha256(d).hexdigest()) for p,d in self.wheels)==self._wheel_identity
                and hashlib.sha256(self.test_patch).hexdigest()==self.task.test_patch_sha256
                and {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(container.__file__).parent.glob('*.py')}==self._package
                and 0<spec.timeout_seconds<=150 and Path(workspace_root).resolve()==self.generation_root
                and dict(os.environ)==self._environment and tree_fingerprint(self.baseline_root)==BASELINE_SHA
                and self._lease_identity==tuple(self.lease[k] for k in ('owner','volume','created_at','file'))
                and not self.lease.get('creation_unknown') and not self.lease.get('creation_in_flight')
                and ownership.recover_fixed_tls(self.owner_root)['status']=='OWNER_ACTIVE'
                and all((Path(container.__file__).parent/k).read_bytes()==v for k,v in self.support.items()))
        except (OSError,ValueError,KeyError,TypeError):return False

    def bind_attempt(self,attempt):
        if (type(attempt) is not VerificationAttempt or attempt.status is not VerificationAttemptStatus.STARTED
                or attempt.run_id!=self.identity.run_id or attempt.task_id!=self.task.instance_id
                or attempt.spec_digest!=verification_spec_digest(self.spec) or attempt.spec_index!=0
                or attempt.attempt_ordinal!=0 or attempt.repair_attempt>2
                or attempt.phase=='baseline' and attempt.repair_attempt!=0
                or attempt.attempt_id in self._seen or self._pending is not None):return False
        self._pending=attempt;return True

    def _source(self):
        return capture_tree(self.generation_root)[1]

    def run(self,spec):
        attempt=self._pending;self._pending=None
        if attempt is None or not self.permits(spec,self.generation_root):return self._error(spec,'Native attempt unavailable')
        self._seen.add(attempt.attempt_id);started=time.monotonic();rid=uuid.uuid4().hex
        case=self.root/rid;inputs=case/'inputs'
        try:
            case.mkdir();inputs.mkdir();(inputs/'wheels').mkdir()
            frozen=freeze_candidate(self.baseline_root,self.generation_root,self.policy,case/'snapshot')
            if not frozen.ok:raise ValueError('Candidate rejected')
            source_sha=frozen.snapshot.tree_sha256
            payload=digest(sorted([[e.path,e.size,e.sha256] for e in frozen.snapshot.entries]))
            shutil.copytree(frozen.snapshot.root,inputs/'candidate')
            for name,target in (('guest.py','guest.py'),('guest_common.py','common.py')):(inputs/target).write_bytes(self.support[name])
            for pin,data in self.wheels:(inputs/'wheels'/pin['filename']).write_bytes(data)
            (inputs/'test.patch').write_bytes(self.test_patch)
            config={'entry_kind':'requests-candidate-v1','instance_id':self.task.instance_id,'base_commit':constants.BASE,
                'variant':'candidate','profile':'historical-compat-v1','expected_source_tree_sha256':constants.SOURCE,
                'expected_candidate_tree_sha256':payload,'expected_wheels':[p for p,_ in self.wheels],
                'test_patch_sha256':self.task.test_patch_sha256,'pytest_args':['-rA','/tmp/work/tests/test_requests.py'],
                'fixed_tls':{'owner':self.lease['owner'],'sha256':self.lease['author']['materials']},
                'environment_materials_sha256':self.environment_sha}
            (inputs/'config.json').write_text(json.dumps(config),encoding='utf-8')
            old_deadline,old_cleanup=self.lease['deadline'],self.lease['cleanup_deadline']
            self.lease['deadline']=min(old_deadline,started+spec.timeout_seconds-15)
            self.lease['cleanup_deadline']=min(old_cleanup,started+spec.timeout_seconds)
            try:
                observed=container.observe(case,self.task,self.lease)
            finally:
                # Restore only the original session horizon, never renew it.
                self.lease['deadline'],self.lease['cleanup_deadline']=old_deadline,old_cleanup
                path=Path(self.lease['file'])
                if not has_single_regular_file_link(path):raise ValueError('Lease journal changed')
                path.write_text(json.dumps(self.lease,indent=2),encoding='utf-8')
            if (observed.get('controller_error') or not observed.get('cleanup_complete')
                    or observed.get('candidate_input_sha256')!=payload):raise ValueError('Native container incomplete')
            guest=json.loads((case/'guest-result.json').read_text(encoding='utf-8'))
            identity=NativeAttemptIdentity(self.task.instance_id,self.task.row_sha256,constants.IMAGE,
                self.environment_sha,source_sha,rid,attempt.phase,attempt.repair_attempt)
            remaining=spec.timeout_seconds-(time.monotonic()-started)
            if remaining<=0:raise ValueError('Native deadline exhausted')
            result=observe_native_result(self.task,identity,expected_identity=identity,log=guest['native_log'],
                exit_code=guest.get('tests_exit_code'),completed=guest.get('phase')=='completed',
                cleanup_complete=observed['cleanup_complete'],directory=self.execution_root,
                runtime_root=self.runtime_root,timeout_seconds=min(30,remaining))
            if result.verification.status is VerificationCheckStatus.EXECUTION_ERROR:return result.verification
            if hashlib.sha256(self._source()).hexdigest()!=source_sha:raise ValueError('Final source changed')
            self.case_mapping=result.case_mapping;self.native_attempts.append(result.native)
            self.receipts.append({'receipt_id':rid,'source_hash':source_sha,'result_digest':
                hashlib.sha256(json.dumps(asdict(VerificationSummary.from_result(result.verification)),sort_keys=True,default=str).encode()).hexdigest()})
            return result.verification
        except (OSError,ValueError,TypeError,KeyError):return self._error(spec,'Native execution could not be verified')

    def bind_attempts(self,result,*,runtime_root):
        if (not self.lease.get('cleanup_complete') or self.lease.get('creation_unknown')
                or ownership.recover_fixed_tls(self.owner_root)['status']!='CLEANED'):
            raise ValueError('Global native cleanup incomplete')
        return bind_native_receipts(result,spec=self.task,runtime_root=runtime_root,
            configured_runtime_root=self.runtime_root,generation_root=self.generation_root,
            receipts=self.receipts,native_attempts=tuple(self.native_attempts),source_reader=self._source,
            receipt_prefix='native_receipt=',case_mapping=self.case_mapping,expected_image=constants.IMAGE,
            expected_environment_sha256=self.environment_sha)

    @staticmethod
    def _error(spec,message):
        return VerificationResult.create(name=spec.name,argv=spec.argv,cwd=spec.cwd,
            status=VerificationCheckStatus.EXECUTION_ERROR,exit_code=None,message=message)


class NativeAdmission:
    def __init__(self,runner):
        if type(runner) is not NativeRequestsRunner:raise ValueError('Concrete native Requests runner required')
        self.runner=runner

    def permits(self,spec,runner,workspace_root):
        return runner is self.runner and type(runner) is NativeRequestsRunner and runner.permits(spec,workspace_root)
