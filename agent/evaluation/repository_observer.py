"""Prepare a fixed host observer for cooperative repository JSON cases."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from agent.workspace import WorkspaceAccessPolicy, WorkspacePathResolver, has_single_regular_file_link
from agent.evaluation import repository_container


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def capture_tree(root):
    root = Path(root).absolute()
    if not root.is_dir() or any(p.is_symlink() or p.is_junction() for p in (root, *root.parents)):
        raise ValueError('Unsafe tree root')
    resolver, files, directories, size = WorkspacePathResolver(root), {}, [], 0
    entries, pending = [], [root]
    while pending:
        with os.scandir(pending.pop()) as iterator:
            for item in iterator:
                if len(entries) >= 4096: raise ValueError('Too many input entries')
                path = Path(item.path)
                if path.is_symlink() or path.is_junction(): raise ValueError('Linked input entry')
                entries.append(path)
                if item.is_dir(follow_symlinks=False): pending.append(path)
    entries.sort()
    aliases = set()
    for path in entries:
        name = path.relative_to(root).as_posix()
        if WorkspaceAccessPolicy.default().is_protected(name): raise ValueError('Protected input path')
        if name.casefold() in aliases or path.is_symlink() or path.is_junction():
            raise ValueError('Aliased input entry')
        aliases.add(name.casefold())
        if path.is_dir():
            if not resolver.resolve_directory(name, allow_absolute=False).ok: raise ValueError('Unsafe directory')
            directories.append(name); continue
        if not resolver.resolve_file(name, allow_absolute=False).ok or not has_single_regular_file_link(path):
            raise ValueError('Unsafe input file')
        before = path.stat()
        size += before.st_size
        if size > 64 * 1024 * 1024: raise ValueError('Input tree too large')
        with path.open('rb') as stream: data = stream.read(before.st_size + 1)
        after = path.stat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_nlink)
        if identity(before) != identity(after) or len(data) != before.st_size:
            raise ValueError('Input changed while reading')
        files[name] = data
    manifest = [[name, digest(data), len(data)] for name, data in sorted(files.items())]
    return files, json.dumps(manifest + [(name, 'directory') for name in sorted(directories)],
                           separators=(',', ':'), ensure_ascii=False).encode()


def tree_fingerprint(root):
    return digest(capture_tree(root)[1])


@dataclass(frozen=True)
class RepositoryTaskSpec:
    task_id: str
    image: str
    argv: tuple[str, ...]
    case_ids: tuple[str, ...]
    baseline_sha256: str
    dependency_sha256: str
    oracle_sha256: str

    def __post_init__(self):
        if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,100}', self.task_id): raise ValueError('Invalid task ID')
        if not re.fullmatch(r'python@sha256:[a-f0-9]{64}', self.image): raise ValueError('Pinned Python image required')
        if (type(self.argv) is not tuple or not 1 <= len(self.argv) <= 32
                or any(type(a) is not str or not a or '\0' in a or len(a) > 4096 for a in self.argv)):
            raise ValueError('Finite trusted argv required')
        if (type(self.case_ids) is not tuple or not 1 <= len(self.case_ids) <= 256
                or len(set(self.case_ids)) != len(self.case_ids)
                or any(type(c) is not str or not re.fullmatch(r'[a-zA-Z0-9_.:/\[\]-]{1,200}', c) for c in self.case_ids)):
            raise ValueError('Exact case roster required')
        if any(not re.fullmatch(r'[a-f0-9]{64}', d) for d in
               (self.baseline_sha256, self.dependency_sha256, self.oracle_sha256)):
            raise ValueError('Trusted source/dependency/oracle pins required')


HOST = '''import json
from pathlib import Path
import pytest
from repository_container import execute,parse_cases
CONFIG=json.loads(Path(__file__).with_name('config.json').read_text(encoding='utf-8'))
@pytest.fixture(scope='session')
def observed():
    control=json.loads(Path(CONFIG['control_path']).read_text(encoding='utf-8'))
    record=execute(control['snapshot'],CONFIG['dependency_root'],Path(__file__).parent,
        CONFIG['image'],CONFIG['argv'],control['container_name'],control['timeout_seconds'])
    receipt={'receipt_id':control['attempt_id'],'source_hash':control['source_hash'],
        'task_digest':CONFIG['task_digest'],'image':CONFIG['image'],'execution':record,
        'cleanup_complete':record['cleanup']}
    Path(CONFIG['receipt_path']).write_text(json.dumps(receipt),encoding='utf-8')
    return parse_cases(record,tuple(CONFIG['case_ids']))
@pytest.mark.parametrize('index,case_id',list(enumerate(CONFIG['case_ids'])),ids=CONFIG['case_ids'])
def test_case(index,case_id,observed):
    if not observed[index]['passed']: pytest.fail('Repository assertion failed',pytrace=False)
'''
INI = b'[pytest]\naddopts =\npython_files = test_observer.py\n'


@dataclass(frozen=True)
class RepositoryObserverSetup:
    root: Path
    baseline_root: Path
    generation_root: Path
    dependency_root: Path
    observer_root: Path
    task: RepositoryTaskSpec
    task_digest: str
    frozen_digest: str


def prepare_repository_observer(output, baseline, generation, dependencies, oracle, task):
    if type(task) is not RepositoryTaskSpec: raise ValueError('Concrete reviewed task required')
    roots = [Path(p).resolve(strict=True) for p in (baseline, generation, dependencies, oracle)]
    output = Path(output).absolute()
    if output.exists() or not output.parent.is_dir() or any(p.is_symlink() or p.is_junction() for p in (output, *output.parents)):
        raise ValueError('Fresh ordinary output root required')
    if any(a == b or a in b.parents or b in a.parents for i, a in enumerate([output, *roots]) for b in [output, *roots][i+1:]):
        raise ValueError('Observer/source roots overlap')
    base, generation, deps, oracle = roots
    dependency_files, dep_manifest = capture_tree(deps)
    oracle_files, oracle_manifest = capture_tree(oracle)
    if (tree_fingerprint(base) != task.baseline_sha256 or digest(dep_manifest) != task.dependency_sha256
            or digest(oracle_manifest) != task.oracle_sha256): raise ValueError('Reviewed task inputs differ')
    task_digest = digest(encoded(task.__dict__))
    output.mkdir(); observer = output/'O'; observer.mkdir(); dep_copy = output/'D'; dep_copy.mkdir()
    for parent, files in ((dep_copy, dependency_files), (observer/'oracle', oracle_files)):
        parent.mkdir(exist_ok=True)
        manifest = dep_manifest if parent == dep_copy else oracle_manifest
        for item in json.loads(manifest):
            if len(item) == 2: (parent/item[0]).mkdir(parents=True, exist_ok=True)
        for name, data in files.items():
            target = parent/name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
    config = {'image':task.image,'argv':task.argv,'case_ids':task.case_ids,'task_digest':task_digest,
        'dependency_root':str(dep_copy),'control_path':str(output/'control.json'),'receipt_path':str(output/'receipt.json')}
    (observer/'test_observer.py').write_bytes(HOST.encode())
    (observer/'pytest.ini').write_bytes(INI)
    (observer/'repository_container.py').write_bytes(Path(repository_container.__file__).read_bytes())
    (observer/'config.json').write_bytes(encoded(config))
    return RepositoryObserverSetup(output,base,generation,dep_copy,observer,task,task_digest,tree_fingerprint(observer))


def validate_setup(setup):
    o = setup.observer_root
    config = {'image':setup.task.image,'argv':list(setup.task.argv),'case_ids':list(setup.task.case_ids),
        'task_digest':setup.task_digest,'dependency_root':str(setup.dependency_root),
        'control_path':str(setup.root/'control.json'),'receipt_path':str(setup.root/'receipt.json')}
    return (type(setup) is RepositoryObserverSetup and type(setup.task) is RepositoryTaskSpec
        and digest(encoded(setup.task.__dict__)) == setup.task_digest
        and tree_fingerprint(setup.baseline_root) == setup.task.baseline_sha256
        and tree_fingerprint(setup.dependency_root) == setup.task.dependency_sha256
        and tree_fingerprint(o/'oracle') == setup.task.oracle_sha256
        and json.loads((o/'config.json').read_text(encoding='utf-8')) == config
        and tree_fingerprint(o) == setup.frozen_digest
        and (o/'test_observer.py').read_bytes() == HOST.encode()
        and (o/'pytest.ini').read_bytes() == INI
        and (o/'repository_container.py').read_bytes() == Path(repository_container.__file__).read_bytes())
