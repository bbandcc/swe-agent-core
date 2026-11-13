"""Fixed-instance cooperative research observer, never a hostile-code oracle.

Only the container imports SymPy/mpmath. Fully valid forged JSON can still fool
the observer; this adapter is unsuitable for adversarial or official scores.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import shutil
import stat

from agent.evaluation.swebench_instance import SwebenchInstance, admit_swebench_instance
from agent.evaluation._swebench_observer_templates import HOST_SOURCE, ROSTER_SOURCE

SOURCE = 'sympy/core/_print_helpers.py'
TEST = 'sympy/core/tests/test_basic.py'
IMAGE = 'python@sha256:2d97f6910b16bd338d3060f261f53f144965f755599aab1acda1e13cf1731b1b'
ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / 'research/swebench-20261112/run_fixed_controls.py'
RUNTIME_PIN = '1b7aae29c3f7f6290780d35419fc383674521e784d2f0155a1c95a2319948b8c'
PINS = {
    'sympy-base.tar.gz': '932ba79e0521f1076e0e14ff134ea1a93d970b3a839b867f11039b4f0a6babda',
    'mpmath-1.3.0-py3-none-any.whl': 'a0b2b9fe80bbcd81a6647ff13108738cfb482d481d826cc0e02f5b35e5c88d2c',
    'sympy__sympy-20590.row.json': 'feb99cda40e77a4391d300261f7a511072080217fef21c94afdd58c0000e9382',
}
OFFICIAL_TREES = ('71accc160fd7b88932a87395fd87c926e79240559dca12bd6abe21def7515b6c',
                  '23a0b9e8717423f6c4fe16e812376c934124708948a2009041081b8f9cc3c722',
                  '3a83348a4fcd5318a2038c8bfbb1c6c64cfbceda4b2d5ae2f9a82586b9822f5a')


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def _load(path: Path) -> dict:
    return json.loads(_read(path, 65536), object_pairs_hook=_unique)


def _read(path: Path, limit: int) -> bytes:
    path = _path(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        raise ValueError('Input is not a bounded single regular file')
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Input grew beyond its bound')
    return data


def _path(path: Path) -> Path:
    path = Path(path).absolute()
    for part in (path, *path.parents):
        if part.is_symlink() or part.is_junction():
            raise ValueError('Linked workspace roots are rejected')
    return path.resolve()


def _tree(root: Path) -> dict[str, str]:
    root = _path(root)
    if not root.is_dir():
        raise ValueError('Workspace directory is missing')
    result, total = {}, 0
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(base) / name
            info = path.lstat()
            if path.is_symlink() or path.is_junction() or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise ValueError('Unsupported workspace entry')
            if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                raise ValueError('Hardlinked files are rejected')
            total += info.st_size if stat.S_ISREG(info.st_mode) else 0
            if len(result) >= 4096 or total > 64 * 1024 * 1024:
                raise ValueError('Workspace inventory exceeds bound')
            result[path.relative_to(root).as_posix()] = _hash(path.read_bytes()) if path.is_file() else 'directory'
    return result


def _tree_hash(root: Path) -> str:
    return _hash(json.dumps(_tree(root), sort_keys=True, separators=(',', ':')).encode())


def _instance() -> SwebenchInstance:
    row = _load(ROOT / 'evals/swebench/sympy__sympy-20590.json')['row']
    result = admit_swebench_instance(row, expected_sha256=PINS['sympy__sympy-20590.row.json'],
                                    editable_paths=(SOURCE,), oracle_paths=(TEST,))
    if not result.valid or result.instance is None:
        raise ValueError('Fixed instance metadata is invalid')
    return result.instance


def parse_cooperative_execution(record: dict, case_ids: tuple[str, ...]) -> dict:
    """Reject transport/setup errors; only valid assertion failures become FAIL."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    if (not isinstance(record, dict) or len(case_ids) != 22 or len(set(case_ids)) != 22
            or record.get('status') != 'completed' or record.get('cleanup') is not True
            or type(record.get('exit_code')) is not int or record['exit_code'] not in (0, 1)
            or not isinstance(record.get('stdout'), str) or len(record['stdout'].encode()) > 65536):
        raise ValueError('Container execution did not complete cleanly')
    try:
        value = json.loads(record['stdout'], object_pairs_hook=unique)
        if (set(value) != {'python', 'cases'} or value['python'] != '3.9.25'
                or not isinstance(value['cases'], list) or len(value['cases']) != len(case_ids)):
            raise ValueError('Unexpected result schema')
        if [case['id'] for case in value['cases']] != list(case_ids) or len(set(case_ids)) != len(case_ids):
            raise ValueError('Missing, duplicate or unknown case ID')
        for case in value['cases']:
            expected = {'id', 'passed'} if case['passed'] is True else {'id', 'passed', 'error', 'traceback'}
            if (set(case) != expected or type(case['passed']) is not bool
                    or (not case['passed'] and (case['error'] != 'AssertionError'
                        or not isinstance(case['traceback'], str) or not case['traceback']))):
                raise ValueError('Test infrastructure error or malformed case')
        if record['exit_code'] != int(not all(case['passed'] for case in value['cases'])):
            raise ValueError('Case results disagree with process exit')
        return value
    except (TypeError, KeyError, AttributeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('Invalid container result') from error



def _runtime_source() -> bytes:
    source = RUNTIME.read_bytes()
    if _hash(source) != RUNTIME_PIN:
        raise ValueError('Sealed research runtime identity changed')
    text = source.decode()
    replacements = {
        'def execute(repo: Path, deps: Path, trusted: Path, argv: list[str]) -> dict:':
        'def execute(repo: Path, deps: Path, trusted: Path, argv: list[str], *, container_name: str) -> dict:',
        "    name = 'swe-sympy-control-' + uuid.uuid4().hex":
        "    name = container_name\n    if not re.fullmatch(r'swe-cooperative-[a-f0-9]{32}', name):\n        raise ValueError('Invalid parent container lease')",
    }
    for old, new in replacements.items():
        if text.count(old) != 1:
            raise ValueError('Runtime template no longer has one replacement site')
        text = text.replace(old, new)
    return text.encode()


def observer_files_for(root: Path, instance: SwebenchInstance, source_test_bytes: bytes) -> dict[str, bytes]:
    """Authoritative fixed O templates, independent of caller-supplied hashes."""
    root = _path(root)
    ids = instance.fail_to_pass + instance.pass_to_pass
    if instance != _instance() or len(source_test_bytes) > 65536:
        raise ValueError('Unsupported instance or oracle size')
    config = {key: str(value) for key, value in {'root': root, 'dependency_root': root / 'D',
        'control_path': root / 'control.json', 'receipt_path': root / 'receipt.json'}.items()}
    config['case_ids'] = list(ids)
    return {'control_runtime.py': _runtime_source(), 'test_basic.py': source_test_bytes,
        'run_roster.py': ROSTER_SOURCE.replace('CASE_IDS', repr(ids)).encode(),
        'test_observer.py': HOST_SOURCE.replace('IDS_LITERAL', repr(ids)).encode(),
        'observer_contract.py': ('import json\n' + inspect.getsource(parse_cooperative_execution)).encode(),
        'config.json': _json(config), 'pytest.ini': b'[pytest]\npython_files = test_observer.py\naddopts = --assert=plain\n'}


@dataclass(frozen=True)
class CooperativeSetup:
    root: Path
    generation_root: Path
    observer_root: Path
    baseline_root: Path
    dependency_root: Path
    receipt_path: Path
    control_path: Path
    instance: SwebenchInstance
    manifest: dict
    image: str = IMAGE


def _setup(root: Path, manifest: dict) -> CooperativeSetup:
    return CooperativeSetup(root, root / 'G', root / 'O', root / 'B', root / 'D',
                            root / 'receipt.json', root / 'control.json', _instance(), manifest)


def _manifest(root: Path, instance: SwebenchInstance, tests: bytes, verified: bool) -> dict:
    return {'schema': 1, 'root': str(root), 'instance_id': instance.instance_id,
        'row_sha256': instance.row_sha256, 'source_verified': verified, 'source_path': SOURCE,
        'image': IMAGE, 'runtime_sha256': RUNTIME_PIN, 'source_pins': dict(PINS),
        'case_ids': list(instance.fail_to_pass + instance.pass_to_pass),
        'baseline_hash': _tree_hash(root / 'B'), 'dependency_hash': _tree_hash(root / 'D'),
        'test_hash': _hash(tests), 'source_hash': _hash((root / 'B' / SOURCE).read_bytes())}


def _finish(root: Path, instance: SwebenchInstance, tests: bytes, verified: bool) -> CooperativeSetup:
    (root / 'B' / TEST).unlink(missing_ok=True)
    shutil.copytree(root / 'B', root / 'G')
    (root / 'O').mkdir()
    for name, data in observer_files_for(root, instance, tests).items():
        (root / 'O' / name).write_bytes(data)
    manifest = _manifest(root, instance, tests, verified)
    (root / 'workspace.json').write_bytes(_json(manifest))
    setup = _setup(root, manifest)
    candidate_source(setup)
    return setup


def prepare_cooperative_workspace(output_root: Path, artifacts_root: Path) -> CooperativeSetup:
    """Only this path proves official archive/wheel identity; no foreign execution."""
    artifacts = _path(artifacts_root)
    for name, expected in PINS.items():
        path = artifacts / name
        if (path.is_symlink() or path.is_junction() or path.stat().st_size > 8 * 1024 * 1024
                or _hash(path.read_bytes()) != expected):
            raise ValueError('Fixed input identity changed')
    _runtime_source()
    root = _path(output_root)
    root.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('_sealed_cooperative_builder', RUNTIME)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.CACHE = artifacts
    module.materialize(root / 'B', root / 'D')
    row = _load(artifacts / 'sympy__sympy-20590.row.json')
    module.apply_fixed_patch(root / 'B', row['test_patch'], TEST)
    return _finish(root, _instance(), (root / 'B' / TEST).read_bytes(), True)


def assemble_cooperative_workspace(output_root: Path, *, instance: SwebenchInstance,
        source_files: dict[str, bytes], dependency_files: dict[str, bytes], source_test_bytes: bytes) -> CooperativeSetup:
    """CI author-data helper: always source_verified=False; never a paid admission."""
    root = _path(output_root)
    root.mkdir(parents=True, exist_ok=False)
    for directory, files in ((root / 'B', source_files), (root / 'D', dependency_files)):
        directory.mkdir()
        for relative, data in files.items():
            path = directory / relative
            if not path.resolve().is_relative_to(directory) or path.is_absolute() and Path(relative).is_absolute():
                raise ValueError('Author fixture escaped its root')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    return _finish(root, instance, source_test_bytes, False)


def load_cooperative_workspace(output_root: Path) -> CooperativeSetup:
    root = _path(output_root)
    setup = _setup(root, _load(root / 'workspace.json'))
    candidate_source(setup)
    return setup


def validate_frozen_inputs(setup: CooperativeSetup) -> None:
    root = _path(setup.root)
    expected = _setup(root, _load(root / 'workspace.json'))
    if setup != expected or setup.instance != _instance():
        raise ValueError('Workspace identity or separated roots changed')
    manifest = setup.manifest
    tests = _read(setup.observer_root / 'test_basic.py', 65536)
    if (type(manifest.get('source_verified')) is not bool
            or manifest != _manifest(root, setup.instance, tests, manifest['source_verified'])):
        raise ValueError('Manifest identity changed')
    actual = (_tree_hash(setup.baseline_root), _tree_hash(setup.dependency_root),
              _hash((setup.observer_root / 'test_basic.py').read_bytes()))
    if actual != tuple(manifest[key] for key in ('baseline_hash', 'dependency_hash', 'test_hash')):
        raise ValueError('Frozen inputs changed')
    if manifest['source_verified'] and actual != OFFICIAL_TREES:
        raise ValueError('Official input trees differ from implementation pins')
    files = observer_files_for(root, setup.instance, tests)
    if _tree(setup.observer_root) != {name: _hash(data) for name, data in files.items()}:
        raise ValueError('Observer differs from fixed implementation templates')


def candidate_source(setup: CooperativeSetup) -> bytes:
    validate_frozen_inputs(setup)
    try:
        path = _path(setup.generation_root / SOURCE)
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 32768:
            raise ValueError('Candidate source must be a bounded single regular file')
    except OSError as error:
        raise ValueError('Candidate source is missing or unreadable') from error
    baseline, generation = _tree(setup.baseline_root), _tree(setup.generation_root)
    baseline.pop(SOURCE, None)
    generation.pop(SOURCE, None)
    if generation != baseline or TEST in generation:
        raise ValueError('Candidate changed a protected path')
    source = _read(path, 32768)
    if len(source) > 32768:
        raise ValueError('Candidate source exceeds 32KiB')
    try:
        source.decode('utf-8')
    except UnicodeError as error:
        raise ValueError('Candidate source is not UTF-8') from error
    return source
