"""Audited b8d53321 metadata subset for the frozen twenty tasks; never execution.

No harness is imported. Paths are evaluator-only; do not give this object to
models. This does not prove image contents, patch applicability or isolation.
"""
from dataclasses import dataclass
import hashlib
import json
import re
from types import MappingProxyType

from agent.evaluation.benchmark_manifest import canonical_bytes

HARNESS_COMMIT = "b8d53321b98c1193f9df999ff11d57ac5f5f551d"
_PYTEST = ("pytest", "-rA")  # Final binding in the pinned constants/python.py.
_EDITABLE = ("python", "-m", "pip", "install", "-e", ".")
_ASTROPY = ("python", "-m", "pip", "install", "-e", ".[test]", "--verbose")
# repo/version -> Python, native command, parser, installation, extra state.
_PROFILES = MappingProxyType({
    ("scikit-learn/scikit-learn", "0.21"): ("3.6", _PYTEST, "pytest-v2", ("python", "-m", "pip", "install", "-v", "--no-use-pep517", "--no-build-isolation", "-e", "."), ("native-build-toolchain",)),
    ("pydata/xarray", "0.12"): ("3.10", _PYTEST, "pytest", _EDITABLE, ()),
    ("sphinx-doc/sphinx", "3.2"): ("3.9", ("tox", "--current-env", "-epy39", "-v", "--"), "pytest-v2", ("python", "-m", "pip", "install", "-e", ".[test]"), ("audited-tox-and-setup-preprocessing",)),
    ("sphinx-doc/sphinx", "3.4"): ("3.9", ("tox", "--current-env", "-epy39", "-v", "--"), "pytest-v2", ("python", "-m", "pip", "install", "-e", ".[test]"), ("audited-tox-and-setup-preprocessing",)),
    ("astropy/astropy", "1.3"): ("3.6", ("pytest", "-rA", "-vv", "-o", "console_output_style=classic", "--tb=no"), "pytest-v2", _ASTROPY, ("native-build-toolchain", "version-specific-plugins")),
    ("astropy/astropy", "5.2"): ("3.9", _PYTEST, "pytest-v2", _ASTROPY, ("native-build-toolchain", "audited-build-requirements-preprocessing")),
    ("matplotlib/matplotlib", "3.6"): ("3.11", _PYTEST, "matplotlib", _EDITABLE, ("native-build-toolchain", "offline-qhull-and-font-materials")),
    ("pallets/flask", "2.0"): ("3.9", _PYTEST, "pytest", _EDITABLE, ()),
    ("pallets/flask", "2.3"): ("3.11", _PYTEST, "pytest", _EDITABLE, ()),
    ("django/django", "3.2"): ("3.6", ("./tests/runtests.py", "--verbosity", "2", "--settings=test_sqlite", "--parallel", "1"), "django", _EDITABLE, ("upstream-eval-writes:/etc/locale.gen", "locale:en_US.UTF-8")),
    ("django/django", "4.1"): ("3.9", ("./tests/runtests.py", "--verbosity", "2", "--settings=test_sqlite", "--parallel", "1"), "django", _EDITABLE, ()),
    ("sympy/sympy", "1.1"): ("3.9", ("bin/test", "-C", "--verbose"), "sympy", _EDITABLE, ("mpmath:1.3.0",)),
    ("sympy/sympy", "1.6"): ("3.9", ("bin/test", "-C", "--verbose"), "sympy", _EDITABLE, ("mpmath:1.3.0",)),
    ("mwaskom/seaborn", "0.12"): ("3.9", ("pytest", "--no-header", "-rA"), "seaborn", ("python", "-m", "pip", "install", "-e", ".[dev]"), ()),
    ("pylint-dev/pylint", "2.15"): ("3.9", _PYTEST, "pytest-options", _EDITABLE, ("upstream-cpu-cap:2",)),
    ("psf/requests", "2.10"): ("3.9", _PYTEST, "pytest-options", ("python", "-m", "pip", "install", "."), ("verify-noneditable-import-origin",)),
    ("pytest-dev/pytest", "7.0"): ("3.9", _PYTEST, "pytest", _EDITABLE, ("verify-candidate-pytest-origin",)),
})


@dataclass(frozen=True, slots=True)
class NativeEnvironmentRequirements:
    python_version: str
    conda_environment: str
    install_argv: tuple[str, ...]
    writable_guest_locations: tuple[str, ...]
    extra_state: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NativeTaskSpec:
    instance_id: str
    repository: str
    version: str
    base_commit: str
    row_sha256: str
    harness_commit: str
    environment: NativeEnvironmentRequirements
    test_argv: tuple[str, ...]
    test_environment: tuple[tuple[str, str], ...]
    parser_id: str
    test_files: tuple[str, ...]
    directives: tuple[str, ...]
    test_patch_sha256: str
    fail_to_pass: tuple[str, ...]
    pass_to_pass: tuple[str, ...]


def _test_files(patch: str) -> tuple[str, ...]:
    """Validate ordinary modification section paths; no applicability claim."""
    if not patch or len(patch.encode()) > 2 * 1024 * 1024 or "\r" in patch or "\x00" in patch:
        raise ValueError("A bounded LF-only test patch is required.")
    files, current, headers, hunks = [], None, [], 0
    old_left = new_left = 0
    for line in patch.splitlines():
        if line.startswith("diff --git "):
            if current is not None and (headers != ["--- a/" + current, "+++ b/" + current] or not hunks or old_left or new_left):
                raise ValueError("Incomplete test patch section.")
            match = re.fullmatch(r"diff --git a/([A-Za-z0-9_./-]+) b/([A-Za-z0-9_./-]+)", line)
            if not match or match[1] != match[2]:
                raise ValueError("Unsupported test path or rename.")
            current = match[1]
            if (not current.endswith(".py") or current.startswith(("/", "-"))
                    or any(part.casefold() in ("", ".", "..", ".git", ".ssh", ".aws")
                           or part.casefold().startswith(".env") or part.endswith(".")
                           or re.fullmatch(r"(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part)
                           for part in current.split("/"))
                    or current.casefold() in {p.casefold() for p in files}):
                raise ValueError("Unsafe or duplicate test path.")
            files.append(current)
            headers, hunks = [], 0
        elif line.startswith(("--- ", "+++ ")) and not hunks:
            headers.append(line)
        elif line.startswith("@@ "):
            match = re.fullmatch(r"@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@.*", line)
            if current is None or not match or old_left or new_left:
                raise ValueError("Invalid hunk marker.")
            old_left, new_left = (int(value) if value is not None else 1 for value in match.groups())
            hunks += 1
        elif hunks:
            if line == "\\ No newline at end of file" or (not line and not old_left and not new_left):
                continue
            if not line or line[0] not in " +-":
                raise ValueError("Invalid hunk body.")
            old_left -= int(line[0] in " -")
            new_left -= int(line[0] in " +")
            if min(old_left, new_left) < 0:
                raise ValueError("Hunk exceeds its declared range.")
        elif not hunks and line and not line.startswith("index "):
            raise ValueError("Only ordinary test modifications are supported.")
    if not files or len(files) > 64 or headers != ["--- a/" + current, "+++ b/" + current] or not hunks or old_left or new_left:
        raise ValueError("Missing complete test patch section.")
    return tuple(files)


def _roster(encoded: str, *, nonempty: bool) -> tuple[str, ...]:
    values = json.loads(encoded)
    if (type(values) is not list or len(values) > 10000 or (nonempty and not values)
            or any(type(case) is not str or not case or case.strip() != case or len(case) > 4096
                   or any(ord(char) < 32 for char in case) for case in values)
            or len(values) != len(set(values))):
        raise ValueError("An exact nonduplicated roster is required.")
    return tuple(values)


def prepare_native_task(row: dict, *, expected_row_sha256: str,
                        harness_commit: str = HARNESS_COMMIT) -> NativeTaskSpec:
    """Build evaluator-only typed requirements for audited versions, without I/O.

    Caller owns the external row pin. Images, filesystem, installations, parser
    execution and repository code are not inspected or admitted by this seam.
    """
    if (type(row) is not dict or len(row) > 32
            or not all(type(k) is str and type(v) is str for k, v in row.items())
            or len(canonical_bytes(row)) > 2 * 1024 * 1024):
        raise ValueError("A bounded string-valued row is required.")
    digest = hashlib.sha256(canonical_bytes(row)).hexdigest()
    if harness_commit != HARNESS_COMMIT or digest != expected_row_sha256:
        raise ValueError("Harness or externally pinned row identity changed.")
    try:
        repo, version = row["repo"], row["version"]
        profile = _PROFILES[(repo, version)]
        if (not re.fullmatch(re.escape(repo.replace("/", "__")) + r"-[1-9][0-9]*", row["instance_id"])
                or not re.fullmatch(r"[0-9a-f]{40}", row["base_commit"])):
            raise ValueError("Invalid exact instance/base identity.")
        files = _test_files(row["test_patch"])
        directives = files
        if repo == "django/django":
            if any(not p.startswith("tests/") for p in files):
                raise ValueError("Django directives must be in the test tree.")
            directives = tuple(p[6:-3].replace("/", ".") for p in files)
            if any(not all(part.isidentifier() for part in p.split(".")) for p in directives):
                raise ValueError("Invalid Django module identity.")
        f2p = _roster(row["FAIL_TO_PASS"], nonempty=True)
        p2p = _roster(row["PASS_TO_PASS"], nonempty=False)
        if set(f2p) & set(p2p):
            raise ValueError("F2P and P2P must be disjoint.")
    except KeyError as error:
        raise ValueError("Missing field or unsupported repository/version.") from error
    python, command, parser, install, state = profile
    environment = (("PYTHONWARNINGS", "ignore::UserWarning,ignore::SyntaxWarning"),) if repo == "sympy/sympy" else ()
    if repo == "django/django" and version == "3.2":
        environment = (("LANG", "en_US.UTF-8"), ("LANGUAGE", "en_US:en"), ("LC_ALL", "en_US.UTF-8"))
    return NativeTaskSpec(row["instance_id"], repo, version, row["base_commit"], digest, harness_commit,
        NativeEnvironmentRequirements(python, "testbed", install,
            ("prepared-repository", "isolated-package-environment", "guest-tmp-and-home"), state),
        command + directives, environment, parser, files, directives,
        hashlib.sha256(row["test_patch"].encode()).hexdigest(), f2p, p2p)
