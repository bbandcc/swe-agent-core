"""Bounded source-byte snapshots; never execution admission or a sandbox.

The policy is trusted input independent of evaluator patches. Source bytes are
captured once and those exact bytes are published; later source changes cannot
change the published tree. Concurrent malicious namespace writers are outside
this data-only seam's contract and require an execution isolation boundary.
"""

from dataclasses import dataclass
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import uuid

from agent.workspace import (
    WorkspaceAccessPolicy, WorkspacePathResolver,
    canonical_workspace_relative_path, has_single_regular_file_link,
)


@dataclass(frozen=True, slots=True)
class CandidatePolicy:
    editable_prefixes: tuple[str, ...] = (".",)
    protected_paths: tuple[str, ...] = ()
    max_entries: int = 4096
    max_total_bytes: int = 64 * 1024 * 1024
    max_changed_bytes: int = 256 * 1024
    # Visible source bytes that must remain identical; protected_paths stay hidden.
    immutable_paths: tuple[str, ...] = ()

    def __post_init__(self):
        for field in ("editable_prefixes", "protected_paths", "immutable_paths"):
            values = getattr(self, field)
            if type(values) is not tuple or (field == "editable_prefixes" and not values):
                raise ValueError("Path policy requires explicit tuples.")
            normalized = tuple(canonical_workspace_relative_path(path) for path in values)
            if None in normalized or len(set(normalized)) != len(normalized):
                raise ValueError("Unsafe or duplicate path policy.")
            object.__setattr__(self, field, normalized)
        for field in ("max_entries", "max_total_bytes", "max_changed_bytes"):
            value = getattr(self, field)
            if type(value) is not int or value <= 0:
                raise ValueError("Snapshot limits must be positive integers.")


@dataclass(frozen=True, slots=True)
class CandidateEntry:
    path: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class CandidateChange:
    path: str
    operation: str
    before_sha256: str | None
    after_sha256: str


@dataclass(frozen=True, slots=True)
class RepositoryCandidateSnapshot:
    root: Path
    tree_sha256: str
    entries: tuple[CandidateEntry, ...]
    changes: tuple[CandidateChange, ...]
    patch: bytes
    patch_sha256: str
    manifest_bytes: bytes


@dataclass(frozen=True, slots=True)
class CandidateSnapshotResult:
    ok: bool
    snapshot: RepositoryCandidateSnapshot | None = None
    error_code: str | None = None


class _Rejected(ValueError):
    pass


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _root(path: Path, *, existing: bool = True) -> Path:
    path = Path(path).absolute()
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise _Rejected("unsafe_root")
    if existing and not path.is_dir():
        raise _Rejected("missing_root")
    return path.resolve(strict=existing)


def _identity(info):
    # Windows path stat synthesizes execute bits from .bat/.cmd/.exe/.com;
    # fd stat cannot. These are not ACLs or executable-mode snapshot evidence.
    mode = info.st_mode & ~0o111 if os.name == "nt" and stat.S_ISREG(info.st_mode) else info.st_mode
    return (info.st_dev, info.st_ino, mode, info.st_nlink,
            info.st_size, info.st_mtime_ns)


def _capture(root: Path, policy: CandidatePolicy):
    files, directories, identities, count, total = {}, [], {}, 0, 0
    resolver = WorkspacePathResolver(root)
    access = WorkspaceAccessPolicy(hidden_paths=policy.protected_paths)
    pending = [root]
    while pending:
        parent = pending.pop()
        with os.scandir(parent) as iterator:
            for entry in iterator:
                count += 1
                if count > policy.max_entries:
                    raise _Rejected("entry_limit")
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                key = canonical_workspace_relative_path(relative, allow_root=False)
                if (key is None or key != os.path.normcase(relative).replace("\\", "/")
                        or any(ord(character) < 32 or ord(character) == 127 for character in relative)):
                    raise _Rejected("unsafe_path")
                if access.is_protected(relative):
                    raise _Rejected("protected_path")
                info = path.lstat()
                if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                    raise _Rejected("linked_entry")
                if stat.S_ISDIR(info.st_mode):
                    if not resolver.resolve_directory(relative, allow_absolute=False).ok:
                        raise _Rejected("unsafe_path")
                    directories.append(relative)
                    identities[key] = _identity(info)
                    pending.append(path)
                    continue
                if not has_single_regular_file_link(path) or not resolver.resolve_file(relative, allow_absolute=False).ok:
                    raise _Rejected("unsupported_file")
                total += info.st_size
                if total > policy.max_total_bytes:
                    raise _Rejected("byte_limit")
                with path.open("rb") as stream:
                    if _identity(os.fstat(stream.fileno())) != _identity(info):
                        raise _Rejected("source_changed")
                    data = stream.read(min(info.st_size + 1, policy.max_total_bytes + 1))
                    if _identity(os.fstat(stream.fileno())) != _identity(info):
                        raise _Rejected("source_changed")
                if len(data) != info.st_size or _identity(path.lstat()) != _identity(info):
                    raise _Rejected("source_changed")
                if key in files or key in identities:
                    raise _Rejected("path_alias")
                files[key] = (relative, data)
                identities[key] = _identity(info)
    return files, tuple(sorted(directories)), identities


def freeze_candidate(baseline: Path, generation: Path, policy: CandidatePolicy,
                     destination: Path) -> CandidateSnapshotResult:
    """Publish a complete captured source tree, with EDIT/CREATE deltas.

    DELETE, protected entries and changes outside the independently registered
    prefixes are refused. UTF-8 is required only for changed files. Empty/no-op
    candidates may be frozen but carry no changes and are not solved outcomes.
    Destination must not exist and must be outside both source trees. Captures
    are source bytes, not file ACL/executable-mode images or Git transactions.
    """
    staging = None
    try:
        if type(policy) is not CandidatePolicy:
            raise _Rejected("invalid_policy")
        base, candidate = _root(baseline), _root(generation)
        destination = _root(destination, existing=False)
        _root(destination.parent)
        roots = (base, candidate, destination)
        if any(a == b or a in b.parents or b in a.parents for i, a in enumerate(roots) for b in roots[i + 1:]):
            raise _Rejected("overlapping_roots")
        if destination.exists():
            raise _Rejected("destination_exists")
        before, before_dirs, before_ids = _capture(base, policy)
        after, directories, after_ids = _capture(candidate, policy)
        immutable = WorkspaceAccessPolicy(hidden_paths=policy.immutable_paths)
        if any(immutable.is_protected(name) for name in set(before_dirs) ^ set(directories)):
            raise _Rejected("immutable_path")
        if set(before) - set(after) or set(before_dirs) - set(directories):
            raise _Rejected("delete_unsupported")
        changes, patches, changed_bytes = [], [], 0
        for key, (name, data) in sorted(after.items()):
            previous = before.get(key)
            if immutable.is_protected(name) and previous != (name, data):
                raise _Rejected("immutable_path")
            if previous is not None and previous[1] == data:
                continue
            if not any(prefix == "." or key == prefix or key.startswith(prefix + "/") for prefix in policy.editable_prefixes):
                raise _Rejected("edit_scope")
            old = previous[1] if previous else b""
            if previous is None and not data:
                raise _Rejected("empty_create_unsupported")
            changed_bytes += len(old) + len(data)
            if changed_bytes > policy.max_changed_bytes:
                raise _Rejected("changed_byte_limit")
            old_text, text = old.decode("utf-8"), data.decode("utf-8")
            if "\x00" in old_text or "\x00" in text:
                raise _Rejected("changed_encoding")
            changes.append(CandidateChange(name, "EDIT" if previous else "CREATE", _hash(old) if previous else None, _hash(data)))
            for line in difflib.unified_diff(old_text.splitlines(keepends=True), text.splitlines(keepends=True),
                    fromfile="a/" + name if previous else "/dev/null", tofile="b/" + name):
                patches.append(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n")
        if (before, before_dirs, before_ids) != _capture(base, policy) or (after, directories, after_ids) != _capture(candidate, policy):
            raise _Rejected("source_changed")
        staging = destination.parent / (".candidate-" + uuid.uuid4().hex)
        staging.mkdir()
        for name in directories:
            (staging / name).mkdir(parents=True, exist_ok=True)
        for name, data in after.values():
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(data)
        if (before, before_dirs, before_ids) != _capture(base, policy) or (after, directories, after_ids) != _capture(candidate, policy):
            raise _Rejected("source_changed")
        entries = tuple(CandidateEntry(name, _hash(data), len(data)) for name, data in sorted(after.values()))
        manifest_bytes = json.dumps([(e.path, e.sha256, e.size) for e in entries] + [(name, "directory") for name in directories],
                                   separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        tree_hash = _hash(manifest_bytes)
        patch = "".join(patches).encode("utf-8")
        staging.rename(destination)
        staging = None
        return CandidateSnapshotResult(True, RepositoryCandidateSnapshot(destination, tree_hash, entries, tuple(changes), patch, _hash(patch), manifest_bytes))
    except _Rejected as error:
        return CandidateSnapshotResult(False, error_code=str(error))
    except UnicodeError:
        return CandidateSnapshotResult(False, error_code="changed_encoding")
    except (TypeError, ValueError):
        return CandidateSnapshotResult(False, error_code="invalid_input")
    except OSError:
        return CandidateSnapshotResult(False, error_code="io_error")
    finally:
        if staging is not None and staging.is_dir() and not staging.is_symlink() and staging.resolve().parent == destination.parent:
            try:
                shutil.rmtree(staging)
            except OSError:
                return CandidateSnapshotResult(False, error_code="cleanup_failed")
