"""Pinned SWE-bench metadata and strict case grading, without repository execution.

Admission validates a deliberately narrow textual patch grammar and path scope.
It does not prove Git object existence, hunk applicability, or execution safety.
The trusted row digest and allowed paths must come from outside the row.
Gold-derived paths are suitable for fixed controls only: exposing them during
model evaluation gives solution-location hints and cannot support an unhinted
official benchmark claim. A model receives only the problem and a separately
preregistered scope, never this module's source row, hints or evaluator patches.
"""

import hashlib
import json
import re
from dataclasses import dataclass

from agent.evaluation.swebench_grading import StrictGrade as StrictGrade
from agent.evaluation.swebench_grading import grade_swebench_instance as grade_swebench_instance
from agent.workspace.paths import canonical_workspace_relative_path


@dataclass(frozen=True, slots=True)
class AdmissionIssue:
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class SwebenchInstance:
    """Minimal metadata; intentionally excludes hints and patch/test bodies."""

    instance_id: str
    repository: str
    base_commit: str
    row_sha256: str
    problem_statement: str
    gold_patch_sha256: str
    test_patch_sha256: str
    editable_scope: tuple[tuple[str, str], ...]
    oracle_paths: tuple[str, ...]
    fail_to_pass: tuple[str, ...]
    pass_to_pass: tuple[str, ...]

    def workspace_task(self) -> dict[str, object]:
        """Return only the existing TaskWorkspace mapping, without execution approval."""
        return {
            "task_id": self.instance_id,
            "target": {"revision": self.base_commit},
            "allowed_edit_scope": [
                {"path": path, "operation": operation}
                for path, operation in self.editable_scope
            ],
            "oracle": {"test_files": [{"path": path} for path in self.oracle_paths]},
        }


@dataclass(frozen=True, slots=True)
class InstanceAdmission:
    valid: bool
    instance: SwebenchInstance | None = None
    issues: tuple[AdmissionIssue, ...] = ()
    execution_admitted: bool = False


def admit_swebench_instance(
    row: object,
    *,
    expected_sha256: str,
    editable_paths: tuple[str, ...],
    oracle_paths: tuple[str, ...],
) -> InstanceAdmission:
    """Admit a decoded mapping, never Git objects or execution.

    Digest encoding is UTF-8 JSON with sorted keys, ensure_ascii=False, indent=2
    and one final LF. A byte-oriented JSON loader must reject duplicate keys
    before passing a mapping here; this function cannot recover discarded keys.
    """
    stage = "row_schema"
    try:
        if (not isinstance(row, dict) or len(row) > 32
                or not all(isinstance(key, str) and isinstance(value, str) for key, value in row.items())
                or sum(len(key) + len(value) for key, value in row.items()) > 2 * 1024 * 1024):
            raise ValueError("A bounded string-valued official row mapping is required.")
        encoded = (
            json.dumps(row, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False)
            + "\n"
        ).encode("utf-8")
        if len(encoded) > 2 * 1024 * 1024:
            raise ValueError("The canonical row exceeds the metadata byte limit.")
        digest = hashlib.sha256(encoded).hexdigest()
        stage = "row_identity"
        if (not isinstance(expected_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
                or digest != expected_sha256):
            raise ValueError("Row digest differs from the trusted canonical JSON pin.")
        stage = "row_schema"
        repository = row["repo"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("Repository must have exact owner/name form.")
        if (not re.fullmatch(re.escape(repository.replace("/", "__")) + r"-[1-9][0-9]*", row["instance_id"])
                or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", row["instance_id"])):
            raise ValueError("Instance identity must match its repository and issue number.")
        if not re.fullmatch(r"[0-9a-f]{40}", row["base_commit"]):
            raise ValueError("Base commit must be an exact SHA-1 identity, not a ref.")
        if not row["problem_statement"].strip() or "\x00" in row["problem_statement"]:
            raise ValueError("A nonempty problem statement is required.")
        f2p = _case_ids(row["FAIL_TO_PASS"], require_nonempty=True)
        p2p = _case_ids(row["PASS_TO_PASS"], require_nonempty=False)
        if set(f2p) & set(p2p):
            raise ValueError("F2P and P2P identities must not overlap.")
        stage = "patch_scope"
        editable = _paths(editable_paths)
        oracle = _paths(oracle_paths)
        if any(_overlap(first, second) for first in editable for second in oracle):
            raise ValueError("Gold and oracle scopes overlap.")
        gold_scope = _patch_scope(row["patch"])
        test_scope = _patch_scope(row["test_patch"])
        if ({path for path, _ in gold_scope} != set(editable)
                or {path for path, _ in test_scope} != set(oracle)):
            raise ValueError("Patch paths differ from the trusted scope.")
    except (TypeError, ValueError, KeyError, UnicodeError, RecursionError) as error:
        return InstanceAdmission(False, issues=(AdmissionIssue(stage, str(error)),))
    return InstanceAdmission(True, SwebenchInstance(
        row["instance_id"], row["repo"], row["base_commit"], digest,
        row["problem_statement"], hashlib.sha256(row["patch"].encode()).hexdigest(),
        hashlib.sha256(row["test_patch"].encode()).hexdigest(),
        gold_scope, oracle,
        f2p, p2p,
    ))


def _case_ids(encoded: str, *, require_nonempty: bool) -> tuple[str, ...]:
    values = json.loads(encoded)
    if not isinstance(values, list) or len(values) > 10_000 or (require_nonempty and not values):
        raise ValueError("Case identities must be a bounded JSON list; F2P cannot be empty.")
    if any(not isinstance(value, str) or not value or len(value) > 4096
           or value.strip() != value or any(ord(char) < 32 for char in value)
           for value in values) or len(set(values)) != len(values):
        raise ValueError("Case identities must be nonempty unique exact strings.")
    return tuple(values)


def _paths(values: object) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or not values or len(values) > 64:
        raise ValueError("The trusted file scope must be a nonempty list or tuple.")
    result: list[str] = []
    for path in values:
        if (not isinstance(path, str) or len(path) > 1024
                or canonical_workspace_relative_path(path, allow_root=False) != path):
            raise ValueError("Paths must already use canonical workspace-relative spelling.")
        parts = path.split("/")
        if any(not re.fullmatch(r"[A-Za-z0-9_.-]+", part) or part.endswith(".")
               or part.casefold() == ".git" or part.casefold().startswith(".env")
               or re.fullmatch(r"(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part)
               for part in parts):
            raise ValueError("Unsupported portable file path.")
        if any(_overlap(path, previous) for previous in result):
            raise ValueError("Duplicate or ancestor-overlapping paths are unsupported.")
        result.append(path)
    return tuple(result)


def _overlap(first: str, second: str) -> bool:
    # Conservative across platforms, including case-insensitive Windows consumers.
    first, second = first.casefold(), second.casefold()
    return first == second or first.startswith(second + "/") or second.startswith(first + "/")


def _patch_scope(patch: object) -> tuple[tuple[str, str], ...]:
    """Parse only ordinary unquoted unified create/modify patches, not general Git."""
    if (not isinstance(patch, str) or not patch or not patch.endswith("\n")
            or "\x00" in patch or "\r" in patch):
        raise ValueError("A nonempty LF textual patch is required.")
    lines = patch.split("\n")[:-1]
    position = 0
    result: list[tuple[str, str]] = []
    while position < len(lines):
        header = re.fullmatch(r"diff --git a/(\S+) b/(\S+)", lines[position])
        if not header or header[1] != header[2]:
            raise ValueError("Only same-path unquoted create/modify patches are supported.")
        path = _paths((header[1],))[0]
        position += 1
        create = position < len(lines) and lines[position] == "new file mode 100644"
        if create:
            position += 1
        if position < len(lines) and re.fullmatch(r"index [0-9a-f]+\.\.[0-9a-f]+(?: 100644)?", lines[position]):
            position += 1
        before = "--- /dev/null" if create else f"--- a/{path}"
        if lines[position:position + 2] != [before, f"+++ b/{path}"]:
            raise ValueError("Unsupported patch metadata or mismatched file headers.")
        position += 2
        hunks = 0
        changed = False
        previous_old_end = previous_new_end = -1
        while position < len(lines) and not lines[position].startswith("diff --git "):
            hunk = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?", lines[position])
            if not hunk:
                raise ValueError("A well-formed unified hunk is required.")
            old_start, new_start = int(hunk[1]), int(hunk[3])
            old, new = int(hunk[2] or 1), int(hunk[4] or 1)
            if ((old_start == 0 and old) or (new_start == 0 and new)
                    or old_start < previous_old_end or new_start < previous_new_end
                    or (old == 0 and new == 0)):
                raise ValueError("Hunk ranges must be nonempty, ordered, and consistent.")
            previous_old_end, previous_new_end = old_start + old, new_start + new
            if create and (old_start != 0 or old != 0 or new_start != 1 or hunks):
                raise ValueError("A create patch must start from an empty file.")
            position += 1
            hunks += 1
            while old or new:
                if position >= len(lines) or not lines[position] or lines[position][0] not in " +-":
                    raise ValueError("Truncated or malformed hunk body.")
                marker = lines[position][0]
                old -= marker != "+"
                new -= marker != "-"
                changed |= marker in "+-"
                if old < 0 or new < 0:
                    raise ValueError("Hunk line counts do not match its body.")
                position += 1
                if position < len(lines) and lines[position] == "\\ No newline at end of file":
                    position += 1
        if not hunks or not changed:
            raise ValueError("Patch files must contain a nonempty change.")
        result.append((path, "create" if create else "modify"))
    _paths(tuple(path for path, _ in result))
    return tuple(result)
