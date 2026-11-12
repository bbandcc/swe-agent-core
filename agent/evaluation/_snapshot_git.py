"""Git data operations with inherited command/configuration channels disabled.

This is configuration isolation, not an OS sandbox or a disk quota. It assumes
an installed, trusted Git and a source object database without concurrent writers.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


class UnsupportedGitEntry(Exception):
    """The source needs object borrowing or contains unsupported tree modes."""


def _run(
    repository: Path, arguments: list[str], *, template: Path | None = None,
) -> subprocess.CompletedProcess[bytes]:
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    environment.update(
        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_SYSTEM=os.devnull,
        GIT_CONFIG_GLOBAL=os.devnull, GIT_ATTR_NOSYSTEM="1",
        GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1",
        GIT_TERMINAL_PROMPT="0",
    )
    empty_hooks = str(template) if template else os.devnull
    command = [
        "git", "--no-pager", "-c", f"safe.directory={repository}",
        "-c", "core.fsmonitor=false", "-c", f"core.hooksPath={empty_hooks}",
        "-c", f"core.attributesFile={os.devnull}", "-c", "core.autocrlf=false",
        "-c", "core.eol=lf", "-c", "protocol.allow=never",
        "-c", "protocol.file.allow=always", "-c", "submodule.recurse=false",
        *arguments,
    ]
    return subprocess.run(
        command, cwd=repository, env=environment, stdin=subprocess.DEVNULL,
        capture_output=True, timeout=30.0, check=False, shell=False,
    )


def _check(result: subprocess.CompletedProcess[bytes]) -> bytes:
    if result.returncode:
        raise subprocess.SubprocessError("Pinned Git snapshot unavailable.")
    return result.stdout


def revision_available(repository: Path, revision: str) -> bool:
    try:
        return _run(repository, ["cat-file", "-e", f"{revision}^{{commit}}"]).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def checkout_snapshot(repository: Path, revision: str, root: Path) -> None:
    """Copy a local commit without hooks, filters, templates or replace refs."""
    common = _check(_run(repository, ["rev-parse", "--git-common-dir"]))
    common_directory = (repository / os.fsdecode(common.strip())).resolve(strict=True)
    # Local clone would preserve borrowed objects. Do not implicitly trust them.
    if (common_directory / "objects/info/alternates").exists():
        raise UnsupportedGitEntry("Borrowed objects are unsupported.")
    template = root.parent / "empty-git-template"
    template.mkdir()
    _check(_run(repository, [
        "clone", "--no-hardlinks", "--local", "--no-checkout",
        "--no-recurse-submodules", f"--template={template}", str(repository), str(root),
    ], template=template))
    # Inspect the clone before checkout; source local config is never copied.
    tree = _check(_run(root, ["ls-tree", "-rz", revision], template=template))
    for entry in tree.split(b"\0"):
        if entry and entry.split(b" ", 1)[0] not in {b"100644", b"100755"}:
            raise UnsupportedGitEntry("Only regular source files are supported.")
    _check(_run(root, ["checkout", "--quiet", "--no-recurse-submodules", "--detach", revision], template=template))
    actual = _check(_run(root, ["rev-parse", "HEAD"], template=template)).decode("ascii").strip()
    if actual != revision:
        raise subprocess.SubprocessError("Pinned Git identity mismatch.")
