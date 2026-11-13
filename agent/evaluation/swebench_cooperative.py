"""Concrete cooperative SymPy adapter; never general production attestation.

Host pytest is author controlled. Repository imports happen only in Docker.
Candidate-reported behavior remains cooperative evidence, not anti-forgery proof.
"""

from dataclasses import asdict, replace
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid

from agent.evaluation.attempt_receipts import bind_attempt_receipts
from agent.verification.contracts import VerificationCheckStatus, VerificationResult, VerificationSpec, VerificationSummary
from agent.verification.runner import VerificationRunner
from agent.workspace import WorkspacePathResolver, has_single_regular_file_link


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def _linked(path: Path) -> bool:
    return path.is_symlink() or bool(hasattr(path, "is_junction") and path.is_junction())


def cooperative_verification_spec(observer_root, *, timeout_seconds=150.0) -> VerificationSpec:
    if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds) or not 30 <= timeout_seconds <= 180):
        raise ValueError("Cooperative checks require a finite 30..180 second deadline.")
    root = Path(observer_root).resolve(strict=True)
    return VerificationSpec("sympy-cooperative", (
        sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--assert=plain",
        "--noconftest", f"--confcutdir={root}", "-c", str(root / "pytest.ini"),
        f"--rootdir={root}", str(root / "test_observer.py"), "--junitxml=report.xml",
    ), timeout_seconds=timeout_seconds, report_path="report.xml")


def cleanup_cooperative_lease(root: Path, *, timeout_seconds=12.0) -> bool:
    """Parent backstop owns one named container and one sibling snapshot only."""
    try:
        if _linked(root) or not root.is_dir():
            return False
        root = root.resolve(strict=True)
        lease_path = root / "lease.json"
        if not lease_path.exists():
            return not lease_path.is_symlink()
        if (not has_single_regular_file_link(lease_path) or lease_path.stat().st_size > 4096):
            return False
        lease = json.loads(lease_path.read_text(encoding="utf-8"))
        if not isinstance(lease, dict) or set(lease) != {"container_name", "snapshot"}:
            return False
        name = lease["container_name"]
        if not isinstance(name, str) or not re.fullmatch(r"swe-cooperative-[a-f0-9]{32}", name):
            return False
        snapshot = Path(lease["snapshot"])
        parent = root / "snapshots"
        if (_linked(parent) or _linked(snapshot) or snapshot != parent / name.removeprefix("swe-cooperative-")
                or snapshot.parent.resolve(strict=True) != parent.resolve(strict=True)):
            return False
        deadline = time.monotonic() + max(0.1, min(12.0, timeout_seconds))
        def command(arguments):
            return subprocess.run(["docker", *arguments], stdin=subprocess.DEVNULL,
                capture_output=True, timeout=max(0.05, min(5.0, deadline - time.monotonic())),
                shell=False, check=False)
        command(["rm", "--force", name])
        absent = command(["container", "ls", "--all", "--filter", f"name=^/{name}$", "--format", "{{.ID}}"])
        if absent.returncode or absent.stdout.strip():
            return False
        if snapshot.exists():
            shutil.rmtree(snapshot)
        lease_path.unlink()
        return True
    except (OSError, subprocess.SubprocessError, TypeError, ValueError, KeyError):
        return False


class CooperativeRunner:
    """Specific host observer plus Docker repo checks under the opted-in profile."""

    def __init__(self, setup, *, runtime_root):
        from agent.evaluation.swebench_observer import IMAGE, validate_frozen_inputs
        validate_frozen_inputs(setup)
        self.setup = setup
        self.generation_root = setup.generation_root.resolve(strict=True)
        self.execution_root = setup.observer_root.resolve(strict=True)
        self.runtime_root = Path(runtime_root).resolve()
        self.receipt_path, self.control_path = setup.receipt_path, setup.control_path
        self.lease_path = setup.root / "lease.json"
        self.image = IMAGE
        self.spec = cooperative_verification_spec(self.execution_root)
        self._fixed_spec = self.spec
        if any(self.runtime_root == r or self.runtime_root in r.parents or r in self.runtime_root.parents
               for r in (self.generation_root, self.execution_root, setup.baseline_root, setup.dependency_root)):
            raise ValueError("Research runtime must be separate from executable inputs.")
        if (os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") != "1"
                or os.environ.get("PYTHONDONTWRITEBYTECODE") != "1"
                or any(os.environ.get(k) for k in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONPATH", "PYTHONHOME"))):
            raise ValueError("The fixed, plugin-free observer environment is required.")
        self._environment = _digest(sorted(os.environ.items()))
        self._manifest = _digest(setup.manifest)
        self._runner = VerificationRunner(self.execution_root, runtime_root=self.runtime_root)
        self._fixed_runner, self._fixed_run = self._runner, self.run
        self._boundary = (self.generation_root, self.execution_root, self.runtime_root,
                          self.receipt_path, self.control_path, self.lease_path, self.image)
        self.receipts = []

    def _source(self) -> bytes:
        from agent.evaluation.swebench_observer import candidate_source
        return candidate_source(self.setup)

    def permits(self, spec, workspace_root) -> bool:
        from agent.evaluation.swebench_observer import validate_frozen_inputs
        try:
            if (not isinstance(spec, VerificationSpec)
                    or Path(workspace_root).resolve(strict=True) != self.generation_root
                    or (self.generation_root, self.execution_root, self.runtime_root,
                        self.receipt_path, self.control_path, self.lease_path, self.image) != self._boundary
                    or type(self._runner) is not VerificationRunner or self._runner is not self._fixed_runner
                    or self.run != self._fixed_run or self._runner.execution_root != self.execution_root
                    or _digest(sorted(os.environ.items())) != self._environment
                    or _digest(self.setup.manifest) != self._manifest
                    or self.spec != self._fixed_spec
                    or not 0 < spec.timeout_seconds <= self._fixed_spec.timeout_seconds
                    or replace(spec, timeout_seconds=self._fixed_spec.timeout_seconds) != self._fixed_spec):
                return False
            validate_frozen_inputs(self.setup)
            self._source()
            return True
        except (OSError, ValueError, TypeError):
            return False

    def cleanup(self) -> bool:
        return cleanup_cooperative_lease(self.setup.root)

    def _write(self, name: str, value) -> None:
        resolver = WorkspacePathResolver(self.setup.root)
        path = resolver.resolve_file(name, must_exist=False)
        if not path.ok or (_linked(path.path) or (path.path.exists() and not has_single_regular_file_link(path.path))):
            raise ValueError("Research control path is unsafe.")
        temporary = self.setup.root / ("control-" + uuid.uuid4().hex + ".tmp")
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(value, stream)
        temporary.replace(path.path)

    def run(self, spec: VerificationSpec) -> VerificationResult:
        from agent.evaluation.swebench_observer import SOURCE
        if not isinstance(spec, VerificationSpec):
            return self._error(self.spec, "A structured verification spec is required.")
        if not self.permits(spec, self.generation_root):
            return self._error(spec, "Research inputs changed before dispatch.")
        started = time.monotonic()
        attempt_id = uuid.uuid4().hex
        snapshots = self.setup.root / "snapshots"
        snapshot = snapshots / attempt_id
        try:
            source = self._source()
            source_hash = hashlib.sha256(source).hexdigest()
            if not self.cleanup():
                raise ValueError("An earlier research lease is unresolved.")
            if _linked(snapshots):
                raise ValueError("Snapshot directory is unsafe.")
            snapshots.mkdir(exist_ok=True)
            if self.receipt_path.is_symlink() or (self.receipt_path.exists() and not has_single_regular_file_link(self.receipt_path)):
                raise ValueError("Receipt path is unsafe.")
            self.receipt_path.unlink(missing_ok=True)
            name = "swe-cooperative-" + attempt_id
            self._write("lease.json", {"container_name": name, "snapshot": str(snapshot)})
            shutil.copytree(self.setup.baseline_root, snapshot)
            snapshot.joinpath(*SOURCE.split("/")).write_bytes(source)
            self._write("control.json", {"snapshot_repo": str(snapshot), "source_hash": source_hash,
                "container_name": name, "attempt_id": attempt_id, "receipt_path": str(self.receipt_path)})
            remaining = spec.timeout_seconds - (time.monotonic() - started) - 15.0
            if remaining <= 0:
                raise ValueError("Snapshot preparation exhausted its deadline.")
            result = self._runner.run(replace(spec, timeout_seconds=remaining))
            if not self.cleanup():
                raise ValueError("Parent cleanup did not confirm container removal.")
            if result.status in {VerificationCheckStatus.TIMEOUT, VerificationCheckStatus.EXECUTION_ERROR}:
                return replace(result, stdout="", stderr="", message="Cooperative observer did not complete.")
            if (not has_single_regular_file_link(self.receipt_path) or self.receipt_path.stat().st_size > 256 * 1024):
                raise ValueError("Cooperative receipt is absent or oversized.")
            receipt = json.loads(self.receipt_path.read_text(encoding="utf-8"))
            if (not isinstance(receipt, dict)
                    or receipt.get("receipt_id") != attempt_id or receipt.get("source_hash") != source_hash
                    or receipt.get("image") != self.image or receipt.get("status") != "completed"
                    or receipt.get("cleanup_complete") is not True
                    or any(r["receipt_id"] == attempt_id for r in self.receipts)
                    or result.report is None or len(result.report.cases) != 22):
                raise ValueError("Cooperative receipt or report identity is invalid.")
            if self._source() != source or not self.permits(spec, self.generation_root):
                raise ValueError("Research inputs changed during execution.")
            result = replace(result, stdout="Cooperative repository check completed; this is not adversarial proof.",
                stderr="", message="cooperative_receipt=" + attempt_id)
            receipt.update(cooperative_only=True, adversarial_proof=False,
                           result_digest=_digest(asdict(VerificationSummary.from_result(result))))
            self.receipts.append(receipt)
            return result
        except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
            return self._error(spec, str(error))
        finally:
            self.cleanup()

    def bind_attempts(self, result, *, runtime_root) -> list[dict]:
        return bind_attempt_receipts(result, runtime_root=runtime_root,
            configured_runtime_root=self.runtime_root, generation_root=self.generation_root,
            receipts=self.receipts, source_reader=self._source, receipt_prefix="cooperative_receipt=")

    @staticmethod
    def _error(spec, message):
        return VerificationResult.create(name=spec.name, argv=spec.argv, cwd=spec.cwd,
            status=VerificationCheckStatus.EXECUTION_ERROR, exit_code=None,
            message=message, allowed_failure_case_ids=spec.allowed_failure_case_ids)


class CooperativeAdmission:
    """No host repository execution: admit only this concrete fixed observer."""

    def __init__(self, runner):
        if type(runner) is not CooperativeRunner:
            raise ValueError("Only the concrete cooperative research runner is supported.")
        self.runner = runner

    def permits(self, spec, runner, workspace_root):
        return runner is self.runner and type(runner) is CooperativeRunner and runner.permits(spec, workspace_root)
