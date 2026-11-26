"""Bind isolated research receipts to original SQLite attempts and RunRecords."""

from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from agent.workspace import WorkspacePathResolver, has_single_regular_file_link


def bind_attempt_receipts(result, *, runtime_root, configured_runtime_root,
                          generation_root, receipts, source_reader,
                          receipt_prefix: str) -> list[dict]:
    """Share the audit check between the two concrete research adapters."""
    from agent.runtime.identity import RunIdentity
    from agent.runtime.trajectory import RunRecord, AuditStatus, record_ref_for

    state = result.state or {}
    if Path(runtime_root).resolve(strict=True) != configured_runtime_root:
        raise ValueError("Records and artifacts must share the configured runtime root.")
    identity = state.get("run_identity")
    if (not isinstance(identity, RunIdentity) or identity.run_id != result.run_id
            or identity.workspace.canonical_root != str(generation_root)
            or result.audit_incomplete or not result.record_ref
            or result.record_ref != record_ref_for(run_id=identity.run_id,
                task_id=identity.task_id, thread_id=identity.thread_id)):
        raise ValueError("Run identity or audit reference is inconsistent.")
    resolved = WorkspacePathResolver(runtime_root).resolve_file(result.record_ref)
    if (not resolved.ok or not has_single_regular_file_link(resolved.path)
            or resolved.path.stat().st_size > 256 * 1024):
        raise ValueError("Original RunRecord is unavailable.")
    record = RunRecord.from_dict(json.loads(resolved.path.read_text(encoding="utf-8")))
    if (record.identity != {"run_id": identity.run_id, "thread_id": identity.thread_id,
            "task_id": identity.task_id, "workspace": {"canonical_root": identity.workspace.canonical_root,
            "root_digest": identity.workspace.root_digest}}
            or record.audit_status is not AuditStatus.COMPLETE
            or record.runtime_status != result.status.value):
        raise ValueError("RunRecord does not belong to the same run/task/thread.")
    attempts = state.get("verification_attempts", ())
    if (not attempts or not receipts
            or len({a.attempt_id for a in attempts}) != len(attempts)):
        raise ValueError("Original verification attempts must be non-empty and unique.")
    if any(a.run_id != identity.run_id or a.task_id != identity.task_id for a in attempts):
        raise ValueError("Verification attempts belong to another identity.")
    bound, receipt_ids, attempt_ids = [], set(), set()
    for receipt in receipts:
        receipt_id = receipt.get("receipt_id")
        if (not isinstance(receipt_id, str) or not receipt_id or "\n" in receipt_id
                or "\r" in receipt_id or receipt_id in receipt_ids):
            raise ValueError("Receipt identities must be non-empty and unique.")
        receipt_ids.add(receipt_id)
        token = receipt_prefix + receipt_id
        matches = [a for a in attempts if a.result is not None and a.run_id == result.run_id
                   and token in a.result.message.splitlines()]
        digest = (hashlib.sha256(json.dumps(asdict(matches[0].result), sort_keys=True,
                  default=str).encode()).hexdigest() if len(matches) == 1 else None)
        if len(matches) != 1 or digest != receipt["result_digest"]:
            raise ValueError("Receipt does not bind exactly one original attempt.")
        attempt = matches[0]
        if attempt.attempt_id in attempt_ids:
            raise ValueError("An original attempt cannot bind more than one receipt.")
        attempt_ids.add(attempt.attempt_id)
        bound.append({"receipt": receipt, "attempt_id": attempt.attempt_id,
                      "phase": attempt.phase, "run_id": result.run_id,
                      "task_id": attempt.task_id, "repair_attempt": attempt.repair_attempt,
                      "record_ref": result.record_ref})
    if (attempt_ids != {a.attempt_id for a in attempts}
            or result.audit_incomplete or not result.record_ref):
        raise ValueError("Research audit is incomplete.")
    if state.get("acceptance") is not None and state["acceptance"].accepted:
        posts = [item for item in bound if item["phase"] == "post"]
        final = max(posts, key=lambda item: item["repair_attempt"]) if posts else None
        if final is None or hashlib.sha256(source_reader()).hexdigest() != final["receipt"]["source_hash"]:
            raise ValueError("Final source differs from the last valid post check.")
    return bound
