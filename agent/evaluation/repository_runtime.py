"""Externally injected Architect/Developer dependencies for repository research."""
from dataclasses import dataclass, replace
import hashlib
import json
import math
from pathlib import Path
from collections.abc import Callable

from langchain_core.messages import BaseMessage

from agent.architect.runtime import ArchitectRuntime, durable_architect_runtime
from agent.common.entities import ImplementationPlan, PlanStatus
from agent.developer.runtime import DeveloperRuntime, durable_developer_runtime
from agent.evaluation.repository_candidate import CandidatePolicy
from agent.evaluation.repository_context import (
    ContextBudgetError, load_structure, project_research_context, research_tools,
)
from agent.runtime.budget import BudgetErrorCode
from agent.runtime.calls import capture_model_exception
from agent.runtime.config import ModelRetryPolicy
from agent.tools.read_contract import clip_utf8
from agent.workspace import (
    WorkspaceAccessPolicy, WorkspacePathResolver, canonical_workspace_relative_path,
    has_single_regular_file_link, workspace_root_scope,
)

MAX_VALUES_BYTES = 8192
HISTORY_BYTES = 4096
FILE_VIEW_BYTES = 2048
TREE_VIEW_BYTES = 1024


@dataclass(frozen=True)
class RepositoryRuntimes:
    architect: ArchitectRuntime
    developer: DeveloperRuntime
    tools: tuple
    load_structure: Callable[[], str]
    access_policy: WorkspaceAccessPolicy


def repository_plan_allowed(plan, workspace_root: Path, policy: CandidatePolicy,
                            access_policy: WorkspaceAccessPolicy | None = None) -> bool:
    """Validate model plan paths without using gold-derived answer locations."""
    if (type(plan) is not ImplementationPlan or plan.status is not PlanStatus.READY
            or not 1 <= len(plan.tasks) <= 32):
        return False
    access = access_policy or WorkspaceAccessPolicy(hidden_paths=policy.protected_paths)
    resolver = WorkspacePathResolver(workspace_root)
    seen = set()
    try:
        for task in plan.tasks:
            path = canonical_workspace_relative_path(task.file_path, allow_root=False)
            if (path is None or any(ord(c) < 32 or ord(c) == 127 for c in path)
                    or path in seen or not access.check_write(path).allowed
                    or WorkspaceAccessPolicy(hidden_paths=policy.protected_paths).is_protected(path)
                    or not any(p == "." or path == p or path.startswith(p + "/") for p in policy.editable_prefixes)
                    or not 1 <= len(task.atomic_tasks) <= 32
                    or not all(step.atomic_task.strip() for step in task.atomic_tasks)):
                return False
            resolved = resolver.resolve_file(path, must_exist=False, allow_absolute=False)
            if not resolved.ok:
                return False
            if resolved.path.exists():
                if not has_single_regular_file_link(resolved.path) or resolved.path.stat().st_size > policy.max_changed_bytes:
                    return False
                data = resolved.path.read_bytes()
                if len(data) > policy.max_changed_bytes or b"\0" in data:
                    return False
                data.decode("utf-8")
            seen.add(path)
    except (OSError, UnicodeError, ValueError):
        return False
    return True


def _excerpt(value: str, limit: int, kind: str) -> str:
    content, clipped = clip_utf8(value, limit)
    if not clipped:
        return value
    raw = value.encode("utf-8")
    return (f"[UNTRUSTED {kind} EXCERPT; INCOMPLETE] total_utf8_bytes={len(raw)} "
            f"sha256={hashlib.sha256(raw).hexdigest()} range=0:{len(content.encode('utf-8'))}\n"
            + content + "\n[INCOMPLETE VIEW: use repository tools to inspect remaining byte ranges; this is not the complete file.]")


def _view(values: dict) -> dict:
    projected = dict(values)
    timeout = projected.get("_model_request_timeout_seconds", 45.0)
    if (type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0):
        raise ContextBudgetError("Model timeout must be finite and positive.")
    for key in ("implementation_research_scratchpad", "atomic_implementation_research", "research_findings", "research"):
        if key in projected:
            projected[key] = project_research_context(projected[key], max_bytes=HISTORY_BYTES)
    for key, limit, kind in (("file_content", FILE_VIEW_BYTES, "FILE"),
                             ("codebase_structure", TREE_VIEW_BYTES, "TREE")):
        if key in projected:
            if not isinstance(projected[key], str):
                raise ContextBudgetError("Expected text model view.")
            projected[key] = _excerpt(projected[key], limit, kind)
    def encode(value):
        if isinstance(value, BaseMessage):
            return {"role": value.type, "content": value.content}
        if hasattr(value, "model_dump"):
            return value.model_dump()
        raise TypeError("Unsupported model-view value.")
    size = len(json.dumps(projected, default=encode, ensure_ascii=False,
                          separators=(",", ":"), allow_nan=False).encode())
    if size > MAX_VALUES_BYTES:
        raise ContextBudgetError("Combined runtime inputs exceed the model-view budget.")
    return projected


def build_repository_runtimes(settings, workspace_root: Path, *, model_factory,
                              policy: CandidatePolicy = CandidatePolicy(), pricing=None,
                              secret_filter=None, access_policy: WorkspaceAccessPolicy | None = None,
                              model_request_timeout_seconds: float = 45.0) -> RepositoryRuntimes:
    """Create lazy model seams; caller supplies the final guarded HTTP client.

    Partial views affect only model inputs; S1 receives the original working
    transaction through the existing Developer graph. Complete HTTP envelopes
    still require the caller's provider/financial admission boundary.
    """
    if type(policy) is not CandidatePolicy:
        raise ValueError("An independent candidate policy is required.")
    if (type(model_request_timeout_seconds) not in (int, float)
            or not math.isfinite(model_request_timeout_seconds) or model_request_timeout_seconds <= 0):
        raise ValueError("Model timeout must be finite and positive.")
    configured = access_policy or WorkspaceAccessPolicy()
    access = WorkspaceAccessPolicy(hidden_paths=tuple(dict.fromkeys((*configured.hidden_paths, *policy.protected_paths))),
                                   oracle_paths=configured.oracle_paths)
    tools = research_tools()
    def structure():
        with workspace_root_scope(workspace_root, access_policy=access):
            return _excerpt(load_structure(), TREE_VIEW_BYTES, "TREE")
    def factory(*args, **kwargs):
        if kwargs.get("max_retries") != 0 or kwargs.get("max_output_tokens") != 2048:
            raise ValueError("Repository research has no provider retries or changed output allowance.")
        return model_factory(*args, **kwargs)
    common = dict(model_factory=factory, research_tools=tools, load_codebase_structure=structure,
                  model_request_timeout_seconds=model_request_timeout_seconds,
                  model_retry_policy=ModelRetryPolicy(max_attempts=1))
    architect = durable_architect_runtime(settings, 2048, pricing, **common)
    developer = durable_developer_runtime(settings, 2048, pricing, workspace_root=workspace_root,
        secret_filter=secret_filter, access_policy=access, **common)
    def guarded(call, *, validate_plan=False):
        def invoke(values):
            try:
                projected = _view(values)
            except (ContextBudgetError, TypeError, ValueError, UnicodeError):
                return capture_model_exception(BudgetErrorCode.MODEL_REQUEST_REJECTED)
            with workspace_root_scope(workspace_root, access_policy=access):
                response = call(projected)
            if validate_plan and response.value is not None and not repository_plan_allowed(
                    response.value, workspace_root, policy, access):
                return replace(response, value=None, error="Repository plan exceeds the independent trusted scope.",
                               error_code=BudgetErrorCode.MODEL_OUTPUT_INVALID)
            return response
        return invoke
    architect = replace(architect, **{name: guarded(getattr(architect, name), validate_plan=name == "extract_implementation_plan")
        for name in ("plan_next_step", "check_research_step", "conduct_research", "extract_implementation_plan")})
    developer = replace(developer, **{name: guarded(getattr(developer, name))
        for name in ("research_atomic_task", "propose_existing_file_edit", "propose_new_file")})
    return RepositoryRuntimes(architect, developer, tools, structure, access)
