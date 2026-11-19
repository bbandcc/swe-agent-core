"""Small unhinted research views; no model I/O or durable-state mutation."""
from collections.abc import Sequence
import hashlib
import json
from typing import Annotated, Any

from langchain_core.messages import AnyMessage, HumanMessage
from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState

from agent.common.tool_message_renderer import render_tool_messages
from agent.tools.codemap import get_raw_file_content
from agent.tools.read_contract import clip_utf8, tool_failure
from agent.tools.search import search_keyword_in_directory
from agent.tools.write import get_files_structure

OBSERVATION_BYTES = 2048


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@tool("get_raw_file_content", parse_docstring=True)
def repository_raw_file(file_path: str, start_byte: int = 0, end_byte: int | None = None,
                        cursor: str | None = None,
                        state: Annotated[Any, InjectedState] = None) -> dict[str, object]:
    """Read at most 2048 UTF-8 bytes from any permitted repository source.

    Args:
        file_path: Workspace path; no answer-location hint is imposed.
        start_byte: Independent inclusive byte offset, zero for the first page.
        end_byte: Optional exclusive end, no more than 2048 bytes after start.
        cursor: Unsupported; use explicit offsets and check content_version.
        state: Trusted graph state injected by ToolNode, never model supplied.
    """
    if cursor is not None:
        return tool_failure(None, "repository_cursor_unsupported", "Use independent byte ranges and check version metadata.")
    if (type(start_byte) is not int or start_byte < 0 or (end_byte is not None and
            (type(end_byte) is not int or not start_byte <= end_byte <= start_byte + OBSERVATION_BYTES))):
        return tool_failure(None, "repository_read_range", "Requested range exceeds the 2048-byte page.")
    result = get_raw_file_content.invoke({"file_path": file_path, "start_byte": start_byte,
        "end_byte": end_byte, "state": state})
    if not result.get("ok"):
        return result
    content, clipped = clip_utf8(result["content"], OBSERVATION_BYTES)
    incomplete = clipped or result["truncated"]
    return {**result, "content": content, "source_page_hash": result["content_hash"],
        "content_hash": _hash(content), "range": {**result["range"], "end_byte": start_byte + len(content.encode())},
        "truncated": incomplete, "continuation": None, "limits": {"max_bytes": OBSERVATION_BYTES},
        "warnings": list(result["warnings"]) + (["Independent page; use end_byte as next start and compare content_version."] if incomplete else [])}


def _small_view(result: dict[str, object], *, list_key: str, max_items: int):
    if not result.get("ok"):
        return result
    # Source cursor advances over the original S4 result, not this projection.
    # Therefore it must never be returned after projection drops an item.
    items = result.get(list_key, [])
    retained = []
    for item in items[:max_items]:
        trial = json.dumps(retained + [item], ensure_ascii=False, separators=(",", ":"))
        if len(trial.encode()) > OBSERVATION_BYTES:
            break
        retained.append(item)
    text = json.dumps(retained, ensure_ascii=False, separators=(",", ":"))
    omitted = len(items) - len(retained)
    return {"ok": True, "path": result["path"], list_key: retained, "content": text,
        "content_hash": _hash(text), "source_content_hash": result.get("content_hash"),
        "omitted_items": omitted, "source_item_count": len(items),
        "truncated": bool(result["truncated"] or omitted), "continuation": None,
        "warnings": list(result.get("warnings", [])) + ["View-only page; narrow the query to inspect omitted material. Cursors are not exposed."]}


@tool("search_keyword_in_directory", parse_docstring=True)
def repository_search(directory: str, search_term: str, cursor: str | None = None) -> dict[str, object]:
    """Find a literal term with at most five matches and 2048 bytes of evidence.

    Args:
        directory: Permitted workspace directory to search.
        search_term: Literal term of at least three characters; narrow if truncated.
        cursor: Unsupported because projected results have different page bounds.
    """
    if cursor is not None:
        return tool_failure(None, "repository_cursor_unsupported", "Narrow the search instead of using a projected cursor.")
    return _small_view(search_keyword_in_directory.invoke({"directory": directory,
        "search_term": search_term, "context": 0}), list_key="results", max_items=5)


@tool("get_files_structure", parse_docstring=True)
def repository_tree(directory: str = ".", cursor: str | None = None) -> dict[str, object]:
    """List a small repository tree without providing answer-location hints.

    Args:
        directory: Permitted workspace directory; inspect children with another call.
        cursor: Unsupported; descend into a narrower directory when truncated.
    """
    if cursor is not None:
        return tool_failure(None, "repository_cursor_unsupported", "Inspect a narrower directory instead of a projected cursor.")
    result = get_files_structure.invoke({"directory": directory, "max_depth": 2, "max_entries": 12})
    if not result.get("ok"):
        return result
    text, clipped = clip_utf8(result["content"], OBSERVATION_BYTES)
    return {"ok": True, "path": result["path"], "content": text, "content_hash": _hash(text),
        "source_content_hash": result["content_hash"], "content_version": result["content_version"],
        "source_range": result["range"], "content_truncated": clipped,
        "truncated": bool(clipped or result["truncated"]), "continuation": None,
        "warnings": list(result["warnings"]) + ["View-only page; descend into a narrower directory to inspect omitted entries."]}


def research_tools() -> tuple:
    return repository_raw_file, repository_search, repository_tree


def load_structure() -> str:
    """Use within the externally supplied workspace/access scope."""
    return "[UNTRUSTED EVIDENCE]\n" + json.dumps(repository_tree.invoke({}), ensure_ascii=False)


class ContextBudgetError(ValueError):
    """The original task cannot fit without silently truncating user input."""


def project_research_context(messages: Sequence[AnyMessage], *, max_bytes: int = 8192,
                             max_messages: int = 14) -> list[AnyMessage]:
    """Render a bounded view, retaining the first task and recent complete pairs.

    Budget covers serialized role/content only; callers must still validate the
    complete provider envelope (prompts, tools and other model inputs included).
    Omission markers are evidence metadata, never a substitute model response.
    """
    if type(max_bytes) is not int or max_bytes <= 0 or type(max_messages) is not int or max_messages < 2:
        raise ContextBudgetError("Invalid context budget.")
    if not messages:
        return []
    rendered = render_tool_messages(messages)
    def encoded(items):
        return json.dumps([{"role": item.type, "content": item.content} for item in items],
                          ensure_ascii=False, separators=(",", ":")).encode()
    head = rendered[:1] if messages[0].type == "human" else []
    start = len(head)
    if head and len(encoded(head)) > max_bytes:
        raise ContextBudgetError("Original task exceeds the context budget.")
    if len(rendered) <= max_messages and len(encoded(rendered)) <= max_bytes:
        return rendered
    groups, index = [], start
    while index < len(rendered):
        current = rendered[index]
        if (current.type == "ai" and isinstance(current.content, str) and current.content.startswith("[UNTRUSTED TOOL CALL]")
                and index + 1 < len(rendered) and rendered[index + 1].type == "human"
                and isinstance(rendered[index + 1].content, str)
                and rendered[index + 1].content.startswith("[UNTRUSTED EVIDENCE]")):
            groups.append(rendered[index:index + 2]); index += 2
        else:
            groups.append([current]); index += 1
    tail = []
    for group in reversed(groups):
        proposed = group + tail
        omitted = rendered[start:len(rendered) - len(proposed)]
        marker = HumanMessage(content=f"[CONTEXT OMITTED] messages={len(omitted)} sha256={hashlib.sha256(encoded(omitted)).hexdigest()}")
        view = [*head, marker, *proposed]
        if len(view) > max_messages or len(encoded(view)) > max_bytes:
            break
        tail = proposed
    omitted = rendered[start:len(rendered) - len(tail)]
    marker = HumanMessage(content=f"[CONTEXT OMITTED] messages={len(omitted)} sha256={hashlib.sha256(encoded(omitted)).hexdigest()}")
    view = [*head, marker, *tail]
    if len(encoded(view)) > max_bytes:
        raise ContextBudgetError("Task and explicit omission metadata exceed the budget.")
    return view
