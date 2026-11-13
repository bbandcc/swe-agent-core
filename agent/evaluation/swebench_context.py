"""Narrow observations for the fixed, hinted cooperative research profile."""

from typing import Annotated, Any

from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState

from agent.developer.editing import canonical_plan_path
from agent.evaluation.swebench_observer import SOURCE
from agent.tools.codemap import get_raw_file_content
from agent.tools.read_contract import tool_failure

MAX_SOURCE_BYTES = 4096


@tool("get_raw_file_content", parse_docstring=True)
def cooperative_source_reader(
    file_path: str,
    start_byte: int = 0,
    end_byte: int | None = None,
    cursor: str | None = None,
    state: Annotated[Any, InjectedState] = None,
) -> dict[str, object]:
    """Read only the complete hinted printing mixin, at most 4096 UTF-8 bytes.

    Args:
        file_path: Only sympy/core/_print_helpers.py; other files are unavailable.
        start_byte: Must be zero; this profile does not offer partial reads.
        end_byte: Must be None; this profile reads the complete small file.
        cursor: Must be None; pagination is unavailable in this profile.
        state: Trusted graph state, injected by ToolNode, never model supplied.
    """
    if canonical_plan_path(file_path) != canonical_plan_path(SOURCE):
        return tool_failure(SOURCE, "cooperative_read_scope", "Only the hinted source file is available.")
    if type(start_byte) is not int or start_byte != 0 or end_byte is not None or cursor is not None:
        return tool_failure(SOURCE, "cooperative_read_range", "Read the complete hinted file without a range or cursor.")
    # Reuse S4 authorization, version/hash checks and the S1 staged working view.
    result = get_raw_file_content.invoke({"file_path": SOURCE, "state": state})
    if result.get("ok") and (result["range"]["total_bytes"] > MAX_SOURCE_BYTES or result["truncated"]):
        return tool_failure(SOURCE, "cooperative_read_size", "The hinted source exceeds the 4096-byte profile limit.")
    return result
