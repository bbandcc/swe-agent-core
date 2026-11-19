"""Bounded unhinted observations through public tool and projection seams."""
from pathlib import Path
import hashlib
import json
import tempfile
import unittest


class RepositoryContextTests(unittest.TestCase):
    def test_raw_read_has_utf8_byte_bound_and_explicit_incomplete_metadata(self):
        from agent.evaluation.repository_context import repository_raw_file
        from agent.workspace import workspace_root_scope
        with tempfile.TemporaryDirectory() as directory, workspace_root_scope(directory):
            Path(directory, "a.py").write_bytes(("中" * 1000).encode())
            result = repository_raw_file.invoke({"file_path": "a.py"})
            self.assertTrue(result["ok"], result)
            self.assertLessEqual(len(result["content"].encode()), 2048)
            self.assertTrue(result["truncated"])
            self.assertIsNone(result["continuation"])
            self.assertEqual(result["range"]["end_byte"], len(result["content"].encode()))

    def test_permissions_escape_range_and_cursor_fail_closed(self):
        from agent.evaluation.repository_context import repository_raw_file, repository_search, repository_tree
        from agent.workspace import workspace_root_scope, WorkspaceAccessPolicy
        with tempfile.TemporaryDirectory() as directory, workspace_root_scope(directory,
                access_policy=WorkspaceAccessPolicy(hidden_paths=("private",))):
            Path(directory, "private").mkdir()
            Path(directory, "private/key.py").write_bytes(b"secret = 1\n")
            for path in ("../outside", "private/key.py"):
                result = repository_raw_file.invoke({"file_path": path})
                self.assertFalse(result["ok"], result)
                self.assertNotIn("content", result)
            self.assertFalse(repository_raw_file.invoke({"file_path": "any", "end_byte": 2049})["ok"])
            for reader, args in ((repository_raw_file, {"file_path": "any"}),
                                 (repository_search, {"directory": ".", "search_term": "secret"}),
                                 (repository_tree, {})):
                result = reader.invoke({**args, "cursor": "old-page"})
                self.assertEqual(result["error_code"], "repository_cursor_unsupported")

    def test_search_and_tree_remain_visible_and_report_omitted_material(self):
        from agent.evaluation.repository_context import repository_search, repository_tree, load_structure, research_tools
        from agent.workspace import workspace_root_scope
        with tempfile.TemporaryDirectory() as directory, workspace_root_scope(directory):
            for i in range(20):
                Path(directory, f"source{i:02}.py").write_bytes(b"needle = 1\n")
            result = repository_search.invoke({"directory": ".", "search_term": "needle"})
            self.assertTrue(result["ok"], result)
            self.assertEqual(len(result["results"]), 5)
            self.assertEqual(result["omitted_items"], 15)
            self.assertTrue(result["truncated"])
            self.assertIsNone(result["continuation"])
            self.assertLessEqual(len(result["content"].encode()), 2048)
            self.assertEqual(result["content_hash"], hashlib.sha256(result["content"].encode()).hexdigest())
            tree = repository_tree.invoke({})
            self.assertIn("source", tree["content"])
            self.assertTrue(tree["truncated"])
            self.assertIn("[UNTRUSTED EVIDENCE]", load_structure())
            self.assertEqual(len(research_tools()), 3)

    def test_raw_toolnode_reads_staged_working_copy(self):
        from langchain_core.messages import AIMessage
        from langgraph.graph import StateGraph, START, END
        from langgraph.prebuilt import ToolNode
        from agent.developer.state import SoftwareDeveloperState
        from agent.editing import WorkspaceEditor, EditProposal, EditOperation
        from agent.evaluation.repository_context import repository_raw_file
        from agent.workspace import workspace_root_scope
        with tempfile.TemporaryDirectory() as directory, workspace_root_scope(directory):
            Path(directory, "a.py").write_bytes(b"value=1\n")
            editor = WorkspaceEditor(directory)
            transaction = editor.begin("a.py").transaction
            staged = editor.stage(transaction, EditProposal(task_id="task.step", path="a.py", operation=EditOperation.EDIT,
                old_text="value=1", new_text="value=2", base_hash=transaction.base_hash))
            self.assertTrue(staged.ok)
            graph = StateGraph(SoftwareDeveloperState)
            graph.add_node("tools", ToolNode([repository_raw_file], messages_key="atomic_implementation_research"))
            graph.add_edge(START, "tools"); graph.add_edge("tools", END)
            state = graph.compile().invoke({"current_file_transaction": staged.transaction,
                "atomic_implementation_research": [AIMessage(content="", tool_calls=[{"name": "get_raw_file_content",
                    "args": {"file_path": "a.py"}, "id": "read", "type": "tool_call"}])]})
            message = state["atomic_implementation_research"][-1]
            result = json.loads(message.content)
            self.assertEqual(message.tool_call_id, "read")
            self.assertEqual(result["view"], "working")
            self.assertIn("value=2", result["content"])
            self.assertEqual(Path(directory, "a.py").read_bytes(), b"value=1\n")

    def test_projection_retains_task_and_complete_recent_pairs_without_state_mutation(self):
        from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
        from agent.evaluation.repository_context import project_research_context, ContextBudgetError
        task = HumanMessage(content="Original unhinted task")
        messages = [task]
        for i in range(8):
            messages.extend([AIMessage(content="", tool_calls=[{"name": "read", "args": {}, "id": str(i), "type": "tool_call"}]),
                             ToolMessage(content="evidence" * 30, tool_call_id=str(i))])
        original = [message.model_dump() for message in messages]
        projected = project_research_context(messages, max_bytes=1500, max_messages=8)
        self.assertIs(projected[0], task)
        self.assertIn("[CONTEXT OMITTED]", projected[1].content)
        self.assertEqual([message.model_dump() for message in messages], original)
        self.assertEqual((len(projected) - 2) % 2, 0)
        for index in range(2, len(projected), 2):
            self.assertIn("[UNTRUSTED TOOL CALL]", projected[index].content)
            self.assertIn("[UNTRUSTED EVIDENCE]", projected[index + 1].content)
        encoded = json.dumps([{"role": m.type, "content": m.content} for m in projected], ensure_ascii=False, separators=(",", ":")).encode()
        self.assertLessEqual(len(encoded), 1500)
        self.assertEqual(project_research_context([]), [])
        with self.assertRaises(ContextBudgetError): project_research_context([HumanMessage(content="x" * 100)], max_bytes=30)

    def test_developer_scratchpad_without_initial_task_does_not_split_first_pair(self):
        from langchain_core.messages import AIMessage, ToolMessage
        from agent.evaluation.repository_context import project_research_context
        messages = []
        for i in range(3):
            messages.extend([AIMessage(content="", tool_calls=[{"name": "read", "args": {}, "id": str(i), "type": "tool_call"}]),
                             ToolMessage(content="evidence", tool_call_id=str(i))])
        projected = project_research_context(messages, max_messages=3)
        self.assertEqual(len(projected), 3)
        self.assertIn("[CONTEXT OMITTED]", projected[0].content)
        self.assertIn("[UNTRUSTED TOOL CALL]", projected[1].content)
        self.assertIn("call_id: 2", projected[1].content)
        self.assertIn("[UNTRUSTED EVIDENCE]", projected[2].content)


if __name__ == "__main__": unittest.main()
