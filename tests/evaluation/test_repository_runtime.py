"""Unhinted runtime seam acceptance; no real provider dispatch."""
from pathlib import Path
import json
import hashlib
import tempfile
import unittest

import httpx
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage


class RepositoryRuntimeTests(unittest.TestCase):
    def sdk_runtime(self, root, reply="local research", usage=None, policy=None):
        from langchain_deepseek import ChatDeepSeek
        from pydantic import SecretStr
        from agent.config import ModelSettings
        from agent.evaluation.pilot_spend import CappedDeepSeekTransport
        from agent.evaluation.repository_candidate import CandidatePolicy
        from agent.evaluation.repository_runtime import build_repository_runtimes
        sent = []
        def handler(request):
            sent.append(json.loads(request.content))
            return httpx.Response(200, json={"id": "local", "object": "chat.completion", "created": 1,
                "model": "deepseek-flash", "choices": [{"index": 0, "message": {"role": "assistant", "content": reply},
                "finish_reason": "stop"}], "usage": usage or {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}})
        ledger_directory = tempfile.TemporaryDirectory()
        self.addCleanup(ledger_directory.cleanup)
        cap = CappedDeepSeekTransport(httpx.MockTransport(handler), Path(ledger_directory.name) / "ledger")
        client = httpx.Client(transport=cap, trust_env=False)
        self.addCleanup(client.close)
        settings = ModelSettings("deepseek", "deepseek-flash", "https://api.deepseek.com", SecretStr("local-runtime-dummy"))
        def factory(settings, *, max_output_tokens, request_timeout_seconds, max_retries):
            self.assertEqual(max_retries, 0)
            return ChatDeepSeek(model=settings.model, api_key=settings.api_key, base_url=settings.base_url,
                max_tokens=max_output_tokens, timeout=request_timeout_seconds, max_retries=0,
                extra_body={"thinking": {"type": "disabled"}}, http_client=client)
        runtime = build_repository_runtimes(settings, Path(root), model_factory=factory, policy=policy or CandidatePolicy())
        return runtime, sent, cap

    def test_typed_multifile_multistep_plan_uses_independent_workspace_scope(self):
        from agent.common.entities import AtomicTask, ImplementationPlan, ImplementationTask
        from agent.evaluation.repository_candidate import CandidatePolicy
        from agent.evaluation.repository_runtime import repository_plan_allowed
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "src").mkdir()
            Path(directory, "src/a.py").write_bytes(b"a=1\n")
            plan = ImplementationPlan(tasks=[ImplementationTask(file_path=path, logical_task="fix", atomic_tasks=[
                AtomicTask(atomic_task="first"), AtomicTask(atomic_task="second")]) for path in ("src/a.py", "src/new.py")])
            self.assertTrue(repository_plan_allowed(plan, Path(directory), CandidatePolicy(editable_prefixes=("src",))))

    def test_plan_refuses_protected_absolute_escape_binary_and_duplicate_aliases(self):
        from agent.common.entities import AtomicTask, ImplementationPlan, ImplementationTask
        from agent.evaluation.repository_candidate import CandidatePolicy
        from agent.evaluation.repository_runtime import repository_plan_allowed
        def plan(*paths):
            return ImplementationPlan(tasks=[ImplementationTask(file_path=p, logical_task="fix",
                atomic_tasks=[AtomicTask(atomic_task="edit")]) for p in paths])
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "binary.py").write_bytes(b"\xff\x00")
            policy = CandidatePolicy(protected_paths=("oracle",))
            for path in ("../a.py", "/a.py", "C:/a.py", "oracle/test.py", ".git/config", ".env.local", "binary.py"):
                self.assertFalse(repository_plan_allowed(plan(path), Path(directory), policy), path)
            self.assertFalse(repository_plan_allowed(plan("a.py", "./a.py"), Path(directory), policy))

    def test_real_sdk_guarded_body_has_bounded_paired_context_and_original_state(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, sent, cap = self.sdk_runtime(directory)
            messages = [HumanMessage(content="Unhinted issue")]
            for i in range(12):
                messages.extend([AIMessage(content="", tool_calls=[{"name": "get_raw_file_content", "args": {"file_path": "a.py"},
                    "id": str(i), "type": "tool_call"}]), ToolMessage(content="evidence" * 100, tool_call_id=str(i))])
            before = [m.model_dump() for m in messages]
            result = runtime.architect.conduct_research({"implementation_research_scratchpad": messages, "codebase_structure": "repository"})
            self.assertIsNone(result.error_code, result)
            self.assertEqual(len(sent), 1)
            body = sent[0]
            self.assertLessEqual(len(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()), 16384)
            content = "\n".join(m["content"] for m in body["messages"])
            self.assertIn("Unhinted issue", content)
            self.assertIn("[CONTEXT OMITTED]", content)
            self.assertEqual(content.count("[UNTRUSTED TOOL CALL]"), content.count("[UNTRUSTED EVIDENCE]"))
            self.assertEqual(before, [m.model_dump() for m in messages])
            self.assertEqual(cap.summary()["requests"], 1)

    def test_oversized_original_task_is_rejected_before_model_dispatch_with_known_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, sent, cap = self.sdk_runtime(directory)
            result = runtime.architect.plan_next_step({"implementation_research_scratchpad": [HumanMessage(content="x" * 20000)],
                "codebase_structure": "repository"})
            self.assertEqual(result.error_code.value, "model_request_rejected")
            self.assertEqual(result.usage.cost_source, "not_dispatched")
            self.assertEqual(result.usage.cost_microusd, 0)
            self.assertEqual(sent, [])
            self.assertEqual(cap.summary()["requests"], 0)
            for timeout in (float("inf"), float("nan"), 0, -1, True):
                rejected = runtime.architect.conduct_research({"implementation_research_scratchpad": [],
                    "codebase_structure": "repository", "_model_request_timeout_seconds": timeout})
                self.assertEqual(rejected.error_code.value, "model_request_rejected")
                self.assertEqual(rejected.usage.cost_source, "not_dispatched")
            self.assertEqual(sent, [])

    def test_developer_sees_explicit_excerpt_but_editor_transaction_retains_full_source(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, sent, _ = self.sdk_runtime(directory)
            source = "# source\n" * 700
            target = Path(directory, "a.py"); target.write_bytes(source.encode())
            # The same public S1 seam used by the graph retains all file bytes.
            from agent.editing import WorkspaceEditor
            transaction = WorkspaceEditor(directory).begin("a.py").transaction
            result = runtime.developer.research_atomic_task({"development_task": "inspect", "target_file": "a.py",
                "file_content": transaction.working_content, "additional_context": "", "codebase_structure": "repository",
                "atomic_implementation_research": []})
            self.assertIsNone(result.error_code, result)
            content = "\n".join(m["content"] for m in sent[0]["messages"])
            self.assertIn("[UNTRUSTED FILE EXCERPT; INCOMPLETE]", content)
            self.assertIn(hashlib.sha256(source.encode()).hexdigest(), content)
            self.assertEqual(transaction.working_content, source)
            self.assertEqual(target.read_bytes(), source.encode())

    def test_actual_extract_rejects_typed_out_of_scope_plan_after_retaining_real_usage(self):
        reply = json.dumps({"tasks": [{"file_path": "oracle/test.py", "logical_task": "bad", "atomic_tasks": [{"atomic_task": "edit"}]}]})
        from agent.common.entities import ImplementationPlan
        from langchain_core.output_parsers import JsonOutputParser
        from agent.evaluation.repository_candidate import CandidatePolicy
        with tempfile.TemporaryDirectory() as directory:
            runtime, sent, _ = self.sdk_runtime(directory, reply=reply, policy=CandidatePolicy(protected_paths=("oracle",)))
            result = runtime.architect.extract_implementation_plan({"research_findings": [HumanMessage(content="Findings")],
                "codebase_structure": "repository", "output_format": JsonOutputParser(pydantic_object=ImplementationPlan).get_format_instructions()})
            self.assertEqual(len(sent), 1)
            self.assertEqual(result.error_code.value, "model_output_invalid")
            self.assertIsNone(result.value)
            self.assertEqual(result.usage.input_tokens, 10)

    def test_actual_sdk_extract_accepts_two_files_with_multiple_atomic_steps(self):
        from agent.common.entities import ImplementationPlan
        from langchain_core.output_parsers import JsonOutputParser
        reply = json.dumps({"tasks": [{"file_path": path, "logical_task": "fix", "atomic_tasks": [
            {"atomic_task": "first"}, {"atomic_task": "second"}]} for path in ("a.py", "new/b.py")]})
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "a.py").write_bytes(b"a=1\n")
            runtime, sent, _ = self.sdk_runtime(directory, reply=reply)
            result = runtime.architect.extract_implementation_plan({"research_findings": [HumanMessage(content="Findings")],
                "codebase_structure": "repository", "output_format": JsonOutputParser(pydantic_object=ImplementationPlan).get_format_instructions()})
            self.assertIsNone(result.error_code, result)
            self.assertEqual(len(sent), 1)
            self.assertEqual(len(result.value.tasks), 2)
            self.assertEqual([len(t.atomic_tasks) for t in result.value.tasks], [2, 2])

    def test_edit_proposal_projects_research_and_s1_stages_against_complete_original(self):
        from agent.editing import WorkspaceEditor
        reply = "<<<<<<< SEARCH\nvalue=1\n=======\nvalue=2\n>>>>>>> REPLACE"
        with tempfile.TemporaryDirectory() as directory:
            source = "value=1\n" + "# tail\n" * 1000
            Path(directory, "a.py").write_bytes(source.encode())
            runtime, sent, _ = self.sdk_runtime(directory, reply=reply)
            research = []
            for i in range(15):
                research.extend([AIMessage(content="", tool_calls=[{"name": "get_raw_file_content", "args": {"file_path": "a.py"},
                    "id": str(i), "type": "tool_call"}]), ToolMessage(content="research" * 60, tool_call_id=str(i))])
            editor = WorkspaceEditor(directory)
            transaction = editor.begin("a.py").transaction
            response = runtime.developer.propose_existing_file_edit({"task": "Change value", "additional_context": "",
                "research": research, "file_path": "a.py", "file_content": transaction.working_content, "verification_feedback": {}})
            self.assertIsNone(response.error_code, response)
            content = "\n".join(m["content"] for m in sent[0]["messages"])
            self.assertIn("[CONTEXT OMITTED]", content)
            staged = runtime.developer.edit_executor().stage(transaction, response.value, task_id="step-1")
            self.assertTrue(staged.ok, staged)
            self.assertEqual(staged.transaction.working_content, source.replace("value=1", "value=2"))
            self.assertEqual(transaction.working_content, source)
            self.assertEqual(Path(directory, "a.py").read_bytes(), source.encode())


    def test_immutable_source_is_visible_but_existing_and_new_plan_targets_are_refused(self):
        from agent.common.entities import AtomicTask,ImplementationPlan,ImplementationTask
        from agent.evaluation.repository_candidate import CandidatePolicy
        from agent.evaluation.repository_runtime import repository_plan_allowed
        def plan(path):
            return ImplementationPlan(tasks=[ImplementationTask(file_path=path,logical_task='edit',
                atomic_tasks=[AtomicTask(atomic_task='change')])])
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'astropy_helpers').mkdir()
            (root/'astropy_helpers/helper.py').write_bytes(b'fixed helper\n')
            (root/'.gitmodules').write_bytes(b'fixed config\n')
            policy=CandidatePolicy(immutable_paths=('astropy_helpers','.gitmodules'))
            runtime,_,_=self.sdk_runtime(directory,policy=policy)
            self.assertTrue(runtime.access_policy.check_read('astropy_helpers/helper.py').allowed)
            self.assertIn('astropy_helpers',runtime.load_structure())
            for path in ('astropy_helpers/helper.py','astropy_helpers/new.py','.gitmodules'):
                self.assertFalse(repository_plan_allowed(plan(path),root,policy,runtime.access_policy),path)
            self.assertTrue(repository_plan_allowed(plan('new_parent.py'),root,policy,runtime.access_policy))

    def test_actual_extract_rejects_immutable_target_before_s1_and_retains_usage(self):
        from agent.common.entities import ImplementationPlan
        from agent.evaluation.repository_candidate import CandidatePolicy
        from langchain_core.output_parsers import JsonOutputParser
        reply=json.dumps({'tasks':[{'file_path':'helpers/helper.py','logical_task':'edit',
            'atomic_tasks':[{'atomic_task':'change'}]}]})
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'helpers/helper.py';path.parent.mkdir();path.write_bytes(b'fixed\n')
            runtime,_,_=self.sdk_runtime(directory,reply=reply,policy=CandidatePolicy(immutable_paths=('helpers',)))
            result=runtime.architect.extract_implementation_plan({'research_findings':[HumanMessage(content='Findings')],
                'codebase_structure':'repository','output_format':JsonOutputParser(pydantic_object=ImplementationPlan).get_format_instructions()})
            self.assertEqual(result.error_code.value,'model_output_invalid')
            self.assertIsNone(result.value);self.assertEqual(result.usage.input_tokens,10)
            self.assertEqual(path.read_bytes(),b'fixed\n')

if __name__ == "__main__": unittest.main()
