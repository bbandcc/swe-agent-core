"""No-fee trial contracts using tiny authored trees, never Docker or model I/O."""

import json
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import httpx

from agent.evaluation import swebench_observer as observer
from agent.evaluation.swebench_trial import prepare_trial, load_trial, run_trial, check_trial, SOURCE
from agent.evaluation.swebench_instance import admit_swebench_instance
from agent.common.entities import AtomicTask, ImplementationTask, ImplementationPlan, PlanStatus
from agent.workspace import WorkspacePathResolver
from agent.verification.contracts import (
    REPORT_SCHEMA, VerificationCase, VerificationCaseStatus,
    VerificationReport, VerificationSummary, VerificationCheckStatus,
)


ROOT = Path(__file__).resolve().parents[2]
ENVIRONMENT = {"AGENT_MODEL_PROVIDER": "deepseek", "AGENT_MODEL": "deepseek-flash",
               "AGENT_MODEL_BASE_URL": "https://api.deepseek.com", "DEEPSEEK_API_KEY": "author-fixture-key"}


class CooperativeTrialTests(unittest.TestCase):
    def test_hinted_reader_limits_observations_to_the_same_source_identity(self):
        from agent.evaluation.swebench_context import cooperative_source_reader
        from agent.workspace import workspace_root_scope

        _, setup, _ = self.prepare("hinted-reads")
        with workspace_root_scope(setup.generation_root):
            for path in (SOURCE, SOURCE.replace("/", "\\"), "./" + SOURCE, "workspace_repo/" + SOURCE):
                result = cooperative_source_reader.invoke({"file_path": path})
                self.assertTrue(result["ok"], result)
                self.assertEqual(result["content"], "class Printable:\n    pass\n")
                self.assertEqual(result["content_hash"], hashlib.sha256(result["content"].encode()).hexdigest())
            for path in ("sympy/core/basic.py", "sympy/core/symbol.py", observer.TEST,
                         "../" + SOURCE, str(setup.generation_root / SOURCE)):
                result = cooperative_source_reader.invoke({"file_path": path})
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["error_code"], "cooperative_read_scope")
                self.assertNotIn("content", result)

    def test_hinted_reader_refuses_ranges_oversize_and_protected_source(self):
        from agent.evaluation.swebench_context import cooperative_source_reader, MAX_SOURCE_BYTES
        from agent.workspace import WorkspaceAccessPolicy, workspace_root_scope

        _, setup, _ = self.prepare("hinted-limits")
        with workspace_root_scope(setup.generation_root):
            for args in ({"start_byte": 1}, {"start_byte": True}, {"end_byte": 3000}, {"cursor": "page"}):
                result = cooperative_source_reader.invoke({"file_path": SOURCE, **args})
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["error_code"], "cooperative_read_range")
            (setup.generation_root / SOURCE).write_bytes(b"a" * MAX_SOURCE_BYTES)
            self.assertTrue(cooperative_source_reader.invoke({"file_path": SOURCE})["ok"])
            (setup.generation_root / SOURCE).write_bytes(b"a" * (MAX_SOURCE_BYTES + 1))
            result = cooperative_source_reader.invoke({"file_path": SOURCE})
            self.assertEqual(result["error_code"], "cooperative_read_size")
            self.assertNotIn("content", result)
        with workspace_root_scope(setup.generation_root, access_policy=WorkspaceAccessPolicy(hidden_paths=(SOURCE,))):
            result = cooperative_source_reader.invoke({"file_path": SOURCE})
            self.assertFalse(result["ok"], result)
            self.assertEqual(result["error_code"], "read_denied")

    def test_hinted_reader_toolnode_preserves_staged_view_and_call_identity(self):
        from langchain_core.messages import AIMessage
        from langgraph.graph import StateGraph, START, END
        from langgraph.prebuilt import ToolNode
        from agent.common.tool_message_renderer import render_tool_messages
        from agent.developer.state import SoftwareDeveloperState
        from agent.editing import EditOperation, EditProposal, WorkspaceEditor
        from agent.evaluation.swebench_context import cooperative_source_reader
        from agent.workspace import workspace_root_scope

        _, setup, _ = self.prepare("hinted-staged")
        with workspace_root_scope(setup.generation_root):
            editor = WorkspaceEditor(setup.generation_root)
            transaction = editor.begin(SOURCE).transaction
            staged = editor.stage(transaction, EditProposal(task_id="hinted.step-1", path=SOURCE,
                operation=EditOperation.EDIT, old_text="pass", new_text="__slots__ = ()", base_hash=transaction.base_hash))
            self.assertTrue(staged.ok, staged)
            call = AIMessage(content="", tool_calls=[{"name": "get_raw_file_content", "args": {"file_path": SOURCE},
                "id": "hinted-read-1", "type": "tool_call"}])
            graph = StateGraph(SoftwareDeveloperState)
            graph.add_node("tools", ToolNode([cooperative_source_reader], messages_key="atomic_implementation_research"))
            graph.add_edge(START, "tools")
            graph.add_edge("tools", END)
            result = graph.compile().invoke({"atomic_implementation_research": [call],
                "current_file_transaction": staged.transaction})
            message = result["atomic_implementation_research"][-1]
            evidence = json.loads(message.content)
            self.assertEqual(message.tool_call_id, "hinted-read-1")
            self.assertEqual(evidence["view"], "working")
            self.assertIn("__slots__ = ()", evidence["content"])
            self.assertEqual(evidence["content_hash"], hashlib.sha256(evidence["content"].encode()).hexdigest())
            self.assertIn("pass", (setup.generation_root / SOURCE).read_text())
            rendered = render_tool_messages([call, message])
            self.assertIn("[UNTRUSTED EVIDENCE]", rendered[-1].content)
            self.assertIn("__slots__ = ()", rendered[-1].content)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.enterContext(patch("agent.evaluation.swebench_trial.source_pins", return_value={"author-fixture": "0" * 64}))
        asset = json.loads((ROOT / "evals/swebench/sympy__sympy-20590.json").read_text())
        self.instance = admit_swebench_instance(
            asset["row"], expected_sha256=asset["provenance"]["canonical_row_sha256"],
            editable_paths=(SOURCE,), oracle_paths=(observer.TEST,),
        ).instance

    def prepare(self, name="trial"):
        root = self.directory / name
        setup = observer.assemble_cooperative_workspace(
            root, instance=self.instance,
            source_files={SOURCE: b"class Printable:\n    pass\n", "sympy/__init__.py": b"# author data only\n"},
            dependency_files={"mpmath/__init__.py": b"# author dependency data only\n"},
            source_test_bytes=b"# author oracle data, never executed by these tests\n",
        )
        with patch.object(observer, "prepare_cooperative_workspace", return_value=setup):
            plan = prepare_trial(root, artifacts_root=self.directory / "unused-artifacts")
        return root, setup, plan

    def test_prepare_load_is_no_fee_and_model_visibility_excludes_evaluator_bodies(self):
        root, setup, plan = self.prepare()
        self.assertEqual(load_trial(root), (root.resolve(), plan))
        self.assertEqual(plan["task"], self.instance.problem_statement)
        self.assertEqual(plan["allowed_edit_scope"], [SOURCE])
        self.assertFalse(plan["adversarial_proof"])
        self.assertTrue(plan["hinted_scope"])
        self.assertFalse(setup.manifest["source_verified"])
        self.assertFalse((root / "spend.jsonl").exists())
        self.assertFalse((root / "runtime").exists())
        self.assertFalse((setup.generation_root / observer.TEST).exists())

    def test_actual_run_requires_fresh_budget_and_consumes_only_its_claim(self):
        root, _, _ = self.prepare()
        with patch("agent.evaluation.swebench_trial.docker_ready", side_effect=AssertionError("Docker is forbidden")):
            result = run_trial(root, environ=ENVIRONMENT)
        self.assertEqual(result["status"], "NOT_STARTED")
        self.assertEqual(result["not_started_reason"], "NEW_BATCH_BUDGET_REQUIRED")
        self.assertEqual(result["paid_requests"], 0)
        self.assertFalse((root / "spend.jsonl").exists())
        self.assertNotIn("author-fixture-key", (root / "execution.json").read_text())
        with self.assertRaises(FileExistsError):
            run_trial(root, environ=ENVIRONMENT, new_batch_budget_cny="1")

    def test_network_transport_cannot_masquerade_as_a_no_fee_control(self):
        root, _, _ = self.prepare()
        with httpx.HTTPTransport(retries=0) as transport, patch(
            "agent.evaluation.swebench_trial.docker_ready", side_effect=AssertionError("No dispatch is allowed")):
            result = run_trial(root, environ=ENVIRONMENT, transport=transport)
        self.assertEqual(result["status"], "NOT_STARTED")
        self.assertEqual(result["not_started_reason"], "UNSUPPORTED_CONTROL_TRANSPORT")
        self.assertFalse((root / "spend.jsonl").exists())

    def test_typed_nested_source_plan_is_allowed_for_the_actual_workspace_file(self):
        from agent.evaluation.swebench_trial import cooperative_plan_allowed

        _, setup, _ = self.prepare("canonical-source")
        original = (setup.baseline_root / SOURCE).read_bytes()
        for path in (SOURCE, SOURCE.replace("/", "\\"), "./" + SOURCE, "workspace_repo/" + SOURCE):
            plan = ImplementationPlan(tasks=[ImplementationTask(file_path=path,
                logical_task="Correct the actual source", atomic_tasks=[AtomicTask(atomic_task="Set empty slots")])])
            self.assertTrue(cooperative_plan_allowed(plan), path)
            resolved = WorkspacePathResolver(setup.generation_root).resolve_file(path, allow_absolute=False)
            self.assertTrue(resolved.ok, path)
            self.assertEqual(resolved.path.read_bytes(), original)

    def test_typed_plan_rejects_other_oracle_escaping_absolute_and_multiple_edits(self):
        from agent.evaluation.swebench_trial import cooperative_plan_allowed

        def task(path=SOURCE, count=1):
            return ImplementationTask(file_path=path, logical_task="One scoped correction",
                atomic_tasks=[AtomicTask(atomic_task="Set empty slots")] * count)

        for path in ("sympy/__init__.py", observer.TEST, "../" + SOURCE, "/" + SOURCE,
                     "C:/outside.py", "sympy/core/../core/_print_helpers.py"):
            self.assertFalse(cooperative_plan_allowed(ImplementationPlan(tasks=[task(path)])), path)
        for plan in (ImplementationPlan(tasks=[]), ImplementationPlan(tasks=[task(), task()]),
                     ImplementationPlan(tasks=[task(count=0)]), ImplementationPlan(tasks=[task(count=2)]),
                     ImplementationPlan(status=PlanStatus.NO_CHANGES, tasks=[task()]), {"tasks": [task()]}):
            self.assertFalse(cooperative_plan_allowed(plan))

    def test_actual_budget_authorization_is_normalized_and_controls_do_not_claim_it(self):
        root, _, _ = self.prepare("authorized-budget")
        result = run_trial(root, environ={}, new_batch_budget_cny="0.950000", cli_budget_limit_cny="1.000")
        self.assertEqual(result["new_batch_budget_cny"], "0.95")
        self.assertEqual(result["cli_budget_limit_cny"], "1")
        self.assertEqual(result["not_started_reason"], "MISSING_CREDENTIAL")
        self.assertFalse((root / "spend.jsonl").exists())
        root, _, _ = self.prepare("control-budget")
        import httpx
        result = run_trial(root, environ={}, transport=httpx.MockTransport(lambda _: self.fail("No HTTP")),
                           new_batch_budget_cny="1", cli_budget_limit_cny="1")
        self.assertNotIn("new_batch_budget_cny", result)
        self.assertNotIn("cli_budget_limit_cny", result)

    def test_invalid_model_configuration_stays_not_started_without_spend(self):
        for index, environment in enumerate(({}, {**ENVIRONMENT, "AGENT_MODEL": "wrong"},
                                              {**ENVIRONMENT, "AGENT_MODEL_PROVIDER": "unsupported"})):
            root, _, _ = self.prepare(str(index))
            with patch("agent.evaluation.swebench_trial.docker_ready", side_effect=AssertionError("Docker is forbidden")):
                result = run_trial(root, environ=environment, new_batch_budget_cny="1")
            self.assertEqual(result["status"], "NOT_STARTED", result)
            self.assertIn(result["not_started_reason"], {"MISSING_CREDENTIAL", "MODEL_CONFIGURATION_MISMATCH"})
            self.assertFalse((root / "spend.jsonl").exists())

    def test_invalid_or_insufficient_fresh_budget_never_creates_ledger_or_transport(self):
        for index, amount in enumerate(("0", "0.9", "NaN", "Infinity", True, "1.01")):
            root, _, _ = self.prepare("budget-" + str(index))
            with patch("agent.evaluation.swebench_trial.docker_ready", side_effect=AssertionError("no Docker")), \
                 patch("httpx.HTTPTransport", side_effect=AssertionError("no transport")):
                result = run_trial(root, environ=ENVIRONMENT, new_batch_budget_cny=amount)
            self.assertEqual(result["status"], "NOT_STARTED", result)
            self.assertFalse((root / "spend.jsonl").exists())
            self.assertEqual(result["paid_requests"], 0)

    def test_check_is_explicitly_no_dispatch_and_author_data_is_not_a_paid_source(self):
        root, _, _ = self.prepare("check")
        result = check_trial(root, environ=ENVIRONMENT)
        self.assertEqual(result["not_started_reason"], "CHECK_ONLY_NO_PAID_DISPATCH")
        self.assertTrue(result["kind"].startswith("COOPERATIVE_SWEBENCH_"))
        self.assertFalse((root / "spend.jsonl").exists())
        root, _, _ = self.prepare("author-source")
        result = run_trial(root, environ=ENVIRONMENT, new_batch_budget_cny="1")
        self.assertEqual(result["not_started_reason"], "OFFICIAL_SOURCE_NOT_VERIFIED")
        self.assertFalse((root / "spend.jsonl").exists())

    def test_resealed_plan_mutation_and_original_candidate_changes_are_rejected(self):
        for index, field in enumerate(("task", "source_pins", "model_policy", "adversarial_proof")):
            root, _, plan = self.prepare("mutation-" + str(index))
            plan.pop("plan_digest")
            plan[field] = "mutated"
            plan["plan_digest"] = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            (root / "plan.json").write_text(json.dumps(plan))
            with self.assertRaises(ValueError):
                load_trial(root)
            result = run_trial(root, environ=ENVIRONMENT, new_batch_budget_cny="1")
            self.assertEqual(result["not_started_reason"], "FROZEN_INPUT_CHANGED")
            self.assertFalse((root / "spend.jsonl").exists())
        root, setup, _ = self.prepare("candidate-drift")
        (setup.generation_root / SOURCE).write_bytes(b"class Printable:\n    __slots__ = ()\n")
        with self.assertRaises(ValueError):
            load_trial(root)
        self.assertEqual(run_trial(root, environ=ENVIRONMENT)["not_started_reason"], "FROZEN_INPUT_CHANGED")

    def test_revision_and_price_guards_precede_any_paid_ledger(self):
        from agent.runtime.revision import AgentCodeRevision, AgentRevisionReason, AgentRevisionStatus

        for index, status in enumerate((AgentRevisionStatus.UNKNOWN, AgentRevisionStatus.KNOWN)):
            root, setup, _ = self.prepare("guard-" + str(index))
            # Stub the separate official-source verifier only to isolate these
            # admission gates. This author fixture is never an official proof.
            setup.manifest["source_verified"] = True
            original = (setup.baseline_root / SOURCE).read_bytes()
            revision = (AgentCodeRevision(None, status, AgentRevisionReason.DIRTY)
                        if status is AgentRevisionStatus.UNKNOWN else AgentCodeRevision("a" * 40, status))
            with patch.object(observer, "load_cooperative_workspace", return_value=setup), \
                 patch.object(observer, "validate_frozen_inputs", return_value=None), \
                 patch.object(observer, "candidate_source", return_value=original), \
                 patch("agent.evaluation.swebench_trial.detect_agent_code_revision", return_value=revision), \
                 patch("agent.evaluation.swebench_trial.datetime") as clock, \
                 patch("agent.evaluation.swebench_trial.docker_ready", side_effect=AssertionError("no Docker")):
                with patch.object(observer, "prepare_cooperative_workspace", return_value=setup):
                    (root / "plan.json").unlink()
                    prepare_trial(root, artifacts_root=self.directory)
                clock.now.return_value.date.return_value.isoformat.return_value = "1900-01-01"
                result = run_trial(root, environ=ENVIRONMENT, new_batch_budget_cny="1")
            self.assertEqual(result["status"], "NOT_STARTED")
            self.assertEqual(result["not_started_reason"], "AGENT_REVISION_NOT_CLEAN" if index == 0 else "PRICING_RECHECK_REQUIRED")
            self.assertFalse((root / "spend.jsonl").exists())

    def test_bound_grading_accepts_final_repair_but_rejects_identity_or_process_errors(self):
        from agent.evaluation.swebench_trial import grade_bound_attempts

        ids = self.instance.fail_to_pass + self.instance.pass_to_pass

        def summary(baseline=False, error=False, regression=False):
            cases = tuple(VerificationCase("sympy-cooperative", f"test_observer::test_case[{case}]",
                          VerificationCaseStatus.FAIL if ((baseline and case in self.instance.fail_to_pass)
                          or (regression and case == self.instance.pass_to_pass[0])) else VerificationCaseStatus.PASS)
                          for case in ids)
            return VerificationSummary("sympy-cooperative", ("author-observer",), ".",
                VerificationCheckStatus.EXECUTION_ERROR if error else VerificationCheckStatus.FAIL if baseline or regression else VerificationCheckStatus.PASS,
                None if error else 1 if baseline or regression else 0, report=VerificationReport("sympy-cooperative", REPORT_SCHEMA, cases))

        attempts = [SimpleNamespace(attempt_id="baseline", phase="baseline", repair_attempt=0, result=summary(True)),
                    SimpleNamespace(attempt_id="post-0", phase="post", repair_attempt=0, result=summary(regression=True)),
                    SimpleNamespace(attempt_id="post-1", phase="post", repair_attempt=1, result=summary())]
        bound = [{"attempt_id": item.attempt_id, "phase": item.phase, "repair_attempt": item.repair_attempt,
                  "receipt": {"source_hash": "final" if item.attempt_id == "post-1" else "earlier"}}
                 for item in attempts]
        state = {"verification_attempts": tuple(attempts)}
        self.assertTrue(grade_bound_attempts(self.instance, state, bound, "final").resolved)
        for bad in (bound[:-1], [bound[0], bound[2]], bound + [bound[-1]]):
            with self.assertRaises(ValueError):
                grade_bound_attempts(self.instance, state, bad, "final")
        with self.assertRaises(ValueError):
            grade_bound_attempts(self.instance, state, bound, "different-source-hash")
        attempts[-1].phase = "baseline"
        with self.assertRaises(ValueError):
            grade_bound_attempts(self.instance, state, bound, "final")
        attempts[-1].phase = "post"
        attempts[-1].result = summary(error=True)
        with self.assertRaises(ValueError):
            grade_bound_attempts(self.instance, state, bound, "final")

    def test_public_cli_help_explains_separate_prepare_check_run_and_fresh_budget(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/swebench_pilot.py"), "--help"],
                                capture_output=True, timeout=30, shell=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        text = result.stdout.decode()
        for option in ("--prepare", "--check", "--run", "--new-batch-budget-cny", "--env-file"):
            self.assertIn(option, text)


if __name__ == "__main__":
    unittest.main()
