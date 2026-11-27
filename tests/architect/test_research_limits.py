"""Research turn allocation is routing, not permission to invent a plan."""
import unittest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command, interrupt
from agent.runtime.checkpointing import checkpoint_serializer
from agent.architect.graph import create_architect_workflow
from agent.architect.runtime import ArchitectRuntime
from agent.architect.models import ResearchStep, ResearchEvaluation
from agent.common.entities import ImplementationPlan, PlanStatus
from agent.architect.state import SoftwareArchitectState
from agent.runtime import BudgetSnapshot, DurableBudgetBoundary, ModelCallResult, UsageMeasurement, UsageStatus, BudgetErrorCode, capture_model_exception


def measured(value):
    return ModelCallResult(value=value,usage=UsageMeasurement(UsageStatus.PARTIAL,1,1,2,None,None),response_digest='d'*64)


class ResearchLimitsTests(unittest.TestCase):
    def test_checkpoint_state_rejects_invalid_counter_values(self):
        # Counters belong to checkpoint state, not the public start-input schema.
        for key,value in (('hypothesis_attempts',-1),('research_turns',True),
                ('research_turns','1'),('hypothesis_attempts',1.5)):
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                SoftwareArchitectState.model_validate({key:value})

    def test_limits_reject_non_integer_or_non_positive_configuration(self):
        for limit in (True,0,-1,1.2,'1',101):
            with self.subTest(limit=limit),self.assertRaises(ValueError):
                create_architect_workflow(research_round_limit=limit)

    def test_completed_subgraph_checkpoints_keep_counters_policy_and_tool_pairs(self):
        @tool
        def inspect_checkpoint() -> str:
            """Return bounded evidence."""
            return 'evidence'
        child=create_architect_workflow(self.runtime(lambda _:measured(AIMessage('',tool_calls=[
            {'name':'inspect_checkpoint','args':{},'id':'paired'}]))),research_tools=[inspect_checkpoint],
            research_round_limit=1,budget_boundary=DurableBudgetBoundary('checkpoint',clock=lambda:100.0))
        parent=StateGraph(SoftwareArchitectState)
        parent.add_node('architect',child);parent.add_edge(START,'architect');parent.add_edge('architect',END)
        saver=InMemorySaver(serde=checkpoint_serializer());app=parent.compile(checkpointer=saver)
        config={'configurable':{'thread_id':'bounded-checkpoint'}}
        app.invoke({'implementation_research_scratchpad':[HumanMessage('task')],
            'budget':BudgetSnapshot.create(max_steps=10,max_cost_usd=None,deadline_at=200.0)},config)
        checkpoints=[c.checkpoint['channel_values'] for c in saver.list(None)
            if c.config['configurable']['checkpoint_ns'].startswith('architect:')]
        completed=next(c for c in checkpoints if c.get('research_turns')==1
            and any(isinstance(m,ToolMessage) for m in c.get('implementation_research_scratchpad',())))
        self.assertEqual(completed['hypothesis_attempts'],1)
        self.assertEqual(completed['architect_research_policy'],'bounded-v1:1')
        restored=SoftwareArchitectState.model_validate(completed)
        self.assertEqual(restored.research_turns,1)
        calls=[call['id'] for m in restored.implementation_research_scratchpad if isinstance(m,AIMessage) for call in m.tool_calls]
        results=[m.tool_call_id for m in restored.implementation_research_scratchpad if isinstance(m,ToolMessage)]
        self.assertEqual(calls,results)

    def test_resume_rejects_changed_policy_before_an_interrupted_tool_runs_again(self):
        starts=[]
        @tool
        def controlled_pause() -> str:
            """Pause one tool for checkpoint testing."""
            starts.append('tool entered')
            return interrupt('resume tool')
        saver=InMemorySaver(serde=checkpoint_serializer())
        def assemble(limit):
            child=create_architect_workflow(self.runtime(lambda _:measured(AIMessage('',tool_calls=[
                {'name':'controlled_pause','args':{},'id':'pause'}]))),research_tools=[controlled_pause],
                research_round_limit=limit,budget_boundary=DurableBudgetBoundary('resume',clock=lambda:100.0))
            parent=StateGraph(SoftwareArchitectState)
            parent.add_node('architect',child);parent.add_edge(START,'architect');parent.add_edge('architect',END)
            return parent.compile(checkpointer=saver)
        config={'configurable':{'thread_id':'policy-drift'}}
        first=assemble(1).invoke({'implementation_research_scratchpad':[HumanMessage('task')],
            'budget':BudgetSnapshot.create(max_steps=10,max_cost_usd=None,deadline_at=200.0)},config)
        self.assertIn('__interrupt__',first)
        with self.assertRaisesRegex(ValueError,'Checkpoint research policy'):
            assemble(2).invoke(Command(resume='done'),config)
        self.assertEqual(starts,['tool entered'])

    def runtime(self, research, *, valid=True):
        return ArchitectRuntime(
            plan_next_step=lambda _:measured(ResearchStep(hypothesis='inspect',reasoning='r')),
            check_research_step=lambda _:measured(ResearchEvaluation(is_valid=valid,reasoning='r')),
            conduct_research=research,
            extract_implementation_plan=lambda _:measured(ImplementationPlan(status=PlanStatus.NO_CHANGES,
                tasks=[],no_change_reason='insufficient evidence')),load_codebase_structure=lambda:'app.py')

    def test_invalid_hypothesis_at_limit_reaches_real_extraction_without_research(self):
        runtime=self.runtime(lambda _:self.fail('Invalid research must not run'),valid=False)
        graph=create_architect_workflow(runtime,research_tools=[],research_round_limit=1,
            budget_boundary=DurableBudgetBoundary('invalid',clock=lambda:100.0))
        events=list(graph.stream({'implementation_research_scratchpad':[HumanMessage('task')],
            'budget':BudgetSnapshot.create(max_steps=10,max_cost_usd=None,deadline_at=200.0)},stream_mode='updates'))
        names=[next(iter(e)) for e in events]
        self.assertNotIn('conduct_research',names)
        self.assertIn('extract_implementation_plan',names)
        self.assertFalse(next(e['check_research_step']['is_valid_research_step'] for e in events if 'check_research_step' in e))
        self.assertEqual(next(e['extract_implementation_plan']['implementation_plan'].status for e in events if 'extract_implementation_plan' in e),PlanStatus.NO_CHANGES)

    def test_model_unknown_and_budget_denial_never_route_to_extraction(self):
        for maximum,response in ((2,measured(AIMessage('not reached'))),
                (10,capture_model_exception(BudgetErrorCode.MODEL_TRANSPORT_ERROR))):
            with self.subTest(maximum=maximum):
                graph=create_architect_workflow(self.runtime(lambda _:response),research_tools=[],research_round_limit=1,
                    budget_boundary=DurableBudgetBoundary('failed',clock=lambda:100.0))
                events=list(graph.stream({'implementation_research_scratchpad':[HumanMessage('task')],
                    'budget':BudgetSnapshot.create(max_steps=maximum,max_cost_usd=None,deadline_at=200.0)},stream_mode='updates'))
                self.assertNotIn('extract_implementation_plan',[next(iter(e)) for e in events])

    def test_tool_error_is_recorded_and_settled_then_stops_without_extraction(self):
        graph=create_architect_workflow(self.runtime(lambda _:measured(AIMessage('',tool_calls=[
            {'name':'unknown_tool','args':{},'id':'missing'}]))),research_tools=[],research_round_limit=1,
            budget_boundary=DurableBudgetBoundary('tool-error',clock=lambda:100.0))
        events=list(graph.stream({'implementation_research_scratchpad':[HumanMessage('task')],
            'budget':BudgetSnapshot.create(max_steps=10,max_cost_usd=None,deadline_at=200.0)},stream_mode='updates'))
        names=[next(iter(e)) for e in events]
        self.assertIn('record_tool_results',names);self.assertIn('settle_tools',names)
        self.assertNotIn('extract_implementation_plan',names)
        final=events[-1]['settle_tools']['budget']
        self.assertFalse(final.active);self.assertEqual(final.reservations[-1].status.value,'failed')

    def test_bounded_graph_finishes_all_tools_before_extracting(self):
        observed=[]
        @tool
        def inspect_source() -> str:
            """Read source evidence."""
            observed.append('tool');return 'source evidence'
        def extract(values):
            self.assertEqual(observed,['tool','tool'])
            self.assertIn('source evidence',str(values['research_findings']))
            return measured(ImplementationPlan(status=PlanStatus.NO_CHANGES,tasks=[],no_change_reason='insufficient evidence'))
        runtime=ArchitectRuntime(
            plan_next_step=lambda _:measured(ResearchStep(hypothesis='inspect',reasoning='r')),
            check_research_step=lambda _:measured(ResearchEvaluation(is_valid=True,reasoning='r')),
            conduct_research=lambda _:measured(AIMessage(content='',tool_calls=[
                {'name':'inspect_source','args':{},'id':'read-a'},
                {'name':'inspect_source','args':{},'id':'read-b'}])),
            extract_implementation_plan=extract,load_codebase_structure=lambda:'app.py')
        graph=create_architect_workflow(runtime,research_tools=[inspect_source],research_round_limit=1,
            budget_boundary=DurableBudgetBoundary('bounded',clock=lambda:100.0))
        events=list(graph.stream({'implementation_research_scratchpad':[HumanMessage('task')],
            'budget':BudgetSnapshot.create(max_steps=20,max_cost_usd=None,deadline_at=200.0)},stream_mode='updates'))
        names=[next(iter(e)) for e in events]
        self.assertEqual(names.count('conduct_research'),1)
        self.assertLess(names.index('settle_tools'),names.index('reserve_extract_implementation_plan'))
        final=events[-1]['settle_extract_implementation_plan']['budget']
        self.assertFalse(final.active);self.assertFalse(final.has_unknown_outcome)
        self.assertEqual(len(final.reservations),6)
