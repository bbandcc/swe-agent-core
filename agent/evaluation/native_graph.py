"""Production graph assembly with one concrete cooperative native Requests observer."""
from agent.evaluation.native_runner import NativeAdmission, NativeRequestsRunner
from agent.evaluation.repository_runtime import RepositoryRuntimes


def native_graph_factory(runner, identity, event_sink, runtimes):
    """Return the durable graph seam; no provider, workspace or sink globals."""
    if type(runner) is not NativeRequestsRunner or type(runtimes) is not RepositoryRuntimes:
        raise ValueError('Concrete repository dependencies required')

    def factory(config, run_id, saver, clock):
        from agent.architect.graph import create_architect_workflow
        from agent.developer.graph import create_developer_workflow
        from agent.graph import create_workflow_graph
        from agent.runtime.boundary import DurableBudgetBoundary
        from agent.runtime.secrets import KnownSecretFilter
        from agent.runtime.trajectory import EventRecorder
        if (run_id != identity.run_id or config.workspace_root != runner.generation_root
                or config.runtime_root != runner.runtime_root
                or tuple(config.verification_specs) != (runner.spec,)
                or config.access_policy != runtimes.access_policy):
            raise ValueError('Repository graph identity/configuration mismatch')
        boundary = DurableBudgetBoundary(run_id, clock=clock,
            model_request_timeout_seconds=config.model_request_timeout_seconds)
        secrets = KnownSecretFilter.from_run_config(config)
        recorder = EventRecorder(event_sink, run_id=run_id, thread_id=identity.thread_id,
            task_id=identity.task_id, secret_filter=secrets, clock=clock)
        common = dict(research_tools=list(runtimes.tools), budget_boundary=boundary,
            secret_filter=secrets, event_recorder=recorder, access_policy=config.access_policy)
        return create_workflow_graph(
            architect=create_architect_workflow(runtimes.architect, **common),
            developer=create_developer_workflow(runtimes.developer, **common),
            verification_specs=config.verification_specs, verification_runner=runner,
            workspace_root=config.workspace_root, runtime_root=config.runtime_root,
            durable_runtime=True, clock=clock, secret_filter=secrets, event_recorder=recorder,
            access_policy=config.access_policy, reviewed_inputs=NativeAdmission(runner),
        ).compile(checkpointer=saver)
    return factory
