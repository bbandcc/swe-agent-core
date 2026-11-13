"""Concrete graph assembly for the cooperative SWE-bench research runner."""


from agent.evaluation.swebench_cooperative import CooperativeAdmission


def cooperative_graph_factory(runner, identity, event_sink, architect_runtime,
                              developer_runtime, *, research_tools=()):
    """Reuse the production graph with one identity, SQLite saver and recorder.

    This adapter is a cooperative, hinted one-file experiment. Its admission
    makes no adversarial isolation claim and does not add resume or retry.
    """
    from agent.architect.graph import create_architect_workflow
    from agent.developer.graph import create_developer_workflow
    from agent.graph import create_workflow_graph
    from agent.runtime.boundary import DurableBudgetBoundary
    from agent.runtime.secrets import KnownSecretFilter
    from agent.runtime.trajectory import EventRecorder

    tools = tuple(research_tools)

    def factory(config, run_id, saver, clock):
        if (run_id != identity.run_id or config.workspace_root != runner.generation_root
                or config.runtime_root != runner.runtime_root
                or tuple(config.verification_specs) != (runner.spec,)):
            raise ValueError("Cooperative graph identity/configuration mismatch.")
        boundary = DurableBudgetBoundary(
            run_id, clock=clock,
            model_request_timeout_seconds=config.model_request_timeout_seconds,
        )
        secrets = KnownSecretFilter.from_run_config(config)
        recorder = EventRecorder(event_sink, run_id=run_id, thread_id=identity.thread_id,
                                 task_id=identity.task_id, secret_filter=secrets, clock=clock)
        architect = create_architect_workflow(
            architect_runtime, research_tools=list(tools), budget_boundary=boundary,
            secret_filter=secrets, event_recorder=recorder, access_policy=config.access_policy,
        )
        developer = create_developer_workflow(
            developer_runtime, research_tools=list(tools), budget_boundary=boundary,
            secret_filter=secrets, event_recorder=recorder, access_policy=config.access_policy,
        )
        return create_workflow_graph(
            architect=architect, developer=developer, verification_specs=config.verification_specs,
            verification_runner=runner, workspace_root=config.workspace_root,
            runtime_root=config.runtime_root, durable_runtime=True, clock=clock,
            secret_filter=secrets, event_recorder=recorder, access_policy=config.access_policy,
            reviewed_inputs=CooperativeAdmission(runner),
        ).compile(checkpointer=saver)

    return factory
