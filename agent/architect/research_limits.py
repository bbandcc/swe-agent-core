"""Checkpointed opt-in research routing; never alter model or tool evidence.

Reference: openai/openai-agents-python c6569cbd89526758c1ba14ce9fb55d3596c85065,
src/agents/run.py:601-610, bounds model turns before the next AI invocation.
This graph instead reserves a real extraction call after completed tools;
extraction may fail and is never an instruction to claim success.
"""


def validate_round_limit(limit: int | None) -> None:
    if limit is not None and (type(limit) is not int or not 1 <= limit <= 100):
        raise ValueError('Research round limit must be an integer in 1..100 or None')


def research_policy_update(state, limit: int | None) -> dict:
    policy = 'unbounded-v1' if limit is None else f'bounded-v1:{limit}'
    if state.architect_research_policy not in (None, policy):
        raise ValueError('Checkpoint research policy differs from the compiled graph')
    return {'architect_research_policy': policy}


def reached_research_limit(state, limit: int | None, *, hypothesis=False) -> bool:
    research_policy_update(state, limit)
    count = state.hypothesis_attempts if hypothesis else state.research_turns
    return limit is not None and count >= limit


def research_tools_failed(messages) -> bool:
    """Inspect only completed results belonging to the latest model tool batch."""
    for index in range(len(messages)-1, -1, -1):
        calls = getattr(messages[index], 'tool_calls', None)
        if calls:
            ids = {call['id'] for call in calls}
            return any(getattr(message, 'type', None) == 'tool'
                and getattr(message, 'tool_call_id', None) in ids
                and getattr(message, 'status', None) == 'error' for message in messages[index+1:])
    return False
