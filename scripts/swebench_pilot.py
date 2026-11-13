"""Prepare/check/run one cooperative hinted SWE-bench research trial."""

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--prepare", action="store_true", help="Prepare local pinned inputs without model/Docker calls")
    modes.add_argument("--check", action="store_true", help="Consume one check-only attempt; a later run needs fresh preparation")
    modes.add_argument("--run", action="store_true", help="Run once; requires an explicitly authorized fresh budget")
    parser.add_argument("--artifacts-root", type=Path, help="Pinned local official artifacts, needed only for preparation")
    parser.add_argument("--env-file", type=Path, help="Existing configuration file; process environment takes precedence")
    parser.add_argument("--new-batch-budget-cny", help="New authorization for this trial; previous budgets are never reused")
    parser.add_argument("--max-trial-cny", default="1", help="Explicit per-trial ceiling, at most 1 CNY (default: 1)")
    args = parser.parse_args(argv)
    try:
        from agent.evaluation.swebench_trial import prepare_trial, check_trial, run_trial

        if args.prepare:
            if args.artifacts_root is None or args.env_file is not None or args.new_batch_budget_cny is not None:
                raise ValueError("Preparation needs artifacts, without credentials or a paid budget.")
            result = prepare_trial(args.output, artifacts_root=args.artifacts_root)
        else:
            if args.artifacts_root is not None or (args.check and args.new_batch_budget_cny is not None):
                raise ValueError("Artifact selection is preparation-only; a check does not authorize spending.")
            from dotenv import dotenv_values

            config = args.env_file if args.env_file is not None else Path(".env.local")
            if args.env_file is not None and not config.is_file():
                raise FileNotFoundError("The explicit configuration file does not exist.")
            environment = {key: value for key, value in {
                **dotenv_values(config, interpolate=False), **os.environ,
            }.items() if value is not None}
            result = (check_trial(args.output, environ=environment) if args.check else run_trial(
                args.output, environ=environment, new_batch_budget_cny=args.new_batch_budget_cny,
                cli_budget_limit_cny=args.max_trial_cny,
            ))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"kind": "COOPERATIVE_SWEBENCH_CLI_REJECTION", "status": "REJECTED",
                          "error_type": type(error).__name__}))
        return 2
    visible = {key: result[key] for key in (
        "kind", "status", "scope", "hinted_scope", "adversarial_proof", "scheduled", "started", "finished",
        "not_started_reason", "resolved", "paid_requests", "spend", "run_id", "record_ref", "cleanup_complete",
    ) if key in result}
    print(json.dumps(visible, ensure_ascii=False))
    if result["status"] == "PREPARED" or result.get("resolved") is True:
        return 0
    return 1 if result["status"] == "FINISHED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
