"""Strict F2P/P2P transitions on externally trusted structured case evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agent.verification.contracts import (
    REPORT_SCHEMA,
    VerificationCase,
    VerificationCaseStatus,
    VerificationReport,
)

if TYPE_CHECKING:
    from agent.evaluation.swebench_instance import SwebenchInstance


@dataclass(frozen=True, slots=True)
class GradingIssue:
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class StrictGrade:
    resolved: bool
    fail_to_pass_passed: bool
    pass_to_pass_passed: bool | None
    issues: tuple[GradingIssue, ...] = ()


def grade_swebench_instance(
    instance: SwebenchInstance,
    baseline: VerificationReport | Sequence[VerificationCase] | None,
    post: VerificationReport | Sequence[VerificationCase] | None,
    *,
    case_id_mapping: Mapping[str, str] | None = None,
) -> StrictGrade:
    """Strict state transitions on trusted evidence, not execution attestation.

    Mapping keys are official IDs and values are exact report IDs. With no
    mapping, IDs must match exactly. Producers remain responsible for command,
    environment, process completion and report provenance outside this function.
    """
    try:
        if (not isinstance(getattr(instance, "fail_to_pass", None), tuple)
                or not isinstance(getattr(instance, "pass_to_pass", None), tuple)
                or not instance.fail_to_pass):
            raise ValueError("A nonempty admitted F2P instance is required.")
        expected = instance.fail_to_pass + instance.pass_to_pass
        if any(not isinstance(case, str) or not case for case in expected) or len(set(expected)) != len(expected):
            raise ValueError("Instance case identities must be disjoint and unique.")
        mapping = (
            {case: case for case in expected}
            if case_id_mapping is None else dict(case_id_mapping)
        )
        if (set(mapping) != set(expected)
                or any(not isinstance(value, str) or not value for value in mapping.values())
                or len(set(mapping.values())) != len(mapping)):
            raise ValueError("Explicit report mapping must be complete and one-to-one.")
        before_check, before = _report_cases(baseline)
        after_check, after = _report_cases(post)
        if (before_check != after_check or set(before) != set(mapping.values())
                or set(after) != set(mapping.values())):
            raise ValueError("Baseline and post must have the same exact mapped case roster and check identity.")
    except (TypeError, ValueError) as error:
        p2p = None if getattr(instance, "pass_to_pass", None) == () else False
        return StrictGrade(False, False, p2p, (GradingIssue("report_identity", str(error)),))
    f2p = all(before[mapping[case]] == VerificationCaseStatus.FAIL
              and after[mapping[case]] == VerificationCaseStatus.PASS
              for case in instance.fail_to_pass)
    p2p = (all(before[mapping[case]] == VerificationCaseStatus.PASS
               and after[mapping[case]] == VerificationCaseStatus.PASS
               for case in instance.pass_to_pass) if instance.pass_to_pass else None)
    issues = (() if f2p else (GradingIssue("f2p_transition", "Every F2P must change from FAIL to PASS."),))
    if p2p is False:
        issues += (GradingIssue("p2p_transition", "Every P2P must remain PASS."),)
    return StrictGrade(f2p and p2p is not False, f2p, p2p, issues)


def _report_cases(report: object) -> tuple[str, dict[str, VerificationCaseStatus]]:
    cases = report.cases if isinstance(report, VerificationReport) else report
    if not isinstance(cases, (list, tuple)) or not cases or len(cases) > 10_000:
        raise ValueError("A nonempty bounded structured report is required.")
    result: dict[str, VerificationCaseStatus] = {}
    check_id = cases[0].check_id if isinstance(cases[0], VerificationCase) else ""
    for case in cases:
        if not isinstance(case, VerificationCase) or case.report_schema != REPORT_SCHEMA:
            raise ValueError("Only supported structured VerificationCase values are accepted.")
        if case.case_id in result or case.check_id != check_id:
            raise ValueError("Duplicate case identities or mixed checks are rejected.")
        result[case.case_id] = case.status
    return check_id, result
