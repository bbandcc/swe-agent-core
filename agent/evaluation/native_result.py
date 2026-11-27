"""Validate externally bound native evidence; never attest or admit execution.

The caller must obtain lifecycle facts and expected identities independently of
candidate output. These data checks cannot prevent a candidate forging its log.
"""
from dataclasses import dataclass
import re

from agent.evaluation.native_log import NativeLogResult, parse_native_log
from agent.evaluation.native_task_spec import NativeTaskSpec


@dataclass(frozen=True, slots=True)
class NativeAttemptIdentity:
    task_id: str
    row_sha256: str
    image: str
    environment_sha256: str
    source_sha256: str
    attempt_id: str
    phase: str
    repair_attempt: int

    def __post_init__(self):
        if (type(self.task_id) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{1,200}', self.task_id)
                or type(self.image) is not str or len(self.image) > 4096
                or not re.fullmatch(r'[a-z0-9][a-z0-9._:/-]*@sha256:[a-f0-9]{64}', self.image)
                or any(type(v) is not str or not re.fullmatch(r'[a-f0-9]{64}', v)
                       for v in (self.row_sha256, self.environment_sha256, self.source_sha256))
                or type(self.attempt_id) is not str or not re.fullmatch(r'[a-f0-9]{32}', self.attempt_id)
                or self.phase not in ('baseline', 'post') or type(self.repair_attempt) is not int
                or not 0 <= self.repair_attempt <= 2
                or self.phase == 'baseline' and self.repair_attempt != 0):
            raise ValueError('Invalid native attempt identity')


@dataclass(frozen=True, slots=True)
class NativeAttemptResult:
    identity: NativeAttemptIdentity
    parsed: NativeLogResult
    exit_code: int | None
    issues: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.issues


@dataclass(frozen=True, slots=True)
class NativeTransitionResult:
    resolved: bool
    issues: tuple[str, ...]


def _roster(spec: NativeTaskSpec) -> tuple[str, ...]:
    if type(spec) is not NativeTaskSpec:
        raise ValueError('An externally prepared native task spec is required')
    # The parser validates the complete exact roster, even on lifecycle failure.
    return spec.fail_to_pass + spec.pass_to_pass


def _case_issues(parsed: NativeLogResult, roster: tuple[str, ...], exit_code) -> set[str]:
    issues = set(parsed.issues)
    if not parsed.complete:
        issues.add('incomplete_native_log')
    if tuple(case for case, _ in parsed.cases) != roster:
        issues.add('case_roster_mismatch')
    if (tuple(case for case, _ in parsed.case_origins) != roster
            or any(type(origin) is not str or not origin for _, origin in parsed.case_origins)):
        issues.add('case_origin_missing')
    if any(status not in ('PASSED', 'FAILED') for _, status in parsed.cases):
        issues.add('non_binary_case_status')
    all_passed = all(status == 'PASSED' for _, status in parsed.cases)
    if parsed.strict_passed != (parsed.complete and all_passed):
        issues.add('inconsistent_parser_result')
    if type(exit_code) is not int or exit_code not in (0, 1):
        issues.add('execution_exit_error')
    elif exit_code != int(not all_passed):
        issues.add('exit_case_mismatch')
    return issues


def validate_native_attempt(spec: NativeTaskSpec, observed_identity: NativeAttemptIdentity, *,
                            expected_identity: NativeAttemptIdentity, log: str,
                            exit_code: int | None, completed: bool,
                            cleanup_complete: bool) -> NativeAttemptResult:
    """Validate one observation against the caller's independent expected pins.

    An ordinary baseline test failure can be valid evidence, but is never a
    successful transition by itself. Timeout, skipped/error cases and cleanup
    uncertainty fail closed. No Docker or host code is executed here.
    """
    roster = _roster(spec)
    if type(expected_identity) is not NativeAttemptIdentity or type(observed_identity) is not NativeAttemptIdentity:
        raise ValueError('Exact native identities required')
    if (expected_identity.task_id != spec.instance_id
            or expected_identity.row_sha256 != spec.row_sha256):
        raise ValueError('Expected identity does not belong to the prepared task')
    parsed = parse_native_log(spec.parser_id, log, roster)
    issues = _case_issues(parsed, roster, exit_code)
    if observed_identity != expected_identity:
        issues.add('attempt_identity_mismatch')
    if completed is not True:
        issues.add('execution_incomplete')
    if cleanup_complete is not True:
        issues.add('cleanup_unknown')
    return NativeAttemptResult(observed_identity, parsed, exit_code, tuple(sorted(issues)))


def grade_native_attempts(spec: NativeTaskSpec,
                          attempts: tuple[NativeAttemptResult, ...]) -> NativeTransitionResult:
    """Grade one baseline and 1..3 consecutive posts from already bound evidence.

    All attempted repairs must be present, with one environment and the same
    raw test origins. This does not bind SQLite/RunRecords or authenticate logs;
    a future concrete runner must perform those independent checks as well.
    """
    roster = _roster(spec)
    if (type(attempts) is not tuple or not 2 <= len(attempts) <= 4
            or any(type(a) is not NativeAttemptResult
                   or type(a.identity) is not NativeAttemptIdentity
                   or type(a.parsed) is not NativeLogResult for a in attempts)):
        return NativeTransitionResult(False, ('attempt_sequence_invalid',))
    issues = set()
    before, after = attempts[0], attempts[-1]
    if before.identity.source_sha256 == after.identity.source_sha256:
        issues.add('unchanged_final_source')
    if (before.identity.phase != 'baseline' or before.identity.repair_attempt != 0
            or any(a.identity.phase != 'post' or a.identity.repair_attempt != i
                   for i, a in enumerate(attempts[1:]))
            or len({a.identity.attempt_id for a in attempts}) != len(attempts)):
        issues.add('attempt_sequence_invalid')
    for attempt in attempts:
        identity = attempt.identity
        if (identity.task_id != spec.instance_id or identity.row_sha256 != spec.row_sha256
                or identity.image != before.identity.image
                or identity.environment_sha256 != before.identity.environment_sha256):
            issues.add('cross_attempt_identity_mismatch')
        if attempt.issues or _case_issues(attempt.parsed, roster, attempt.exit_code):
            issues.add('invalid_attempt_evidence')
        if attempt.parsed.case_origins != before.parsed.case_origins:
            issues.add('cross_attempt_origin_mismatch')
    old, new = dict(before.parsed.cases), dict(after.parsed.cases)
    # S2 only repairs regressions against the original baseline. An unchanged
    # failure or an already successful post cannot authorize another attempt.
    for intermediate in attempts[1:-1]:
        current = dict(intermediate.parsed.cases)
        if not any(status == 'PASSED' and current.get(case) != 'PASSED'
                   for case, status in old.items()):
            issues.add('repair_without_regression')
    if not spec.fail_to_pass or any(old.get(c) != 'FAILED' or new.get(c) != 'PASSED' for c in spec.fail_to_pass):
        issues.add('f2p_transition')
    if any(old.get(c) != 'PASSED' or new.get(c) != 'PASSED' for c in spec.pass_to_pass):
        issues.add('p2p_transition')
    return NativeTransitionResult(not issues, tuple(sorted(issues)))
