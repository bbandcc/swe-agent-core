"""Native result data contracts do not grant execution admission."""
from dataclasses import replace
import unittest

from agent.evaluation.native_result import (
    NativeAttemptIdentity, grade_native_attempts, validate_native_attempt,
)
from agent.evaluation.native_task_spec import NativeEnvironmentRequirements, NativeTaskSpec


class NativeResultTests(unittest.TestCase):
    def setUp(self):
        self.spec = NativeTaskSpec('psf__requests-3362', 'psf/requests', '2.10', '0'*40,
            'a'*64, '1'*40, NativeEnvironmentRequirements('3.9', 'testbed', ('pip',), (), ()),
            ('pytest',), (), 'pytest', ('tests/test_a.py',), ('tests/test_a.py',),
            '2'*64, ('f2p',), ('p2p',))
        self.before = NativeAttemptIdentity(self.spec.instance_id, self.spec.row_sha256,
            'swebench/image@sha256:'+'b'*64, 'c'*64, 'd'*64, '1'*32, 'baseline', 0)
        self.after = replace(self.before, source_sha256='e'*64, attempt_id='2'*32, phase='post')

    def attempt(self, identity, log, exit_code):
        return validate_native_attempt(self.spec, identity, expected_identity=identity,
            log=log, exit_code=exit_code, completed=True, cleanup_complete=True)

    def test_exact_completed_baseline_and_post_resolve(self):
        before = self.attempt(self.before, 'FAILED f2p\nPASSED p2p\n', 1)
        after = self.attempt(self.after, 'PASSED f2p\nPASSED p2p\n', 0)
        self.assertTrue(before.valid)
        self.assertTrue(after.valid)
        self.assertTrue(grade_native_attempts(self.spec, (before, after)).resolved)

    def test_unchanged_final_source_cannot_be_claimed_as_a_fix(self):
        before = self.attempt(self.before, 'FAILED f2p\nPASSED p2p\n', 1)
        after = self.attempt(replace(self.after, source_sha256=self.before.source_sha256),
            'PASSED f2p\nPASSED p2p\n', 0)
        self.assertFalse(grade_native_attempts(self.spec, (before, after)).resolved)

    def test_each_observed_identity_field_is_bound_to_external_expectation(self):
        changes = dict(task_id='another-task', row_sha256='3'*64,
            image='other/image@sha256:'+'4'*64, environment_sha256='5'*64,
            source_sha256='6'*64, attempt_id='7'*32, phase='baseline', repair_attempt=1)
        for field, value in changes.items():
            with self.subTest(field=field):
                observed = replace(self.after, **{field: value})
                result = validate_native_attempt(self.spec, observed, expected_identity=self.after,
                    log='PASSED f2p\nPASSED p2p\n', exit_code=0,
                    completed=True, cleanup_complete=True)
                self.assertFalse(result.valid)
                self.assertIn('attempt_identity_mismatch', result.issues)

    def test_incomplete_or_unknown_cleanup_cannot_be_success(self):
        for flags in ((False, True), (True, False), (1, True), (True, 1), (None, None)):
            with self.subTest(flags=flags):
                result = validate_native_attempt(self.spec, self.after, expected_identity=self.after,
                    log='PASSED f2p\nPASSED p2p\n', exit_code=0,
                    completed=flags[0], cleanup_complete=flags[1])
                self.assertFalse(result.valid)

    def test_statuses_and_exit_codes_must_both_be_real_binary_results(self):
        for status, code in (('ERROR', 1), ('SKIPPED', 0), ('XFAIL', 0), ('XPASS', 0),
                             ('PASSED', 1), ('FAILED', 0), ('PASSED', None),
                             ('PASSED', 2), ('PASSED', -9), ('PASSED', False)):
            with self.subTest(status=status, code=code):
                self.assertFalse(self.attempt(self.after, status+' f2p\nPASSED p2p\n', code).valid)

    def test_missing_conflicting_or_extra_failure_is_never_hidden_by_roster(self):
        for log in ('PASSED p2p\n', 'PASSED f2p\nFAILED f2p\nPASSED p2p\n',
                    'PASSED f2p\nPASSED p2p\nERROR unrelated\n',
                    'PASSED f2p\x00\nPASSED p2p\n'):
            with self.subTest(log=log):
                self.assertFalse(self.attempt(self.after, log, 0).valid)

    def test_preexisting_or_unfixed_failures_are_not_resolved(self):
        variants = (('PASSED f2p\nPASSED p2p\n', 0, 'PASSED f2p\nPASSED p2p\n', 0),
                    ('FAILED f2p\nFAILED p2p\n', 1, 'PASSED f2p\nPASSED p2p\n', 0),
                    ('FAILED f2p\nPASSED p2p\n', 1, 'FAILED f2p\nPASSED p2p\n', 1),
                    ('FAILED f2p\nPASSED p2p\n', 1, 'PASSED f2p\nFAILED p2p\n', 1))
        for old, old_code, new, new_code in variants:
            with self.subTest(old=old, new=new):
                result = grade_native_attempts(self.spec, (
                    self.attempt(self.before, old, old_code), self.attempt(self.after, new, new_code)))
                self.assertFalse(result.resolved)

    def test_attempts_require_exact_sequence_and_unique_identifiers(self):
        before = self.attempt(self.before, 'FAILED f2p\nPASSED p2p\n', 1)
        after = self.attempt(self.after, 'PASSED f2p\nPASSED p2p\n', 0)
        wrong_post = self.attempt(replace(self.after, repair_attempt=1), 'PASSED f2p\nPASSED p2p\n', 0)
        duplicate_id = self.attempt(replace(self.after, attempt_id=self.before.attempt_id),
            'PASSED f2p\nPASSED p2p\n', 0)
        for attempts in ((), (before,), (before, wrong_post), (before, duplicate_id),
                         (after, before), (before, after, after), (before, after)*3):
            with self.subTest(attempts=attempts):
                self.assertFalse(grade_native_attempts(self.spec, attempts).resolved)

    def test_valid_bounded_repair_chain_keeps_all_intermediate_evidence(self):
        before = self.attempt(self.before, 'FAILED f2p\nPASSED p2p\n', 1)
        post = self.attempt(self.after, 'FAILED f2p\nFAILED p2p\n', 1)
        repair = self.attempt(replace(self.after, attempt_id='3'*32, repair_attempt=1,
            source_sha256='8'*64), 'PASSED f2p\nPASSED p2p\n', 0)
        self.assertTrue(grade_native_attempts(self.spec, (before, post, repair)).resolved)
        bad_post = replace(post, issues=('cleanup_unknown',))
        self.assertFalse(grade_native_attempts(self.spec, (before, bad_post, repair)).resolved)

    def test_only_regression_can_authorize_a_following_repair(self):
        before = self.attempt(self.before, 'FAILED f2p\nPASSED p2p\n', 1)
        repair = self.attempt(replace(self.after, attempt_id='3'*32, repair_attempt=1,
            source_sha256='8'*64), 'PASSED f2p\nPASSED p2p\n', 0)
        for log, code in (('FAILED f2p\nPASSED p2p\n',1), ('PASSED f2p\nPASSED p2p\n',0)):
            with self.subTest(log=log):
                post = self.attempt(self.after,log,code)
                result = grade_native_attempts(self.spec,(before,post,repair))
                self.assertFalse(result.resolved)
                self.assertIn('repair_without_regression',result.issues)

    def test_environment_and_image_cannot_change_across_individually_valid_attempts(self):
        before = self.attempt(self.before, 'FAILED f2p\nPASSED p2p\n', 1)
        for updates in (dict(environment_sha256='8'*64), dict(image='other/image@sha256:'+'9'*64)):
            after = self.attempt(replace(self.after, **updates), 'PASSED f2p\nPASSED p2p\n', 0)
            self.assertTrue(after.valid)
            self.assertIn('cross_attempt_identity_mismatch',
                grade_native_attempts(self.spec, (before, after)).issues)

    def test_raw_origins_must_match_even_when_normalized_case_ids_match(self):
        self.spec = replace(self.spec, parser_id='pytest-options', fail_to_pass=('f2p[/a]',))
        before = self.attempt(self.before, 'FAILED f2p[/one/a]\nPASSED p2p\n', 1)
        after = self.attempt(self.after, 'PASSED f2p[/two/a]\nPASSED p2p\n', 0)
        self.assertTrue(before.valid)
        self.assertTrue(after.valid)
        self.assertIn('cross_attempt_origin_mismatch', grade_native_attempts(self.spec, (before, after)).issues)

    def test_invalid_configuration_and_nested_result_types_fail_closed(self):
        for updates in (dict(attempt_id='bad'), dict(environment_sha256='bad'),
                        dict(phase='baseline', repair_attempt=1), dict(repair_attempt=True),
                        dict(repair_attempt=3), dict(image='image:latest')):
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                replace(self.after, **updates)
        with self.assertRaises(ValueError):
            validate_native_attempt(self.spec, self.after,
                expected_identity=replace(self.after, row_sha256='8'*64), log='',
                exit_code=0, completed=True, cleanup_complete=True)
        before = self.attempt(self.before, 'FAILED f2p\nPASSED p2p\n', 1)
        after = self.attempt(self.after, 'PASSED f2p\nPASSED p2p\n', 0)
        for invalid in (replace(after, identity=None), replace(after, parsed=None)):
            self.assertFalse(grade_native_attempts(self.spec, (before, invalid)).resolved)

    def test_absent_p2p_roster_can_be_graded_without_inventing_cases(self):
        self.spec = replace(self.spec, pass_to_pass=())
        before = self.attempt(self.before, 'FAILED f2p\n', 1)
        after = self.attempt(self.after, 'PASSED f2p\n', 0)
        self.assertTrue(grade_native_attempts(self.spec, (before, after)).resolved)


if __name__ == '__main__': unittest.main()
