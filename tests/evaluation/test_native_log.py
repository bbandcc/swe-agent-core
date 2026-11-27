"""Strict native log data parsing never grants execution admission."""
import unittest
import subprocess
import sys
from pathlib import Path

from agent.evaluation.native_log import parse_native_log

CASE='tests/test_basic.py::test_error_handling'
CAPTURE='------------------------------ Captured log call -------------------------------\n'
LOGGER='ERROR    flask_test:app.py:1441 Exception on / [GET]\n'
SUMMARY='=========================== short test summary info ===========================\n'


class NativeLogTests(unittest.TestCase):
    def test_old_pytest_verbose_options_keep_normalization_and_raw_origin(self):
        identity = 'tests/a.py::test_case[/a.txt]'
        origin = 'tests/a.py::test_case[/temporary/root/a.txt]'
        result = parse_native_log('pytest-options-v2', origin+' PASSED [ 10%]\n', (identity,))
        self.assertTrue(result.strict_passed)
        self.assertEqual(result.case_origins, ((identity, origin),))
        collision = origin+' PASSED\ntests/a.py::test_case[/another/a.txt] PASSED\n'
        self.assertFalse(parse_native_log('pytest-options-v2', collision, (identity,)).complete)

    def test_reads_each_reviewed_family_with_exact_case_identity(self):
        fixtures = (
            ('pytest', 'PASSED tests/test_a.py::test_a\n', 'tests/test_a.py::test_a'),
            ('pytest-options', 'PASSED tests/test_a.py::test_a[/tmp/data.txt]\n', 'tests/test_a.py::test_a[/data.txt]'),
            ('pytest-v2', '\x1b[32mtests/test_a.py::test_a PASSED\x1b[0m\n', 'tests/test_a.py::test_a'),
            ('matplotlib', 'PASSED tests/test_a.py::test_a[MouseButton.LEFT]\n', 'tests/test_a.py::test_a[1]'),
            ('seaborn', 'tests/test_a.py::test_a PASSED [100%]\n', 'tests/test_a.py::test_a'),
            ('django', 'test_a (tests.Example) ... setup message\nok\n', 'test_a (tests.Example)'),
            ('sympy', 'test_a ok\n', 'test_a'),
        )
        for parser, log, identity in fixtures:
            with self.subTest(parser=parser):
                result = parse_native_log(parser, log, (identity,))
                self.assertTrue(result.complete, result)
                self.assertTrue(result.strict_passed)
                self.assertEqual(result.cases, ((identity, 'PASSED'),))

    def test_retains_failure_skip_error_and_missing_as_non_success(self):
        for status in ('FAILED', 'ERROR', 'SKIPPED', 'XFAIL', 'XPASS'):
            suffix = ' - diagnostic' if status in ('FAILED', 'ERROR') else ''
            result = parse_native_log('pytest', status+' case'+suffix+'\n', ('case',))
            self.assertTrue(result.complete)
            self.assertFalse(result.strict_passed)
            self.assertEqual(result.cases, (('case', status),))
        result = parse_native_log('pytest', 'PASSED unrelated\n', ('required',))
        self.assertFalse(result.complete)
        self.assertIn('missing_case', result.issues)

    def test_refuses_conflicting_and_colliding_cases(self):
        result = parse_native_log('pytest', 'PASSED case\nFAILED case - reason\n', ('case',))
        self.assertFalse(result.complete)
        self.assertIn('conflicting_case', result.issues)
        result = parse_native_log('pytest-options',
            'PASSED case[/one/a]\nPASSED case[/two/a]\n', ('case[/a]',))
        self.assertFalse(result.complete)
        self.assertIn('aliased_case', result.issues)

    def test_repeated_identical_summary_is_allowed_but_not_failure_masking(self):
        result = parse_native_log('pytest-v2', 'case PASSED\nPASSED case\n', ('case',))
        self.assertTrue(result.strict_passed)
        result = parse_native_log('django', 'case (Class) ... ok\nERROR: case (Class)\n', ('case (Class)',))
        self.assertFalse(result.complete)
        self.assertIn('conflicting_case', result.issues)

    def test_keeps_parameter_identity_and_exports_cross_attempt_origin(self):
        result = parse_native_log('pytest', 'PASSED case[a - b]\nPASSED case[a - c]\n', ('case[a',))
        self.assertFalse(result.complete)
        result = parse_native_log('pytest', 'PASSED case[a - b]\n', ('case[a - b]',))
        self.assertTrue(result.strict_passed)
        result = parse_native_log('pytest-options', 'PASSED case[/one/a]\n', ('case[/a]',))
        self.assertEqual(result.case_origins, (('case[/a]', 'case[/one/a]'),))

    def test_django_accepts_native_double_space_ok(self):
        result = parse_native_log('django', 'case (Class) ...  OK\n', ('case (Class)',))
        self.assertTrue(result.strict_passed)

    def test_long_malformed_native_line_finishes_within_process_deadline(self):
        program = ("from agent.evaluation.native_log import parse_native_log; "
                   "r=parse_native_log('pytest-v2','case'+' '*65000+'unknown',('case',)); "
                   "print(r.complete)")
        result = subprocess.run([sys.executable, '-c', program],
            cwd=Path(__file__).resolve().parents[2], capture_output=True,
            check=True, timeout=5, shell=False)
        self.assertEqual(result.stdout.strip(), b'False')

    def test_sympy_ambiguous_bare_names_and_failure_sections_are_rejected(self):
        result = parse_native_log('sympy', 'a/tests/test_a.py[1]\ntest_a ok\nb/tests/test_b.py[1]\ntest_a ok\n', ('test_a',))
        self.assertFalse(result.complete)
        self.assertIn('aliased_case', result.issues)
        result = parse_native_log('sympy', 'test_a ok\n____ a/tests/test_a.py:test_a ____\n', ('test_a',))
        self.assertFalse(result.complete)
        self.assertIn('conflicting_case', result.issues)

    def test_refuses_unbounded_or_malformed_input(self):
        for parser, ids in (('unknown', ('case',)), ('pytest', ()), ('pytest', ('case', 'case'))):
            with self.assertRaises(ValueError): parse_native_log(parser, 'PASSED case\n', ids)
        result = parse_native_log('pytest', 'x'*(4*1024*1024+1), ('case',))
        self.assertFalse(result.complete)
        self.assertIn('output_limit', result.issues)
        result = parse_native_log('pytest', 'PASSED case\x00\n', ('case',))
        self.assertFalse(result.complete)
        result = parse_native_log('pytest', 'noise\x0bPASSED case\n', ('case',))
        self.assertFalse(result.complete)


class NativeCapturedLoggingTests(unittest.TestCase):
    def test_pytest_default_error_logging_is_diagnostic_inside_capture(self):
        for parser in ('pytest','pytest-options','pytest-v2','pytest-options-v2','matplotlib','seaborn'):
            with self.subTest(parser=parser):
                result=parse_native_log(parser,CAPTURE+LOGGER+'Traceback text\n'+SUMMARY+'PASSED '+CASE+'\n',(CASE,))
                self.assertTrue(result.strict_passed,result)
                self.assertEqual(result.cases,((CASE,'PASSED'),))

    def test_logger_looking_error_outside_capture_is_still_rejected(self):
        for prefix in ('',SUMMARY):
            result=parse_native_log('pytest',prefix+LOGGER+'PASSED '+CASE+'\n',(CASE,))
            self.assertFalse(result.complete)
            self.assertIn('unexpected_failure',result.issues)

    def test_unknown_real_error_and_failure_are_never_roster_filtered(self):
        for status in ('ERROR','FAILED'):
            for prefix in (CAPTURE+LOGGER,CAPTURE+LOGGER+SUMMARY):
                unknown='tests/test_other.py::test_case[flask_test:app.py:1441]'
                log=prefix+status+' '+unknown+' - reason\nPASSED '+CASE+'\n'
                result=parse_native_log('pytest',log,(CASE,))
                self.assertFalse(result.complete)
                self.assertIn('unexpected_failure',result.issues)

    def test_malformed_and_truncated_logging_is_not_silently_discarded(self):
        for line in ('ERROR    flask_test:app.py:', 'ERROR    flask_test:app.py:not-a-line message',
                'ERROR tests/test_other.py::test_case', 'ERROR    flask_test:app.py:1441\x00'):
            with self.subTest(line=line):
                result=parse_native_log('pytest',CAPTURE+line+'\nPASSED '+CASE+'\n',(CASE,))
                self.assertFalse(result.complete)

    def test_missing_outcome_and_conflicting_real_case_stay_rejected(self):
        missing=parse_native_log('pytest',CAPTURE+LOGGER,(CASE,))
        self.assertIn('missing_case',missing.issues)
        result=parse_native_log('pytest',CAPTURE+LOGGER+SUMMARY+'PASSED '+CASE+'\nERROR '+CASE+' - failure\n',(CASE,))
        self.assertFalse(result.complete)
        self.assertIn('conflicting_case',result.issues)

    def test_capture_end_restores_strict_handling(self):
        for separator in (SUMMARY,'________________________ next_test ________________________\n',
                '------------------------------ Captured stderr call ------------------------------\n'):
            result=parse_native_log('pytest',CAPTURE+LOGGER+separator+LOGGER+'PASSED '+CASE+'\n',(CASE,))
            self.assertFalse(result.complete)
            self.assertIn('unexpected_failure',result.issues)


if __name__ == '__main__': unittest.main()
