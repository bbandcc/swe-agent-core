"""Bounded strict research parsing, separate from official SWE-bench grading.

Format references: SWE-bench b8d53321, harness/log_parsers/python.py.
This module neither executes code nor establishes output authenticity.
"""
from dataclasses import dataclass
import re

PARSERS = frozenset(('pytest', 'pytest-options', 'pytest-v2', 'matplotlib',
                     'seaborn', 'django', 'sympy'))
STATUSES = 'PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS'
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
MAX_LOG_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class NativeLogResult:
    cases: tuple[tuple[str, str], ...]
    issues: tuple[str, ...]
    complete: bool
    strict_passed: bool
    case_origins: tuple[tuple[str, str], ...] = ()


def parse_native_log(parser_id: str, log: str, required_ids: tuple[str, ...]) -> NativeLogResult:
    """Read exact required IDs; never overwrite conflicting or aliased outcomes.

    Repeated identical progress/summary lines are accepted. SKIP/XFAIL/XPASS
    remain non-passing. Unlike official parsers, no missing-ID fallback or
    last-write-wins behavior is used. Callers must independently validate the
    process lifecycle, exit code, image and candidate execution identity, and
    bind case_origins across baseline/post attempts before accepting changes.
    """
    if (type(parser_id) is not str or parser_id not in PARSERS
            or type(log) is not str or type(required_ids) is not tuple
            or not 1 <= len(required_ids) <= 10000
            or any(type(i) is not str or not 1 <= len(i) <= 4096
                   or any(ord(c) < 32 or ord(c) == 127 for c in i) for i in required_ids)
            or len(set(required_ids)) != len(required_ids)):
        raise ValueError('Invalid strict parser configuration')
    issues, outcomes, origins = set(), {}, {}
    required = set(required_ids)

    def result():
        if not required <= outcomes.keys(): issues.add('missing_case')
        cases = tuple((identity, outcomes.get(identity, 'MISSING')) for identity in required_ids)
        complete = not issues
        return NativeLogResult(cases, tuple(sorted(issues)), complete,
                               complete and all(status == 'PASSED' for _, status in cases),
                               tuple((i, origins[i]) for i in required_ids if i in origins))

    try:
        if len(log) > MAX_LOG_BYTES or len(log.encode('utf-8')) > MAX_LOG_BYTES:
            issues.add('output_limit'); return result()
    except UnicodeEncodeError:
        issues.add('invalid_encoding'); return result()
    log = ANSI.sub('', log)
    if any((ord(c) < 32 and c not in '\n\r\t') or 127 <= ord(c) <= 159 for c in log):
        issues.add('invalid_control'); return result()

    def observe(identity, status, origin):
        if identity not in required:
            if status in ('FAILED', 'ERROR'): issues.add('unexpected_failure')
            return
        if identity in origins and origins[identity] != origin:
            issues.add('aliased_case')
        if identity in outcomes and outcomes[identity] != status:
            issues.add('conflicting_case')
            outcomes[identity] = 'CONFLICT'
        else:
            outcomes[identity] = status
        origins[identity] = origin

    previous, context = None, ''
    for raw_line in log.split('\n'):
        if len(raw_line) > 65536:
            issues.add('line_limit'); continue
        line = ANSI.sub('', raw_line).strip()
        if any(ord(c) < 32 and c != '\t' or ord(c) == 127 for c in line):
            issues.add('invalid_control'); continue
        if parser_id == 'django':
            if ' ... ' in line:
                previous, tail = line.split(' ... ', 1)
                token = tail.strip().split(' ', 1)[0]
                status = {'ok': 'PASSED', 'OK': 'PASSED', 'FAIL': 'FAILED',
                          'ERROR': 'ERROR', 'skipped': 'SKIPPED'}.get(token)
                if status: observe(previous, status, previous); previous = None
            elif line in ('ok', 'OK') and previous:
                observe(previous, 'PASSED', previous); previous = None
            else:
                match = re.fullmatch(r'(FAIL|ERROR):\s+(.+)', line)
                if match:
                    status, identity = match.groups()
                    observe(identity, 'FAILED' if status == 'FAIL' else 'ERROR', identity)
            continue
        if parser_id == 'sympy':
            header = re.fullmatch(r'(.+\.py)\[\d+\].*', line)
            if header: context = header[1]
            failure = re.fullmatch(r'_+\s+(.+\.py):([^\s]+)\s+_+', line)
            if failure:
                path, identity = failure.groups()
                observe(identity, 'FAILED', path + ':' + identity)
            match = re.fullmatch(r'(test_\S+)\s+(ok|F|E|XFAIL|SKIP)', line)
            if match:
                identity, token = match.groups()
                observe(identity, {'ok': 'PASSED', 'F': 'FAILED', 'E': 'ERROR',
                                   'XFAIL': 'XFAIL', 'SKIP': 'SKIPPED'}[token],
                        context + ':' + identity)
            continue
        match = re.fullmatch(r'(' + STATUSES + r')\s+(.+)', line)
        if match:
            status, identity = match.groups()
            if status in ('FAILED', 'ERROR'):
                # Diagnostics begin outside parameter brackets. In particular,
                # PASSED parameter IDs containing ' - ' must stay intact.
                depth = 0
                for index, char in enumerate(identity):
                    if char == '[': depth += 1
                    elif char == ']': depth = max(0, depth - 1)
                    elif depth == 0 and identity[index:index+3] == ' - ':
                        identity = identity[:index]; break
        elif parser_id in ('pytest-v2', 'seaborn'):
            match = re.fullmatch(r'(.+?)\s+(' + STATUSES + r')(?:\s+\[\s*\d+%\])?', line)
            if not match: continue
            identity, status = match.groups()
        else:
            continue
        origin = identity
        if parser_id == 'pytest-options':
            option = re.fullmatch(r'(.*?)\[(/[^\]]*)\]', identity)
            if option and not option[2].startswith('//') and '*' not in option[2]:
                identity = option[1] + '[/' + option[2].rsplit('/', 1)[-1] + ']'
        elif parser_id == 'matplotlib':
            identity = identity.replace('MouseButton.LEFT', '1').replace('MouseButton.RIGHT', '3')
        observe(identity, status, origin)
    return result()
