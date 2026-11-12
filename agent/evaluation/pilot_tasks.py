"""Closed author-reviewed integer JSON tasks; no caller-supplied oracle code."""

from dataclasses import dataclass
import hashlib
import json


def _program(expression: str) -> bytes:
    return ('import json,sys\nvalues=json.load(sys.stdin)["values"]\n'
            'print(json.dumps({"total":' + expression + '}))\n').encode("utf-8")


def _function_program(body: str) -> bytes:
    return ('import json,sys\n' + body + '\nvalues=json.load(sys.stdin)["values"]\n'
            'print(json.dumps({"total":solve(values)}))\n').encode("utf-8")


_MAX_SUBARRAY = '''def solve(values):
    if not values:
        return 0
    best = 0
    current = 0
    for value in values:
        current = max(value, current + value)
        best = max(best, current)
    return best
'''
_LIS_LENGTH = '''def solve(values):
    lengths = [1] * len(values)
    for i in range(len(values)):
        for j in range(i):
            if values[j] <= values[i]:
                lengths[i] = max(lengths[i], lengths[j] + 1)
    return max(lengths, default=0)
'''
_LOWER_MEDIAN = '''def solve(values):
    if not values:
        return 0
    ordered = values
    return ordered[(len(ordered) - 1) // 2]
'''


@dataclass(frozen=True)
class PilotTask:
    task_id: str
    instruction: str
    original: bytes
    gold: bytes
    cases: tuple[tuple[tuple[int, ...], int], ...]

    @property
    def case_literal(self) -> str:
        return repr(tuple((list(values), expected) for values, expected in self.cases))

    @property
    def fingerprint(self) -> str:
        value = {"id": self.task_id, "instruction": self.instruction,
                 "original": self.original.hex(), "gold": self.gold.hex(), "cases": self.cases}
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


_TASKS = (
    PilotTask("json-sum", "Read JSON containing an integer list 'values'; output exactly JSON {'total': sum of every integer}. Modify only main.py.",
              _program("sum(values[:-1])"), _program("sum(values)"),
              (((), 0), ((1, 2, 3), 6), ((-2, 5, 7), 10))),
    PilotTask("json-sum-squares", "Read JSON containing an integer list 'values'; output exactly JSON with one integer 'total', the sum of the square of each integer. Modify only main.py.",
              _program("sum(values)"), _program("sum(value * value for value in values)"),
              (((), 0), ((1, 2, 3), 14), ((-2, 5, 7), 78))),
    PilotTask("json-weighted-sum", "Read JSON containing an integer list 'values'; output exactly JSON with one integer 'total', the sum of each value multiplied by its one-based position. Modify only main.py.",
              _program("sum(values)"), _program("sum(index * value for index, value in enumerate(values, 1))"),
              (((), 0), ((1, 2, 3), 14), ((-2, 5, 7), 29))),
    PilotTask("json-max-subarray", "Read JSON containing an integer list 'values'; output exactly JSON with one integer 'total': the maximum sum of a non-empty contiguous subarray, or 0 for an empty list. Modify only main.py.",
              _function_program(_MAX_SUBARRAY),
              _function_program(_MAX_SUBARRAY.replace("best = 0", "best = values[0]", 1)),
              (((), 0), ((-5,), -5), ((-8, -3, -6), -3), ((4, -1, 2, 1), 6),
               ((-2, 1, -3, 4, -1, 2, 1, -5, 4), 6), ((0, 0), 0))),
    PilotTask("json-lis-length", "Read JSON containing an integer list 'values'; output exactly JSON with one integer 'total': the length of its longest strictly increasing subsequence, which need not be contiguous. Empty lists return 0; equal elements do not increase the length. Modify only main.py.",
              _function_program(_LIS_LENGTH),
              _function_program(_LIS_LENGTH.replace("values[j] <= values[i]", "values[j] < values[i]", 1)),
              (((), 0), ((2, 2, 2), 1), ((1, 2, 2, 3), 3), ((3, 2, 1), 1),
               ((10, 9, 2, 5, 3, 7, 101, 18), 4), ((0, 1, 0, 3, 2, 3), 4))),
    PilotTask("json-lower-median", "Read JSON containing an integer list 'values'; output exactly JSON with one integer 'total': after sorting the values in nondecreasing order, select the element at zero-based index (n-1)//2. Empty lists return 0. Modify only main.py.",
              _function_program(_LOWER_MEDIAN),
              _function_program(_LOWER_MEDIAN.replace("ordered = values", "ordered = sorted(values)", 1)),
              (((), 0), ((5,), 5), ((9, 1), 1), ((7, 1, 4), 4),
               ((8, -2, 4, 1), 1), ((2, 2, 1, 3), 2), ((0, -1, -2, -3), -2))),
)
PILOT_TASK_IDS = tuple(task.task_id for task in _TASKS)


def get_pilot_task(task_id: str) -> PilotTask:
    """Reject all identifiers outside the closed, reviewed task set."""
    for task in _TASKS:
        if type(task_id) is str and task.task_id == task_id:
            return task
    raise ValueError("Unknown fixed pilot task.")
