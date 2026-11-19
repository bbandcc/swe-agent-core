"""New 0.2 CNY cohort contract; known settlements release unused reservations.

Reuses the frozen single-request protocol/usage guard. Its historical ledgers
are never refunded or reopened. A new trial owns a fresh directory and cannot
resume. Twenty separately allocated trials cost at most 4 CNY under the same
published protocol/pricing assumptions; an unknown stops admission.
"""
import json
import os
from pathlib import Path
import threading

import httpx

from agent.evaluation.pilot_spend import CappedDeepSeekTransport, RESERVE_MICROCNY
from agent.runtime.budget import BudgetErrorCode
from agent.runtime.calls import ModelRequestRejected

TRIAL_LIMIT_MICROCNY = 200000
MAX_REQUESTS = 20
POLICY_ID = "settled-cny-v1"


class _BorrowedTransport(httpx.BaseTransport):
    def __init__(self, inner):
        self.inner = inner

    def handle_request(self, request):
        return self.inner.handle_request(request)

    def close(self):
        pass  # The cohort transport owns the one underlying client connection.


class SettledTrialTransport(httpx.BaseTransport):
    """Serial, once-only allowance; keep every per-request reservation receipt."""

    def __init__(self, inner: httpx.BaseTransport, directory: Path):
        self._directory = Path(directory)
        self._directory.mkdir(parents=True, exist_ok=False)
        self._writer = (self._directory / "trial.jsonl").open("x", encoding="utf-8")
        self._inner, self._lock = inner, threading.Lock()
        self._known = self._held = self._requests = self._attempts = 0
        self._unknown = self._closed = False
        try:
            self._record("POLICY", policy_id=POLICY_ID, limit_microcny=TRIAL_LIMIT_MICROCNY, max_requests=MAX_REQUESTS,
                         settlement_release="known_only", automatic_resume=False)
        except BaseException:
            self._writer.close()
            raise

    def _record(self, event, **values):
        self._writer.write(json.dumps({"event": event, **values}, separators=(",", ":")) + "\n")
        self._writer.flush()
        os.fsync(self._writer.fileno())

    def summary(self):
        return {"policy_id": POLICY_ID, "currency": "CNY", "requests": self._requests, "known_microcny": self._known,
                "held_microcny": self._held, "upper_microcny": self._known + self._held,
                "limit_microcny": TRIAL_LIMIT_MICROCNY, "unknown": self._unknown,
                "max_requests": MAX_REQUESTS, "automatic_resume": False}

    def handle_request(self, request):
        if not self._lock.acquire(blocking=False):
            raise ModelRequestRejected(BudgetErrorCode.MODEL_REQUEST_REJECTED, "TRIAL_CONCURRENT_REQUEST")
        child, response = None, None
        try:
            if self._unknown:
                raise httpx.TransportError("TRIAL_UNKNOWN_STOP")
            if self._closed or self._attempts >= MAX_REQUESTS or self._known + RESERVE_MICROCNY > TRIAL_LIMIT_MICROCNY:
                raise ModelRequestRejected(BudgetErrorCode.MODEL_REQUEST_LIMIT_EXCEEDED, "TRIAL_ALLOWANCE_EXHAUSTED")
            self._attempts += 1
            requests_before = self._requests
            child = CappedDeepSeekTransport(_BorrowedTransport(self._inner),
                                           self._directory / f"request-{self._attempts:03}.jsonl")
            self._held = RESERVE_MICROCNY
            try:
                self._record("RESERVED", attempt=self._attempts, microcny=self._held)
                response = child.handle_request(request)
                result = child.summary()
                self._requests += result["requests"]
                cost = result["settled_microcny"]
                if result["unknown"] or cost > self._held:
                    raise ValueError("Unsettled request")
                self._record("SETTLED", attempt=self._attempts, microcny=cost,
                             released_microcny=self._held - cost)
                self._known += cost
                self._held = 0
                return response
            except ModelRequestRejected:
                try:
                    self._record("REJECTED_NOT_DISPATCHED", attempt=self._attempts, released_microcny=self._held)
                    self._held = 0
                except OSError:
                    self._unknown = True
                    raise
                raise
            except BaseException:
                self._unknown = True
                self._requests = requests_before + child.summary()["requests"]
                if response is not None:
                    response.close()
                try:
                    self._record("UNKNOWN", attempt=self._attempts, held_microcny=self._held)
                except OSError:
                    pass  # In-memory refusal survives an unavailable audit disk.
                raise
            finally:
                child.close()
        except ModelRequestRejected:
            raise
        except (OSError, httpx.TransportError):
            self._unknown = True
            raise
        finally:
            self._lock.release()

    def close(self):
        with self._lock:
            if not self._closed:
                self._closed = True
                try:
                    self._inner.close()
                finally:
                    self._writer.close()
