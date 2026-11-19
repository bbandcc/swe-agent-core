"""New cohort allowance; old non-refundable trial policy stays unchanged."""
import json
from pathlib import Path
import tempfile
import unittest
import httpx
from agent.runtime.calls import ModelRequestRejected


def body():
    return {"model": "deepseek-flash", "messages": [{"role": "user", "content": "Inspect the repository"}],
            "max_tokens": 2048, "stream": False, "thinking": {"type": "disabled"}}


class TrialSpendTests(unittest.TestCase):
    def test_twenty_known_settlements_fit_two_tenths_without_reusing_old_policy(self):
        from agent.evaluation.trial_spend import SettledTrialTransport
        calls = []
        def provider(request):
            calls.append(request)
            return httpx.Response(200, json={"model": "deepseek-flash", "usage": {"prompt_tokens": 100, "completion_tokens": 50}})
        with tempfile.TemporaryDirectory() as directory:
            cap = SettledTrialTransport(httpx.MockTransport(provider), Path(directory)/"trial")
            with httpx.Client(transport=cap) as client:
                for _ in range(20): client.post("https://api.deepseek.com/chat/completions", json=body())
                with self.assertRaises(ModelRequestRejected):
                    client.post("https://api.deepseek.com/chat/completions", json=body())
            self.assertEqual(len(calls), 20)
            self.assertEqual(cap.summary()["known_microcny"], 12000)
            self.assertFalse(cap.summary()["unknown"])
            self.assertLessEqual(cap.summary()["upper_microcny"], 200000)

    def test_full_usage_rejects_next_dispatch_before_spending_above_trial_limit(self):
        from agent.evaluation.trial_spend import SettledTrialTransport
        calls = []
        def provider(request):
            calls.append(request)
            return httpx.Response(200, json={"model": "deepseek-flash", "usage": {"prompt_tokens": 49152, "completion_tokens": 2048}})
        with tempfile.TemporaryDirectory() as directory:
            cap = SettledTrialTransport(httpx.MockTransport(provider), Path(directory)/"trial")
            with httpx.Client(transport=cap) as client:
                client.post("https://api.deepseek.com/chat/completions", json=body())
                with self.assertRaises(ModelRequestRejected):
                    client.post("https://api.deepseek.com/chat/completions", json=body())
            self.assertEqual(len(calls), 1)
            self.assertEqual(cap.summary()["upper_microcny"], 114688)
            self.assertFalse(cap.summary()["unknown"])

    def test_missing_usage_retains_reservation_and_stops_next_request(self):
        from agent.evaluation.trial_spend import SettledTrialTransport
        calls = []
        def provider(request):
            calls.append(request)
            return httpx.Response(200, json={"model": "deepseek-flash"})
        with tempfile.TemporaryDirectory() as directory:
            cap = SettledTrialTransport(httpx.MockTransport(provider), Path(directory)/"trial")
            with httpx.Client(transport=cap) as client:
                for _ in range(2):
                    with self.assertRaises(httpx.TransportError):
                        client.post("https://api.deepseek.com/chat/completions", json=body())
            self.assertEqual(len(calls), 1)
            self.assertEqual(cap.summary()["requests"], 1)
            self.assertEqual(cap.summary()["held_microcny"], 114688)
            self.assertTrue(cap.summary()["unknown"])

    def test_invalid_envelope_and_once_only_directory_do_not_dispatch(self):
        from agent.evaluation.trial_spend import SettledTrialTransport
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"trial"
            cap = SettledTrialTransport(httpx.MockTransport(lambda _: self.fail("No dispatch")), path)
            with httpx.Client(transport=cap) as client:
                with self.assertRaises(ModelRequestRejected):
                    client.post("https://api.deepseek.com/chat/completions", json={**body(), "stream": True})
            self.assertFalse(cap.summary()["unknown"])
            self.assertEqual(cap.summary()["upper_microcny"], 0)
            with self.assertRaises(FileExistsError):
                SettledTrialTransport(httpx.MockTransport(lambda _: self.fail("No dispatch")), path)

    def test_concurrent_call_is_known_zero_and_does_not_close_owner_transport(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        from agent.evaluation.trial_spend import SettledTrialTransport
        entered, release = threading.Event(), threading.Event()
        def provider(request):
            entered.set()
            self.assertTrue(release.wait(10))
            return httpx.Response(200, json={"model": "deepseek-flash", "usage": {"prompt_tokens": 100, "completion_tokens": 50}})
        with tempfile.TemporaryDirectory() as directory:
            cap = SettledTrialTransport(httpx.MockTransport(provider), Path(directory)/"trial")
            with httpx.Client(transport=cap) as client, ThreadPoolExecutor(max_workers=1) as pool:
                first = pool.submit(client.post, "https://api.deepseek.com/chat/completions", json=body())
                try:
                    self.assertTrue(entered.wait(10))
                    with self.assertRaises(ModelRequestRejected):
                        client.post("https://api.deepseek.com/chat/completions", json=body())
                finally:
                    release.set()
                self.assertEqual(first.result().status_code, 200)
                self.assertEqual(client.post("https://api.deepseek.com/chat/completions", json=body()).status_code, 200)
            self.assertEqual(cap.summary()["requests"], 2)
            self.assertFalse(cap.summary()["unknown"])

    def test_unwritable_request_journal_stops_without_any_dispatch(self):
        from agent.evaluation.trial_spend import SettledTrialTransport
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"trial"
            cap = SettledTrialTransport(httpx.MockTransport(lambda _: self.fail("No dispatch")), path)
            (path/"request-001.jsonl").mkdir()
            with httpx.Client(transport=cap) as client:
                with self.assertRaises(httpx.TransportError):
                    client.post("https://api.deepseek.com/chat/completions", json=body())
                with self.assertRaises(httpx.TransportError):
                    client.post("https://api.deepseek.com/chat/completions", json=body())
            self.assertTrue(cap.summary()["unknown"])
            self.assertEqual(cap.summary()["requests"], 0)

    def test_provider_cannot_forge_known_zero_after_dispatch(self):
        from agent.evaluation.trial_spend import SettledTrialTransport
        from agent.runtime.budget import BudgetErrorCode
        sent = []
        def provider(request):
            sent.append(request)
            raise ModelRequestRejected(BudgetErrorCode.MODEL_REQUEST_REJECTED, "untrusted rejection")
        with tempfile.TemporaryDirectory() as directory:
            cap = SettledTrialTransport(httpx.MockTransport(provider), Path(directory)/"trial")
            with httpx.Client(transport=cap) as client:
                for _ in range(2):
                    with self.assertRaises(httpx.TransportError):
                        client.post("https://api.deepseek.com/chat/completions", json=body())
            self.assertEqual(len(sent), 1)
            self.assertTrue(cap.summary()["unknown"])
            self.assertEqual(cap.summary()["held_microcny"], 114688)

    def test_settlement_audit_failure_cannot_release_reserved_allowance(self):
        import os
        from unittest.mock import patch
        from agent.evaluation.trial_spend import SettledTrialTransport
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"trial"
            cap = SettledTrialTransport(httpx.MockTransport(lambda _: httpx.Response(200, json={
                "model": "deepseek-flash", "usage": {"prompt_tokens": 100, "completion_tokens": 50}})), path)
            original = os.fsync
            def disk_failure(fd):
                if '"event":"SETTLED"' in (path/'trial.jsonl').read_text():
                    raise OSError("Injected audit disk failure")
                return original(fd)
            with httpx.Client(transport=cap) as client, patch('os.fsync', side_effect=disk_failure):
                with self.assertRaises(OSError):
                    client.post("https://api.deepseek.com/chat/completions", json=body())
                with self.assertRaises(httpx.TransportError):
                    client.post("https://api.deepseek.com/chat/completions", json=body())
            self.assertTrue(cap.summary()["unknown"])
            self.assertEqual(cap.summary()["known_microcny"], 0)
            self.assertEqual(cap.summary()["held_microcny"], 114688)


if __name__ == "__main__": unittest.main()
