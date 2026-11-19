"""Public read-only preflight; supplied facts never authorize execution."""

import json
from pathlib import Path
import shutil
import subprocess
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/windows_guest_preflight.ps1"
PWSH = shutil.which("pwsh.exe") or shutil.which("pwsh")


@unittest.skipUnless(PWSH, "PowerShell 7 is not installed")
class WindowsGuestPreflightTests(unittest.TestCase):
    def invoke(self, facts=None):
        command = [PWSH, "-NoProfile", "-NonInteractive", "-File", str(SCRIPT)]
        if facts is not None:
            command += ["-FactsJson", json.dumps(facts)]
        result = subprocess.run(command, capture_output=True, timeout=20, shell=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(result.stderr, b"")
        return json.loads(result.stdout.decode("utf-8-sig"))

    def facts(self, **changes):
        return {"platform": "windows", "edition": "Professional", "build": 26100,
                "hyperv_feature": "enabled", "hyperv_module": True,
                "vmms_running": True, "hypervisor_present": True, **changes}

    def test_home_is_blocked_and_cannot_admit_even_if_role_facts_claim_ready(self):
        result = self.invoke(self.facts(edition="CoreCountrySpecific"))
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("UNSUPPORTED_WINDOWS_EDITION", result["reasons"])
        self.assertFalse(result["execution_admitted"])
        self.assertEqual(result["evidence_source"], "supplied_facts")

    def test_supported_host_facts_still_require_image_and_real_gates(self):
        for edition, build in (("Professional", 26100), ("ServerStandard", 20348)):
            with self.subTest(edition=edition):
                result = self.invoke(self.facts(edition=edition, build=build))
                self.assertEqual(result["status"], "HOST_READY")
                self.assertFalse(result["execution_admitted"])
                self.assertIn("REVIEWED_GUEST_AND_REAL_GATES_REQUIRED", result["remaining_conditions"])

    def test_unknown_disabled_legacy_and_non_windows_remain_explicit(self):
        for changes, status, reason in (
            ({"hyperv_feature": "unknown"}, "UNKNOWN", "HYPERV_FEATURE_UNKNOWN"),
            ({"hyperv_feature": "disabled"}, "BLOCKED", "HYPERV_FEATURE_DISABLED"),
            ({"hypervisor_present": None}, "UNKNOWN", "HYPERVISOR_STATE_UNKNOWN"),
            ({"build": 19045}, "BLOCKED", "UNSUPPORTED_WINDOWS_BUILD"),
            ({"platform": "non_windows"}, "BLOCKED", "WINDOWS_HOST_REQUIRED"),
        ):
            with self.subTest(changes=changes):
                result = self.invoke(self.facts(**changes))
                self.assertEqual(result["status"], status)
                self.assertIn(reason, result["reasons"])
                self.assertFalse(result["execution_admitted"])

    def test_invalid_facts_fail_as_data_and_are_not_echoed(self):
        result = self.invoke({"platform": "windows", "unexpected": "private-marker"})
        self.assertEqual(result["status"], "INVALID_FACTS")
        self.assertNotIn("private-marker", json.dumps(result))
        self.assertFalse(result["execution_admitted"])

    def test_actual_probe_is_structured_read_only_and_never_admits_execution(self):
        result = self.invoke()
        self.assertEqual(result["schema_version"], 1)
        self.assertTrue(result["read_only"])
        self.assertEqual(result["evidence_source"], "local_read_only_probe")
        self.assertFalse(result["execution_admitted"])
        self.assertIn(result["status"], {"BLOCKED", "UNKNOWN", "HOST_READY"})
        self.assertEqual(set(result["facts"]), set(self.facts()))
        for forbidden in ("device_id", "serial_number", "username", "credential", "api_key"):
            self.assertNotIn(forbidden, json.dumps(result["facts"]).lower())


if __name__ == "__main__":
    unittest.main()
