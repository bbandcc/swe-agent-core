"""Public recovery behavior; no Docker daemon needed for refusal cases."""
import json
from pathlib import Path
import tempfile
import unittest

from agent.evaluation.native_requests.ownership import lease_owner, recover_fixed_tls


class RecoveryContractTests(unittest.TestCase):
    def test_live_owner_refuses_recovery_without_touching_lease(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'owned'
            with lease_owner(root):
                result = recover_fixed_tls(root)
                self.assertEqual(result['status'], 'OWNER_ACTIVE')
                self.assertFalse(result['cleanup_complete'])
                self.assertFalse((root / 'materials').exists())

    def test_missing_or_malformed_lease_never_attests_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'owned'
            with lease_owner(root):
                pass
            self.assertEqual(recover_fixed_tls(root)['status'], 'UNKNOWN')
            (root / 'materials').mkdir()
            (root / 'materials/lease.json').write_text('{', encoding='utf-8')
            result = recover_fixed_tls(root)
            self.assertFalse(result['cleanup_complete'])
            self.assertFalse(result['restart_permitted'])

    def test_invalid_owner_or_image_is_rejected_before_docker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'owned'
            with lease_owner(root):
                pass
            (root / 'materials').mkdir()
            for value in ({}, {'owner': '../escape'}, {'owner': 'a'*32, 'image': 'unreviewed'}):
                (root / 'materials/lease.json').write_text(json.dumps(value), encoding='utf-8')
                result = recover_fixed_tls(root)
                self.assertEqual(result['status'], 'UNKNOWN')
                self.assertIn('invalid_lease', result['issues'])

    def test_timeout_must_be_finite_and_bounded(self):
        for timeout in (0, -1, float('inf'), float('nan'), True, 61):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    recover_fixed_tls(Path('unused'), timeout_seconds=timeout)


if __name__ == '__main__':
    unittest.main()
