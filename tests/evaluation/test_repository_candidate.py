"""Public, data-only acceptance for repository candidate snapshots."""

from pathlib import Path
import hashlib
import os
import tempfile
import unittest
from unittest.mock import patch


class RepositoryCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.baseline, self.generation = self.root / "B", self.root / "G"
        self.baseline.mkdir(); self.generation.mkdir()
        for root in (self.baseline, self.generation):
            (root / "src").mkdir()
            (root / "src/a.py").write_bytes(b"a=1\r\n")

    def freeze(self, policy=None, destination=None):
        from agent.evaluation.repository_candidate import CandidatePolicy, freeze_candidate
        return freeze_candidate(self.baseline, self.generation, policy or CandidatePolicy(),
                                destination or self.root / "snapshot")

    def test_complete_tree_keeps_windows_executable_suffix_bytes(self):
        for root in (self.baseline,self.generation):
            (root/'docs').mkdir()
            for suffix in ('bat','cmd','exe','com'):
                (root/'docs'/('source.'+suffix)).write_bytes(b'authored byte-only fixture\n')
        (self.generation/'src/a.py').write_bytes(b'a=2\r\n')
        result=self.freeze()
        self.assertTrue(result.ok,result)
        for suffix in ('bat','cmd','exe','com'):
            self.assertEqual((result.snapshot.root/'docs'/('source.'+suffix)).read_bytes(),
                             b'authored byte-only fixture\n')

    def test_two_edits_are_in_the_same_complete_frozen_tree(self):
        from agent.evaluation.repository_candidate import CandidatePolicy, freeze_candidate

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline, generation = root / "B", root / "G"
            baseline.mkdir(); generation.mkdir()
            for name, old, new in (("a.py", "a=1\n", "a=2\n"), ("b.py", "b=1\n", "b=3\n"),
                                   ("README.md", "unchanged\n", "unchanged\n")):
                (baseline / name).write_bytes(old.encode())
                (generation / name).write_bytes(new.encode())
            result = freeze_candidate(baseline, generation, CandidatePolicy(), root / "snapshot")
            self.assertTrue(result.ok, result)
            self.assertEqual([item.path for item in result.snapshot.changes], ["a.py", "b.py"])
            self.assertEqual((root / "snapshot/README.md").read_bytes(), b"unchanged\n")
            self.assertEqual((root / "snapshot/a.py").read_bytes(), b"a=2\n")
            for entry in result.snapshot.entries:
                data = (root / "snapshot" / entry.path).read_bytes()
                self.assertEqual(entry.sha256, hashlib.sha256(data).hexdigest())
                self.assertEqual(entry.size, len(data))
            self.assertEqual(result.snapshot.patch_sha256, hashlib.sha256(result.snapshot.patch).hexdigest())
            self.assertEqual(result.snapshot.tree_sha256, hashlib.sha256(result.snapshot.manifest_bytes).hexdigest())

    def test_create_nested_source_and_leave_unchanged_binary_bytes_intact(self):
        (self.generation / "src/new").mkdir()
        (self.generation / "src/new/b.py").write_bytes("值=2\n".encode())
        for root in (self.baseline, self.generation):
            (root / "image.dat").write_bytes(b"\xff\x00")
        result = self.freeze()
        self.assertTrue(result.ok, result)
        self.assertEqual([(c.path, c.operation, c.before_sha256) for c in result.snapshot.changes],
                         [("src/new/b.py", "CREATE", None)])
        self.assertEqual((result.snapshot.root / "image.dat").read_bytes(), b"\xff\x00")

    def test_noop_snapshot_is_not_an_edit_and_tree_hash_is_deterministic(self):
        first = self.freeze()
        second = self.freeze(destination=self.root / "second")
        self.assertTrue(first.ok and second.ok)
        self.assertEqual(first.snapshot.changes, ())
        self.assertEqual(first.snapshot.patch, b"")
        self.assertEqual(first.snapshot.tree_sha256, second.snapshot.tree_sha256)

    def test_protected_oracle_credentials_and_vcs_entries_are_rejected(self):
        from agent.evaluation.repository_candidate import CandidatePolicy
        for name in (".env.local", ".git/config", "oracle/test_hidden.py"):
            path = self.generation / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"never publish")
            result = self.freeze(CandidatePolicy(protected_paths=("oracle",)))
            self.assertFalse(result.ok, name)
            self.assertEqual(result.error_code, "protected_path")
            self.assertFalse((self.root / "snapshot").exists())
            path.unlink()

    def test_edit_prefix_delete_and_changed_encoding_fail_closed(self):
        from agent.evaluation.repository_candidate import CandidatePolicy
        target = self.generation / "src/a.py"
        target.write_bytes(b"a=2\n")
        self.assertEqual(self.freeze(CandidatePolicy(editable_prefixes=("other",))).error_code, "edit_scope")
        target.unlink()
        self.assertEqual(self.freeze().error_code, "delete_unsupported")
        target.write_bytes(b"\xff")
        self.assertEqual(self.freeze().error_code, "changed_encoding")

    def test_entry_total_and_changed_byte_limits(self):
        from agent.evaluation.repository_candidate import CandidatePolicy
        (self.generation / "src/a.py").write_bytes(b"a=2\n")
        self.assertEqual(self.freeze(CandidatePolicy(max_entries=1)).error_code, "entry_limit")
        self.assertEqual(self.freeze(CandidatePolicy(max_total_bytes=1)).error_code, "byte_limit")
        self.assertEqual(self.freeze(CandidatePolicy(max_changed_bytes=1)).error_code, "changed_byte_limit")

    def test_policy_cannot_escape_and_existing_destination_is_preserved(self):
        from agent.evaluation.repository_candidate import CandidatePolicy
        for path in ("../src", "/src", "C:/src", "src/../src"):
            with self.assertRaises(ValueError):
                CandidatePolicy(editable_prefixes=(path,))
        with self.assertRaises(ValueError):
            CandidatePolicy(max_entries=True)
        self.assertEqual(self.freeze(destination=self.generation / "snapshot").error_code, "overlapping_roots")
        destination = self.root / "snapshot"
        destination.mkdir(); (destination / "keep").write_bytes(b"user")
        self.assertEqual(self.freeze().error_code, "destination_exists")
        self.assertEqual((destination / "keep").read_bytes(), b"user")

    def test_hardlink_and_directory_link_are_not_published(self):
        target = self.generation / "src/a.py"
        os.link(target, self.generation / "alias.py")
        self.assertEqual(self.freeze().error_code, "unsupported_file")
        (self.generation / "alias.py").unlink()
        link = self.generation / "outside"
        try:
            link.symlink_to(self.baseline, target_is_directory=True)
        except OSError:
            return  # Windows without symbolic-link privilege; hardlink rejection was still checked.
        self.assertEqual(self.freeze().error_code, "linked_entry")

    def test_source_change_during_snapshot_write_rejects_without_publication(self):
        original_open = Path.open
        def mutating_open(path, *args, **kwargs):
            if any(parent.name.startswith(".candidate-") for parent in path.parents):
                (self.generation / "src/a.py").write_bytes(b"a=concurrent\n")
            return original_open(path, *args, **kwargs)
        with patch.object(Path, "open", mutating_open):
            result = self.freeze()
        self.assertFalse(result.ok, result)
        self.assertEqual(result.error_code, "source_changed")
        self.assertFalse((self.root / "snapshot").exists())
        self.assertEqual(list(self.root.glob(".candidate-*")), [])

    def test_utf8_crlf_and_missing_final_newline_have_hashed_patch_evidence(self):
        (self.generation / "src/a.py").write_bytes("值=2".encode())
        result = self.freeze()
        self.assertTrue(result.ok, result)
        self.assertEqual((result.snapshot.root / "src/a.py").read_bytes(), "值=2".encode())
        self.assertIn(b"\\ No newline at end of file\n", result.snapshot.patch)
        (self.generation / "src/empty.py").write_bytes(b"")
        self.assertEqual(self.freeze(destination=self.root / "empty-snapshot").error_code, "empty_create_unsupported")

    def test_snapshot_write_fault_keeps_destination_absent_and_cleans_owned_stage(self):
        original_open = Path.open
        def failed_open(path, *args, **kwargs):
            if any(parent.name.startswith(".candidate-") for parent in path.parents):
                raise OSError("Authored output disk failure")
            return original_open(path, *args, **kwargs)
        with patch.object(Path, "open", failed_open):
            result = self.freeze()
        self.assertFalse(result.ok, result)
        self.assertEqual(result.error_code, "io_error")
        self.assertFalse((self.root / "snapshot").exists())
        self.assertEqual(list(self.root.glob(".candidate-*")), [])


if __name__ == "__main__":
    unittest.main()
