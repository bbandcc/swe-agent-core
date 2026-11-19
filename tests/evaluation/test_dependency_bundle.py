"""Public wheel-only input admission; no candidate code is imported."""
import hashlib
import tempfile
from pathlib import Path
import unittest
import zipfile

from agent.evaluation.dependency_bundle import WheelPin, prepare_dependency_bundle


class DependencyBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cache = self.root / 'cache'
        self.cache.mkdir()

    def wheel(self, extra=None):
        path = self.cache / 'demo-1.0-py3-none-any.whl'
        members = {'demo/__init__.py': "raise RuntimeError('never import payload')\n",
            'demo-1.0.dist-info/METADATA': 'Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n',
            'demo-1.0.dist-info/WHEEL': 'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
            'demo-1.0.dist-info/RECORD': ''}
        members.update(extra or {})
        with zipfile.ZipFile(path, 'w') as archive:
            for name, value in members.items():
                entry = zipfile.ZipInfo(name)
                entry.filename = name  # Preserve hostile Windows backslashes in the ZIP.
                archive.writestr(entry, value)
        return WheelPin(path.name, hashlib.sha256(path.read_bytes()).hexdigest(), 'demo', '1.0')

    def test_prepares_exact_bytes_and_manifest_without_installing(self):
        pin = self.wheel()
        result = prepare_dependency_bundle(self.cache, (pin,), self.root / 'bundle')
        self.assertTrue(result.ok, result)
        self.assertFalse(result.execution_admitted)
        self.assertEqual((self.root / 'bundle' / pin.path).read_bytes(), (self.cache / pin.path).read_bytes())
        self.assertTrue((self.root / 'bundle' / 'manifest.json').is_file())
        self.assertFalse((self.root / 'bundle' / 'demo').exists())

    def test_refuses_hash_identity_and_path_mismatch_before_output(self):
        pin = self.wheel()
        for index, bad in enumerate((WheelPin(pin.path, '0'*64, 'demo', '1.0'),
            WheelPin('../'+pin.path, pin.sha256, 'demo', '1.0'),
            WheelPin(pin.path, pin.sha256, 'other', '1.0'))):
            output = self.root / str(index)
            self.assertFalse(prepare_dependency_bundle(self.cache, (bad,), output).ok)
            self.assertFalse(output.exists())

    def test_refuses_unsafe_or_executable_install_layouts(self):
        for index, name in enumerate(('../outside', '/outside', 'C:/outside', 'demo\\evil',
                                    'start.pth', 'demo-1.0.data/scripts/tool', 'demo-1.0.dist-info/entry_points.txt',
                                    'demo/NUL.py', 'demo/trailing.')):
            pin = self.wheel({name: 'payload'})
            output = self.root / ('bad'+str(index))
            self.assertFalse(prepare_dependency_bundle(self.cache, (pin,), output).ok, name)
            self.assertFalse(output.exists())

    def test_rejects_zip_symlink_and_corrupt_payload(self):
        pin = self.wheel()
        path = self.cache / pin.path
        with zipfile.ZipFile(path, 'a') as archive:
            entry = zipfile.ZipInfo('demo/link')
            entry.create_system = 3
            entry.external_attr = 0o120777 << 16
            archive.writestr(entry, '../elsewhere')
        pin = WheelPin(pin.path, hashlib.sha256(path.read_bytes()).hexdigest(), pin.name, pin.version)
        self.assertFalse(prepare_dependency_bundle(self.cache, (pin,), self.root/'symlink').ok)
        path.write_bytes(b'not a zip')
        pin = WheelPin(pin.path, hashlib.sha256(path.read_bytes()).hexdigest(), pin.name, pin.version)
        self.assertFalse(prepare_dependency_bundle(self.cache, (pin,), self.root/'corrupt').ok)

    def test_rejects_duplicates_links_and_existing_destination(self):
        pin = self.wheel()
        self.assertFalse(prepare_dependency_bundle(self.cache, (pin, pin), self.root/'dupe').ok)
        output = self.root/'existing'; output.mkdir()
        self.assertFalse(prepare_dependency_bundle(self.cache, (pin,), output).ok)
        alias = self.cache/'alias.whl'
        try: alias.hardlink_to(self.cache/pin.path)
        except OSError: self.skipTest('hardlinks unavailable')
        self.assertFalse(prepare_dependency_bundle(self.cache, (pin,), self.root/'link').ok)
