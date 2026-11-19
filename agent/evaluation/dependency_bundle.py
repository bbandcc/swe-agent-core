"""Frozen wheel inputs only: never an installer or execution safety approval."""
from dataclasses import dataclass
from email.parser import BytesParser
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile
import zlib

from agent.workspace import WorkspacePathResolver, canonicalize_root_path, has_single_regular_file_link

MAX_WHEEL_BYTES = 32 * 1024 * 1024
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
_DEVICES = {'con', 'prn', 'aux', 'nul'} | {f'{prefix}{n}' for prefix in ('com', 'lpt') for n in range(1, 10)}


@dataclass(frozen=True)
class WheelPin:
    path: str
    sha256: str
    name: str
    version: str


@dataclass(frozen=True)
class BundleResult:
    ok: bool
    manifest_sha256: str | None = None
    error_code: str | None = None
    execution_admitted: bool = False
    cleanup_complete: bool = True


def _normalized(name: str) -> str:
    return re.sub(r'[-_.]+', '-', name).lower()


def _validate_wheel(data: bytes, pin: WheelPin) -> None:
    prefix = pin.name.replace('-', '_') + '-' + pin.version + '.dist-info/'
    expected = {prefix + leaf for leaf in ('METADATA', 'WHEEL', 'RECORD')}
    seen, metadata, size = set(), {}, 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if not 1 <= len(entries) <= 4096:
            raise ValueError('wheel_entries')
        for entry in entries:
            name = entry.orig_filename
            parts = PurePosixPath(name).parts
            mode = stat.S_IFMT(entry.external_attr >> 16)
            key = name.casefold().rstrip('/')
            if (name != entry.filename or not parts or name.startswith('/') or '\\' in name or ':' in name or '\0' in name
                    or any(part in ('', '..', '.') for part in name.rstrip('/').split('/'))
                    or any(part.rstrip(' .') != part or part.split('.')[0].casefold() in _DEVICES for part in parts)
                    or key in seen or mode not in (0, stat.S_IFREG, stat.S_IFDIR)
                    or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or entry.flag_bits & 1 or entry.file_size > MAX_EXPANDED_BYTES
                    or any(part.endswith('.data') for part in parts)
                    or name.lower().endswith(('.pth', '/entry_points.txt'))
                    or any(part.endswith('.dist-info') and part != prefix.rstrip('/') for part in parts)):
                raise ValueError('wheel_layout')
            seen.add(key)
            if entry.is_dir():
                continue
            collected = bytearray()
            with archive.open(entry) as stream:
                while chunk := stream.read(65536):
                    size += len(chunk)
                    if size > MAX_EXPANDED_BYTES:
                        raise ValueError('wheel_expanded_limit')
                    if name in expected:
                        if len(collected) + len(chunk) > 65536:
                            raise ValueError('wheel_metadata_limit')
                        collected.extend(chunk)
            if name in expected:
                metadata[name] = bytes(collected)
        if set(metadata) != expected:
            raise ValueError('wheel_metadata_missing')
        package = BytesParser().parsebytes(metadata[prefix + 'METADATA'])
        wheel = BytesParser().parsebytes(metadata[prefix + 'WHEEL'])
        if (package.get_all('Name') != [pin.name] or package.get_all('Version') != [pin.version]
                or wheel.get_all('Root-Is-Purelib') != ['true']
                or wheel.get_all('Tag') != ['py3-none-any']):
            raise ValueError('wheel_identity')


def prepare_dependency_bundle(cache_root: Path, pins: tuple[WheelPin, ...], destination: Path) -> BundleResult:
    """Validate reviewed pins and copy those exact bytes into a fresh directory.

    Only pure-Python py3-none-any wheels without .pth/.data/entrypoints are
    admitted in this slice. Requirements resolution, installation, provenance
    review and execution in a concrete container remain separate obligations.
    No model-generated lock or arbitrary URL is accepted by this interface.
    """
    owned = []
    made = False
    try:
        if not isinstance(pins, tuple) or not 1 <= len(pins) <= 16:
            raise ValueError('pins')
        cache = canonicalize_root_path(cache_root, must_exist=True)
        resolver = WorkspacePathResolver(cache)
        destination = Path(destination).absolute()
        parent = canonicalize_root_path(destination.parent, must_exist=True)
        destination = parent / destination.name
        if destination.exists() or destination.is_symlink() or destination == cache or cache in destination.parents:
            raise ValueError('destination')
        payloads, identities, total = [], set(), 0
        for pin in pins:
            if (not isinstance(pin, WheelPin) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}', pin.name)
                    or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.!+_-]{0,63}', pin.version)
                    or not re.fullmatch(r'[0-9a-f]{64}', pin.sha256)):
                raise ValueError('pin_schema')
            filename = pin.name.replace('-', '_') + '-' + pin.version + '-py3-none-any.whl'
            if pin.path != filename or _normalized(pin.name) in identities:
                raise ValueError('pin_identity')
            identities.add(_normalized(pin.name))
            resolved = resolver.resolve_file(pin.path, allow_absolute=False)
            if not resolved.ok or not has_single_regular_file_link(resolved.path):
                raise ValueError('wheel_path')
            before = resolved.path.stat()
            if before.st_size > MAX_WHEEL_BYTES:
                raise ValueError('wheel_size')
            with resolved.path.open('rb') as stream:
                data = stream.read(MAX_WHEEL_BYTES + 1)
            after = resolved.path.stat()
            signature = lambda s: (s.st_dev, s.st_ino, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if (len(data) > MAX_WHEEL_BYTES or hashlib.sha256(data).hexdigest() != pin.sha256
                    or signature(before) != signature(after) or not has_single_regular_file_link(resolved.path)):
                raise ValueError('wheel_drift')
            total += len(data)
            if total > MAX_BUNDLE_BYTES:
                raise ValueError('bundle_size')
            _validate_wheel(data, pin)
            payloads.append((pin, data))
        manifest = {'schema_version': 1, 'kind': 'REVIEWED_WHEEL_INPUTS', 'execution_admitted': False,
            'installation_performed': False, 'wheels': [
                {'file': p.path, 'name': p.name, 'version': p.version, 'sha256': p.sha256, 'bytes': len(b)}
                for p, b in payloads]}
        encoded = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
        destination.mkdir()
        made = True
        for name, data in [(p.path, b) for p, b in payloads] + [('manifest.json', encoded)]:
            target = destination / name
            with target.open('xb') as stream:
                owned.append(target)
                stream.write(data)
        return BundleResult(True, hashlib.sha256(encoded).hexdigest())
    except (OSError, ValueError, TypeError, zipfile.BadZipFile, RuntimeError, zlib.error):
        # Delete only paths created by this call, never a pre-existing directory.
        cleaned = True
        if made:
            for target in owned:
                try: target.unlink()
                except OSError: cleaned = False
            try: destination.rmdir()
            except OSError: cleaned = False
        return BundleResult(False, error_code='dependency_bundle_rejected', cleanup_complete=cleaned)
