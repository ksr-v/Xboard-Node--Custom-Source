"""Publication-integrity fixtures; no network or binary execution."""
import hashlib
from pathlib import Path
import tempfile
import unittest

import verify_release_assets as release


class ReleaseAssetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.installer = self.directory / 'tagged.sh'
        pins = []
        for name in sorted(release.ASSETS - {'install.sh'}):
            header = bytearray(20)
            header[:4] = b'\x7fELF'
            header[18:20] = (62 if name.endswith('amd64') else 183).to_bytes(2, 'little')
            (self.directory / name).write_bytes(header)
            kind = 'node' if name.startswith('xboard-node') else 'xbctl'
            pins.append(f"    {kind}:{name.rsplit('-', 1)[1]}) expected={hashlib.sha256(header).hexdigest()} ;;")
        self.installer.write_text('\n'.join(pins) + '\n', encoding='utf-8')
        (self.directory / 'install.sh').write_bytes(self.installer.read_bytes())
        self.manifest()

    def manifest(self):
        (self.directory / 'SHA256SUMS').write_text(''.join(
            hashlib.sha256((self.directory / name).read_bytes()).hexdigest() + '  ' + name + '\n'
            for name in sorted(release.ASSETS)), encoding='ascii')

    def test_exact_immutable_asset_set_passes(self):
        release.verify(self.directory, self.installer)

    def test_modified_binary_is_refused(self):
        (self.directory / 'xbctl-linux-amd64').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            release.verify(self.directory, self.installer)

    def test_recomputed_manifest_cannot_override_tagged_binary_pin(self):
        (self.directory / 'xbctl-linux-amd64').write_bytes(b'tampered')
        self.manifest()
        with self.assertRaisesRegex(ValueError, 'installer binary pins'):
            release.verify(self.directory, self.installer)

    def test_unexpected_path_or_duplicate_entry_is_refused(self):
        manifest = self.directory / 'SHA256SUMS'
        original = manifest.read_text(encoding='ascii')
        for bad in ('0' * 64 + '  ../escape\n', original.splitlines()[0] + '\n'):
            manifest.write_text(original + bad, encoding='ascii')
            with self.assertRaisesRegex(ValueError, 'checksum entry'):
                release.verify(self.directory, self.installer)

    def test_changed_installer_is_refused(self):
        (self.directory / 'install.sh').write_bytes(self.installer.read_bytes() + b'# changed\n')
        self.manifest()
        with self.assertRaisesRegex(ValueError, 'differs from tagged source'):
            release.verify(self.directory, self.installer)


if __name__ == '__main__':
    unittest.main()
