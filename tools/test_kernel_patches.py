import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import kernel_patches as k


class MaintainedCorePatchTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.module = self.root / 'cache/core'
        self.original = self.module / 'app/dispatcher/default.go'
        self.original.parent.mkdir(parents=True)
        self.original.write_bytes(b'original fixed core\n')
        self.patched = self.root / 'patches/xray-core/app/dispatcher/default.go'
        self.patched.parent.mkdir(parents=True)
        self.patched.write_bytes(b'maintained fixed core\n')
        (self.root / 'go.mod').write_text('module test/root\n\ngo 1.26\n')
        source_hash = k._tree_hash(self.module, 'test/frozen-core@v1.0.0/')
        (self.root / 'go.sum').write_text('test/frozen-core v1.0.0 ' + source_hash + '\n')
        self.manifest = self.root / 'patches/xray-core/manifest.json'
        self.manifest.write_text(json.dumps({'schema': 1, 'module': 'test/core',
            'replacement': 'test/frozen-core', 'version': 'v1.0.0', 'files': [{
                'path': 'app/dispatcher/default.go',
                'original_sha256': hashlib.sha256(self.original.read_bytes()).hexdigest(),
                'patched_sha256': hashlib.sha256(self.patched.read_bytes()).hexdigest()}]}))
        self.resolve = patch.object(k, '_go', return_value={'Replace': {
            'Path': 'test/frozen-core', 'Version': 'v1.0.0', 'Dir': str(self.module)}})
        self.resolve.start()
        self.addCleanup(self.resolve.stop)

    def test_uses_verified_maintained_copy_without_mutating_cache_or_go_mod(self):
        flags = k.prepare({}, self.root)
        self.assertIn('-modfile=', flags)
        maintained = next((self.root / '.dependency-work').glob('xray-core-*'))
        self.assertEqual((maintained / 'app/dispatcher/default.go').read_bytes(), self.patched.read_bytes())
        self.assertEqual(self.original.read_bytes(), b'original fixed core\n')
        self.assertEqual((self.root / 'go.mod').read_text(), 'module test/root\n\ngo 1.26\n')
        self.assertIn('./.dependency-work/' + maintained.name, (self.root / '.dependency-work/kernel-build.mod').read_text())
        self.assertNotIn(self.root.as_posix(), (self.root / '.dependency-work/kernel-build.mod').read_text())

    def test_modified_maintained_copy_refused(self):
        k.prepare({}, self.root)
        maintained = next((self.root / '.dependency-work').glob('xray-core-*'))
        (maintained / 'unexpected.go').write_text('unexpected source')
        with self.assertRaisesRegex(ValueError, 'Maintained kernel copy was modified'):
            k.prepare({}, self.root)

    def test_original_module_tampering_refused(self):
        self.original.write_bytes(b'wrong original')
        with self.assertRaisesRegex(ValueError, 'Original pinned core'):
            k.prepare({}, self.root)

    def test_patch_tampering_refused(self):
        self.patched.write_bytes(b'wrong patch')
        with self.assertRaisesRegex(ValueError, 'Maintained core patch checksum'):
            k.prepare({}, self.root)

    def test_changed_module_version_refused(self):
        with patch.object(k, '_go', return_value={'Replace': {'Path': 'test/frozen-core', 'Version': 'v2.0.0'}}):
            with self.assertRaisesRegex(ValueError, 'fixed module version'):
                k.prepare({}, self.root)


if __name__ == '__main__':
    unittest.main()
