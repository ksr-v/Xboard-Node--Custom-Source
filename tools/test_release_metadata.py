"""Release metadata must survive the later installer-pin commit unchanged."""
import unittest
import release_metadata


class ReleaseMetadataTests(unittest.TestCase):
    def test_pinned_release_has_fixed_metadata_without_commit_identity(self):
        value = release_metadata.settings('v1.13-orphan.10', 'go version go1.26.8 linux/amd64')
        self.assertEqual(value, '-s -w -X main.version=v1.13-orphan.10 '
                               '-X main.buildTime=2026-10-31T00:00:00Z')
        self.assertNotIn('commit', value)

    def test_other_toolchain_cannot_produce_installer_pinned_release(self):
        with self.assertRaisesRegex(ValueError, 'requires go1.26.8'):
            release_metadata.settings('v1.13-orphan.10', 'go version go1.27.0 linux/amd64')

    def test_development_version_preserves_normal_build_behavior(self):
        self.assertIsNone(release_metadata.settings('development', 'go version go1.27.0 linux/amd64'))


if __name__ == '__main__':
    unittest.main()
