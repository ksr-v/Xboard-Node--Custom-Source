import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace
import urllib.request
import zipfile

import dependencies as d
import recovery_test


class RecoveryToolsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.original = d.ROOT, d.LOCK, d.STATE
        d.ROOT = Path(self.temp.name)
        d.LOCK = d.ROOT / 'dependency-lock.json'
        d.STATE = d.ROOT / '.dependency-work'
        d.STATE.mkdir()
        self.row = dict(path='example.com/Owner/mod/v2', version='v2.0.0', backup=True, risk='C',
                        logical_path='example.com/Owner/mod/v2', logical_version='v2.0.0', usage=['linux/amd64:build+test'])
        mod = b'module example.com/Owner/mod/v2\n'
        prefix = self.row['path'] + '@' + self.row['version'] + '/'
        source = [(prefix + 'go.mod', mod), (prefix + 'LICENSE', b'License fixture')]
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as z:
            for name, body in source:
                z.writestr(name, body)
        self.content = dict(zip=archive.getvalue(), mod=mod, info=b'{"Version":"v2.0.0","Time":"2026-01-01T00:00:00Z"}')
        self.row.update(sum=d.h1(source), mod_sum=d.h1([('go.mod', mod)]))
        for name, data in [('go.mod', b'module test.invalid/root\n'), ('go.sum', b''), ('dependency-policy.json', b'{}')]:
            (d.ROOT / name).write_bytes(data)
        self.lock = dict(tags=d.TAGS, modules=[self.row], go_sum_only=[], go_mod_sha256=d.sha((d.ROOT / 'go.mod').read_bytes()),
                         go_sum_sha256=d.sha(b''), policy_sha256=d.sha(b'{}'))
        d.write_json(d.LOCK, self.lock)
        self.snapshot = d.STATE / 'snapshot'
        files = {}
        for ext, body in self.content.items():
            rel = 'proxy/' + d.module_key(self.row['path'], self.row['version']) + '.' + ext
            d.immutable(self.snapshot / rel, body)
            files[rel] = dict(sha256=d.sha(body), bytes=len(body))
        index = self.snapshot / 'proxy' / d.escape(self.row['path']) / '@v/list'
        index.write_text('v2.0.0\n')
        self.manifest = dict(lock_sha256=d.sha(d.LOCK.read_bytes()), modules=[dict(self.row, files=files)], graph_metadata=[])
        d.write_json(self.snapshot / 'manifest.json', self.manifest)

    def tearDown(self):
        d.ROOT, d.LOCK, d.STATE = self.original
        self.temp.cleanup()

    def test_real_checksum_and_metadata(self):
        d.verify(self.snapshot)

    def test_case_escape_and_pseudoversion(self):
        self.assertEqual(d.module_key('github.com/Owner/Repo', 'v0.0.0-20260101010101-abcdefabcdef'),
                         'github.com/!owner/!repo/@v/v0.0.0-20260101010101-abcdefabcdef')

    def test_cannot_exempt_c(self):
        with self.assertRaises(ValueError):
            d.classify('x', dict(overrides={'x': dict(risk='C', backup=False, reason='test')}))

    def test_stale_maintenance_evidence_stays_protected(self):
        evidence = dict(contributors_sample=[{}] * 5, pushed_at='2010-01-01',
                        releases=[dict(date='2010-01-01'), dict(date='2010-02-01')])
        pol = dict(overrides={}, low_risk_prefixes=[], _evidence={'owner/repo': evidence})
        self.assertEqual(d.classify('github.com/owner/repo', pol)[:2], ('review_required', True))
        today = d.datetime.now(d.timezone.utc).date().isoformat()
        evidence.update(pushed_at=today, releases=[dict(date=today), dict(date=None)])
        self.assertEqual(d.classify('github.com/owner/repo', pol)[:2], ('B', True))

    def test_corrupt_zip_fails_closed(self):
        path = self.snapshot / next(k for k in self.manifest['modules'][0]['files'] if k.endswith('.zip'))
        data = bytearray(path.read_bytes())
        data[len(data) // 2] ^= 1
        path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            d.verify(self.snapshot)

    def test_cannot_weaken_manifest_policy(self):
        self.manifest['modules'][0]['backup'] = False
        d.write_json(self.snapshot / 'manifest.json', self.manifest)
        with self.assertRaisesRegex(ValueError, 'protection policy'):
            d.verify(self.snapshot)

    def test_hashes_cannot_override_go_sum(self):
        self.manifest['modules'][0]['sum'] = 'h1:fake'
        d.write_json(self.snapshot / 'manifest.json', self.manifest)
        with self.assertRaisesRegex(ValueError, 'trusted Go checksum'):
            d.verify(self.snapshot)

    def test_archive_round_trip_and_immutable(self):
        archive = d.export_snapshot(self.snapshot, d.STATE / 'exports')
        restored = d.STATE / 'restored'
        d.restore(archive, restored, d.sha(archive.read_bytes()))
        d.verify(restored)
        with self.assertRaisesRegex(ValueError, 'empty'):
            d.restore(archive, restored, d.sha(archive.read_bytes()))

    def test_archive_wrong_digest(self):
        archive = d.export_snapshot(self.snapshot, d.STATE / 'exports')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            d.restore(archive, d.STATE / 'restored', 'wrong')

    def test_archive_traversal_refused(self):
        path = d.STATE / 'evil.zip'
        with zipfile.ZipFile(path, 'w') as z:
            z.writestr('../outside', b'bad')
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            d.restore(path, d.STATE / 'restored', d.sha(path.read_bytes()))

    def test_historical_bytes_immutable(self):
        path = d.STATE / 'one.mod'
        d.immutable(path, b'original')
        d.immutable(path, b'original')
        with self.assertRaises(ValueError):
            d.immutable(path, b'different')
        self.assertEqual(path.read_bytes(), b'original')

    def test_unsafe_module_path(self):
        for path in ['../outside', 'github.com/a/../b', 'file:/token', 'github.com//a']:
            with self.assertRaises(ValueError):
                d.module_key(path, 'v1.0.0')

    def test_lock_change_requires_reaudit(self):
        (d.ROOT / 'go.mod').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'run audit'):
            d.verify(self.snapshot)

    def test_checkout_line_endings_do_not_break_pin(self):
        for path in (d.ROOT / 'go.mod', d.LOCK):
            path.write_bytes(path.read_bytes().replace(b'\n', b'\r\n'))
        d.verify(self.snapshot)

    def test_changed_build_tags_require_audit(self):
        self.lock['tags'] = 'with_naive_outbound'
        d.write_json(d.LOCK, self.lock)
        with self.assertRaisesRegex(ValueError, 'Build tags changed'):
            d.verify(self.snapshot)

    def test_release_builds_remove_local_source_paths(self):
        build_policy = dict(d.policy(), public_proxy='https://proxy.example.com')
        with mock.patch.object(d, 'policy', return_value=build_policy), \
                mock.patch.object(d, 'run', return_value='fixture-commit') as execute:
            for arch in ('amd64', 'arm64'):
                d.build(self.snapshot, arch)
        commands = [call.args[0] for call in execute.call_args_list if call.args[0][:2] == ['go', 'build']]
        self.assertEqual(len(commands), 4)
        for command in commands:
            self.assertIn('-trimpath', command)
            self.assertIn('-ldflags', command)

    def test_recovery_refuses_source_mutation_after_successful_commands(self):
        # Fault injection: every external command reports success, but a build
        # rewrites go.sum. Exercise the real recovery gateway and final result.
        d.write_json(d.ROOT / 'dependency-snapshot.json', dict(
            lock_sha256=d.text_sha(d.LOCK), manifest_sha256=d.sha((self.snapshot / 'manifest.json').read_bytes())))

        def successful_command(argv, cwd=None, env=None, **kwargs):
            if argv[:3] == ['go', 'mod', 'download']:
                url = env['GOPROXY'] + '/' + d.module_key(self.row['path'], self.row['version']) + '.zip'
                with urllib.request.urlopen(url, timeout=3) as response:
                    self.assertEqual(response.read(), self.content['zip'])
            if argv[:2] == ['go', 'build']:
                machine = {'amd64': 62, 'arm64': 183}[env.get('GOARCH', 'amd64')]
                Path(argv[argv.index('-o') + 1]).write_bytes(b'\x7fELF' + b'\0' * 14 + machine.to_bytes(2, 'little'))
                (Path(cwd) / 'go.sum').write_bytes(b'changed by simulated build\n')
            return SimpleNamespace(returncode=0, stdout='go version simulated\n', stderr='')

        with mock.patch.object(recovery_test.subprocess, 'run', side_effect=successful_command):
            with self.assertRaisesRegex(ValueError, 'changed go.mod/go.sum'):
                recovery_test.recovery_test(self.snapshot)
        evidence = json.loads(next(d.STATE.glob('recovery-*/results.json')).read_text())
        self.assertFalse(evidence['source_unchanged'])
        self.assertFalse(evidence['passed'])
        self.assertEqual((d.ROOT / 'go.sum').read_bytes(), b'')


if __name__ == '__main__':
    unittest.main()
