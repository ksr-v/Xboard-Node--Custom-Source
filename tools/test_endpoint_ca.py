"""Linux Root fixtures for private NodeEndpoint trust; no services or network."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / 'install.sh').read_text(encoding='utf-8')
HELPER = SCRIPT.split("<<'PY_ENDPOINT_CA'\n", 1)[1].split('\nPY_ENDPOINT_CA', 1)[0]

@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'requires Linux Root path/ownership semantics')
class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='nodeendpoint-ca-test-', dir='/root')
        self.base = Path(self.temporary.name)
        self.root = self.base / 'owned'; self.root.mkdir(mode=0o700)
        self.stage = self.base / 'stage'; self.stage.mkdir(mode=0o700)
        self.helper = self.base / 'helper.py'; self.helper.write_text(HELPER)
        self.ca = self.certificate('root', True)
        self.pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.ca.decode())).hexdigest()
    def tearDown(self): self.temporary.cleanup()
    def certificate(self, name, ca, digest='sha256'):
        pem = self.base / (name + '.pem')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-' + digest,
            '-keyout', str(self.base / (name + '.key')), '-out', str(pem), '-days', '30',
            '-subj', '/CN=' + name, '-addext', 'basicConstraints=critical,CA:' + ('TRUE' if ca else 'FALSE'),
            '-addext', 'keyUsage=critical,' + ('keyCertSign,cRLSign' if ca else 'digitalSignature')],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return pem.read_bytes()
    def run_helper(self, mode='stage', ca=None, pins=None, url='https://192.0.2.10:8443'):
        args = ['python3', str(self.helper), mode, str(self.stage), str(self.root)]
        if mode == 'stage':
            args += [base64.b64encode(self.ca if ca is None else ca).decode(), pins or self.pin, url]
        return subprocess.run(args, capture_output=True)
    def stored(self):
        self.assertEqual(self.run_helper().returncode, 0)
        for p in self.stage.iterdir(): shutil.copy2(p, self.root / p.name)
    def test_stage_fingerprint_permissions_and_system_roots(self):
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        ca = (self.stage / 'node-endpoint-ca.pem').read_bytes()
        trust = (self.stage / 'node-endpoint-trust.pem').read_bytes()
        self.assertTrue(trust.endswith(ca))
        self.assertGreater(len(trust), len(ca))
        for p in self.stage.iterdir(): self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
    def test_invalid_pin_and_payload_leave_stage_empty(self):
        for ca, pin in ((self.ca, '0'*64), (self.ca + b'PRIVATE KEY', self.pin),
                        (self.ca*2, self.pin+','+self.pin), (b'invalid', self.pin)):
            self.assertNotEqual(self.run_helper(ca=ca, pins=pin).returncode, 0)
            self.assertEqual(list(self.stage.iterdir()), [])
    def test_leaf_and_weak_signature_refused(self):
        for ca in (self.certificate('leaf', False), self.certificate('sha1', True, 'sha1')):
            pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca.decode())).hexdigest()
            self.assertNotEqual(self.run_helper(ca=ca, pins=pin).returncode, 0)
    def test_plain_https_origin_required(self):
        for url in ('http://192.0.2.10', 'https://a:b@host', 'https://host/path', 'https://host/?key=value'):
            self.assertNotEqual(self.run_helper(url=url).returncode, 0)
    def test_stored_checksum_and_modes_checked(self):
        self.stored()
        self.assertEqual(self.run_helper('check').returncode, 0)
        p = self.root / 'node-endpoint-trust.pem'; p.write_bytes(p.read_bytes()+b'changed')
        self.assertNotEqual(self.run_helper('check').returncode, 0)
        self.stored(); p.chmod(0o644)
        self.assertNotEqual(self.run_helper('verify').returncode, 0)
    def test_symlink_and_hardlink_refused(self):
        self.stored()
        p = self.root / 'node-endpoint-ca.pem'; target = self.base / 'copy.pem'
        p.rename(target); p.symlink_to(target)
        self.assertNotEqual(self.run_helper('check').returncode, 0)
        p.unlink(); os.link(target, p)
        self.assertNotEqual(self.run_helper('check').returncode, 0)
    def test_dual_trust_roundtrip(self):
        second = self.certificate('second', True)
        pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(second.decode())).hexdigest()
        self.assertEqual(self.run_helper(ca=self.ca+second, pins=self.pin+','+pin).returncode, 0)
        for p in self.stage.iterdir(): shutil.copy2(p, self.root / p.name)
        for p in self.stage.iterdir(): p.unlink()
        self.assertEqual(self.run_helper('verify').returncode, 0)
        meta = json.loads((self.stage / 'node-endpoint-trust.json').read_bytes())
        self.assertEqual(meta['fingerprints'], [self.pin, pin])

if __name__ == '__main__': unittest.main()
