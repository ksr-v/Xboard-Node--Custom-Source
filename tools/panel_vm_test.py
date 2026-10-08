"""Authorized, isolated panel VM deployment and traffic test driver.

Runtime state, configuration, credentials and diagnostic logs remain private.
Public result JSON contains named checks and their Boolean outcomes only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


SERVICE = 'xboard-node.service'
INSTALL_ROOT = Path('/etc/xboard-node')
OWNER_FILE = INSTALL_ROOT / '.panel-e2e-owner'
FILES = dict(binary=Path('/usr/local/bin/xboard-node'), xbctl=Path('/usr/local/bin/xbctl'),
             config=INSTALL_ROOT / 'config.yml', credentials=INSTALL_ROOT / 'credentials.env',
             metadata=INSTALL_ROOT / 'install-meta.json',
             service=Path('/etc/systemd/system/xboard-node.service'))


def private_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
    path.chmod(0o600)


def public_projection(value):
    """Export check outcomes without copying any private runtime fields."""
    checks = []

    def visit(rows):
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = row.get('check')
            if isinstance(name, str) and re.fullmatch(r'[a-z][a-z0-9:_-]*', name):
                checks.append(dict(check=name, passed=row.get('passed') is True))
            elif name is not None:
                checks.append(dict(check='redacted-check', passed=False))
            nested = row.get('checks', [])
            if isinstance(nested, list):
                visit(nested)

    if isinstance(value, dict):
        rows = value.get('checks', [])
        if isinstance(rows, list):
            visit(rows)
    return dict(passed=isinstance(value, dict) and value.get('passed') is True,
                checks=checks)


def privacy_self_test():
    """Exercise the export boundary with synthetic private runtime values."""
    private = dict(token='synthetic-secret', uuid='synthetic-credential',
                   username='fixture-owner', path='/private/runtime/example',
                   host='203.0.113.17', machine_id=548217, user_id=548218,
                   node_id=548219, sha256='ab' * 32, count=48127,
                   traffic_bytes=9387214, online_devices=487)
    value = dict(passed=True, **private, checks=[
        dict(check='fixture-auth', passed=True, **private),
        dict(check='fixture-traffic', passed=False, checks=[
            dict(check='fixture-tls', passed=True, **private)]),
        dict(check=private['path'], passed=True)])
    before = json.dumps(value, sort_keys=True)
    expected = dict(passed=True, checks=[
        dict(check='fixture-auth', passed=True),
        dict(check='fixture-traffic', passed=False),
        dict(check='fixture-tls', passed=True),
        dict(check='redacted-check', passed=False)])
    public = public_projection(value)
    if public != expected or json.dumps(value, sort_keys=True) != before:
        raise RuntimeError('Public projection privacy test failed')
    return dict(passed=True, checks=[dict(check='public-projection-private-fields-excluded', passed=True),
                                     dict(check='private-runtime-values-preserved', passed=True)])


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


class Driver:
    def __init__(self, args):
        self.args = args
        self.base = args.base.resolve()
        self.source = self.base.parent / 'source'
        self.case = self.base / (args.arch + '-' + args.kernel)
        state_path = self.base / 'state.json'
        metadata = state_path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise RuntimeError('Private runtime state must be a regular mode-600 file')
        self.state = json.loads(state_path.read_text(encoding='utf-8'))
        self.binding = self.state['machines'][args.kernel]
        self.secrets = [self.state['uuid']]
        for machine in self.state['machines'].values():
            self.secrets.append(machine['token'])
        self.panel_url = args.panel_url or self.state.get('panel_url')
        if not isinstance(self.panel_url, str) or not self.panel_url:
            raise RuntimeError('Panel URL must be provided explicitly')
        self.recovery = args.recovery.resolve()
        self.cert = self.base / 'tls/cert.pem'
        self.key = self.base / 'tls/key.pem'
        self.health_port = free_port()
        self.owner = str(uuid.uuid4())
        self.owns_install = False
        self.process = None
        self.node_log_thread = None
        self.node_log_error = None
        self.started_at = None
        self.node_started_at_unix = None
        self.rows = []
        self.result = dict(passed=False, checks=self.rows)

    def private_path(self, name):
        directory = self.case / 'private-runtime'
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
        return directory / name

    def sanitized(self, value):
        for secret in self.secrets:
            if secret:
                value = value.replace(secret, '[REDACTED]')
        return value

    def save_log(self, label, value):
        path = self.private_path(label + '.log')
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(self.sanitized(value))
        path.chmod(0o600)

    def run(self, command, label, expected=0, timeout=420):
        # Never use check=True: CalledProcessError/TimeoutExpired include argv,
        # and the original installer must receive a private machine token.
        try:
            completed = subprocess.run(command, cwd=self.case, capture_output=True,
                                       text=True, errors='replace', timeout=timeout)
        except subprocess.TimeoutExpired as error:
            out = error.stdout or b''
            if isinstance(out, bytes):
                out = out.decode('utf-8', errors='replace')
            self.save_log(label, out)
            raise RuntimeError(label + ' timed out') from None
        self.save_log(label, completed.stdout + completed.stderr)
        if expected is not None and completed.returncode != expected:
            raise RuntimeError(label + ' exited with ' + str(completed.returncode))
        return completed

    def row(self, step, **values):
        # Details stay in private diagnostics or local variables used by assertions.
        row = dict(check=self.args.arch + '-' + self.args.kernel + ':' + step,
                   passed=True)
        self.rows.append(row)
        print(json.dumps(row), flush=True)

    def assert_install_owner(self):
        completed = self.run(['sudo', '-n', 'cat', str(OWNER_FILE)], 'ownership-check')
        if completed.stdout.strip() != self.owner:
            raise RuntimeError('Installation ownership marker changed; refusing mutation')

    def hashes(self, label):
        self.assert_install_owner()
        result = {}
        for name, path in FILES.items():
            output = self.run(['sudo', '-n', 'sha256sum', str(path)], label + '-' + name).stdout
            digest = output.split()[0]
            if len(digest) != 64:
                raise RuntimeError('Invalid file hash for ' + name)
            result[name] = digest
        return result

    def installer(self, action, binary=None, xbctl=None, version='e2e-initial'):
        command = ['sudo', '-n', 'bash', str(self.source / 'install.sh'), action,
                   '--health-port', str(self.health_port), '--kernel', self.args.kernel,
                   '--version', version, '--yes']
        if action == 'install':
            command.extend(['--mode', 'machine', '--panel', self.panel_url,
                            '--machine-id', str(self.binding['machine_id']),
                            '--token', self.binding['token']])
        if action == 'uninstall':
            command.append('--purge')
        if binary:
            command.extend(['--binary', str(binary)])
        if xbctl:
            command.extend(['--xbctl-binary', str(xbctl)])
        return command

    def configuration(self):
        route = dict(ip_cidr=['127.0.0.1/32'], outbound='direct')
        if self.args.kernel == 'xray':
            route = dict(type='field', ip=['127.0.0.1/32'], outboundTag='direct')
        return dict(panel=dict(url=self.panel_url),
                    machine=dict(machine_id=self.binding['machine_id'], token=self.binding['token']),
                    kernel=dict(type=self.args.kernel, config_dir=str(self.case / 'kernel-config'),
                                log_level='warn', custom_route=[route]),
                    cert=dict(cert_mode='file', cert_file=str(self.cert), key_file=str(self.key)),
                    node=dict(push_interval=5, pull_interval=2, track_interval=1,
                              device_report_interval=1),
                    log=dict(level='info', output='stdout'), health_port=self.health_port)

    def machine_auth_checks(self):
        def request(path, payload, method='POST'):
            url = self.panel_url.rstrip('/') + path
            body = None
            if method == 'GET':
                url += '?' + urllib.parse.urlencode(payload)
            else:
                body = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(url, data=body, method=method,
                                         headers={'Accept': 'application/json', 'Content-Type': 'application/json'})
            try:
                with urllib.request.urlopen(req, timeout=20) as response:
                    return response.status, json.loads(response.read(4 * 1024 * 1024))
            except urllib.error.HTTPError as error:
                error.close()
                return error.code, None

        auth = dict(machine_id=self.binding['machine_id'], token=self.binding['token'])
        status_code, payload = request('/api/v2/server/machine/nodes', auth)
        if status_code != 200 or {int(row['id']) for row in payload['nodes']} != {int(self.binding['node_id'])}:
            raise RuntimeError('Machine discovery did not return exactly its isolated fixture node')
        self.row('machine-api-valid-token', http_status=status_code, fixture_nodes=1)
        node_auth = dict(auth, node_id=self.binding['node_id'])
        status_code, handshake = request('/api/v2/server/handshake', node_auth)
        if status_code != 200:
            raise RuntimeError('Valid machine handshake was rejected')
        self.row('machine-api-handshake', http_status=status_code,
                 websocket_enabled=bool(handshake.get('websocket', {}).get('enabled')))
        status_code, config = request('/api/v2/server/config', node_auth, 'GET')
        if status_code != 200 or int(config['server_port']) != int(self.binding['port']):
            raise RuntimeError('Machine configuration did not match the fixture listener')
        status_code, users = request('/api/v2/server/user', node_auth, 'GET')
        if status_code != 200 or {int(row['id']) for row in users['users']} != {int(self.state['user_id'])}:
            raise RuntimeError('Machine user feed did not contain exactly the fixture user')
        self.row('machine-api-config-and-user-feed', fixture_users=1)
        status_code, _ = request('/api/v2/server/machine/nodes', dict(auth, token='invalid-fixture-token-' + uuid.uuid4().hex))
        if not 400 <= status_code < 500:
            raise RuntimeError('Invalid machine token was not refused with a client error')
        self.row('machine-api-invalid-token-rejected', http_status=status_code)
        other = next(value for name, value in self.state['machines'].items() if name != self.args.kernel)
        status_code, _ = request('/api/v2/server/config', dict(auth, node_id=other['node_id']), 'GET')
        if not 400 <= status_code < 500:
            raise RuntimeError('Cross-machine node access was not refused with a client error')
        self.row('machine-api-cross-machine-node-rejected', http_status=status_code)

    def stream_node_log(self):
        try:
            path = self.private_path('node.log')
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
                for line in self.process.stdout:
                    stream.write(self.sanitized(line))
                    stream.flush()
        except BaseException as error:
            self.node_log_error = type(error).__name__

    def wait_healthy(self, label, timeout=40):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process and self.process.poll() is not None:
                raise RuntimeError('ARM Node exited before health check')
            try:
                with urllib.request.urlopen('http://127.0.0.1:' + str(self.health_port) + '/healthz', timeout=1) as response:
                    if response.status == 200:
                        with socket.create_connection(('127.0.0.1', int(self.binding['port'])), timeout=1):
                            break
            except (OSError, ValueError):
                time.sleep(0.2)
        else:
            raise RuntimeError(label + ' did not become healthy with a VLESS listener')
        if self.args.arch == 'amd64':
            self.run(['systemctl', 'is-active', '--quiet', SERVICE], label + '-active')
        self.row(label, health=True, vless_listener=True)

    def preflight_install(self):
        # --purge later is authorized only because these complete installation
        # objects did not exist before this particular case created them.
        paths = [INSTALL_ROOT, FILES['binary'], FILES['xbctl'], FILES['service'], Path('/usr/bin/xbctl')]
        for path in paths:
            check = subprocess.run(['sudo', '-n', 'test', '-e', str(path)], capture_output=True)
            link = subprocess.run(['sudo', '-n', 'test', '-L', str(path)], capture_output=True)
            if check.returncode != 1 or link.returncode != 1:
                raise RuntimeError('Existing installation object or inaccessible path: ' + str(path))
        loaded = self.run(['systemctl', 'show', SERVICE, '--property=LoadState', '--value'],
                          'preflight-unit', expected=None)
        if loaded.stdout.strip() not in ('', 'not-found'):
            raise RuntimeError('An existing Node service is loaded; refusing installation')
        self.row('fresh-installation-preflight', all_installation_paths_absent=True)
        # Claim a new empty install directory before running the unmodified
        # installer, including its partial-failure path.
        self.run(['sudo', '-n', 'install', '-d', '-m', '700', str(INSTALL_ROOT)], 'claim-install-directory')
        owner_path = self.case / 'installation-owner'
        owner_path.write_text(self.owner + '\n', encoding='utf-8')
        self.run(['sudo', '-n', 'install', '-m', '600', str(owner_path), str(OWNER_FILE)], 'claim-install-owner')
        self.owns_install = True

    def start(self):
        if not self.cert.is_file() or not self.key.is_file():
            raise RuntimeError('Runtime TLS certificate/key are missing')
        config_path = self.case / 'private-config.json'
        private_json(config_path, self.configuration())
        if self.args.arch == 'amd64':
            self.preflight_install()
            self.run(self.installer('install', self.recovery / 'xboard-node-linux-amd64',
                                    self.recovery / 'xbctl-linux-amd64'), 'installer-initial')
            self.assert_install_owner()
            self.run(['sudo', '-n', 'install', '-m', '600', str(config_path), str(FILES['config'])],
                     'install-test-configuration')
            self.run(['sudo', '-n', 'systemctl', 'restart', SERVICE], 'restart-test-configuration')
            version = self.run([str(FILES['binary']), '-v'], 'initial-version').stdout.strip()
            self.row('original-installer-machine-install', binary_version=self.sanitized(version))
            self.hashes('initial-sha256')
        else:
            qemu = (shutil.which('qemu-aarch64-static') or shutil.which('qemu-aarch64')
                    or str(self.base.parent / 'qemu-tools/usr/bin/qemu-aarch64-static'))
            binary = self.recovery / 'xboard-node-linux-arm64'
            self.process = subprocess.Popen([qemu, str(binary), '-c', str(config_path)],
                                            cwd=self.case, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            text=True, errors='replace')
            self.node_log_thread = threading.Thread(target=self.stream_node_log, daemon=True)
            self.node_log_thread.start()
            self.row('arm64-qemu-process-started', native_arm_hardware=False)
        self.started_at = time.monotonic()
        self.node_started_at_unix = time.time()
        self.wait_healthy('initial-runtime-health')

    def probe(self, expected_rejected=False, device_limit=False):
        credential_path = self.case / 'private-credential.json'
        private_json(credential_path, dict(uuid=self.state['uuid']))
        label = ('revoked' if expected_rejected else 'device-limit' if device_limit else 'restored') + '-' + str(time.time_ns())
        output = self.private_path(label + '.json')
        private_json(output, {})
        command = [sys.executable, str(self.source / 'tools/panel_traffic_client.py'),
                   '--port', str(self.binding['port']), '--credential-file', str(credential_path),
                   '--ca-file', str(self.cert), '--server-name', 'localhost', '--output', str(output)]
        if expected_rejected:
            command.append('--expect-rejected')
        elif device_limit:
            command.extend(['--device-limit', '--hold-seconds', '8'])
        self.run(command, label, timeout=140)
        evidence = json.loads(output.read_text(encoding='utf-8'))
        if not evidence.get('passed') or not evidence.get('encrypted') or not evidence.get('tls', {}).get('verified'):
            raise RuntimeError('Traffic probe did not pass verified TLS checks')
        self.row('traffic-tls-verified')
        self.row('traffic-probe-' + ('revoked' if expected_rejected else 'device-limit' if device_limit else 'restored'),
                 evidence=output.name, test_count=len(evidence['tests']))
        return output

    def upgrade_and_rollback(self):
        before = self.hashes('before-upgrade')
        self.run(self.installer('upgrade', self.source / 'xboard-node-linux-amd64',
                                self.source / 'xbctl-linux-amd64', self.args.upgrade_version), 'installer-upgrade')
        self.wait_healthy('upgraded-runtime-health')
        version = self.run([str(FILES['binary']), '-v'], 'upgraded-version').stdout.strip()
        if self.args.upgrade_version not in version:
            raise RuntimeError('Upgraded binary did not report the expected normal-build version')
        after = self.hashes('after-upgrade')
        preserved = ('config', 'credentials', 'metadata', 'service')
        if any(before[name] != after[name] for name in preserved):
            raise RuntimeError('Successful upgrade changed configuration or deployment metadata')
        for name, source_name in (('binary', 'xboard-node-linux-amd64'), ('xbctl', 'xbctl-linux-amd64')):
            expected = hashlib.sha256((self.source / source_name).read_bytes()).hexdigest()
            if after[name] != expected:
                raise RuntimeError('Successful upgrade did not install the selected ' + name)
        self.row('original-installer-successful-upgrade', binary_version=version,
                 configuration_preserved=True, six_file_sha256=after)
        self.probe()
        fake = self.case / 'deliberately-unhealthy-node'
        fake.write_text('#!/bin/sh\nif [ "${1:-}" = "-v" ]; then echo "xboard-node deliberate-test-failure"; exit 0; fi\nexit 42\n',
                        encoding='utf-8', newline='\n')
        fake.chmod(0o755)
        time.sleep(1.1)  # The original installer names backups with second precision.
        failed = self.run(self.installer('upgrade', fake, self.source / 'xbctl-linux-amd64',
                                         'deliberate-test-failure'), 'installer-deliberate-failure', expected=None)
        if failed.returncode == 0:
            raise RuntimeError('Deliberately unhealthy upgrade unexpectedly succeeded')
        self.wait_healthy('rollback-runtime-health')
        restored = self.hashes('after-rollback')
        if restored != after:
            raise RuntimeError('Automatic rollback did not restore all six deployment file hashes')
        restored_version = self.run([str(FILES['binary']), '-v'], 'rollback-version').stdout.strip()
        if restored_version != version:
            raise RuntimeError('Rollback changed the restored version')
        self.row('original-installer-automatic-rollback', failed_upgrade_exit=failed.returncode,
                 six_files_restored=True, six_file_sha256=restored, binary_version=restored_version)
        self.probe()

    def wait_for_root(self):
        private_json(self.case / 'ready-for-revoke', dict(ready=True,
                     node_started_at_unix=self.node_started_at_unix, minimum_runtime_seconds=65))
        self.row('ready-for-revoke')
        deadline = time.monotonic() + 240
        while not (self.case / 'continue').is_file():
            if self.process and self.process.poll() is not None:
                raise RuntimeError('ARM Node exited while waiting for panel tests')
            if time.monotonic() > deadline:
                raise RuntimeError('Timed out waiting for root continue marker')
            time.sleep(0.5)
        while time.monotonic() - self.started_at < 65:
            time.sleep(0.5)
        self.row('panel-control-window-completed', runtime_seconds=round(time.monotonic() - self.started_at, 2))

    def cleanup(self):
        if self.args.arch == 'amd64' and self.owns_install:
            self.assert_install_owner()
            journal = self.run(['sudo', '-n', 'journalctl', '-u', SERVICE, '--since',
                                '@' + str(int((self.node_started_at_unix or time.time()) - 10)),
                                '--no-pager', '-o', 'short-iso'], 'node-journal', expected=None)
            self.run(self.installer('uninstall'), 'installer-uninstall')
            for path in (INSTALL_ROOT, FILES['binary'], FILES['xbctl'], FILES['service'], Path('/usr/bin/xbctl')):
                exists = subprocess.run(['sudo', '-n', 'test', '-e', str(path)], capture_output=True)
                link = subprocess.run(['sudo', '-n', 'test', '-L', str(path)], capture_output=True)
                if exists.returncode != 1 or link.returncode != 1:
                    raise RuntimeError('Own test installation object remained after purge: ' + str(path))
            active = self.run(['systemctl', 'is-active', '--quiet', SERVICE], 'uninstall-inactive', expected=None)
            if active.returncode == 0:
                raise RuntimeError('Own test service remained active after uninstall')
            self.owns_install = False
            self.row('original-installer-purge-verified', all_installation_paths_absent=True)
        elif self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=25)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                raise RuntimeError('ARM Node did not stop gracefully') from None
            self.node_log_thread.join(timeout=5)
            if self.node_log_thread.is_alive() or self.node_log_error:
                raise RuntimeError('ARM Node sanitized log reader did not complete')
            if self.process.returncode != 0:
                raise RuntimeError('ARM Node graceful shutdown exited with ' + str(self.process.returncode))
            self.row('arm64-graceful-shutdown', exit_code=0)

    def run_case(self):
        self.case.mkdir(parents=True, exist_ok=False, mode=0o700)
        with (self.case / 'run-started').open('x', encoding='utf-8') as stream:
            stream.write(str(time.time()) + '\n')
        try:
            self.machine_auth_checks()
            self.start()
            self.probe(device_limit=True)
            self.wait_for_root()
            if self.args.arch == 'amd64' and self.args.kernel == 'singbox':
                self.upgrade_and_rollback()
            self.result['passed'] = True
        except BaseException as error:
            self.save_log('runtime-error', type(error).__name__ + ': ' + str(error))
            self.rows.append(dict(check='runtime-completed', passed=False))
            raise
        finally:
            try:
                self.cleanup()
            except BaseException as error:
                self.result['passed'] = False
                self.save_log('cleanup-error', type(error).__name__ + ': ' + str(error))
                self.rows.append(dict(check='runtime-cleanup', passed=False))
            public = public_projection(self.result)
            private_json(self.case / 'results.json', public)
            print(json.dumps(dict(check='runtime-completed', passed=public['passed'])), flush=True)
        if not self.result['passed']:
            raise RuntimeError('Case cleanup did not complete; inspect sanitized results')


def main():
    if sys.argv[1:] == ['--privacy-self-test']:
        print(json.dumps(privacy_self_test()), flush=True)
        return 0
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('action', choices=('run-case', 'run-probe'))
    ap.add_argument('--base', type=Path, required=True)
    ap.add_argument('--recovery', type=Path, required=True)
    ap.add_argument('--upgrade-version', required=True)
    ap.add_argument('--arch', choices=('amd64', 'arm64'), required=True)
    ap.add_argument('--kernel', choices=('singbox', 'xray'), required=True)
    ap.add_argument('--panel-url')
    ap.add_argument('--expect-rejected', action='store_true')
    args = ap.parse_args()
    driver = None
    try:
        driver = Driver(args)
        if args.action == 'run-case':
            driver.run_case()
        else:
            if not (driver.case / 'ready-for-revoke').is_file():
                raise RuntimeError('Probe requires an active case ready-for-revoke marker')
            driver.probe(expected_rejected=args.expect_rejected)
            print(json.dumps(dict(check='runtime-probe', passed=True)), flush=True)
    except BaseException:
        print(json.dumps(dict(check='runtime-command', passed=False)), flush=True)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
