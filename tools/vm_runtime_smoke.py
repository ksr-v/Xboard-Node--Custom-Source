"""Authorized Linux VM: standalone access through loopback, both kernels/CPUs.

listen_ip is a requested configuration value; a successful loopback connection
does not establish that the kernel bound only loopback interfaces.
"""
import argparse
import getpass
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
import dependencies as d


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def wait_port(port, process=None):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process and process.poll() is not None:
            raise RuntimeError('Node exited before listen; inspect runtime log')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError('Loopback listener did not appear')


def make_config(work, kernel, port):
    cfg = dict(standalone=dict(enabled=True, node=dict(protocol='vless', listen_ip='127.0.0.1', server_port=port,
                                                    network='tcp', tls=0),
                               users=[dict(id=1, uuid='11111111-1111-1111-1111-111111111111')]),
               kernel=dict(type=kernel, config_dir=str(work / 'kernel-config'), log_level='warn'),
               cert=dict(cert_mode='none'), log=dict(level='info', output='stdout'), health_port=0)
    path = work / 'config.yml'
    d.write_json(path, cfg)
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('recovery_dir', type=Path)
    ap.add_argument('--service-user', default=getpass.getuser())
    ap.add_argument('--work-dir', type=Path)
    args = ap.parse_args()
    binaries = args.recovery_dir.resolve()
    result = json.loads((binaries / 'results.json').read_text())
    if not result.get('passed'):
        raise ValueError('Recovery build must have passed first')
    work = args.work_dir.resolve() if args.work_dir else Path(tempfile.mkdtemp(prefix='runtime-', dir=d.STATE)).resolve()
    work.mkdir(parents=True, exist_ok=True)
    rows = []
    qemu = shutil.which('qemu-aarch64') or shutil.which('qemu-aarch64-static')
    if not qemu:
        raise ValueError('ARM64 runtime smoke requires qemu')
    try:
        for arch in ('amd64', 'arm64'):
            runner = [] if arch == 'amd64' else [qemu]
            for kernel in ('singbox', 'xray'):
                case = work / (arch + '-' + kernel)
                case.mkdir()
                port = free_port()
                config = make_config(case, kernel, port)
                print('runtime ' + arch + ' ' + kernel, flush=True)
                with (case / 'node.log').open('w') as log:
                    p = subprocess.Popen(runner + [str(binaries / ('xboard-node-linux-' + arch)), '-c', str(config)],
                                         cwd=case, stdout=log, stderr=subprocess.STDOUT)
                    try:
                        wait_port(port, p)
                        time.sleep(1)
                        if p.poll() is not None:
                            raise RuntimeError('Node exited after listen')
                    finally:
                        p.terminate()
                        try:
                            code = p.wait(timeout=20)
                        except subprocess.TimeoutExpired:
                            p.kill()
                            p.wait()
                            raise
                    if code != 0:
                        raise RuntimeError(f'{arch}/{kernel} graceful stop returned {code}')
                rows.append(dict(step=arch + '/' + kernel, loopback_connection_verified=True,
                                 bind_address_verified=False, passed=True))
        # Actual native manager generates both deployment modes, all output confined
        # to the test directory. Synthetic token is deliberately not a credential.
        for mode in ('node', 'machine'):
            case = work / ('config-init-' + mode)
            case.mkdir()
            command = [str(binaries / 'xbctl-linux-amd64'), 'config', 'init', '--mode', mode,
                       '--panel-url', 'http://127.0.0.1:9', '--token', 'dependency-test-synthetic-only',
                       '--kernel', 'singbox', '--output', str(case / 'config.yml'),
                       '--credentials-out', str(case / 'credentials.env'), '--meta', str(case / 'meta.json'),
                       '--install-root', str(case / 'install-root'), '--version', 'recovery-test',
                       '--node-id' if mode == 'node' else '--machine-id', '1']
            subprocess.run(command, check=True, cwd=case, stdout=subprocess.DEVNULL)
            if not all((case / name).is_file() for name in ('config.yml', 'credentials.env', 'meta.json')):
                raise RuntimeError('xbctl did not generate isolated deployment files')
            rows.append(dict(step='xbctl-config-init-' + mode, passed=True))
        # A transient unit verifies systemd deployment without replacing installed
        # binaries, /etc/xboard-node, or a persistent unit. Always stop our own unit.
        case = work / 'systemd'
        case.mkdir()
        port = free_port()
        config = make_config(case, 'singbox', port)
        unit = 'xboard-dependency-smoke-' + uuid.uuid4().hex[:10]
        try:
            subprocess.run(['sudo', '-n', 'systemd-run', '--unit=' + unit, '--collect',
                            '--property=User=' + args.service_user, '--property=WorkingDirectory=' + str(case),
                            '--property=RuntimeMaxSec=90', '--property=NoNewPrivileges=yes',
                            str(binaries / 'xboard-node-linux-amd64'), '-c', str(config)], check=True, capture_output=True)
            wait_port(port)
            subprocess.run(['systemctl', 'is-active', '--quiet', unit], check=True)
            rows.append(dict(step='native-systemd-transient-deployment', passed=True))
        finally:
            subprocess.run(['sudo', '-n', 'systemctl', 'stop', unit], check=True)
        state = subprocess.run(['systemctl', 'is-active', '--quiet', unit]).returncode
        if state == 0:
            raise RuntimeError('Test unit remained active')
        rows.append(dict(step='transient-unit-stopped', passed=True))
    finally:
        d.write_json(work / 'results.json', dict(results=rows, passed=len(rows) == 8,
                                                limit='No real panel binding, encrypted client traffic, persistent installer or native ARM hardware test'))
        print('Validation evidence saved locally', flush=True)


if __name__ == '__main__':
    main()
