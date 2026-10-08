"""Run actual Dockerfile smoke tests on an authorized Linux test machine.

Uses unique local image/container names, keeps images and logs, and removes only
the containers created by this invocation. Requires a working sudo Docker daemon.
"""
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid

import dependencies as d


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--arch', choices=('amd64', 'arm64'), default='amd64')
    ap.add_argument('--image', help='Use a previously built image for runtime retry')
    ap.add_argument('--work-dir', type=Path)
    args = ap.parse_args()
    work = args.work_dir.resolve() if args.work_dir else Path(tempfile.mkdtemp(prefix='container-', dir=d.STATE)).resolve()
    work.mkdir(parents=True, exist_ok=True)
    tag = args.image or ('xboard-node-dependency-test:' + uuid.uuid4().hex[:12] + '-' + args.arch)
    rows = []
    before = {name: d.text_sha(d.ROOT / name) for name in ('go.mod', 'go.sum')}
    result = dict(arch=args.arch, results=rows, passed=False,
                  built_in_this_run=not bool(args.image), snapshot_verified=False,
                  limits=['Standalone connection readiness only; real panel tested separately',
                          'ARM64 runs through QEMU when host is AMD64'])

    def run(label, command, capture=False):
        path = work / (label + '.log')
        print(label, flush=True)
        with path.open('wb') as log:
            proc = subprocess.run(command, cwd=d.ROOT, stdout=log, stderr=subprocess.STDOUT)
        output = path.read_bytes()
        rows.append(dict(step=label, passed=proc.returncode == 0))
        if proc.returncode:
            raise RuntimeError(label + ' failed; inspect the private local log')
        return output.decode(errors='replace') if capture else None

    def docker(*command):
        return ['sudo', '-n', 'docker', *command]

    @contextmanager
    def isolate_port(label, port):
        # Older tested binaries may ignore standalone.listen_ip. Restrict only
        # this invocation's random port before starting the host-network container.
        token = 'xboard-docker-smoke-' + uuid.uuid4().hex[:12]
        rule = ['!', '-i', 'lo', '-p', 'tcp', '--dport', str(port),
                '-m', 'comment', '--comment', token, '-j', 'REJECT']
        installed = []
        try:
            for family in ('iptables', 'ip6tables'):
                run(label + '-' + family + '-install', ['sudo', '-n', family, '-I', 'INPUT', '1', *rule])
                installed.append(family)
            yield
        finally:
            failures = []
            for family in reversed(installed):
                try:
                    run(label + '-' + family + '-remove', ['sudo', '-n', family, '-D', 'INPUT', *rule])
                except Exception as exc:
                    failures.append(str(exc))
            if failures:
                raise RuntimeError('Firewall cleanup failed: ' + '; '.join(failures))

    try:
        d.verify(d.STATE / 'snapshot')
        result['snapshot_verified'] = True
        run('docker-info', docker('info', '--format', '{{json .}}'))
        run('preexisting-images', docker('image', 'ls', '--format', '{{.ID}} {{.Repository}}:{{.Tag}}'))
        run('preexisting-containers', docker('ps', '-a', '--format', '{{.ID}} {{.Names}}'))
        if not args.image:
            # This is the repository Dockerfile and the real .dockerignore context.
            run('docker-build', docker('build', '--progress=plain', '--platform', 'linux/' + args.arch,
                                      '--build-arg', 'VERSION=docker-dependency-test',
                                      '--build-arg', 'COMMIT=dependency-test', '-t', tag, '.'))
        inspect = json.loads(run('image-inspect', docker('image', 'inspect', tag), True))[0]
        if inspect['Architecture'] != args.arch:
            raise ValueError('Docker image architecture differs from requested target')
        result['image_architecture_verified'] = True
        extract_container = 'xboard-dependency-extract-' + uuid.uuid4().hex[:12]
        try:
            run('create-extraction-container', docker('create', '--name', extract_container,
                                                     '--platform', 'linux/' + args.arch,
                                                     '--entrypoint', '/bin/true', tag))
            result['binary_elf'] = {}
            for name in ('xboard-node', 'xbctl'):
                target = work / name
                run(name + '-copy', docker('cp', extract_container + ':/usr/local/bin/' + name, str(target)))
                data = target.read_bytes()
                machine = int.from_bytes(data[18:20], 'little')
                if data[:5] != b'\x7fELF\x02' or machine != {'amd64': 62, 'arm64': 183}[args.arch]:
                    raise ValueError('Image contains executable for the wrong CPU: ' + name)
                result['binary_elf'][name] = dict(architecture_verified=True)
                rows.append(dict(step=name + '-elf-architecture', passed=True))
        finally:
            subprocess.run(docker('rm', '-f', extract_container), stdout=subprocess.DEVNULL, check=True)
        for name in ('xboard-node', 'xbctl'):
            text = run(name + '-version', docker('run', '--rm', '--network=none', '--entrypoint', name,
                                                '--platform', 'linux/' + args.arch, tag,
                                                '-v' if name == 'xboard-node' else 'version'), True)
            if 'docker-dependency-test' not in text:
                raise ValueError('Docker build lost version metadata')
        for kernel in ('singbox', 'xray'):
            case = work / kernel
            case.mkdir()
            port = free_port()
            cfg = dict(standalone=dict(enabled=True, node=dict(protocol='vless', listen_ip='127.0.0.1',
                                                               server_port=port, network='tcp', tls=0),
                                       users=[dict(id=1, uuid='11111111-1111-1111-1111-111111111111')]),
                       kernel=dict(type=kernel, config_dir='/etc/xboard-node/kernel-config', log_level='warn'),
                       cert=dict(cert_mode='none'), log=dict(level='info', output='stdout'), health_port=0)
            d.write_json(case / 'config.yml', cfg)
            container = 'xboard-dependency-test-' + uuid.uuid4().hex[:12]
            with isolate_port(kernel, port):
                try:
                    run(kernel + '-start', docker('run', '-d', '--name', container, '--network=host',
                                                 '--platform', 'linux/' + args.arch,
                                                 '--mount', 'type=bind,src=' + str(case) + ',dst=/etc/xboard-node',
                                                 tag))
                    deadline = time.monotonic() + 45
                    while True:
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                                break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise RuntimeError(kernel + ' loopback connection timed out')
                            time.sleep(0.2)
                    time.sleep(1)
                    run(kernel + '-listening-sockets', ['ss', '-lntp', 'sport = :' + str(port)])
                    state = json.loads(run(kernel + '-inspect-running', docker('inspect', container), True))[0]['State']
                    if not state['Running']:
                        raise ValueError(kernel + ' container exited after listening')
                    run(kernel + '-stop', docker('stop', '-t', '20', container))
                    state = json.loads(run(kernel + '-inspect-stopped', docker('inspect', container), True))[0]['State']
                    if state['Running'] or state['ExitCode'] != 0:
                        raise ValueError(kernel + ' graceful container stop failed')
                    rows.append(dict(step=kernel + '-connection-and-graceful-stop', passed=True,
                                     loopback_connection_verified=True, interface_isolation_verified=True))
                finally:
                    try:
                        run(kernel + '-logs', docker('logs', container))
                    finally:
                        # Only this invocation's unique temporary container is removed.
                        subprocess.run(docker('rm', '-f', container), stdout=subprocess.DEVNULL, check=True)
        result['passed'] = True
    finally:
        result['source_dependencies_unchanged'] = all(d.text_sha(d.ROOT / name) == digest for name, digest in before.items())
        if not result['source_dependencies_unchanged']:
            result['passed'] = False
        d.write_json(work / 'results.json', result)
        print('Validation evidence saved locally', flush=True)
    if not result['source_dependencies_unchanged']:
        raise RuntimeError('Docker validation changed dependency files')


if __name__ == '__main__':
    main()
