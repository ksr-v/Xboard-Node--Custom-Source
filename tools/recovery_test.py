"""Disposable request-gated proxy proves protected sources never use public caches."""
import collections
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request
import urllib.parse

import dependencies as d


def recovery_test(snapshot, compiler_cache=None):
    manifest = d.verify(snapshot)
    protected = {d.escape(r['path']) for r in manifest['modules'] if r['backup']}
    known = {d.escape(r['path']) for r in manifest['modules']}
    requests = []
    guard = threading.Lock()
    work = Path(tempfile.mkdtemp(prefix='recovery-', dir=d.STATE))
    stage = work / 'source'
    shutil.copytree(d.ROOT, stage, ignore=shutil.ignore_patterns('.git', '.dependency-work', '__pycache__', 'xboard-node-linux-*', 'xbctl-linux-*', '*.exe'))
    # Reproduce Linux Git checkout of tracked control text even when launched from
    # a Windows/NTFS working tree. Third-party module payloads remain byte-exact.
    for name in ('go.mod', 'go.sum', 'dependency-policy.json', 'dependency-lock.json', 'dependency-snapshot.json'):
        path = stage / name
        path.write_bytes(path.read_bytes().replace(b'\r\n', b'\n'))
    original = {f: d.sha((stage / f).read_bytes()) for f in ('go.mod', 'go.sum')}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            path = urllib.parse.unquote(self.path.split('?', 1)[0]).lstrip('/')
            if '..' in path.split('/') or '\\' in path or ':' in path:
                self.send_error(400)
                return
            module = path.split('/@v/', 1)[0]
            local = snapshot / 'proxy' / path
            status, source, body = 200, 'local', b''
            if local.is_file():
                body = local.read_bytes()
            elif module in protected:
                # 503 stops Go fallback; there is only this GOPROXY, never direct.
                status, source = 503, 'protected_missing_refused'
            elif path.startswith('sumdb/'):
                status, source = 404, 'sumdb_direct_discovery'
            elif module not in known:
                status, source = 503, 'unaudited_module_refused'
            else:
                source = 'public_nonprotected'
                try:
                    with urllib.request.urlopen(d.policy()['public_proxy'] + '/' + path, timeout=90) as response:
                        body = response.read()
                except urllib.error.HTTPError as exc:
                    status = exc.code
                except OSError:
                    status = 502
            with guard:
                requests.append(dict(path=path, module=module, source=source, status=status, bytes=len(body)))
            self.send_response(status)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class Server(ThreadingHTTPServer):
        request_queue_size = 256
        daemon_threads = True

    server = Server(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env = dict(os.environ, GOPROXY=f'http://127.0.0.1:{server.server_port}',
               GOMODCACHE=str(work / 'gomodcache'), GOCACHE=str(work / 'gocache'),
               GOPATH=str(work / 'gopath'), GOSUMDB='sum.golang.org', GOPRIVATE='',
               GONOPROXY='', GONOSUMDB='', GOFLAGS='-mod=readonly', GOWORK='off',
               GOTOOLCHAIN='local', GOENV='off', CGO_ENABLED='0')
    if compiler_cache:
        env['GOCACHE'] = str(compiler_cache.resolve())
    result = dict(work=str(work), mode='protected-local-only; nonprotected-public-proxy',
                  toolchain=d.run(['go', 'version']).strip(), fresh_module_cache=True,
                  fresh_compiler_cache=not bool(compiler_cache), simulated_lf_checkout=True, results=[])

    def execute(label, args, target):
        print(label, flush=True)
        with (work / (label + '.log')).open('w', encoding='utf-8') as log:
            p = subprocess.run(args, cwd=stage, env=target, stdout=log, stderr=subprocess.STDOUT)
        result['results'].append(dict(step=label, exit_code=p.returncode))
        if p.returncode:
            raise RuntimeError(label + ' failed; see ' + str(work / (label + '.log')))

    try:
        # Require EVERY protected version to be requested from this fresh cache,
        # including host-only dependencies, and authenticate it with go.sum/sumdb.
        modules = [r['path'] + '@' + r['version'] for r in manifest['modules'] if r['backup']]
        execute('protected-download', ['go', 'mod', 'download'] + modules, env)
        for arch in ('amd64', 'arm64'):
            target = dict(env, GOOS='linux', GOARCH=arch)
            for name in ('xboard-node', 'xbctl'):
                output = work / (name + '-linux-' + arch)
                execute(name + '-' + arch, ['go', 'build', '-tags', d.TAGS, '-ldflags', '-s -w -X main.version=recovery-test',
                                           '-o', str(output), './cmd/' + name], target)
                header = output.read_bytes()[:20]
                machine = int.from_bytes(header[18:20], 'little')
                if header[:4] != b'\x7fELF' or machine != {'amd64': 62, 'arm64': 183}[arch]:
                    raise ValueError('Wrong ELF architecture')
                result['results'][-1].update(sha256=d.sha(output.read_bytes()), bytes=output.stat().st_size, elf_machine=machine)
        native = dict(env)
        native.pop('GOOS', None)
        native.pop('GOARCH', None)
        execute('unit-tests-original-tags', ['go', 'test', '-count=1', './internal/...'], native)
        execute('unit-tests-production-tags', ['go', 'test', '-tags', d.TAGS, '-count=1', './internal/...'], native)
        for name, arg in [('xboard-node', '-v'), ('xbctl', 'version')]:
            output = work / (name + ('.exe' if os.name == 'nt' else '-host'))
            execute(name + '-host', ['go', 'build', '-tags', d.HOST_TAGS, '-ldflags', '-X main.version=recovery-test', '-o', str(output), './cmd/' + name], native)
            execute(name + '-version', [str(output), arg], native)
        # On Linux execute target AMD64/ARM64 via native CPU or qemu when installed.
        if os.name != 'nt':
            import platform
            host_arch = 'arm64' if platform.machine() in ('aarch64', 'arm64') else 'amd64'
            for arch in ('amd64', 'arm64'):
                emulator = 'qemu-' + ('aarch64' if arch == 'arm64' else 'x86_64')
                runner = [] if arch == host_arch else [shutil.which(emulator) or shutil.which(emulator + '-static') or '']
                if runner and not runner[0]:
                    result['results'].append(dict(step=arch + '-linux-execution', status='NOT RUN: qemu missing'))
                    continue
                for name, arg in [('xboard-node', '-v'), ('xbctl', 'version')]:
                    execute(name + '-' + arch + '-version', runner + [str(work / (name + '-linux-' + arch)), arg], env)
        else:
            result['results'].append(dict(step='Linux target execution', status='NOT RUN: Windows host; use Linux CI/WSL'))
        downloaded = {r['module'] for r in requests if r['source'] == 'local' and r['path'].endswith('.zip')}
        if not protected <= downloaded:
            raise ValueError('Protected module not proven local: ' + str(protected - downloaded))
        if any(r['module'] in protected and r['source'] != 'local' for r in requests):
            raise ValueError('Protected module used network or was missing')
        result.update(protected_local_zip_modules=len(downloaded & protected), passed=True)
    finally:
        server.shutdown()
        server.server_close()
        result['requests'] = requests
        result['source_unchanged'] = all((stage / f).is_file() and d.sha((stage / f).read_bytes()) == checksum
                                         for f, checksum in original.items())
        if not result['source_unchanged']:
            result['passed'] = False
        d.write_json(work / 'results.json', result)
        print('Evidence: ' + str(work / 'results.json'), flush=True)
    if not result['source_unchanged']:
        raise ValueError('Recovery changed go.mod/go.sum; refusing successful validation')


if __name__ == '__main__':
    recovery_test(d.STATE / 'snapshot')
