#!/usr/bin/env python3
"""Real firewall regression in fresh network + mount namespaces only.

Build the tagged test binary unprivileged, then run:
  sudo python3 tools/test_inputfirewall_netns.py --binary /absolute/test-binary
No host rules, services, persisted firewall files or existing namespaces are used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time


def run(argv):
    subprocess.run(argv, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def legacy_nft_environment(args, env):
    """Copy verified public binaries into root-owned, private /run only."""
    if not args.legacy_root:
        return env
    source = Path(args.legacy_root).resolve()
    executable = source / 'usr/sbin/nft'
    if not executable.is_file() or executable.is_symlink() or not re.fullmatch('[a-f0-9]{64}', args.legacy_nft_sha256):
        raise RuntimeError('explicit legacy executable and checksum are required')
    data = executable.read_bytes()
    if hashlib.sha256(data).hexdigest() != args.legacy_nft_sha256:
        raise RuntimeError('legacy executable checksum differs')
    target = Path('/run/xb-legacy-nft')
    target.mkdir(mode=0o700)
    (target / 'bin').mkdir(mode=0o700)
    (target / 'nft-real').write_bytes(data)
    (target / 'nft-real').chmod(0o755)
    libraries = []
    for prefix in ('usr/lib/x86_64-linux-gnu', 'lib/x86_64-linux-gnu'):
        directory = source / prefix
        if not directory.is_dir():
            continue
        destination = target / prefix
        destination.mkdir(mode=0o700, parents=True)
        for path in directory.glob('*.so*'):
            if path.name.startswith(('libc.so', 'libpthread.so', 'librt.so', 'libdl.so', 'libm.so', 'ld-linux')):
                continue
            resolved = path.resolve()
            if not resolved.is_relative_to(source) or not resolved.is_file():
                raise RuntimeError('legacy library escaped its verified public root')
            # Dereference only contained, public-library links. New files belong
            # to root in this private mount; no host package is installed.
            (destination / path.name).write_bytes(resolved.read_bytes())
            (destination / path.name).chmod(0o644)
        libraries.append(str(destination))
    wrapper = target / 'bin/nft'
    wrapper.write_text('#!/bin/sh\nexport LD_LIBRARY_PATH=' + shlex.quote(':'.join(libraries)) +
                       '\nexec ' + shlex.quote(str(target / 'nft-real')) + ' "$@"\n')
    wrapper.chmod(0o755)
    return dict(env, PATH=str(target / 'bin') + ':' + env['PATH'])


def inside(args):
    current = os.readlink('/proc/self/ns/net')
    mount_id = os.readlink('/proc/self/ns/mnt')
    if current == args.host_net or mount_id == args.host_mount or not args.host_net or not args.host_mount:
        raise SystemExit('refusing to change rules outside fresh namespaces')
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # All mounts below belong only to this new private mount namespace.
    run(['mount', '--make-rprivate', '/'])
    run(['mount', '-t', 'tmpfs', '-o', 'mode=0755', 'xb-input-test-run', '/run'])
    run(['ip', 'link', 'set', 'lo', 'up'])
    client = subprocess.Popen(['unshare', '--net', 'python3', '-c', 'import time;time.sleep(180)'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 3
        while os.readlink(f'/proc/{client.pid}/ns/net') == current:
            if time.monotonic() > deadline:
                raise RuntimeError('client namespace did not start')
            time.sleep(.02)
        run(['ip', 'link', 'add', 'xb_server', 'type', 'veth', 'peer', 'name', 'xb_client'])
        run(['ip', 'link', 'set', 'xb_client', 'netns', str(client.pid)])
        for prefix, link, ipv4, ipv6 in [([], 'xb_server', '10.253.30.1/24', 'fd00:253:30::1/64'),
                                        (['nsenter', '--target', str(client.pid), '--net'], 'xb_client',
                                         '10.253.30.2/24', 'fd00:253:30::2/64')]:
            run(prefix + ['ip', 'link', 'set', 'lo', 'up'])
            run(prefix + ['ip', 'addr', 'add', ipv4, 'dev', link])
            run(prefix + ['ip', '-6', 'addr', 'add', ipv6, 'dev', link, 'nodad'])
            run(prefix + ['ip', 'link', 'set', link, 'up'])
        env = dict(os.environ, XB_NETNS_HOST_ID=args.host_net, XB_NETNS_PRIVATE_RUN='1',
                   XB_NETNS_CLIENT_PID=str(client.pid), XB_NETNS_FILTER_BACKEND=args.filter_backend)
        env = legacy_nft_environment(args, env)
        version = subprocess.check_output(['nft', '--version'], env=env, text=True, timeout=5)
        match = re.search(r'\bv([0-9]+\.[0-9]+\.[0-9]+)\b', version)
        if not match or args.legacy_root and match[1] != '0.9.0':
            raise RuntimeError('unexpected nftables version')
        test_name = {'input': 'TestManagedInputNetwork', 'nat': 'TestPortableNATNetworkLifecycle',
                     'migration': 'TestPortableNATMigrateOldInetNetns'}[args.suite]
        result = subprocess.run([args.binary, '-test.v', '-test.run', '^' + test_name + '$',
                                 '-test.timeout', '100s'], env=env, capture_output=True, text=True, timeout=110)
        # Export only fixed test names/results, never arbitrary host rule output.
        passed = re.findall(r'^\s*--- PASS: TestManagedInputNetwork/([a-z_]+) ', result.stdout, re.M)
        failed = re.findall(r'^\s*--- FAIL: TestManagedInputNetwork/([a-z_]+) ', result.stdout, re.M)
        if args.suite == 'nat':
            passed = ['portable_nat_lifecycle'] if re.search(r'^--- PASS: TestPortableNATNetworkLifecycle ', result.stdout, re.M) else []
            failed = ['portable_nat_lifecycle'] if not passed else []
        elif args.suite == 'migration':
            passed = re.findall(r'^\s*--- PASS: TestPortableNATMigrateOldInetNetns/([^ ]+) ', result.stdout, re.M)
            failed = re.findall(r'^\s*--- FAIL: TestPortableNATMigrateOldInetNetns/([^ ]+) ', result.stdout, re.M)
        if result.returncode == 0 and not passed:
            raise RuntimeError('selected namespace suite did not run')
        report = dict(schema=1, isolated_network=True, isolated_mount=True, private_run=True,
                      nft_version=match[1], legacy_nft=bool(args.legacy_root), suite=args.suite,
                      backends=(['iptables-legacy', 'ip6tables-legacy'] if args.filter_backend == 'legacy' else
                                ['iptables-nft', 'ip6tables-nft', 'iptables-legacy', 'ip6tables-legacy']) if args.suite == 'input' else ['nft-ip', 'nft-ip6'],
                      passed=passed, failed=failed, exit_code=result.returncode)
        # This log contains only this synthetic test and public source errors.
        suffix = '.' + args.label if args.label else ''
        Path(args.binary + suffix + '.netns.log').write_text(result.stdout + result.stderr)
        Path(args.binary + suffix + '.netns.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report), flush=True)
        return result.returncode
    finally:
        client.terminate()
        client.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--host-net', default='')
    parser.add_argument('--host-mount', default='')
    parser.add_argument('--legacy-root', default='')
    parser.add_argument('--legacy-nft-sha256', default='')
    parser.add_argument('--suite', choices=['input', 'nat', 'migration'], default='input')
    parser.add_argument('--label', default='')
    parser.add_argument('--filter-backend', choices=['all', 'legacy'], default='all')
    args = parser.parse_args()
    if args.label and not re.fullmatch('[a-z0-9-]{1,32}', args.label):
        raise SystemExit('invalid report label')
    if args.legacy_root and args.suite == 'migration':
        raise SystemExit('v8 inet/table-comment seed requires the modern nft profile')
    if os.geteuid() != 0 or not Path(args.binary).is_absolute() or not Path(args.binary).is_file():
        raise SystemExit('root and an absolute, prebuilt test binary are required')
    if args.inside:
        return inside(args)
    extra = ['--legacy-root', args.legacy_root, '--legacy-nft-sha256', args.legacy_nft_sha256] if args.legacy_root else []
    return subprocess.run(['unshare', '--mount', '--net', '--fork', sys.executable, str(Path(__file__).resolve()),
                           '--inside', '--binary', args.binary,
                           '--host-net', os.readlink('/proc/self/ns/net'),
                           '--host-mount', os.readlink('/proc/self/ns/mnt'), '--suite', args.suite, '--label', args.label,
                           '--filter-backend', args.filter_backend, *extra]).returncode


if __name__ == '__main__':
    raise SystemExit(main())
