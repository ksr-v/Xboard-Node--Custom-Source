#!/usr/bin/env python3
"""Real firewall regression in fresh network + mount namespaces only.

Build the tagged test binary unprivileged, then run:
  sudo python3 tools/test_inputfirewall_netns.py --binary /absolute/test-binary
No host rules, services, persisted firewall files or existing namespaces are used.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


def run(argv):
    subprocess.run(argv, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def inside(args):
    current = os.readlink('/proc/self/ns/net')
    mount_id = os.readlink('/proc/self/ns/mnt')
    if current == args.host_net or mount_id == args.host_mount or not args.host_net or not args.host_mount:
        raise SystemExit('refusing to change rules outside fresh namespaces')
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
                   XB_NETNS_CLIENT_PID=str(client.pid))
        result = subprocess.run([args.binary, '-test.v', '-test.run', '^TestManagedInputNetwork$',
                                 '-test.timeout', '100s'], env=env, capture_output=True, text=True, timeout=110)
        # Export only fixed test names/results, never arbitrary host rule output.
        passed = re.findall(r'^\s*--- PASS: TestManagedInputNetwork/([a-z_]+) ', result.stdout, re.M)
        failed = re.findall(r'^\s*--- FAIL: TestManagedInputNetwork/([a-z_]+) ', result.stdout, re.M)
        report = dict(schema=1, isolated_network=True, isolated_mount=True, private_run=True,
                      backends=['iptables-nft', 'ip6tables-nft', 'iptables-legacy', 'ip6tables-legacy'],
                      passed=passed, failed=failed, exit_code=result.returncode)
        # This log contains only this synthetic test and public source errors.
        Path(args.binary + '.netns.log').write_text(result.stdout + result.stderr)
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
    args = parser.parse_args()
    if os.geteuid() != 0 or not Path(args.binary).is_absolute() or not Path(args.binary).is_file():
        raise SystemExit('root and an absolute, prebuilt test binary are required')
    if args.inside:
        return inside(args)
    return subprocess.run(['unshare', '--mount', '--net', '--fork', sys.executable, str(Path(__file__).resolve()),
                           '--inside', '--binary', args.binary,
                           '--host-net', os.readlink('/proc/self/ns/net'),
                           '--host-mount', os.readlink('/proc/self/ns/mnt')]).returncode


if __name__ == '__main__':
    raise SystemExit(main())
