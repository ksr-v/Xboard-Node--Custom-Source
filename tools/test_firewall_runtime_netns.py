#!/usr/bin/env python3
"""Exercise the actual Node service, runtime registry, CLI and firewall together.

Run as root on Linux with prebuilt production-tagged binaries:
  python3 tools/test_firewall_runtime_netns.py --binary /absolute/xboard-node \
      --xbctl /absolute/xbctl --label nft-modern
  # Exercise arbitrary VLESS listen ports with the same runtime pipeline:
  # --initial-port 25444 --updated-port 25445

Only fresh server/client network namespaces and a private mount namespace are
used. All configuration and self-signed test certificates live in private /run.
No panel, existing credentials, host services or persisted rules are accessed.
The QUIC probe verifies version negotiation, not an authenticated HY2 session.
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


TOOLS = ('iptables-nft', 'ip6tables-nft', 'iptables-legacy', 'ip6tables-legacy')
USER_UUID = '25f07d20-f332-4c2c-aafe-c42c5ac02254'  # synthetic public fixture


def command(argv, *, env=None, check=True, timeout=15):
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout)
    if len(result.stdout) + len(result.stderr) > 4 * 1024 * 1024:
        raise RuntimeError('synthetic test command exceeded its output limit')
    if check and result.returncode:
        raise RuntimeError('isolated command failed: ' + Path(argv[0]).name)
    return result


def stop_child(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        process.kill()  # Only this exact Popen child; never by name or port.
        process.wait(timeout=5)


def normalized_rules(tool, *, foreign_only=False):
    text = command([tool + '-save', '-t', 'filter']).stdout
    lines = []
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        if foreign_only and ('XB_IN_' in line or 'xboard-node-input:v1:' in line):
            continue
        lines.append(re.sub(r'\[\d+:\d+\]', '[0:0]', line))
    return '\n'.join(lines)


def rules_hashes(*, foreign_only=False):
    return {tool: hashlib.sha256(normalized_rules(tool, foreign_only=foreign_only).encode()).hexdigest()
            for tool in TOOLS}


def preflight_tools(report):
    """Run the same read commands under the daemon's clean environment first."""
    probes = [[tool, '--version'] for tool in ('nft',) + TOOLS]
    probes += [[tool + '-save', '-t', 'filter'] for tool in TOOLS]
    probes.append(['nft', '-j', 'list', 'ruleset'])
    rows = []
    report['tool_preflight'] = rows
    for argv in probes:
        result = command(argv, env=synthetic_environment(), check=False)
        row = {'tool': argv[0], 'arguments': argv[1:], 'exit_code': result.returncode,
               'stderr': result.stderr[:4096]}
        if argv[-1] == '--version':
            row['version'] = result.stdout.strip()[:4096]
        else:
            row['synthetic_output_sha256'] = hashlib.sha256(result.stdout.encode()).hexdigest()
        rows.append(row)
        if result.returncode:
            raise RuntimeError('clean-environment tool preflight failed: ' + argv[0])


def synthetic_environment():
    # Do not inherit panel endpoints/tokens, certificate overrides, proxy
    # credentials or arbitrary application environment into this local fixture.
    environment = {'PATH': os.environ.get('PATH', '/usr/sbin:/usr/bin:/sbin:/bin'),
                   'TMPDIR': '/run/xb-runtime-fixture',
                   'LANG': 'C.UTF-8', 'XBOARD_NODE_MANAGED_INPUT': '1',
                   'GOMEMLIMIT': '512MiB', 'GOMAXPROCS': '2'}
    # The isolated download-only tools may need their public shared libraries
    # and xtables modules. These are tool paths, never panel credentials.
    for name in ('LD_LIBRARY_PATH', 'XTABLES_LIBDIR'):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def fixture_config(directory, vless_port):
    instances = []
    for name, node_id, protocol, port in [('runtime-vless', 101, 'vless', vless_port),
                                          ('runtime-hy2', 102, 'hysteria', 17443)]:
        node = {'protocol': protocol, 'listen_ip': '', 'server_port': port}
        cert = {'cert_mode': 'none'}
        if protocol == 'vless':
            node.update(network='tcp', tls=0)
        else:
            node.update(version=2, tls=1, server_name='firewall-runtime.invalid',
                        tls_settings={'server_name': 'firewall-runtime.invalid', 'alpn': ['h3']})
            cert = {'cert_mode': 'self', 'domain': 'firewall-runtime.invalid',
                    'cert_dir': str(directory / name / 'certs')}
        instances.append({'id': name, 'panel': {'node_id': node_id},
                          'kernel': {'type': 'singbox', 'config_dir': str(directory / name),
                                     'log_level': 'warn'},
                          'cert': cert, 'health_port': 0,
                          'standalone': {'enabled': True, 'node': node,
                                         'users': [{'id': 1, 'uuid': USER_UUID}]}})
    # JSON is also valid YAML and avoids requiring an external YAML module.
    return {'log': {'level': 'info'}, 'firewall': {'managed_input': True},
            'health_port': 0, 'instances': instances}


def write_config(path, value):
    # Write, rather than rename, to exercise the existing debounced watcher.
    with path.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
    path.chmod(0o600)


def cli(binary, action, *, expected=None):
    result = command([binary, 'firewall', action, '--output', 'json'],
                     env=synthetic_environment(), check=False, timeout=40)
    if expected is not None and result.returncode != expected:
        raise RuntimeError('firewall ' + action + ' returned unexpected exit status')
    if not result.stdout.strip():
        return result.returncode, None
    try:
        return result.returncode, json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError('firewall CLI did not return a JSON report') from error


def expected_runtime(response, port):
    if not response or not response.get('report', {}).get('healthy'):
        return False
    ports = response['report'].get('ports', [])
    observed = {(item.get('instance_id'), item.get('transport'), item.get('listen_port'))
                for item in ports if item.get('runtime_status') == 'running'
                and item.get('rule_status') == 'allowed'
                and item.get('effective_status') == 'allowed' and item.get('managed')}
    return observed == {('runtime-vless', 'tcp', port), ('runtime-hy2', 'udp', 17443)}


def await_runtime(binary, process, port):
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('synthetic Node exited during startup or reload')
        _, response = cli(binary, 'status')
        if expected_runtime(response, port):
            return response
        time.sleep(.15)
    raise RuntimeError('actual runtime registry never reached the expected allowed listeners')


def external_probe(client_pid, mode, port):
    code = r'''import socket,struct,sys
mode,port=sys.argv[1],int(sys.argv[2])
sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM if mode=='tcp' else socket.SOCK_DGRAM)
sock.settimeout(1.5)
try:
 if mode=='tcp':
  sock.connect(('10.253.31.1',port)); print('yes')
 else:
  # A deliberately unsupported QUIC version requests a version-negotiation
  # reply from the actual HY2 listener without possessing a real user's auth.
  dcid,scid=b'xb-fw-dc',b'xb-fw-sc'
  packet=b'\xc0'+struct.pack('!I',0xfaceb00c)+bytes([len(dcid)])+dcid+bytes([len(scid)])+scid
  sock.sendto(packet+b'\x00'*(1200-len(packet)),('10.253.31.1',port))
  data,_=sock.recvfrom(4096)
  valid=len(data)>=7 and bool(data[0]&0x80) and data[1:5]==b'\x00\x00\x00\x00'
  print('yes' if valid else 'no')
except OSError:
 print('no')
finally:
 sock.close()
'''
    result = command(['nsenter', '--target', str(client_pid), '--net', sys.executable,
                      '-c', code, mode, str(port)], timeout=5)
    return result.stdout.strip() == 'yes'


def remove_vless_accept(response, port):
    owners = response['report']['owners']
    chain = next(owner['status']['chain'] for owner in owners if owner['instance_id'] == 'runtime-vless')
    if not re.fullmatch(r'XB_IN_[0-9a-f]{20}', chain):
        raise RuntimeError('runtime owner chain has an unexpected shape')
    removed = 0
    for tool in TOOLS:
        saved = command([tool + '-save', '-t', 'filter']).stdout
        for line in saved.splitlines():
            tokens = shlex.split(line)
            if len(tokens) < 2 or tokens[:2] != ['-A', chain]:
                continue
            if not all(value in tokens for value in ('tcp', '--dport', str(port), 'ACCEPT')):
                continue
            if '--comment' not in tokens or not tokens[tokens.index('--comment') + 1].startswith('xboard-node-input:v1:'):
                raise RuntimeError('refusing to remove a rule without Node ownership')
            command([tool, '-D'] + tokens[1:])
            removed += 1
    if removed != 4:
        raise RuntimeError('expected one VLESS grant in each active family/backend')
    return chain


def ensure_private(args):
    current_net = os.readlink('/proc/self/ns/net')
    current_mount = os.readlink('/proc/self/ns/mnt')
    if not args.host_net or not args.host_mount or current_net == args.host_net or current_mount == args.host_mount:
        raise RuntimeError('refusing runtime firewall tests outside fresh network and mount namespaces')


def inside(args):
    ensure_private(args)
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    command(['mount', '--make-rprivate', '/'])
    command(['mount', '-t', 'tmpfs', '-o', 'mode=0755', 'xb-runtime-test-run', '/run'])
    command(['ip', 'link', 'set', 'lo', 'up'])
    directory = Path('/run/xb-runtime-fixture')
    directory.mkdir(mode=0o700)
    report = {'schema': 1, 'suite': 'runtime', 'isolated_network': True, 'isolated_mount': True,
              'private_run': True, 'panel_contacted': False, 'production_credentials_used': False,
              'success': False, 'passed': [], 'failed': [], 'backends': list(TOOLS),
              'limits': ['standalone fixture; no real panel handshake',
                         'QUIC version negotiation does not verify authenticated HY2 traffic']}
    report['vless_initial_port'] = args.initial_port
    report['vless_updated_port'] = args.updated_port
    daemon, client, log_stream = None, None, None
    config_path = directory / 'config.yml'
    daemon_log = directory / 'node.log'
    baseline = None
    try:
        client = subprocess.Popen(['unshare', '--net', sys.executable, '-c', 'import time;time.sleep(360)'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 3
        while os.readlink('/proc/' + str(client.pid) + '/ns/net') == os.readlink('/proc/self/ns/net'):
            if time.monotonic() > deadline:
                raise RuntimeError('client network namespace did not start')
            time.sleep(.02)
        client_net = os.readlink('/proc/' + str(client.pid) + '/ns/net')
        if client_net == args.host_net:
            raise RuntimeError('client namespace equals the host namespace')
        command(['ip', 'link', 'add', 'xb_rt_server', 'type', 'veth', 'peer', 'name', 'xb_rt_peer'])
        command(['ip', 'link', 'set', 'xb_rt_peer', 'netns', str(client.pid)])
        for prefix, link, address, address6 in [([], 'xb_rt_server', '10.253.31.1/24', 'fd00:253:31::1/64'),
                                              (['nsenter', '--target', str(client.pid), '--net'],
                                               'xb_rt_peer', '10.253.31.2/24', 'fd00:253:31::2/64')]:
            command(prefix + ['ip', 'link', 'set', 'lo', 'up'])
            command(prefix + ['ip', 'addr', 'add', address, 'dev', link])
            command(prefix + ['ip', '-6', 'addr', 'add', address6, 'dev', link, 'nodad'])
            command(prefix + ['ip', 'link', 'set', link, 'up'])
        # A synthetic default route supplies sing-box's interface discovery;
        # neither namespace has a route or a link to the host or Internet.
        command(['ip', 'route', 'add', 'default', 'via', '10.253.31.2', 'dev', 'xb_rt_server'])
        command(['nsenter', '--target', str(client.pid), '--net', 'ip', 'route', 'add',
                 'default', 'via', '10.253.31.1', 'dev', 'xb_rt_peer'])
        for tool in TOOLS:
            command([tool, '-N', 'FOREIGN_RUNTIME_KEEP'])
            command([tool, '-A', 'FOREIGN_RUNTIME_KEEP', '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'])
            command([tool, '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'])
            command([tool, '-A', 'INPUT', '-p', 'ipv6-icmp' if tool.startswith('ip6') else 'icmp', '-j', 'ACCEPT'])
            command([tool, '-A', 'INPUT', '-j', 'FOREIGN_RUNTIME_KEEP'])
            command([tool, '-A', 'INPUT', '-j', 'REJECT'])
            command([tool, '-P', 'INPUT', 'DROP'])
        baseline = rules_hashes()
        report['host_fixture_rule_hashes_before'] = baseline
        report['passed'].append('isolated_reject_drop_nft_legacy_fixture')
        preflight_tools(report)
        write_config(config_path, fixture_config(directory, args.initial_port))
        log_stream = daemon_log.open('w', encoding='utf-8')
        daemon = subprocess.Popen([args.binary, '-c', str(config_path)], env=synthetic_environment(),
                                  stdout=log_stream, stderr=subprocess.STDOUT, start_new_session=True)
        response = await_runtime(args.binary, daemon, args.initial_port)
        report['initial_ports'] = response['report']['ports']
        if not external_probe(client.pid, 'tcp', args.initial_port):
            raise RuntimeError('external TCP cannot reach the actual VLESS listener on ' + str(args.initial_port))
        report['passed'].append('actual_vless_runtime_registry_and_external_tcp_' + str(args.initial_port))
        _, alias = cli(args.xbctl, 'ports', expected=0)
        if not expected_runtime(alias, args.initial_port):
            raise RuntimeError('xbctl alias disagrees with the actual Node runtime registry')
        report['passed'].append('xbctl_queries_same_live_registry')
        if not external_probe(client.pid, 'quic', 17443):
            raise RuntimeError('external UDP did not receive QUIC version negotiation from actual HY2')
        report['passed'].append('actual_hy2_external_udp_quic_version_negotiation')
        if rules_hashes(foreign_only=True) != baseline:
            raise RuntimeError('runtime startup changed foreign host fixture rules')
        remove_vless_accept(response, args.initial_port)
        if external_probe(client.pid, 'tcp', args.initial_port):
            raise RuntimeError('removed grant did not reproduce the blocked TCP listener')
        before_check = rules_hashes()
        code, missing = cli(args.binary, 'check')
        after_check = rules_hashes()
        if code == 0 or missing is None or missing['report']['healthy'] or before_check != after_check:
            raise RuntimeError('check failed to report missing permission without changing rules')
        report['passed'].append('missing_vless_permission_detected_read_only')
        _, repaired = cli(args.binary, 'repair', expected=0)
        if not expected_runtime(repaired, args.initial_port) or not external_probe(client.pid, 'tcp', args.initial_port):
            raise RuntimeError('repair failed to restore the actual VLESS path')
        report['passed'].append('explicit_repair_restores_external_tcp')
        write_config(config_path, fixture_config(directory, args.updated_port))
        changed = await_runtime(args.binary, daemon, args.updated_port)
        if not external_probe(client.pid, 'tcp', args.updated_port) or external_probe(client.pid, 'tcp', args.initial_port):
            raise RuntimeError('configuration watcher did not move the actual listener')
        for tool in TOOLS:
            owned = '\n'.join(line for line in command([tool + '-save', '-t', 'filter']).stdout.splitlines()
                              if 'XB_IN_' in line)
            if re.search(r'--dport ' + str(args.initial_port) + r'(?:\s|$)', owned):
                raise RuntimeError('old VLESS permission remained after the port change')
        report['changed_ports'] = changed['report']['ports']
        report['passed'].append('config_watcher_moves_listener_and_owned_permission_to_' + str(args.updated_port))
        stop_child(daemon)
        if daemon.returncode != 0 or rules_hashes() != baseline:
            raise RuntimeError('graceful stop did not preserve every foreign rule and policy')
        unavailable = command([args.binary, 'firewall', 'ports'], env=synthetic_environment(), check=False)
        if unavailable.returncode == 0 or 'unavailable' not in unavailable.stderr:
            raise RuntimeError('stopped Node CLI invented a runtime snapshot')
        report['passed'].append('graceful_stop_cleans_only_owned_rules_and_runtime_socket')
        daemon = subprocess.Popen([args.binary, '-c', str(config_path)], env=synthetic_environment(),
                                  stdout=log_stream, stderr=subprocess.STDOUT, start_new_session=True)
        await_runtime(args.binary, daemon, args.updated_port)
        if not external_probe(client.pid, 'tcp', args.updated_port):
            raise RuntimeError('new process did not reconstruct necessary permissions')
        report['passed'].append('new_node_process_rebuilds_permissions_from_successful_runtime')
        stop_child(daemon)
        if daemon.returncode != 0 or rules_hashes() != baseline:
            raise RuntimeError('final stop changed foreign host fixture rules')
        report['success'] = True
    except Exception as error:
        report['failed'].append(str(error))
    finally:
        stop_child(daemon)
        stop_child(client)
        if log_stream is not None:
            log_stream.close()
        if baseline is not None:
            report['host_fixture_rule_hashes_after'] = rules_hashes(foreign_only=True)
            report['foreign_rules_preserved'] = report['host_fixture_rule_hashes_after'] == baseline
        suffix = '.' + args.label if args.label else ''
        output = args.binary + suffix + '.runtime-netns'
        # These logs contain only this public synthetic fixture, never host
        # rules, panel tokens, inherited credentials or real user UUIDs.
        log = daemon_log.read_text(encoding='utf-8', errors='replace') if daemon_log.exists() else ''
        Path(output + '.log').write_text(log[:2 * 1024 * 1024], encoding='utf-8')
        Path(output + '.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report), flush=True)
    return 0 if report['success'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--xbctl', required=True)
    parser.add_argument('--label', default='')
    parser.add_argument('--initial-port', type=int, default=443)
    parser.add_argument('--updated-port', type=int, default=8443)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--host-net', default='')
    parser.add_argument('--host-mount', default='')
    args = parser.parse_args()
    if (not 1 <= args.initial_port <= 65535 or not 1 <= args.updated_port <= 65535 or
            args.initial_port == args.updated_port or {args.initial_port, args.updated_port} & {22, 17443}):
        raise SystemExit('VLESS test ports must be distinct valid ports outside the SSH/HY2 fixture ports')
    if not sys.platform.startswith('linux') or os.geteuid() != 0:
        raise SystemExit('root on Linux is required')
    for value in (args.binary, args.xbctl):
        if not Path(value).is_absolute() or not Path(value).is_file() or not os.access(value, os.X_OK):
            raise SystemExit('absolute executable Node and xbctl paths are required')
    if args.label and not re.fullmatch(r'[a-z0-9-]{1,32}', args.label):
        raise SystemExit('invalid report label')
    if args.inside:
        return inside(args)
    return subprocess.run(['unshare', '--mount', '--net', '--fork', sys.executable,
                           str(Path(__file__).resolve()), '--inside', '--binary', args.binary,
                           '--xbctl', args.xbctl, '--label', args.label,
                           '--initial-port', str(args.initial_port), '--updated-port', str(args.updated_port),
                           '--host-net', os.readlink('/proc/self/ns/net'),
                           '--host-mount', os.readlink('/proc/self/ns/mnt')]).returncode


if __name__ == '__main__':
    raise SystemExit(main())
