"""Coordinate authorized two-VM integration without saving runtime credentials locally.

Requires existing fixture state from panel_fixture.php, authorized SSH access, and
panel_vm_test.py on the Node test VM. Evidence contains only public test results.
"""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time

import dependencies as d
from panel_vm_test import privacy_self_test, public_projection


def private_result(payload):
    """Decode an authorized private reply without changing IDs or counters."""
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise RuntimeError('Unexpected private fixture response')
    return value


def main():
    if sys.argv[1:] == ['--privacy-self-test']:
        public = privacy_self_test()
        raw = dict(token='synthetic-secret', user_id=548218,
                   u=9387214, d=48127, count=487)
        if private_result(json.dumps(raw)) != raw:
            raise RuntimeError('Private fixture response changed')
        public['checks'].append(dict(check='private-fixture-reply-preserved', passed=True))
        print(json.dumps(public), flush=True)
        return
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--panel-host', required=True)
    ap.add_argument('--node-host', required=True)
    ap.add_argument('--user', required=True)
    ap.add_argument('--panel-user', required=True)
    ap.add_argument('--php-bin', required=True)
    ap.add_argument('--panel-root', required=True)
    ap.add_argument('--panel-url', required=True)
    ap.add_argument('--recovery', required=True)
    ap.add_argument('--upgrade-version', required=True)
    ap.add_argument('--identity', action='append', required=True)
    ap.add_argument('--fixture-dir', required=True)
    ap.add_argument('--vm-base', required=True)
    args = ap.parse_args()
    if not args.fixture_dir.startswith('/') or args.fixture_dir == '/' or '..' in Path(args.fixture_dir).parts:
        raise SystemExit('Unexpected fixture directory')
    if not args.vm_base.startswith('/') or args.vm_base == '/' or '..' in Path(args.vm_base).parts:
        raise SystemExit('Unexpected test VM directory')
    work = Path(tempfile.mkdtemp(prefix='panel-e2e-', dir=d.STATE))
    base = args.vm_base + '/panel-e2e'
    source = args.vm_base + '/source'
    ssh_base = ['ssh', '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
                '-o', 'StrictHostKeyChecking=yes']
    for identity in args.identity:
        ssh_base += ['-i', identity]
    rows = []
    result = dict(passed=False, checks=rows)
    active = None
    rules = []
    log = None
    cleaned = False

    def ssh(host, command, data=None, check=True):
        cmd = command if isinstance(command, str) else shlex.join(command)
        proc = subprocess.run(ssh_base + [args.user + '@' + host, cmd], input=data,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if check and proc.returncode:
            # Never interpolate argv or stderr: remote commands may use secrets.
            raise RuntimeError('Remote operation failed')
        return proc

    def fixture(command, **opts):
        private_result_path = args.fixture_dir + '/private-result.json'
        cmd = ['sudo', '-n', '-u', args.panel_user, args.php_bin,
               args.fixture_dir + '/panel_fixture.php', command,
               '--state=' + args.fixture_dir + '/state.json', '--panel-root=' + args.panel_root,
               '--private-result=' + private_result_path]
        cmd += ['--' + k.replace('_', '-') + '=' + str(v).lower() for k, v in opts.items()]
        value = json.loads(ssh(args.panel_host, cmd).stdout)
        if not value.get('passed'):
            raise RuntimeError('Fixture operation failed: ' + command)
        d.write_json(work / (command + '-' + str(time.time_ns()) + '.json'), public_projection(value))
        # Detailed IDs and counters stay in the private remote runtime file and
        # process memory. They are never copied into public local artifacts.
        return private_result(ssh(args.panel_host, ['sudo', '-n', 'cat', private_result_path]).stdout)

    def driver(command, arch, kernel, *extra):
        return ['python3', source + '/tools/panel_vm_test.py', command,
                '--base', base, '--arch', arch, '--kernel', kernel, *extra,
                '--panel-url', args.panel_url, '--recovery', args.recovery,
                '--upgrade-version', args.upgrade_version]

    try:
        initial = fixture('status')
        if not initial['baseline']['original_configuration_unchanged']:
            raise RuntimeError('Panel configuration changed before testing')
        # State is captured in process memory, validated, then piped directly to
        # the private Node runtime file; neither stdout nor local disk receives it.
        secret = ssh(args.panel_host, ['sudo', '-n', 'cat', args.fixture_dir + '/state.json']).stdout
        state = json.loads(secret)
        if state.get('phase') != 'active' or set(state['machines']) != {'singbox', 'xray'}:
            raise RuntimeError('Unexpected fixture state')
        ports = [int(state['machines'][k]['port']) for k in ('singbox', 'xray')]
        if any(p < 1024 or p > 65535 for p in ports):
            raise RuntimeError('Unexpected fixture port')
        ssh(args.node_host, 'umask 077; cat > ' + shlex.quote(base + '/state.json') +
            '; chmod 600 ' + shlex.quote(base + '/state.json'), secret)
        del state, secret
        for tool, address in (('iptables', '127.0.0.0/8'), ('ip6tables', '::1/128')):
            rule = ['INPUT', '-p', 'tcp', '-m', 'multiport', '--dports', ','.join(map(str, ports)),
                    '!', '-s', address, '-m', 'comment', '--comment', 'xboard-panel-e2e-' + work.name,
                    '-j', 'REJECT']
            ssh(args.node_host, ['sudo', '-n', tool, '-I', *rule])
            rules.append((tool, rule))
        rows.append(dict(check='listener-isolation', passed=True))
        for arch in ('amd64', 'arm64'):
            for kernel in ('singbox', 'xray'):
                case_name = arch + '-' + kernel
                case_dir = base + '/' + case_name
                fixture('reset-devices', nodes_stopped=True)
                before = fixture('status')
                active = subprocess.Popen(ssh_base + [args.user + '@' + args.node_host,
                    shlex.join(driver('run-case', arch, kernel))], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                row = dict(check=case_name, passed=False, checks=[])
                rows.append(row)
                deadline = time.monotonic() + 420
                next_status = 0
                maximum_online_count = 0
                while True:
                    if active.poll() is not None:
                        raise RuntimeError(case_name + ' exited before revocation test')
                    ready = ssh(args.node_host, ['test', '-f', case_dir + '/ready-for-revoke'], check=False)
                    if ready.returncode == 0:
                        break
                    if time.monotonic() >= next_status:
                        sample = fixture('status')
                        maximum_online_count = max(maximum_online_count, int(sample['user']['online_count'] or 0))
                        next_status = time.monotonic() + 3
                    if time.monotonic() >= deadline:
                        raise RuntimeError(case_name + ' initial traffic timed out')
                    time.sleep(2)
                print(json.dumps(dict(check=case_name + ':encrypted-client-device', passed=True)), flush=True)
                fixture('set-user-state', banned=True)
                deadline = time.monotonic() + 35
                started = time.monotonic()
                attempt = 0
                while True:
                    attempt += 1
                    probe = ssh(args.node_host, driver('run-probe', arch, kernel, '--expect-rejected'), check=False)
                    if probe.returncode == 0:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError(case_name + ' panel revocation did not apply')
                    time.sleep(2)
                row['checks'].append(dict(check='user-revocation', passed=True))
                fixture('set-user-state', banned=False)
                started = time.monotonic()
                deadline = started + 35
                attempt = 0
                while True:
                    attempt += 1
                    probe = ssh(args.node_host, driver('run-probe', arch, kernel), check=False)
                    if probe.returncode == 0:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError(case_name + ' panel recovery did not apply')
                    time.sleep(2)
                row['checks'].append(dict(check='user-restoration', passed=True))
                # Wait for machine status's real 60-second report and account
                # traffic through the original panel handlers, fixture IDs only.
                deadline = time.monotonic() + 100
                while True:
                    fixture('process-jobs')
                    status = fixture('status')
                    now = status['machines'][kernel]
                    old = before['machines'][kernel]
                    traffic = int(now['node']['u']) + int(now['node']['d'])
                    old_traffic = int(old['node']['u']) + int(old['node']['d'])
                    if (traffic > old_traffic and status['user_stat_rows'] > 0 and now['stat_rows'] > 0
                            and now['load_history_count'] > old['load_history_count']):
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError(case_name + ' panel traffic/stat/heartbeat not observed')
                    time.sleep(3)
                user_traffic_delta = (int(status['user']['u']) + int(status['user']['d'])
                    - int(before['user']['u']) - int(before['user']['d']))
                if user_traffic_delta <= 0:
                    raise RuntimeError('Fixture user traffic was not accounted')
                if maximum_online_count <= 0:
                    raise RuntimeError('Fixture online device report was not observed')
                ssh(args.node_host, ['touch', case_dir + '/continue'])
                active.wait(timeout=300)
                if active.returncode:
                    raise RuntimeError(case_name + ' VM driver failed')
                active = None
                public = json.loads(ssh(args.node_host, ['cat', case_dir + '/results.json']).stdout)
                public = public_projection(public)
                d.write_json(work / (case_name + '-results.json'), public)
                if not public.get('passed'):
                    raise RuntimeError(case_name + ' VM result failed')
                row['checks'].extend(public['checks'])
                row['checks'].append(dict(check='panel-traffic-stat-heartbeat', passed=True))
                row['passed'] = True
                print(json.dumps(dict(check=case_name, passed=True)), flush=True)
        fixture('process-jobs')
        cleanup = fixture('cleanup', nodes_stopped=True)
        rows.append(dict(check='fixture-cleanup', passed=True))
        cleaned = True
        result['passed'] = True
    except BaseException as error:
        rows.append(dict(check='integration-completed', passed=False))
    finally:
        if active is not None:
            # Ask the driver's finally block to perform its owned teardown.
            ssh(args.node_host, ['touch', case_dir + '/continue'], check=False)
            try:
                active.wait(timeout=300)
            except subprocess.TimeoutExpired:
                active.terminate()
                active.wait(timeout=15)
        if log:
            log.close()
        # Only cleanup after driver proves there is no installed or running Node.
        # QEMU processes and long Linux executable names are not reliably
        # detected by pgrep -x. Check actual executable arguments as root.
        stop_check = '''from pathlib import Path
import sys
names = {'xboard-node', 'xboard-node-linux-amd64', 'xboard-node-linux-arm64', 'panel_vm_test.py'}
busy = Path('/etc/xboard-node').exists()
for process in Path('/proc').iterdir():
    if not process.name.isdigit():
        continue
    try:
        argv = (process / 'cmdline').read_bytes().split(b'\\0')
    except (FileNotFoundError, ProcessLookupError):
        continue
    busy = busy or any(Path(arg.decode(errors='replace')).name in names for arg in argv if arg)
sys.exit(1 if busy else 0)
'''
        stopped = ssh(args.node_host, ['sudo', '-n', 'python3', '-c', stop_check], check=False)
        if stopped.returncode == 0 and not cleaned:
            try:
                fixture('cleanup', nodes_stopped=True)
                rows.append(dict(check='fixture-cleanup', passed=True))
                cleaned = True
            except Exception as error:
                rows.append(dict(check='fixture-cleanup', passed=False))
        if cleaned:
            for host, path, prefix in (
                    (args.node_host, base + '/state.json', []),
                    (args.panel_host, args.fixture_dir + '/state.json', ['sudo', '-n'])):
                deleted = ssh(host, prefix + ['rm', '-f', path], check=False)
                absent = ssh(host, prefix + ['test', '!', '-e', path], check=False)
                if deleted.returncode or absent.returncode:
                    result['credential_cleanup_errors'] = True
        else:
            result['fixture_cleanup_unconfirmed'] = True
        if stopped.returncode == 0:
            for tool, rule in reversed(rules):
                proc = ssh(args.node_host, ['sudo', '-n', tool, '-D', *rule], check=False)
                if proc.returncode:
                    result['firewall_cleanup_errors'] = True
        else:
            result['firewall_retained_for_unconfirmed_node_shutdown'] = True
        cleanup_errors = ('credential_cleanup_errors', 'fixture_cleanup_unconfirmed',
                          'firewall_cleanup_errors', 'firewall_retained_for_unconfirmed_node_shutdown')
        if any(result.get(key) for key in cleanup_errors):
            result['passed'] = False
        result = dict(passed=result['passed'], checks=rows + [dict(check=key, passed=not bool(result.get(key))) for key in cleanup_errors])
        result = public_projection(result)
        d.write_json(work / 'results.json', result)
        print(json.dumps(dict(check='integration-completed', passed=result['passed'])), flush=True)
    if not result['passed']:
        raise RuntimeError('Integration cleanup did not pass; inspect public results')


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        print(json.dumps(dict(check='integration-completed', passed=False)), flush=True)
        raise SystemExit(1) from None
