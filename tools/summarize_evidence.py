"""Publish validation outcomes only; keep detailed evidence private."""
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path
import dependencies as d


def public_outcomes(value):
    """Whitelist output fields instead of copying private runtime objects."""
    runs = value['recovery_runs']
    snapshot = value['final_snapshot']
    public_snapshot = {name: snapshot[name] for name in (
        'schema', 'archive', 'sha256', 'bytes', 'manifest_sha256',
        'lock_sha256', 'release_tag')}
    checks = dict(protected_upstream_recovery=True, protected_network_fallback_refused=True,
                  dependency_sources_unchanged=True,
                  fresh_module_cache_verified=any(row['fresh_module_cache'] for row in runs),
                  fresh_compiler_cache_verified=any(row['fresh_compiler_cache'] for row in runs))
    for name in ('ubuntu_vm_validation', 'ubuntu_vm_runtime', 'remote_ci', 'docker', 'panel_integration'):
        if name in value:
            checks[name] = True
    return dict(schema=2, passed=True, final_snapshot=public_snapshot, checks=checks,
                scope=dict(platforms=['linux/amd64', 'linux/arm64'],
                           programs=['xboard-node', 'xbctl'], kernels=['sing-box', 'Xray'],
                           arm64_execution='QEMU'),
                limitations=[
                    'Native ARM installation has not been verified',
                    'Legacy global-token authentication and WebSocket coordination have not been verified',
                    'Docker runtime validation is standalone; panel TLS uses separate Node processes',
                    'Whole-system from-scratch disaster recovery has not been verified'])


def privacy_self_test():
    """Prove that arbitrary runtime metadata cannot cross the public boundary."""
    private = dict(username='fixture-owner', host='203.0.113.17',
                   path='/private/runtime/example', count=487,
                   token='synthetic-secret', run_id=548218)
    value = dict(
        recovery_runs=[dict(fresh_module_cache=True, fresh_compiler_cache=True, **private)],
        final_snapshot=dict(
            schema=1, archive='module-proxy-example.zip', sha256='a' * 64,
            bytes=123, manifest_sha256='b' * 64, lock_sha256='c' * 64,
            release_tag='dependencies-example', **private),
        ubuntu_vm_validation=dict(passed=True, **private),
        docker=dict(passed=True, **private),
        panel_integration=dict(passed=True, **private))
    public = public_outcomes(value)
    encoded = json.dumps(public, sort_keys=True)
    if any(str(item) in encoded for item in private.values()):
        raise RuntimeError('Public outcome contains private runtime metadata')
    return dict(passed=True, checks=[dict(
        check='public-outcomes-private-fields-excluded', passed=True)])


if __name__ == '__main__' and __import__('sys').argv[1:] == ['--privacy-self-test']:
    print(json.dumps(privacy_self_test()))
    raise SystemExit(0)

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('recovery_results', nargs='+', type=Path)
ap.add_argument('--vm-validation', type=Path)
ap.add_argument('--vm-runtime', type=Path)
ap.add_argument('--ci', type=Path, help='Successful public CI summary')
ap.add_argument('--docker', type=Path, help='Successful Docker build/runtime summary')
ap.add_argument('--panel', type=Path, help='Successful public panel E2E result')
args = ap.parse_args()
if bool(args.vm_validation) != bool(args.vm_runtime):
    ap.error('Both VM validation and runtime evidence are required together')

rows = []
for filename in args.recovery_results:
    path = Path(filename)
    run = json.loads(path.read_text(encoding='utf-8'))
    if not run.get('passed') or not run.get('source_unchanged'):
        raise ValueError('Cannot summarize an incomplete/failed recovery run: ' + str(path))
    requests = run['requests']
    protected = {d.escape(r['path']) for r in d.load_lock()['modules'] if r['backup']}
    bad = [r for r in requests if r['module'] in protected and r['source'] != 'local']
    if bad:
        raise ValueError('Protected source used public fallback')
    rows.append(dict(run=path.parent.name, toolchain=run['toolchain'], passed=run['passed'],
                     source_unchanged=run['source_unchanged'], requests=len(requests),
                     protected_local_zip_modules=run['protected_local_zip_modules'],
                     protected_network_requests=len(bad),
                     nonprotected_public_zip_requests=sum(r['source'] == 'public_nonprotected' and r['path'].endswith('.zip') for r in requests),
                     fresh_module_cache=run.get('fresh_module_cache', True),
                     fresh_compiler_cache=run.get('fresh_compiler_cache', True),
                     simulated_lf_checkout=run.get('simulated_lf_checkout', False),
                     steps=run['results']))
result = dict(date=datetime.now(timezone.utc).date().isoformat(), recovery_runs=rows,
             final_snapshot=json.loads((d.ROOT / 'dependency-snapshot.json').read_text()),
             limitations=['ARM64 runtime uses QEMU, not native ARM hardware',
                          'Whole-panel from-scratch disaster recovery is outside this Node validation'])
if args.vm_validation:
    validation = json.loads(args.vm_validation.read_text(encoding='utf-8'))
    runtime = json.loads(args.vm_runtime.read_text(encoding='utf-8'))
    if not validation.get('passed') or not validation.get('source_unchanged') or not runtime.get('passed'):
        raise ValueError('VM validation and runtime must pass before summarizing')
    # Historical evidence recorded the successful connection target as
    # "listener". Keep the result, but do not imply a verified bind address.
    for row in runtime.get('results', []):
        if 'listener' in row:
            row['connection_target'] = row.pop('listener')
            row['bind_address_verified'] = False
    result['ubuntu_vm_validation'] = validation
    result['ubuntu_vm_runtime'] = runtime
for key, filename, missing in (
        ('remote_ci', args.ci, 'No remote CI run'),
        ('docker', args.docker, 'No Docker daemon build/runtime test'),
        ('panel_integration', args.panel, 'No real panel or encrypted client traffic test')):
    if filename:
        value = json.loads(filename.read_text(encoding='utf-8'))
        if not value.get('passed'):
            raise ValueError('Cannot summarize unsuccessful ' + key)
        result[key] = value
    else:
        result['limitations'].append(missing)
if args.panel:
    result['limitations'] += [
        'Legacy global-token node authentication was not configured on the test panel',
        'Real-panel traffic uses temporary VLESS TCP/TLS fixtures and original allowlisted job handlers; Docker runtime is standalone',
    ]
d.write_json(d.ROOT / 'dependency-test-results.json', public_outcomes(result))
print('Published validation outcomes without runtime metadata')
