"""Run normal Makefile/race/runtime checks after the authorized VM recovery run."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import dependencies as d

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('recovery_dir', type=Path)
ap.add_argument('--version', default='dependency-check')
ap.add_argument('--output', type=Path, default=d.STATE / 'vm-validation-results.json')
args = ap.parse_args()
recovery = args.recovery_dir.resolve()
if not json.loads((recovery / 'results.json').read_text()).get('passed'):
    raise SystemExit('Recovery must pass before VM normal/deployment verification')
env = dict(os.environ, GOMODCACHE=str(recovery / 'gomodcache'), GOCACHE=str(recovery / 'gocache'),
           GOPATH=str(recovery / 'gopath'), GOTOOLCHAIN='local')
rows = []
result = dict(results=rows, passed=False)
before = {f: d.sha((d.ROOT / f).read_bytes()) for f in ('go.mod', 'go.sum')}
try:
    for label, command in [('tool-tests', ['python3', 'tools/test_dependencies.py']),
                           ('corruption', ['python3', 'tools/corruption_test.py']),
                           ('normal-make-build-all', ['make', 'build-all', 'VERSION=' + args.version]),
                           ('normal-make-test-including-race', ['make', 'test']),
                           ('runtime-deployment', ['python3', 'tools/vm_runtime_smoke.py', str(recovery)])]:
        print(label, flush=True)
        log = d.STATE / ('vm-' + label + '.log')
        with log.open('w', encoding='utf-8') as stream:
            p = subprocess.run(command, cwd=d.ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT)
        rows.append(dict(step=label, passed=p.returncode == 0))
        if p.returncode:
            raise RuntimeError(label + ' failed; inspect the private local log')
    for arch in ('amd64', 'arm64'):
        for name, flag in [('xboard-node', '-v'), ('xbctl', 'version')]:
            runner = [] if arch == 'amd64' else ['qemu-aarch64-static']
            output = subprocess.check_output(runner + [str(d.ROOT / (name + '-linux-' + arch)), flag], env=env, text=True)
            if args.version not in output:
                raise RuntimeError('Make VERSION did not reach binary metadata')
            rows.append(dict(step='normal-' + name + '-' + arch + '-version', passed=True))
    result['passed'] = True
finally:
    result['source_unchanged'] = all(d.sha((d.ROOT / f).read_bytes()) == digest for f, digest in before.items())
    if not result['source_unchanged']:
        result['passed'] = False
    d.write_json(args.output, result)
    print('Validation evidence saved locally', flush=True)
if not result['source_unchanged']:
    raise RuntimeError('VM validation changed dependency files')
