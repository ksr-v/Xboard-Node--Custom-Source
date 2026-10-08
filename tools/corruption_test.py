"""Damage an actual C-risk module in a disposable snapshot, preserving all originals."""
import json
from pathlib import Path
import shutil
import tempfile
import dependencies as d


def corruption_test(snapshot):
    manifest = d.verify(snapshot)
    row = next(r for r in manifest['modules'] if r['risk'] == 'C' and r['backup'])
    rel = next(p for p in row['files'] if p.endswith('.zip'))
    work = Path(tempfile.mkdtemp(prefix='corruption-', dir=d.STATE))
    copy = work / 'snapshot'
    shutil.copytree(snapshot, copy)
    target = copy / rel
    data = bytearray(target.read_bytes())
    before = d.sha(data)
    data[len(data) // 2] ^= 0x01
    target.write_bytes(data)
    try:
        d.verify(copy)
    except ValueError as exc:
        if 'SHA256 mismatch' not in str(exc):
            raise
        result = dict(passed=True, module=row['path'], version=row['version'],
                      before=before, damaged=d.sha(data), refusal=str(exc),
                      original_unchanged=d.sha((snapshot / rel).read_bytes()) == before)
    else:
        raise ValueError('Corrupted module was accepted')
    d.verify(snapshot)
    d.write_json(work / 'results.json', result)
    print(json.dumps(result, ensure_ascii=False))
    print('Evidence: ' + str(work / 'results.json'))


if __name__ == '__main__':
    d.STATE.mkdir(parents=True, exist_ok=True)
    corruption_test(d.STATE / 'snapshot')
