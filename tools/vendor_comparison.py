"""Inspect the historical full vendor archive without extracting or changing it."""
import collections
import json
from pathlib import Path
import sys
import zipfile
import dependencies as d

archive = Path(sys.argv[1])
groups = collections.defaultdict(lambda: [0, 0])
with zipfile.ZipFile(archive) as z:
    entries = z.infolist()
    modules_file = next(i.filename for i in entries if i.filename.endswith('vendor/modules.txt'))
    modules_text = z.read(modules_file).decode('utf-8')
    for i in entries:
        parts = i.filename.split('/')
        if 'vendor' not in parts:
            continue
        parts = parts[parts.index('vendor') + 1:]
        key = '/'.join(parts[:3] if parts and parts[0] == 'github.com' else parts[:2])
        groups[key][0] += i.file_size
        groups[key][1] += i.compress_size
    headers = [line for line in modules_text.splitlines() if line.startswith('# ') and not line.startswith('##')]
    data = dict(vendor_file=archive.name, vendor_bytes=archive.stat().st_size,
                vendor_sha256=d.sha(archive.read_bytes()), entries=len(entries),
                uncompressed_bytes=sum(i.file_size for i in entries), module_headers=len(headers),
                largest_groups=[dict(path=k, uncompressed_bytes=v[0], compressed_bytes=v[1]) for k, v in sorted(groups.items(), key=lambda kv: kv[1][0], reverse=True)[:15]])
pin = json.loads((d.ROOT / 'dependency-snapshot.json').read_text(encoding='utf-8'))
lock = d.load_lock()
data.update(selective_archive=pin['archive'], selective_bytes=pin['bytes'],
            reduction_percent=round(100 * (1 - pin['bytes'] / data['vendor_bytes']), 2),
            selected_modules=len(lock['modules']), protected_modules=sum(r['backup'] for r in lock['modules']))
d.write_json(d.ROOT / 'dependency-size-comparison.json', data)
print(json.dumps(data, ensure_ascii=False, indent=2))
