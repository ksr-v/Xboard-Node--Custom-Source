"""Create source-only LF checkout for the explicitly authorized clean VM test."""
import argparse
import io
import json
from pathlib import Path
import tarfile
import dependencies as d

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--output', type=Path, default=d.STATE / 'vm-source.tar.gz')
args = ap.parse_args()
archive = args.output.resolve()
archive.parent.mkdir(parents=True, exist_ok=True)
files = d.run(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z']).split('\0')
with tarfile.open(archive, 'w:gz') as tar:
    for name in sorted(set(filter(None, files))):
        path = d.ROOT / name
        if path.is_symlink() or not path.is_file() or name.startswith('.dependency-work/'):
            raise ValueError('Unexpected source entry: ' + name)
        if path.name in ('.env', 'config.yml', 'config.json') or path.suffix in ('.zip', '.exe', '.db', '.sqlite3'):
            raise ValueError('Refusing secret/runtime/archive source entry: ' + name)
        data = path.read_bytes()
        if path.suffix in ('.go', '.py', '.mod', '.sum', '.md', '.json', '.yml', '.yaml', '.sh', '.txt') or path.name in ('Dockerfile', 'Makefile'):
            data = data.replace(b'\r\n', b'\n')
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mode = 0o755 if path.suffix == '.sh' else 0o644
        tar.addfile(info, io.BytesIO(data))
print(json.dumps(dict(created=True, source_only=True)))
