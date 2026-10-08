"""Optional Python 3.12+ test helper: fetch official SHA256-checked Linux Go."""
import argparse
import json
from pathlib import Path
import tarfile
import urllib.request
import dependencies as d

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--version', default='go1.26.5')
ap.add_argument('--arch', choices=('amd64', 'arm64'), default='amd64')
ap.add_argument('--destination', type=Path, default=d.STATE / 'linux-toolchain')
args = ap.parse_args()
version = args.version
with urllib.request.urlopen('https://go.dev/dl/?mode=json&include=all', timeout=60) as response:
    releases = json.load(response)
release = next(r for r in releases if r['version'] == version)
asset = next(f for f in release['files'] if f['os'] == 'linux' and f['arch'] == args.arch and f['kind'] == 'archive')
dest = args.destination.resolve()
dest.mkdir(parents=True, exist_ok=True)
archive = dest / asset['filename']
if not archive.exists():
    with urllib.request.urlopen('https://go.dev/dl/' + asset['filename'], timeout=120) as response:
        d.immutable(archive, response.read())
if d.sha(archive.read_bytes()) != asset['sha256']:
    raise ValueError('Official Go archive checksum mismatch')
with tarfile.open(archive) as tar:
    # Official checksum trusted; reject traversal and escaping links before extraction.
    for member in tar.getmembers():
        if (member.name != 'go' and not member.name.startswith('go/')) or '..' in member.name.split('/') or member.issym() or member.islnk():
            raise ValueError('Unexpected toolchain archive entry: ' + member.name)
    tar.extractall(dest, filter='data')
d.write_json(dest / 'source.json', dict(official_archive=True, checksum_verified=True))
print(json.dumps(dict(installed=True, checksum_verified=True)))
