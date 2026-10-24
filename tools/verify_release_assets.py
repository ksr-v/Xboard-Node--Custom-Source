"""Verify the exact immutable Release asset set without executing binaries."""
import argparse
import hashlib
from pathlib import Path
import re


ASSETS = {
    'xboard-node-linux-amd64', 'xboard-node-linux-arm64',
    'xbctl-linux-amd64', 'xbctl-linux-arm64', 'install.sh',
}


def verify(directory, installer):
    installer_text = installer.read_text(encoding='utf-8')
    pinned = {}
    for kind, arch, digest in re.findall(r'^\s*(node|xbctl):(amd64|arm64)\) expected=([a-f0-9]{64}) ;;$', installer_text, re.M):
        name = ('xboard-node' if kind == 'node' else kind) + '-linux-' + arch
        if name in pinned:
            raise ValueError('Repeated installer asset pin')
        pinned[name] = digest
    if set(pinned) != ASSETS - {'install.sh'}:
        raise ValueError('Installer must pin all four binary checksums')
    expected = {}
    for line in (directory / 'SHA256SUMS').read_text(encoding='ascii').splitlines():
        match = re.fullmatch(r'([a-f0-9]{64}) [ *]([A-Za-z0-9.-]+)', line)
        if not match or match[2] not in ASSETS or match[2] in expected:
            raise ValueError('Unexpected, malformed or repeated checksum entry')
        expected[match[2]] = match[1]
    if set(expected) != ASSETS:
        raise ValueError('Missing checksum entry')
    if any(expected[name] != digest for name, digest in pinned.items()):
        raise ValueError('Release manifest disagrees with the tagged installer binary pins')
    for name, digest in expected.items():
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Missing regular release asset: ' + name)
        calculated = hashlib.sha256()
        with path.open('rb') as stream:
            header = stream.read(20)
            calculated.update(header)
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                calculated.update(chunk)
        if calculated.hexdigest() != digest:
            raise ValueError('Asset checksum mismatch: ' + name)
        if name != 'install.sh':
            machine = 62 if name.endswith('amd64') else 183
            if header[:4] != b'\x7fELF' or int.from_bytes(header[18:20], 'little') != machine:
                raise ValueError('Release asset architecture mismatch: ' + name)
    # Checkout text can use CRLF locally; Git blob and Linux release use LF.
    if (directory / 'install.sh').read_bytes().replace(b'\r\n', b'\n') != installer.read_bytes().replace(b'\r\n', b'\n'):
        raise ValueError('Published installer differs from tagged source')
    print('Verified five Release assets, manifest and tagged installer; no assets changed.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--installer', type=Path, default=Path('install.sh'))
    args = parser.parse_args()
    verify(args.directory, args.installer)
