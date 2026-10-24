"""Checksum-verified maintained copies of the frozen, locally backed-up core.

The module archive and historical go.sum remain immutable. Every supported
build uses a private modfile; the application has a compile-time guard.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile


def _go(arguments, root, env):
    result = subprocess.run(['go', *arguments], cwd=root, env=env, capture_output=True,
                            encoding='utf-8', timeout=120)
    if result.returncode:
        raise RuntimeError('Cannot resolve the pinned Xray core for the maintained patch: ' + result.stderr)
    return json.loads(result.stdout)


def _tree_hash(directory, prefix, overrides=None):
    overrides = overrides or {}
    digest = hashlib.sha256()
    for path in sorted(directory.rglob('*'), key=lambda p: p.relative_to(directory).as_posix()):
        if path.is_symlink():
            raise ValueError('Symlink in fixed kernel source')
        if path.is_file():
            relative = path.relative_to(directory).as_posix()
            data = overrides.get(relative, path).read_bytes()
            digest.update((hashlib.sha256(data).hexdigest() + '  ' + prefix + relative + '\n').encode())
    return 'h1:' + base64.b64encode(digest.digest()).decode()


def prepare(env, root=None):
    root = Path(root or Path(__file__).resolve().parents[1]).resolve()
    patches = root / 'patches/xray-core'
    manifest = json.loads((patches / 'manifest.json').read_text(encoding='utf-8'))
    if manifest['schema'] != 1:
        raise ValueError('Unsupported kernel patch manifest')
    inspect_env = dict(env)
    inspect_env['GOFLAGS'] = '-mod=readonly'
    module = _go(['list', '-m', '-json', manifest['module']], root, inspect_env).get('Replace', {})
    if module.get('Path') != manifest['replacement'] or module.get('Version') != manifest['version']:
        raise ValueError('Maintained kernel patch does not match the fixed module version')
    directory = module.get('Dir')
    if not directory:
        # This protected module must come from the verified local file proxy,
        # never a public fallback or the historical source owner.
        inspect_env['GOPROXY'] = inspect_env.get('GOPROXY', 'off').split(',')[0]
        downloaded = _go(['mod', 'download', '-json', manifest['module']], root, inspect_env)
        directory = downloaded.get('Dir')
    if not directory:
        raise ValueError('Pinned core is unavailable; restore the trusted dependency snapshot first')
    directory = Path(directory).resolve()
    replacements = {}
    for row in manifest['files']:
        relative = Path(row['path'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Unsafe maintained kernel patch path')
        original = directory / relative
        patched = patches / relative
        if hashlib.sha256(original.read_bytes()).hexdigest() != row['original_sha256']:
            raise ValueError('Original pinned core file checksum differs: ' + row['path'])
        if hashlib.sha256(patched.read_bytes()).hexdigest() != row['patched_sha256']:
            raise ValueError('Maintained core patch checksum differs: ' + row['path'])
        replacements[row['path']] = patched
    prefix = manifest['replacement'] + '@' + manifest['version'] + '/'
    sums = [line.split()[2] for line in (root / 'go.sum').read_text().splitlines()
            if line.split()[:2] == [manifest['replacement'], manifest['version']]]
    if len(sums) != 1 or _tree_hash(directory, prefix) != sums[0]:
        raise ValueError('Fixed kernel source tree differs from historical go.sum')
    expected = _tree_hash(directory, prefix, replacements)
    identity = hashlib.sha256(expected.encode()).hexdigest()[:20]
    state = root / '.dependency-work'
    state.mkdir(parents=True, exist_ok=True)
    maintained = state / ('xray-core-' + identity)
    if not maintained.exists():
        temporary = Path(tempfile.mkdtemp(prefix='kernel-copy-', dir=state))
        for path in directory.rglob('*'):
            relative = path.relative_to(directory)
            destination = temporary / relative
            if path.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
            elif path.is_file():
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(replacements.get(relative.as_posix(), path), destination)
        if _tree_hash(temporary, prefix) != expected:
            raise ValueError('Maintained kernel copy checksum differs')
        os.replace(temporary, maintained)
    if maintained.is_symlink() or _tree_hash(maintained, prefix) != expected:
        raise ValueError('Maintained kernel copy was modified')
    destination = state / 'kernel-build.mod'
    destination.write_bytes((root / 'go.mod').read_bytes())
    destination.with_suffix('.sum').write_bytes((root / 'go.sum').read_bytes())
    result = subprocess.run(['go', 'mod', 'edit', '-modfile=' + str(destination),
                             '-replace=' + manifest['module'] + '=./' + maintained.relative_to(root).as_posix()],
                            cwd=root, env=inspect_env, capture_output=True, encoding='utf-8', timeout=30)
    if result.returncode:
        raise RuntimeError('Cannot prepare the private maintained kernel modfile: ' + result.stderr)
    return '-mod=readonly ' + json.dumps('-modfile=' + destination.as_posix())


if __name__ == '__main__':
    print(prepare(dict(os.environ)))
