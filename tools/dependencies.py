#!/usr/bin/env python3
"""Selective, immutable Go file-proxy snapshots. Python 3.9+, standard library only."""
import argparse
import base64
import collections
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / '.dependency-work'
LOCK = ROOT / 'dependency-lock.json'
TAGS = 'with_quic,with_utls,with_wireguard,with_acme,with_clash_api'
HOST_TAGS = 'with_quic,with_utls,with_wireguard,with_clash_api'


def run(args, env=None, capture=True, cwd=ROOT):
    p = subprocess.run(args, cwd=cwd, env=env, text=True, encoding='utf-8',
                       stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.PIPE if capture else None)
    if p.returncode:
        raise RuntimeError(f'{args}: exit {p.returncode}\n{p.stderr or ""}')
    return p.stdout or ''


def objects(text):
    decoder = json.JSONDecoder()
    while text.strip():
        text = text.lstrip()
        obj, end = decoder.raw_decode(text)
        yield obj
        text = text[end:]


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.new')
    with tmp.open('w', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    os.replace(tmp, path)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def text_sha(path):
    # Normalize tracked source text only, NEVER original module payloads.
    return sha(path.read_bytes().replace(b'\r\n', b'\n'))


def escape(value):
    return ''.join('!' + c.lower() if 'A' <= c <= 'Z' else c for c in value)


def module_key(path, version):
    if not re.fullmatch(r'[A-Za-z0-9._~!+/-]+', path) or not re.fullmatch(r'v[A-Za-z0-9.+_-]+', version):
        raise ValueError('Unsafe module path/version')
    if any(x in ('', '.', '..') for x in path.split('/')):
        raise ValueError('Unsafe module path')
    return escape(path) + '/@v/' + escape(version)


def policy():
    return json.loads((ROOT / 'dependency-policy.json').read_text(encoding='utf-8'))


def classify(path, pol):
    override = pol['overrides'].get(path)
    if override:
        if override['risk'] == 'C' and not override.get('backup', True):
            raise ValueError('C risk cannot be exempted: ' + path)
        return override['risk'], override.get('backup', True), override['reason']
    repo = '/'.join(path.split('/')[1:3]) if path.startswith('github.com/') else ''
    evidence = pol.get('_evidence', {}).get(repo, {})
    if evidence.get('archived') or evidence.get('disabled'):
        return 'C', True, 'GitHub 官方元数据确认已归档/禁用；当前使用时必须保护精确版本。'
    if any(path.startswith(p) for p in pol['low_risk_prefixes']):
        return 'A', False, '成熟机构/生态维护的模块，精确版本与 go.sum 固定；仍依赖公共代理和校验数据库，不承诺永久可用。'
    cutoff = (datetime.now(timezone.utc) - timedelta(days=365)).date().isoformat()
    if (len(evidence.get('contributors_sample', [])) >= 5 and
            len(evidence.get('releases', [])) >= 2 and
            evidence.get('pushed_at', '') >= cutoff and
            any((r.get('date') or '') >= cutoff for r in evidence.get('releases', []))):
        return 'B', True, '官方 API 显示多贡献者、持续提交及近期版本发布；仍采用保守源码备份，不凭 Stars 或账户归属免备份。'
    return 'review_required', True, '尚无充分维护者/发布/替代性证据；不凭个人账号、Stars 或 indirect 判安全，保守保护。'


def upstream(path):
    parts = path.split('/')
    return 'https://' + '/'.join(parts[:3] if parts[0] == 'github.com' else parts)


def sums():
    return {(p, v): h for p, v, h in (line.split() for line in (ROOT / 'go.sum').read_text().splitlines())}


def license_id(text):
    lower = text.lower()
    if 'mozilla public license' in lower: return 'MPL-2.0'
    if 'gnu general public license' in lower: return 'GPL (check version and extra terms)'
    if 'apache license' in lower: return 'Apache-2.0 (check notices)'
    if 'permission is hereby granted, free of charge' in lower: return 'MIT-like (review exact text)'
    if 'redistribution and use in source and binary forms' in lower: return 'BSD-like (review exact clauses)'
    if 'permission to use, copy, modify, and/or distribute' in lower: return 'ISC-like (review exact text)'
    return 'review_required'


def local_license(module):
    directory = Path(module['Dir']) if module.get('Dir') else None
    entries = []
    if directory and directory.is_dir():
        for p in sorted(directory.iterdir()):
            if p.is_file() and p.name.lower().startswith(('license', 'copying', 'notice', 'copyright')):
                data = p.read_bytes()
                entries.append(dict(file=p.name, sha256=sha(data), identification=license_id(data.decode('utf-8', errors='replace'))))
    return entries or [dict(identification='review_required: no cached root license text')]


def audit():
    pol = policy()
    evidence_path = ROOT / 'dependency-evidence.json'
    if evidence_path.exists():
        pol['_evidence'] = json.loads(evidence_path.read_text(encoding='utf-8'))['repositories']
    env = dict(os.environ, GOWORK='off', GOENV='off', GOPRIVATE='', GONOPROXY='',
               GONOSUMDB='', GOSUMDB='sum.golang.org', GOTOOLCHAIN='local')
    # Restored snapshots also serve clean-cache maintenance audits. Never use direct.
    local_proxy = STATE / 'snapshot' / 'proxy'
    env['GOPROXY'] = (local_proxy.resolve().as_uri() + ',' if local_proxy.is_dir() else '') + pol['public_proxy']
    env['GOFLAGS'] = '-mod=readonly'
    modules = list(objects(run(['go', 'list', '-m', '-json', 'all'], env)))
    used = collections.defaultdict(set)
    for arch in ('amd64', 'arm64'):
        target = dict(env, GOOS='linux', GOARCH=arch, CGO_ENABLED='0')
        pkgs = objects(run(['go', 'list', '-deps', '-test', '-json', '-tags', TAGS, './...'], target))
        for pkg in pkgs:
            m = pkg.get('Module')
            if m and not m.get('Main'):
                m = m.get('Replace', m)
                used[(m['Path'], m['Version'])].add('linux/' + arch + ':build+test')
    # Host test dependencies can differ from Linux production dependencies.
    for pkg in objects(run(['go', 'list', '-deps', '-test', '-json', './internal/...'], env)):
        m = pkg.get('Module')
        if m and not m.get('Main'):
            m = m.get('Replace', m)
            used[(m['Path'], m['Version'])].add('host:test')
    checksum = sums()
    rows = []
    for logical in modules:
        if logical.get('Main'):
            continue
        m = logical.get('Replace', logical)
        path, version = m['Path'], m['Version']
        risk, protect, reason = classify(path, pol)
        usage = sorted(used[(path, version)])
        # Graph-only requirements need their original .mod for version selection, not
        # platform ZIPs (e.g. Android Cronet), unless an explicit override requires it.
        protect = protect and (bool(usage) or risk == 'C' or path in pol['overrides'])
        rows.append(dict(path=path, version=version, logical_path=logical['Path'],
                         logical_version=logical['Version'], upstream=upstream(path),
                         risk=risk, backup=protect, reason=reason,
                         usage=usage,
                         sum=checksum.get((path, version)), mod_sum=checksum.get((path, version + '/go.mod')),
                         evidence=pol.get('_evidence', {}).get('/'.join(path.split('/')[1:3])) if path.startswith('github.com/') else None,
                         license=local_license(m)))
    # All selected graph modules are covered, including graph-only and platform-specific modules.
    # go.sum-only entries are historical evidence, not automatically current dependencies.
    current = {(r['path'], r['version']) for r in rows}
    historical = [dict(path=p, version=v, sum=h) for (p, v), h in sorted(checksum.items())
                  if (p, v.removesuffix('/go.mod')) not in current]
    lock = dict(schema=1, go_mod_sha256=text_sha(ROOT / 'go.mod'),
                go_sum_sha256=text_sha(ROOT / 'go.sum'), policy_sha256=text_sha(ROOT / 'dependency-policy.json'),
                tags=TAGS, modules=sorted(rows, key=lambda r: r['path']), go_sum_only=historical)
    write_json(LOCK, lock)
    graph = run(['go', 'mod', 'graph'], env)
    (ROOT / 'dependency-graph.txt').write_text(graph, encoding='utf-8')
    report()
    print(f'Audited {len(rows)} selected modules; {sum(bool(r["usage"]) for r in rows)} build/test modules; {len(historical)} historical checksum entries')


def load_lock():
    lock = json.loads(LOCK.read_text(encoding='utf-8'))
    if lock.get('tags') != TAGS:
        raise ValueError('Build tags changed; run audit before backup/build')
    for name, key in [('go.mod', 'go_mod_sha256'), ('go.sum', 'go_sum_sha256'), ('dependency-policy.json', 'policy_sha256')]:
        if text_sha(ROOT / name) != lock[key]:
            raise ValueError(name + ' changed; run audit before backup/build')
    return lock


def h1(files):
    # Go dirhash.Hash1: sorted paths, SHA256(contents), then SHA256 of hash/path lines.
    text = ''.join(f'{sha(data)}  {name}\n' for name, data in sorted(files))
    return 'h1:' + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()


def validate_module(row, content):
    info = json.loads(content['info'])
    if info['Version'] != row['version']:
        raise ValueError('Wrong .info version: ' + row['path'])
    mod_sum = h1([('go.mod', content['mod'])])
    if row.get('mod_sum') and mod_sum != row['mod_sum']:
        raise ValueError('go.sum mod mismatch: ' + row['path'])
    import io
    with zipfile.ZipFile(io.BytesIO(content['zip'])) as z:
        prefix = row['path'] + '@' + row['version'] + '/'
        names = z.namelist()
        if len(names) != len(set(names)):
            raise ValueError('Duplicate ZIP entry')
        files = []
        licenses = []
        for n in names:
            if not n.startswith(prefix) or '..' in PurePosixPath(n).parts or '\\' in n or '\n' in n:
                raise ValueError('Unsafe module ZIP path: ' + n)
            if n.endswith('/'):
                continue
            data = z.read(n)
            files.append((n, data))
            if PurePosixPath(n).name.lower().startswith(('license', 'copying', 'notice', 'copyright')):
                licenses.append(dict(path=n, sha256=sha(data), identification=license_id(data.decode('utf-8', errors='replace')), text=data.decode('utf-8', errors='replace')))
        zip_sum = h1(files)
    if row.get('sum') and zip_sum != row['sum']:
        raise ValueError('go.sum ZIP mismatch: ' + row['path'])
    # A missing go.sum entry is not silently trusted: Go must authenticate it via the normal sumdb.
    return zip_sum, mod_sum, licenses


def immutable(path, data):
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError('Refusing to overwrite different historical bytes: ' + str(path))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.new')
    tmp.write_bytes(data)
    os.replace(tmp, path)


def backup(dest):
    lock = load_lock()
    pol = policy()
    cache = Path(run(['go', 'env', 'GOMODCACHE']).strip()) / 'cache' / 'download'
    dest.mkdir(parents=True, exist_ok=True)
    rows = []
    for number, row in enumerate(lock['modules'], 1):
        key = module_key(row['path'], row['version'])
        # Preserve graph metadata for ALL selected versions. Source ZIPs are selected
        # by actual Linux build/test reachability, never by the indirect annotation.
        extensions = ('mod', 'info', 'zip') if row['backup'] else ('mod', 'info')
        content = {}
        for ext in extensions:
            src = cache / (key + '.' + ext)
            if not src.exists():
                staged = dest / ('proxy/' + key + '.' + ext)
                if staged.exists():
                    content[ext] = staged.read_bytes()
                    continue
                if any(row['path'].startswith(p) for p in pol['blocked_network_prefixes']):
                    raise ValueError('Forbidden upstream missing locally: ' + key)
                if ext != 'zip':
                    with urllib.request.urlopen(pol['public_proxy'] + '/' + key + '.' + ext, timeout=60) as response:
                        content[ext] = response.read()
                    continue
                env = dict(os.environ, GOPROXY=pol['public_proxy'], GOFLAGS='-mod=readonly',
                           GOWORK='off', GOENV='off', GOPRIVATE='', GONOPROXY='',
                           GONOSUMDB='', GOSUMDB='sum.golang.org', GOTOOLCHAIN='local')
                result = list(objects(run(['go', 'mod', 'download', '-json', row['path'] + '@' + row['version']], env)))[0]
                if result.get('Error'):
                    raise ValueError(result['Error'])
            content[ext] = src.read_bytes()
        metadata = dict(row)
        if row['backup']:
            zs, ms, licenses = validate_module(row, content)
            # Require Go's checksum database authentication for selected graph-only versions not
            # present in the root go.sum, using an isolated temporary module (never edits go.sum).
            if not row.get('sum') or not row.get('mod_sum'):
                with tempfile.TemporaryDirectory(prefix='checksum-', dir=STATE) as temp:
                    Path(temp, 'go.mod').write_text('module checksum.invalid/verify\ngo 1.26\n')
                    env = dict(os.environ, GOPROXY=cache.resolve().as_uri(), GOFLAGS='', GOSUMDB='sum.golang.org',
                               GONOSUMDB='', GONOPROXY='', GOPRIVATE='', GOWORK='off', GOENV='off', GOTOOLCHAIN='local')
                    result = list(objects(run(['go', 'mod', 'download', '-json', row['path'] + '@' + row['version']], env, cwd=temp)))[0]
                    if result.get('Error') or result.get('Sum') != zs or result.get('GoModSum') != ms:
                        raise ValueError('Checksum DB authentication failed: ' + row['path'])
            metadata.update(sum=zs, mod_sum=ms, licenses=licenses,
                            license_status='texts_preserved_review_obligations' if licenses else 'review_required_no_license_found')
        else:
            if row.get('mod_sum') and h1([('go.mod', content['mod'])]) != row['mod_sum']:
                raise ValueError('Metadata checksum mismatch: ' + row['path'])
        metadata['files'] = {}
        for ext, data in content.items():
            rel = 'proxy/' + key + '.' + ext
            immutable(dest / rel, data)
            metadata['files'][rel] = dict(sha256=sha(data), bytes=len(data))
        listing = dest / 'proxy' / (escape(row['path']) + '/@v/list')
        versions = set(listing.read_text().splitlines()) if listing.exists() else set()
        versions.add(row['version'])
        listing.write_text('\n'.join(sorted(versions)) + '\n', encoding='utf-8')
        rows.append(metadata)
        if number % 25 == 0:
            print(f'backup {number}/{len(lock["modules"])}', flush=True)
    graph_metadata = []
    for entry in lock['go_sum_only']:
        if not entry['version'].endswith('/go.mod'):
            continue
        version = entry['version'].removesuffix('/go.mod')
        key = module_key(entry['path'], version)
        src = cache / (key + '.mod')
        if src.exists():
            data = src.read_bytes()
        else:
            if any(entry['path'].startswith(p) for p in pol['blocked_network_prefixes']):
                raise ValueError('Missing forbidden historical metadata: ' + key)
            with urllib.request.urlopen(pol['public_proxy'] + '/' + key + '.mod', timeout=60) as response:
                data = response.read()
        if h1([('go.mod', data)]) != entry['sum']:
            raise ValueError('Historical graph go.mod checksum mismatch: ' + key)
        rel = 'proxy/' + key + '.mod'
        immutable(dest / rel, data)
        graph_metadata.append(dict(path=entry['path'], version=version, file=rel, sha256=sha(data), mod_sum=entry['sum']))
    manifest = dict(schema=1, lock_sha256=text_sha(LOCK), modules=rows, graph_metadata=graph_metadata)
    write_json(dest / 'manifest.json', manifest)
    verify(dest)
    report(dest)


def verify(dest):
    lock = load_lock()
    manifest = json.loads((dest / 'manifest.json').read_text(encoding='utf-8'))
    if manifest['lock_sha256'] != text_sha(LOCK):
        raise ValueError('Snapshot belongs to another lock; use matching source/lock')
    pin = ROOT / 'dependency-snapshot.json'
    if pin.exists():
        trusted = json.loads(pin.read_text(encoding='utf-8'))
        if trusted['lock_sha256'] == text_sha(LOCK) and trusted['manifest_sha256'] != sha((dest / 'manifest.json').read_bytes()):
            raise ValueError('Manifest does not match the source-controlled snapshot pin')
    expected = {(r['path'], r['version']) for r in lock['modules']}
    if len(manifest['modules']) != len(expected) or {(r['path'], r['version']) for r in manifest['modules']} != expected:
        raise ValueError('Snapshot module coverage mismatch')
    expected_rows = {(r['path'], r['version']): r for r in lock['modules']}
    for row in manifest['modules']:
        trusted = expected_rows[(row['path'], row['version'])]
        if any(row.get(k) != trusted.get(k) for k in ('backup', 'risk', 'logical_path', 'logical_version', 'usage')):
            raise ValueError('Snapshot changed audited protection policy')
        if any(trusted.get(k) and row.get(k) != trusted[k] for k in ('sum', 'mod_sum')):
            raise ValueError('Snapshot changed trusted Go checksum')
        key = module_key(row['path'], row['version'])
        extensions = ('mod', 'info', 'zip') if row['backup'] else ('mod', 'info')
        files = {'proxy/' + key + '.' + ext for ext in extensions}
        if set(row['files']) != files:
            raise ValueError('Snapshot file coverage mismatch')
        content = {}
        for rel, meta in row['files'].items():
            data = (dest / rel).read_bytes()
            if sha(data) != meta['sha256'] or len(data) != meta['bytes']:
                raise ValueError('SHA256 mismatch: ' + rel)
            content[rel.rsplit('.', 1)[1]] = data
        if row['backup']:
            validate_module(row, content)
        else:
            if json.loads(content['info'])['Version'] != row['version']:
                raise ValueError('Wrong metadata version')
            if row.get('mod_sum') and h1([('go.mod', content['mod'])]) != row['mod_sum']:
                raise ValueError('Graph module checksum mismatch')
        if row['version'] not in (dest / 'proxy' / (escape(row['path']) + '/@v/list')).read_text().splitlines():
            raise ValueError('Missing version index')
    expected_meta = {(r['path'], r['version'].removesuffix('/go.mod')): r['sum'] for r in lock['go_sum_only'] if r['version'].endswith('/go.mod')}
    actual_meta = {(r['path'], r['version']): r for r in manifest.get('graph_metadata', [])}
    if len(actual_meta) != len(manifest.get('graph_metadata', [])) or set(actual_meta) != set(expected_meta):
        raise ValueError('Historical graph metadata coverage mismatch')
    for key, row in actual_meta.items():
        rel = 'proxy/' + module_key(*key) + '.mod'
        if row['file'] != rel:
            raise ValueError('Unexpected graph metadata path')
        data = (dest / rel).read_bytes()
        if sha(data) != row['sha256'] or h1([('go.mod', data)]) != expected_meta[key]:
            raise ValueError('Historical graph checksum mismatch')
    print(f'Verified {len(manifest["modules"])} modules', flush=True)
    return manifest


def export_snapshot(dest, output):
    manifest = verify(dest)
    # Export only the audited generation, never arbitrary files/credentials accidentally
    # placed in staging. Previous immutable archives retain earlier module versions.
    owned = {'manifest.json'}
    indexes = collections.defaultdict(set)
    for row in manifest['modules']:
        owned.update(row['files'])
        indexes['proxy/' + escape(row['path']) + '/@v/list'].add(row['version'])
    owned.update(r['file'] for r in manifest['graph_metadata'])
    entries = []
    for rel in sorted(owned):
        p = dest / rel
        if p.is_symlink():
            raise ValueError('Symlink in snapshot')
        entries.append((rel, p.read_bytes()))
    entries.extend((rel, ('\n'.join(sorted(versions)) + '\n').encode()) for rel, versions in indexes.items())
    entries.sort()
    # Content-addressed archive name; never overwrite a historical backup.
    identity = sha(''.join(name + '\0' + sha(data) + '\n' for name, data in entries).encode())[:16]
    output.mkdir(parents=True, exist_ok=True)
    archive = output / ('module-proxy-' + identity + '.zip')
    with tempfile.TemporaryDirectory(dir=STATE) as temp:
        tmp = Path(temp) / archive.name
        with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for name, data in entries:
                zi = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.external_attr = 0o100644 << 16
                z.writestr(zi, data)
        immutable(archive, tmp.read_bytes())
    immutable(output / (archive.name + '.sha256'), (sha(archive.read_bytes()) + '  ' + archive.name + '\n').encode())
    write_json(ROOT / 'dependency-snapshot.json', dict(schema=1, archive=archive.name,
               sha256=sha(archive.read_bytes()), bytes=archive.stat().st_size,
               manifest_sha256=sha((dest / 'manifest.json').read_bytes()), lock_sha256=text_sha(LOCK),
               release_tag='dependencies-' + identity))
    print(f'{archive}: {archive.stat().st_size} bytes')
    return archive


def restore(archive, dest, checksum):
    actual = sha(archive.read_bytes())
    if actual != checksum:
        raise ValueError('Archive checksum mismatch')
    if dest.exists() and any(dest.iterdir()):
        raise ValueError('Restore destination must be empty; no historical overwrite')
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        if len(names) != len(set(names)):
            raise ValueError('Duplicate snapshot paths')
        for info in z.infolist():
            n = info.filename
            if not n or n.startswith('/') or '\\' in n or ':' in n or '..' in PurePosixPath(n).parts or (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('Unsafe snapshot entry')
        z.extractall(dest)
    verify(dest)


def report(dest=None):
    lock = load_lock()
    manifest = json.loads((dest / 'manifest.json').read_text(encoding='utf-8')) if dest else None
    details = {(r['path'], r['version']): r for r in manifest['modules']} if manifest else {}
    lines = ['# 依赖审计与保护清单', '', '自动生成；构建/测试可达且风险不明确的模块标为 review_required 并备份。所有选定图模块都保留元数据；protected 模块保存完整 ZIP。仅模块图且未被使用的其他平台源码不纳入当前 Linux 恢复目标，改变 tags/平台后必须重新审计。', '',
             '| 模块（实际下载路径） | 固定版本 | 风险 | 构建/测试使用 | 保护 | 许可证/理由 |', '|---|---|---|---|---|---|']
    for r in lock['modules']:
        d = details.get((r['path'], r['version']), {})
        license_names = ', '.join(x['identification'] for x in d.get('licenses', [])[:3]) or ', '.join(x['identification'] for x in r['license'])
        status = ('已保存 ZIP/mod/info' if r['backup'] else '仅图元数据，源码联网') if d else ('待备份' if r['backup'] else '源码联网')
        lines.append(f'| [{r["path"]}]({r["upstream"]}) | {r["version"]} | {r["risk"]} | {", ".join(r["usage"]) or "仅模块图/其他平台"} | {status} | {license_names}；{r["reason"]} |')
    lines += ['', '## 校验历史', '', f'go.sum 中另有 {len(lock["go_sum_only"])} 条非当前选定版本校验记录，完整保留在 dependency-lock.json；不自动升级或删除。']
    (ROOT / 'DEPENDENCY-AUDIT.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')


def build(dest, arch, test=False, host=False, isolated=False):
    verify(dest)
    env = dict(os.environ, GOPROXY=(dest / 'proxy').resolve().as_uri() + ',' + policy()['public_proxy'],
               GOFLAGS='-mod=readonly', GOSUMDB='sum.golang.org', GOPRIVATE='', GONOPROXY='', GONOSUMDB='',
               GOTOOLCHAIN='local', GOWORK='off', GOENV='off')
    if isolated:
        # Copy protected objects into a fresh private module cache, then disable network
        # fallback for their MODULE PATHS with GOPRIVATE/GONOPROXY. The 'direct' lookup
        # is never used: all protected zip/mod/info objects are preseeded and verified.
        # A controlled proxy is used by recovery-test below for proof at request level.
        raise ValueError('Use recovery-test for enforced isolation')
    if not host:
        env.update(GOOS='linux', GOARCH=arch, CGO_ENABLED='0')
    if test:
        run(['go', 'test', '-tags', TAGS, '-count=1', './internal/...'], env, capture=False)
        # Preserve the original race check on Linux hosts with a C toolchain.
        if host and sys.platform.startswith('linux'):
            race_env = dict(env, CGO_ENABLED='1')
            run(['go', 'test', '-race', '-count=1', './internal/...'], race_env, capture=False)
    else:
        out = ROOT
        out.mkdir(parents=True, exist_ok=True)
        try:
            commit = run(['git', 'rev-parse', '--short', 'HEAD']).strip()
        except (RuntimeError, OSError):
            commit = os.environ.get('COMMIT', 'unknown')
        version = os.environ.get('VERSION', commit + '-deps')
        build_time = os.environ.get('BUILD_TIME', datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
        ldflags = os.environ.get('LDFLAGS', f'-s -w -X main.version={version} -X main.buildTime={build_time} -X main.commit={commit}')
        for name in ('xboard-node', 'xbctl'):
            suffix = '.exe' if host and os.name == 'nt' else ('' if host else '-linux-' + arch)
            run(['go', 'build', '-tags', HOST_TAGS if host else TAGS, '-ldflags', ldflags,
                 '-o', str(out / (name + suffix)), './cmd/' + name], env, capture=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command', choices=['audit', 'backup', 'verify', 'export', 'restore', 'report', 'build', 'test', 'recovery-test'])
    ap.add_argument('--snapshot', type=Path, default=STATE / 'snapshot')
    ap.add_argument('--archive', type=Path)
    ap.add_argument('--sha256')
    ap.add_argument('--output', type=Path, default=STATE / 'exports')
    ap.add_argument('--arch', choices=['amd64', 'arm64'], default='amd64')
    ap.add_argument('--host', action='store_true')
    ap.add_argument('--compiler-cache', type=Path, help='Optional reuse of a compiler cache; module cache always fresh in recovery-test')
    args = ap.parse_args()
    STATE.mkdir(parents=True, exist_ok=True)
    if args.command == 'audit': audit()
    elif args.command == 'backup': backup(args.snapshot)
    elif args.command == 'verify': verify(args.snapshot)
    elif args.command == 'export': export_snapshot(args.snapshot, args.output)
    elif args.command == 'restore':
        if not args.archive or not args.sha256: ap.error('restore requires --archive and trusted --sha256')
        restore(args.archive, args.snapshot, args.sha256)
    elif args.command == 'report': report(args.snapshot)
    elif args.command == 'recovery-test':
        from recovery_test import recovery_test
        recovery_test(args.snapshot, args.compiler_cache)
    else: build(args.snapshot, args.arch, test=args.command == 'test', host=args.host)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError, KeyError, zipfile.BadZipFile) as exc:
        print('ERROR:', exc, file=sys.stderr)
        sys.exit(1)
