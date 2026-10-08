"""Collect primary GitHub maintenance evidence using gh's existing authentication."""
import concurrent.futures
from datetime import datetime, timezone
import json
import subprocess
from pathlib import Path
import dependencies as d


def api(path):
    p = subprocess.run(['gh', 'api', path], capture_output=True, text=True, encoding='utf-8')
    if p.returncode:
        return {'review_required': True, 'error': 'GitHub metadata unavailable'}
    return json.loads(p.stdout)


def collect(repo):
    info = api('repos/' + repo)
    if 'full_name' not in info:
        return repo, info
    contributors = api('repos/' + repo + '/contributors?per_page=20&anon=false')
    releases = api('repos/' + repo + '/releases?per_page=5')
    return repo, dict(url=info['html_url'], archived=info['archived'], disabled=info['disabled'],
                      pushed_at=info['pushed_at'], created_at=info['created_at'],
                      owner_type=info['owner']['type'], stars=info['stargazers_count'],
                      license=info.get('license'),
                      contributors_sample=[dict(login=c['login'], contributions=c['contributions']) for c in contributors] if isinstance(contributors, list) else [],
                      releases=[dict(tag=r['tag_name'], date=r['published_at'], url=r['html_url']) for r in releases] if isinstance(releases, list) else [],
                      limitations='Contributor count is a capped sample; push/release recency is evidence, not maintenance or security guarantee. No Stars-only classification.')


def main():
    lock = d.load_lock()
    repos = sorted({'/'.join(r['path'].split('/')[1:3]) for r in lock['modules']
                    if r['usage'] and r['path'].startswith('github.com/') and not r['path'].startswith('github.com/cedar2025/')})
    evidence = {'date': datetime.now(timezone.utc).date().isoformat(), 'source': 'GitHub REST API: repo, contributors (20), releases (5)',
                'repositories': {}}
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        for i, (repo, row) in enumerate(pool.map(collect, repos), 1):
            evidence['repositories'][repo] = row
            if i % 20 == 0:
                print(f'evidence {i}/{len(repos)}', flush=True)
    d.write_json(d.ROOT / 'dependency-evidence.json', evidence)
    print(f'Saved primary evidence for {len(repos)} repositories')


if __name__ == '__main__':
    main()
