"""Restore only the source-pinned immutable dependency release (or supplied archive)."""
import json
import os
from pathlib import Path
import subprocess
import sys
import dependencies as d

pin = json.loads((d.ROOT / 'dependency-snapshot.json').read_text(encoding='utf-8'))
d.STATE.mkdir(parents=True, exist_ok=True)
archive = Path(sys.argv[1]) if len(sys.argv) > 1 else d.STATE / pin['archive']
if not archive.exists():
    if len(sys.argv) > 1:
        raise SystemExit('Supplied archive does not exist')
    subprocess.run(['gh', 'release', 'download', pin['release_tag'], '--repo', os.environ['GH_REPO'],
                    '--pattern', pin['archive'], '--dir', str(d.STATE)], check=True)
d.restore(archive, d.STATE / 'snapshot', pin['sha256'])
