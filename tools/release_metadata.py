"""Immutable metadata for reproducible, installer-pinned release binaries."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def settings(version, toolchain, root=ROOT):
    pin = json.loads((root / 'release-build.json').read_text(encoding='utf-8'))
    if version != pin['version']:
        return None
    if toolchain.split()[2] != pin['go_version']:
        raise ValueError(f"Release {version} requires {pin['go_version']}; got {toolchain.strip()}")
    # Do not embed HEAD: the installer hash pins are committed after the build.
    # Source provenance belongs in the separately published verification record.
    return (f"-s -w -X main.version={pin['version']} "
            f"-X main.buildTime={pin['build_time']}")
