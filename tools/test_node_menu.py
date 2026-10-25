"""Management fixtures: no network, root log reads, or real service changes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest

spec = importlib.util.spec_from_file_location('installer_fixture', Path(__file__).with_name('test_installer.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


class NodeManagementTests(unittest.TestCase):
    def shell(self, code, data='', env=None):
        settings = dict(env or {})
        if os.name == 'nt':
            settings['MENU_TEST_PYTHON'] = Path(sys.executable).as_posix()
            code = 'python3() { "$MENU_TEST_PYTHON" "$@"; }\n' + code
        return base.InstallerTests().shell(code, data, settings)

    def test_new_menu_choices_need_no_token(self):
        for choice, action in [('4', 'configure'), ('5', 'logs'), ('6', 'status')]:
            r = self.shell('management_menu; printf "ACTION:%s" "$ACTION"', choice + '\n')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('ACTION:' + action, r.stdout)

    def test_log_action_is_bounded_to_owned_service(self):
        r = self.shell('journalctl() { printf "JOURNAL:%s\\n" "$*"; }; perform_logs')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('JOURNAL:-u xboard-node.service -n 100 --no-pager', r.stdout)

    def test_configure_empty_inputs_do_not_stop_service(self):
        with tempfile.TemporaryDirectory() as directory:
            cli = Path(directory) / 'cli'
            cli.write_text('#!/usr/bin/env bash\nprintf \'%s\\n\' \'{"instances":[{"id":"selected","panel_url":"https://panel.example","mode":"machine","machine_id":7}]}\'\n', encoding='utf-8')
            cli.chmod(0o700)
            r = self.shell('CLI_PATH="$FAKE_CLI"; detect_current_state() { CURRENT_STATE=installed; }; '
                           'verify_managed_service() { :; }; stop_existing_service() { echo UNEXPECTED_STOP; }; perform_configure', '\n\n', {'FAKE_CLI': cli.as_posix()})
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertNotIn('UNEXPECTED_STOP', r.stdout)
            self.assertIn('No changes requested', r.stdout)

    def release(self, directory, *, tamper=False, duplicate=False, foreign=False, draft=False):
        root = Path(directory)
        installer = b'''#!/usr/bin/env bash
perform_upgrade() { :; }
verify_endpoint_binary() { :; }
[[ "$1" == upgrade ]] || exit 71
[[ -z "${XBOARD_NODE_RELEASE_VERSION:-}${XBOARD_NODE_DOWNLOAD_BASE:-}${XBOARD_NODE_ASSET_BASE:-}" ]] || exit 72
echo VERIFIED_RELEASE_EXECUTED
'''
        digest = hashlib.sha256(installer).hexdigest()
        (root / 'install.sh').write_bytes(installer + (b'# tampered\n' if tamper else b''))
        (root / 'SHA256SUMS').write_text((digest + '  install.sh\n') * (2 if duplicate else 1), encoding='utf-8')
        assets = []
        for name in ['install.sh', 'SHA256SUMS']:
            assets.append({'name': name, 'state': 'uploaded', 'digest': None,
                           'browser_download_url': 'https://github.com/' + ('foreign/repository' if foreign else 'ksr-v/Xboard-Node--Custom-Source') + '/releases/download/v1.14.0/' + name})
        (root / 'release.json').write_text(json.dumps({'tag_name': 'v1.14.0', 'draft': draft, 'prerelease': False, 'assets': assets}), encoding='utf-8')

    def update(self, directory, fail=''):
        return self.shell('''
curl() {
    local dest='' url='' arg
    while [ "$#" -gt 0 ]; do
        case "$1" in -o) dest="$2"; shift 2 ;; https://*) url="$1"; shift ;; *) shift ;; esac
    done
    case "$url" in
      https://api.github.com/repos/ksr-v/Xboard-Node--Custom-Source/releases/latest) arg=release.json ;;
      https://github.com/ksr-v/Xboard-Node--Custom-Source/releases/download/v1.14.0/install.sh) arg=install.sh ;;
      https://github.com/ksr-v/Xboard-Node--Custom-Source/releases/download/v1.14.0/SHA256SUMS) arg=SHA256SUMS ;;
      *) echo UNEXPECTED_SOURCE; return 90 ;;
    esac
    if [ "$arg" = "$FAKE_FAIL_ASSET" ]; then printf partial > "$dest"; return 22; fi
    cp "$FAKE_RELEASE_DIR/$arg" "$dest"
}
XBOARD_NODE_RELEASE_VERSION=invalid; XBOARD_NODE_DOWNLOAD_BASE=https://untrusted.invalid; XBOARD_NODE_ASSET_BASE=https://untrusted.invalid
export XBOARD_NODE_RELEASE_VERSION XBOARD_NODE_DOWNLOAD_BASE XBOARD_NODE_ASSET_BASE
upgrade_from_menu
''', env={'FAKE_RELEASE_DIR': Path(directory).as_posix(), 'FAKE_FAIL_ASSET': fail})

    def test_stable_release_is_verified_and_overrides_are_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            self.release(directory)
            r = self.update(directory)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn('VERIFIED_RELEASE_EXECUTED', r.stdout)
            self.assertNotIn('UNEXPECTED_SOURCE', r.stdout)

    def test_bad_or_partial_releases_never_execute(self):
        for flags in [{'tamper': True}, {'duplicate': True}, {'foreign': True}, {'draft': True}, {'fail': 'install.sh'}]:
            with self.subTest(flags=flags), tempfile.TemporaryDirectory() as directory:
                options = dict(flags)
                fail = options.pop('fail', '')
                self.release(directory, **options)
                r = self.update(directory, fail)
                self.assertNotEqual(r.returncode, 0)
                self.assertNotIn('VERIFIED_RELEASE_EXECUTED', r.stdout)

    def test_hidden_retarget_passes_token_only_in_private_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cli = root / 'cli'
            cli.write_text('''#!/usr/bin/env bash
[[ "$*" != *synthetic-menu-secret* ]] || exit 89
if [ "$2" = inspect ]; then
 printf '%s\n' '{"instances":[{"id":"selected","panel_url":"https://old.example","mode":"machine","machine_id":7}]}'
 exit
fi
while [ "$#" -gt 0 ]; do
 case "$1" in
   --input-file) input="$2"; shift 2 ;;
   --out-config) config="$2"; shift 2 ;;
   --out-credentials) credentials="$2"; shift 2 ;;
   --out-meta) meta="$2"; shift 2 ;;
   *) shift ;;
 esac
done
grep -q synthetic-menu-secret "$input" || exit 88
printf 'health_port: 0\npanel: {url: https://new.example}\n' > "$config"
printf 'TOKEN=staged\n' > "$credentials"
printf '{}\n' > "$meta"
''', encoding='utf-8')
            cli.chmod(0o700)
            r = self.shell('''
CLI_PATH="$FAKE_ROOT/cli"; INSTALL_ROOT="$FAKE_ROOT/active"; mkdir "$INSTALL_ROOT"
CONFIG_FILE="$INSTALL_ROOT/config.yml"; CREDENTIALS_FILE="$INSTALL_ROOT/credentials.env"; INSTALL_META="$INSTALL_ROOT/install-meta.json"
ENDPOINT_TRUST_PATH="$FAKE_ROOT/no-trust"
detect_current_state() { CURRENT_STATE=installed; }
verify_managed_service() { :; }
ensure_dirs() { :; }; load_health_port_from_config() { :; }
backup_existing_state() { SERVICE_WAS_ACTIVE=0; }
stop_existing_service() { echo STOPPED_AFTER_PREFLIGHT; }
perform_configure
grep -q 'https://new.example' "$CONFIG_FILE"
''', 'https://new.example\nsynthetic-menu-secret\n', {'FAKE_ROOT': root.as_posix()})
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn('STOPPED_AFTER_PREFLIGHT', r.stdout)
            self.assertNotIn('synthetic-menu-secret', r.stdout + r.stderr)

    def test_custom_service_paths_and_dropins_are_refused(self):
        for valid in [True, False]:
            with tempfile.TemporaryDirectory() as directory:
                unit = Path(directory) / 'fixture.service'
                unit.write_text('ExecStart=/fixture/node -c /fixture/config.yml\nEnvironmentFile=-/fixture/credentials.env\n', encoding='utf-8')
                r = self.shell('''
SERVICE_PATH="$FIXTURE_UNIT"; BINARY_PATH=/fixture/node; CONFIG_FILE=/fixture/config.yml; CREDENTIALS_FILE=/fixture/credentials.env
systemctl() {
  case "$2" in
    --property=FragmentPath) printf '%s\n' "$SERVICE_PATH" ;;
    --property=DropInPaths) printf '%s\n' "$FIXTURE_DROPIN" ;;
    --property=ExecStart) echo '{ path=/fixture/node ; argv[]=/fixture/node -c /fixture/config.yml ; }' ;;
  esac
}
verify_managed_service
''', env={'FIXTURE_UNIT': unit.as_posix(), 'FIXTURE_DROPIN': '' if valid else '/foreign/override.conf'})
                self.assertEqual(r.returncode == 0, valid, r.stdout + r.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
