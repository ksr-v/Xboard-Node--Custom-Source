"""Replacement/rollback fixtures: real temporary files, never real system services.

All managed paths, including the command links, are redirected into one private
temporary directory. Network, dependency installation and systemctl are fakes.
These checks do not prove Linux cgroup shutdown or production port release.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import test_installer as harness


def native_symlinks_available():
    try:
        with tempfile.TemporaryDirectory(prefix="node-link-capability-") as directory:
            root = Path(directory)
            (root / "target").touch()
            os.symlink(root / "target", root / "link")
            return (root / "link").is_symlink()
    except OSError:
        return False


NATIVE_SYMLINKS = native_symlinks_available()


SETUP = r'''
if command -v cygpath >/dev/null 2>&1; then TASK_FIXTURE_ROOT=$(cygpath -u "$TASK_FIXTURE_ROOT"); fi
INSTALL_ROOT="$TASK_FIXTURE_ROOT/etc/xboard-node"
BACKUP_DIR="$INSTALL_ROOT/backups"
INSTALL_META="$INSTALL_ROOT/install-meta.json"
CONFIG_FILE="$INSTALL_ROOT/config.yml"
CREDENTIALS_FILE="$INSTALL_ROOT/credentials.env"
BINARY_PATH="$TASK_FIXTURE_ROOT/bin/xboard-node"
CLI_PATH="$TASK_FIXTURE_ROOT/bin/xbctl"
CLI_LINK_PATH="$TASK_FIXTURE_ROOT/usrbin/xbctl"
NODE_COMMAND_PATH="$TASK_FIXTURE_ROOT/bin/node"
SERVICE_PATH="$TASK_FIXTURE_ROOT/systemd/$SERVICE_NAME"
INSTALLER_COPY_PATH="$INSTALL_ROOT/install.sh"
TMPDIR="$TASK_FIXTURE_ROOT/tmp"
export TMPDIR
TASK_TRACE="$TASK_FIXTURE_ROOT/trace"
TASK_ACTIVE="$TASK_FIXTURE_ROOT/active"
TASK_ENABLED="$TASK_FIXTURE_ROOT/enabled"
mkdir -p "$INSTALL_ROOT" "$BACKUP_DIR" "${BINARY_PATH%/*}" "${CLI_LINK_PATH%/*}" "${SERVICE_PATH%/*}" "$TMPDIR"
printf 'collector-do-not-delete\n' > "$INSTALL_ROOT/collector-sentinel"
mkdir -p "$TASK_FIXTURE_ROOT/external-cert"
printf 'certificate-do-not-delete\n' > "$TASK_FIXTURE_ROOT/external-cert/key.pem"
trace() { printf '%s\n' "$*" >> "$TASK_TRACE"; }
# Git Bash otherwise silently copies rather than creating links. Without native
# Windows symlink permission, simulate ONLY link creation; real link-security
# checks are a separately skipped test, not a claimed filesystem verification.
if [ "$TASK_NATIVE_SYMLINKS" != 1 ]; then
    ln() { trace "simulated-link $*"; }
fi
check_root() { :; }
ensure_systemd() { :; }
acquire_install_lock() { trace lock; }
detect_arch() { ARCH=amd64; }
detect_os() { OS=fixture; }
install_dependencies() { trace dependencies; }
show_recent_logs() { :; }
systemctl() {
    trace "systemctl $*"
    case "$1" in
        show) printf '%s\n' "${TASK_KILL_MODE-control-group}" ;;
        is-active) [ -f "$TASK_ACTIVE" ] ;;
        is-enabled) [ -f "$TASK_ENABLED" ] ;;
        stop)
            if [ "${TASK_STOP_BEHAVIOR:-}" = fail ]; then return 13; fi
            if [ "${TASK_STOP_BEHAVIOR:-}" != sticky ]; then rm -f "$TASK_ACTIVE"; fi
            ;;
        start|restart)
            if [ "${TASK_START_FAILURE:-0}" = 1 ] && [ ! -f "$TASK_FIXTURE_ROOT/start-failed" ]; then
                touch "$TASK_FIXTURE_ROOT/start-failed"
                return 17
            fi
            touch "$TASK_ACTIVE"
            if [ "${TASK_CREATE_NEW_INSTANCE:-0}" = 1 ]; then
                mkdir -p "$INSTALL_ROOT/instances/new-target"
                printf 'new generated kernel\n' > "$INSTALL_ROOT/instances/new-target/config.json"
            fi
            ;;
        enable) touch "$TASK_ENABLED" ;;
        disable)
            if [ "${TASK_STRICT_DISABLE:-0}" = 1 ] && [ ! -f "$SERVICE_PATH" ]; then return 25; fi
            rm -f "$TASK_ENABLED"
            ;;
        daemon-reload|reset-failed) : ;;
        *) printf 'Unexpected systemctl action: %s\n' "$*" >&2; return 90 ;;
    esac
}
wait_for_health() {
    trace health
    if [ "${TASK_HEALTH_FAIL_ONCE:-0}" = 1 ] && [ ! -f "$TASK_FIXTURE_ROOT/health-failed" ]; then
        touch "$TASK_FIXTURE_ROOT/health-failed"
        return 19
    fi
    [ -f "$TASK_ACTIVE" ]
}
curl() { printf 'Unexpected network in isolated fixture\n' >&2; return 92; }
seed_old() {
    cat > "$CONFIG_FILE" <<'OLD_CONFIG'
instances:
  - instance_id: old-machine-one
    health_port: 65530
    panel:
      url: https://old.example.com
    machine:
      machine_id: 1
      token_env: OLD_MACHINE_ONE
  - instance_id: old-machine-two
    health_port: 65530
    panel:
      url: https://old.example.com
    machine:
      machine_id: 2
      token_env: OLD_MACHINE_TWO
OLD_CONFIG
    printf 'OLD_MACHINE_ONE=old-secret-one\nOLD_MACHINE_TWO=old-secret-two\n' > "$CREDENTIALS_FILE"
    printf '{"instance_count":2,"version":"old"}\n' > "$INSTALL_META"
    printf '#!/usr/bin/env bash\necho old-binary\n' > "$BINARY_PATH"
    printf '#!/usr/bin/env bash\necho 65530\n' > "$CLI_PATH"
    chmod +x "$BINARY_PATH" "$CLI_PATH"
    printf 'old systemd unit\n' > "$SERVICE_PATH"
    printf '#!/usr/bin/env bash\n# old maintained installer\n' > "$INSTALLER_COPY_PATH"
    printf '#!/usr/bin/env bash\n# XBOARD_NODE_MENU_V1\n# old wrapper\n' > "$NODE_COMMAND_PATH"
    chmod +x "$NODE_COMMAND_PATH"
    ln -sf "$CLI_PATH" "$CLI_LINK_PATH"
    mkdir -p "$INSTALL_ROOT/instances/old-machine-one" "$INSTALL_ROOT/instances/old-machine-two"
    printf 'old kernel one\n' > "$INSTALL_ROOT/instances/old-machine-one/config.json"
    printf 'old kernel two\n' > "$INSTALL_ROOT/instances/old-machine-two/config.json"
    touch "$TASK_ACTIVE" "$TASK_ENABLED"
}
stage_binary() {
    trace stage-binary
    if [ "${TASK_DOWNLOAD_FAILURE:-0}" = 1 ]; then return 21; fi
    printf '#!/usr/bin/env bash\necho new-binary\n' > "$TMP_DIR/xboard-node"
    chmod +x "$TMP_DIR/xboard-node"
}
stage_xbctl() {
    trace stage-cli
    cat > "$TMP_DIR/xbctl" <<'FIXTURE_CLI'
#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = config ] && [ "$2" = health-port ]; then echo 65530; exit 0; fi
if [ "$1" = version ]; then echo new-cli; exit 0; fi
shift 2
out= envout= meta= mode= node= machine= panel= token= health=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --config|--credentials-in) echo UNEXPECTED_OLD_MERGE >&2; exit 93 ;;
        --output) out="$2" ;;
        --credentials-out) envout="$2" ;;
        --meta) meta="$2" ;;
        --mode) mode="$2" ;;
        --node-id) node="$2" ;;
        --machine-id) machine="$2" ;;
        --panel-url) panel="$2" ;;
        --token) token="$2" ;;
        --health-port) health="$2" ;;
    esac
    shift 2
done
printf 'instances:\n  - instance_id: new-target\n    panel:\n      url: %s\n      node_id: %s\n    machine_id: %s\n    health_port: %s\n' "$panel" "${node:-0}" "${machine:-0}" "$health" > "$out"
printf 'NEW_FIXTURE_TOKEN=%s\n' "$token" > "$envout"
printf '{"instance_count":1,"mode":"%s"}\n' "$mode" > "$meta"
printf 'INSTANCE_ID=new-target\n'
FIXTURE_CLI
    chmod +x "$TMP_DIR/xbctl"
}
# Staging uses the real installer function, including Bash syntax validation and
# management wrapper generation. Every output path is already inside the fixture.
'''


class ReplacementTests(unittest.TestCase):
    def run_fixture(self, code, data="", env=None):
        task_env = dict(os.environ)
        for key in ("XBOARD_NODE_RELEASE_VERSION", "XBOARD_NODE_DOWNLOAD_BASE", "XBOARD_NODE_ASSET_BASE"):
            task_env.pop(key, None)
        task_env.update(env or {})
        task_env["TASK_NATIVE_SYMLINKS"] = str(int(NATIVE_SYMLINKS))
        if os.name == "nt" and NATIVE_SYMLINKS:
            task_env["MSYS"] = task_env.get("MSYS", "") + " winsymlinks:nativestrict"
        with tempfile.TemporaryDirectory(prefix="node-replacement-") as directory:
            root = Path(directory)
            task_env["TASK_FIXTURE_ROOT"] = root.as_posix()
            script = root / "fixture.sh"
            script.write_text(harness.FUNCTIONS + SETUP + "\n" + code, encoding="utf-8", newline="\n")
            result = subprocess.run([harness.BASH, "--noprofile", "--norc", script.as_posix()],
                                    input=data.encode(), capture_output=True, env=task_env, timeout=20,
                                    start_new_session=os.name != "nt")
            # Snapshot while the temporary directory is still alive; never follow
            # symbolic links out of the fixture when reading its outputs.
            files = {str(path.relative_to(root)).replace("\\", "/"): path.read_bytes()
                     for path in root.rglob("*") if path.is_file() and not path.is_symlink()}
            links = {str(path.relative_to(root)).replace("\\", "/"): os.readlink(path)
                     for path in root.rglob("*") if path.is_symlink()}
            return result, files, links

    def ok(self, code, data="", env=None):
        result, files, links = self.run_fixture(code, data, env)
        self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())
        return result.stdout.decode() + result.stderr.decode(), files, links

    def backups(self, files):
        return sorted({name.split("/")[3] for name in files
                       if name.startswith("etc/xboard-node/backups/recovery-")})

    def assert_sentinels(self, files):
        self.assertEqual(files["etc/xboard-node/collector-sentinel"], b"collector-do-not-delete\n")
        self.assertEqual(files["external-cert/key.pem"], b"certificate-do-not-delete\n")

    def assert_old_restored(self, files, active=True):
        self.assertIn(b"old-machine-one", files["etc/xboard-node/config.yml"])
        self.assertEqual(files["etc/xboard-node/credentials.env"],
                         b"OLD_MACHINE_ONE=old-secret-one\nOLD_MACHINE_TWO=old-secret-two\n")
        self.assertEqual(files["etc/xboard-node/install-meta.json"], b'{"instance_count":2,"version":"old"}\n')
        self.assertIn(b"old-binary", files["bin/xboard-node"])
        self.assertIn(b"echo 65530", files["bin/xbctl"])
        self.assertEqual(files["systemd/xboard-node.service"], b"old systemd unit\n")
        self.assertIn(b"old maintained installer", files["etc/xboard-node/install.sh"])
        self.assertIn(b"old wrapper", files["bin/node"])
        self.assertEqual(files["etc/xboard-node/instances/old-machine-one/config.json"], b"old kernel one\n")
        self.assertEqual(files["etc/xboard-node/instances/old-machine-two/config.json"], b"old kernel two\n")
        if active:
            self.assertIn("active", files)
        else:
            self.assertNotIn("active", files)
        self.assert_sentinels(files)

    def test_replace_all_old_bindings_and_archive_instance_files(self):
        for target in ("--node-id 11", "--machine-id 41"):
            with self.subTest(target=target):
                output, files, _ = self.ok("seed_old\nparse_args --yes --panel https://new.example.com --token new-fixture-token "
                                           + target + "\nperform_install\n")
                cfg = files["etc/xboard-node/config.yml"].decode()
                self.assertEqual(cfg.count("instance_id:"), 1)
                self.assertEqual(cfg.count("health_port: 65530"), 1)
                self.assertNotIn("old-machine", cfg)
                self.assertNotIn("old.example.com", cfg)
                self.assertEqual(files["etc/xboard-node/credentials.env"], b"NEW_FIXTURE_TOKEN=new-fixture-token\n")
                self.assertEqual(json.loads(files["etc/xboard-node/install-meta.json"])["instance_count"], 1)
                self.assertFalse(any(name.startswith("etc/xboard-node/instances/") for name in files))
                backup = self.backups(files)
                self.assertEqual(len(backup), 1)
                prefix = "etc/xboard-node/backups/" + backup[0] + "/"
                self.assertEqual(files[prefix + "instances/old-machine-one/config.json"], b"old kernel one\n")
                self.assertEqual(files[prefix + "instances/old-machine-two/config.json"], b"old kernel two\n")
                self.assertNotIn("new-fixture-token", output)
                self.assert_sentinels(files)
                trace = files["trace"].decode().splitlines()
                self.assertLess(trace.index("stage-cli"), trace.index("systemctl stop xboard-node.service"))
                self.assertLess(trace.index("systemctl stop xboard-node.service"), trace.index("systemctl restart xboard-node.service"))
                self.assertIn(b"KillMode=control-group\n", files["systemd/xboard-node.service"])
                self.assertIn(b"TimeoutStopSec=30\n", files["systemd/xboard-node.service"])
                self.assertIn(b"# XBOARD_NODE_MENU_V1\n", files["bin/node"])
                self.assertIn(b"/etc/xboard-node/install.sh manage", files["bin/node"])

    def test_stop_failure_or_still_active_never_replaces_files(self):
        for behavior in ("fail", "sticky"):
            with self.subTest(behavior=behavior):
                result, files, _ = self.run_fixture("seed_old\nparse_args --yes --panel https://new.example.com --token new-fixture-token --machine-id 41\nperform_install\n",
                                                     env={"TASK_STOP_BEHAVIOR": behavior})
                self.assertNotEqual(result.returncode, 0)
                self.assert_old_restored(files)
                self.assertNotIn("systemctl restart", files["trace"].decode())
                self.assertFalse(any("/backups/" in name and "/instances/" in name for name in files))

    def test_download_failure_does_not_stop_old_service(self):
        result, files, _ = self.run_fixture("seed_old\nparse_args --yes --panel https://new.example.com --token new-fixture-token --node-id 11\nperform_install\n",
                                             env={"TASK_DOWNLOAD_FAILURE": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assert_old_restored(files)
        self.assertNotIn("systemctl stop", files["trace"].decode())
        self.assertEqual(self.backups(files), [])

    def test_unsafe_service_kill_modes_refuse_replacement(self):
        for mode in ("process", "none", "", "unexpected"):
            with self.subTest(mode=mode):
                result, files, _ = self.run_fixture("seed_old\nparse_args --yes --panel https://new.example.com --token new-fixture-token --machine-id 41\nperform_install\n",
                                                     env={"TASK_KILL_MODE": mode})
                self.assertNotEqual(result.returncode, 0)
                self.assert_old_restored(files)
                self.assertNotIn("systemctl stop", files["trace"].decode())

    def test_restart_and_health_failures_restore_old_installation(self):
        for failure in ({"TASK_START_FAILURE": "1"}, {"TASK_HEALTH_FAIL_ONCE": "1"}):
            with self.subTest(failure=failure):
                result, files, _ = self.run_fixture("seed_old\ntrap 'on_error $LINENO' ERR\nparse_args --yes --panel https://new.example.com --token new-fixture-token --machine-id 41\nperform_install\n",
                                                     env={**failure, "TASK_CREATE_NEW_INSTANCE": "1"})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"Rollback complete", result.stdout)
                self.assert_old_restored(files)
                # A restored service can generate the fixture's new-target again;
                # the real rollback must archive failed generated files first.
                if "TASK_HEALTH_FAIL_ONCE" in failure:
                    self.assertTrue(any("/failed-instances/new-target/config.json" in name for name in files))

    def test_failed_replacement_restores_original_stopped_disabled_service(self):
        result, files, _ = self.run_fixture(r'''
seed_old
rm -f "$TASK_ACTIVE" "$TASK_ENABLED"
trap 'on_error $LINENO' ERR
parse_args --yes --panel https://new.example.com --token new-fixture-token --machine-id 41
perform_install
''', env={"TASK_HEALTH_FAIL_ONCE": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Rollback complete", result.stdout)
        self.assert_old_restored(files, active=False)
        self.assertNotIn("enabled", files)
        trace = files["trace"].decode().splitlines()
        self.assertEqual(trace.count("systemctl restart xboard-node.service"), 1)

    def test_failed_replacement_restores_original_active_disabled_service(self):
        result, files, _ = self.run_fixture(r'''
seed_old
rm -f "$TASK_ENABLED"
trap 'on_error $LINENO' ERR
parse_args --yes --panel https://new.example.com --token new-fixture-token --machine-id 41
perform_install
''', env={"TASK_HEALTH_FAIL_ONCE": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Rollback complete", result.stdout)
        self.assert_old_restored(files)
        self.assertNotIn("enabled", files)
        trace = files["trace"].decode().splitlines()
        self.assertEqual(trace.count("systemctl restart xboard-node.service"), 2)

    def test_partial_file_install_failure_restores_old_state(self):
        result, files, _ = self.run_fixture(r'''
seed_old
install() {
    if [ "${@: -1}" = "$CONFIG_FILE" ] && [ ! -f "$TASK_FIXTURE_ROOT/install-failed" ]; then
        touch "$TASK_FIXTURE_ROOT/install-failed"
        return 23
    fi
    command install "$@"
}
trap 'on_error $LINENO' ERR
parse_args --yes --panel https://new.example.com --token new-fixture-token --node-id 11
perform_install
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Rollback complete", result.stdout)
        self.assert_old_restored(files)

    def test_rollback_restore_failure_never_restarts_partial_configuration(self):
        result, files, _ = self.run_fixture(r'''
seed_old
backup_existing_state
stop_existing_service
archive_instance_files
printf 'partially replaced config\n' > "$CONFIG_FILE"
install() {
    if [ "${@: -1}" = "$CONFIG_FILE" ]; then return 24; fi
    command install "$@"
}
# An explicit conditional reproduces the on_error "rollback || true" context,
# where Bash disables implicit errexit inside the called function.
if rollback_install; then echo UNSAFE_ROLLBACK_SUCCEEDED; exit 96; fi
printf 'RESTORE_REFUSED\n'
''')
        self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())
        self.assertIn(b"RESTORE_REFUSED", result.stdout)
        self.assertNotIn("systemctl restart", files["trace"].decode())
        self.assertNotIn("active", files)
        self.assertIn(b"old-machine-one", next(content for name, content in files.items()
                                               if "/backups/" in name and name.endswith("/config.yml")))

    def test_fresh_failed_install_has_no_active_config_or_generated_instances(self):
        result, files, _ = self.run_fixture("trap 'on_error $LINENO' ERR\nparse_args --yes --panel https://new.example.com --token new-fixture-token --node-id 11\nperform_install\n",
                                             env={"TASK_HEALTH_FAIL_ONCE": "1", "TASK_CREATE_NEW_INSTANCE": "1", "TASK_STRICT_DISABLE": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Rollback complete", result.stdout)
        for name in ("etc/xboard-node/config.yml", "etc/xboard-node/credentials.env", "etc/xboard-node/install-meta.json", "bin/xboard-node", "bin/xbctl", "bin/node", "etc/xboard-node/install.sh", "systemd/xboard-node.service"):
            self.assertNotIn(name, files)
        self.assertFalse(any(name.startswith("etc/xboard-node/instances/") for name in files))
        self.assertTrue(any("/failed-instances/new-target/config.json" in name for name in files))
        self.assert_sentinels(files)

    def test_upgrade_preserves_existing_config_credentials_and_instances(self):
        _, files, _ = self.ok("seed_old\nparse_args upgrade\nperform_upgrade\n")
        self.assertIn(b"old-machine-one", files["etc/xboard-node/config.yml"])
        self.assertIn(b"old-machine-two", files["etc/xboard-node/config.yml"])
        self.assertEqual(files["etc/xboard-node/credentials.env"], b"OLD_MACHINE_ONE=old-secret-one\nOLD_MACHINE_TWO=old-secret-two\n")
        self.assertEqual(files["etc/xboard-node/instances/old-machine-one/config.json"], b"old kernel one\n")
        self.assertEqual(files["etc/xboard-node/instances/old-machine-two/config.json"], b"old kernel two\n")
        self.assertIn(b"new-binary", files["bin/xboard-node"])
        self.assertIn(b"management_menu()", files["etc/xboard-node/install.sh"])
        self.assert_sentinels(files)

    def test_uninstall_keeps_private_recovery_backup_and_external_data(self):
        _, files, links = self.ok("seed_old\nparse_args uninstall --yes --purge\nperform_uninstall\n")
        for name in ("etc/xboard-node/config.yml", "etc/xboard-node/credentials.env", "etc/xboard-node/install-meta.json", "bin/xboard-node", "bin/xbctl", "bin/node", "etc/xboard-node/install.sh", "systemd/xboard-node.service", "active"):
            self.assertNotIn(name, files)
        self.assertNotIn("usrbin/xbctl", links)
        self.assertFalse(any(name.startswith("etc/xboard-node/instances/") for name in files))
        backup = self.backups(files)
        self.assertEqual(len(backup), 1)
        prefix = "etc/xboard-node/backups/" + backup[0] + "/"
        self.assertIn(b"old-secret-one", files[prefix + "credentials.env"])
        self.assertEqual(files[prefix + "instances/old-machine-two/config.json"], b"old kernel two\n")
        self.assert_sentinels(files)

    def test_uninstall_stop_failure_does_not_delete_active_files(self):
        result, files, _ = self.run_fixture("seed_old\nparse_args uninstall --yes\nperform_uninstall\n",
                                             env={"TASK_STOP_BEHAVIOR": "fail"})
        self.assertNotEqual(result.returncode, 0)
        self.assert_old_restored(files)

    def test_uninstall_confirmation_is_exact_and_eof_safe(self):
        for data in ("yes\n", "uninstall\n", "\n", ""):
            with self.subTest(data=data):
                result, files, _ = self.run_fixture("seed_old\nperform_uninstall\necho UNREACHABLE\n", data)
                self.assertNotIn(b"UNREACHABLE", result.stdout)
                self.assert_old_restored(files)
                self.assertEqual(self.backups(files), [])
        _, files, _ = self.ok("seed_old\nperform_uninstall\n", "UNINSTALL\n")
        self.assertNotIn("etc/xboard-node/config.yml", files)

    def test_replacement_confirmation_is_exact_and_eof_safe(self):
        for data in ("yes\n", "replace\n", "", "\n"):
            with self.subTest(data=data):
                result, files, _ = self.run_fixture("seed_old\ndetect_current_state\nrequire_reconfigure_confirmation\necho UNREACHABLE\n", data)
                self.assertNotIn(b"UNREACHABLE", result.stdout)
                self.assert_old_restored(files)
                self.assertEqual(self.backups(files), [])

    def test_backup_names_are_unique_without_clock_dependence(self):
        output, files, _ = self.ok("seed_old\nbackup_existing_state\nfirst=\"$BACKUP_PATH\"\nbackup_existing_state\n[[ \"$first\" != \"$BACKUP_PATH\" ]]\nprintf 'UNIQUE\\n'\n")
        self.assertIn("UNIQUE", output)
        self.assertEqual(len(self.backups(files)), 2)

    def test_foreign_node_command_is_not_overwritten_or_uninstalled(self):
        for location in ("managed", "other-path"):
            with self.subTest(location=location):
                code = r'''
seed_old
printf 'foreign Node.js executable\n' > "$NODE_COMMAND_PATH"
command() {
    if [ "$1" = -v ] && [ "$2" = node ]; then
        if [ "$TASK_NODE_LOCATION" = other-path ]; then printf '%s\n' "$TASK_FIXTURE_ROOT/other/bin/node";
        else printf '%s\n' "$NODE_COMMAND_PATH"; fi
        return
    fi
    builtin command "$@"
}
if check_node_command; then echo UNSAFE_ALLOWED; exit 94; fi
parse_args uninstall --yes
perform_uninstall
'''
                _, files, _ = self.ok(code, env={"TASK_NODE_LOCATION": location})
                self.assertEqual(files["bin/node"], b"foreign Node.js executable\n")
                self.assert_sentinels(files)

    def test_owned_node_wrapper_is_allowed_and_other_path_shadow_is_rejected(self):
        self.ok(r'''
seed_old
command() {
    if [ "$1" = -v ] && [ "$2" = node ]; then printf '%s\n' "$NODE_COMMAND_PATH"; return; fi
    builtin command "$@"
}
check_node_command
''')
        result, _, _ = self.run_fixture(r'''
seed_old
command() {
    if [ "$1" = -v ] && [ "$2" = node ]; then printf '%s\n' "$TASK_FIXTURE_ROOT/other/bin/node"; return; fi
    builtin command "$@"
}
check_node_command
''')
        self.assertNotEqual(result.returncode, 0)

    @unittest.skipUnless(NATIVE_SYMLINKS, "Native symlinks unavailable; Git Bash ln otherwise copies files")
    def test_symlinked_managed_path_is_rejected_before_mutation(self):
        for target in ("CONFIG_FILE", "CREDENTIALS_FILE", "SERVICE_PATH", "INSTALLER_COPY_PATH", "BINARY_PATH", "CLI_PATH"):
            with self.subTest(target=target):
                result, files, _ = self.run_fixture("seed_old\nrm -f \"$" + target + "\"\nln -s \"$TASK_FIXTURE_ROOT/external-cert/key.pem\" \"$" + target + "\"\ncheck_owned_paths\n")
                self.assertNotEqual(result.returncode, 0)
                self.assert_sentinels(files)
                self.assertEqual(self.backups(files), [])

    def test_foreign_cli_link_regular_file_refuses_uninstall(self):
        result, files, _ = self.run_fixture(r'''
seed_old
printf 'foreign executable do not remove\n' > "$CLI_LINK_PATH"
parse_args uninstall --yes
perform_uninstall
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(files["usrbin/xbctl"], b"foreign executable do not remove\n")
        self.assert_old_restored(files)

    def test_no_terminal_without_yes_is_refused_before_mutation(self):
        result, files, _ = self.run_fixture("main --panel https://new.example.com --token hidden-fixture-token --machine-id 41\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"requires a Bash terminal", result.stdout)
        self.assertNotIn("etc/xboard-node/config.yml", files)
        self.assertNotIn("trace", files)

    def test_management_menu_mapping_and_invalid_input(self):
        for choice, action in (("1", "upgrade"), ("2", "restart"), ("3", "uninstall")):
            with self.subTest(choice=choice):
                output, _, _ = self.ok("management_menu\nprintf 'ACTION:%s\\n' \"$ACTION\"\n", choice + "\n")
                self.assertIn("ACTION:" + action, output)
        for data in ("9\n", "", "upgrade\n"):
            result, _, _ = self.run_fixture("management_menu\necho UNREACHABLE\n", data)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"UNREACHABLE", result.stdout)

    def test_panel_arguments_still_require_menu_and_yes_bypasses_it(self):
        for automatic in (False, True):
            with self.subTest(automatic=automatic):
                code = r'''
open_menu_terminal() { trace open-menu; MENU_FD=0; }
check_node_command() { :; }
perform_install() { validate_install_request; trace install-target; }
main --panel https://new.example.com --token hidden-fixture-token --machine-id 41
'''
                if automatic:
                    code = code.replace("--machine-id 41", "--machine-id 41 --yes")
                output, files, _ = self.ok(code, "1\n")
                self.assertEqual("open-menu" in files["trace"].decode(), not automatic)
                self.assertIn("install-target", files["trace"].decode())
                self.assertNotIn("hidden-fixture-token", output)

    def test_panel_menu_uninstall_needs_no_install_validation_or_dependencies(self):
        output, files, _ = self.ok(r'''
open_menu_terminal() { MENU_FD=0; }
perform_uninstall() { trace uninstall-selected; }
validate_install_request() { echo UNEXPECTED_VALIDATION; return 95; }
main --panel https://new.example.com --token hidden-fixture-token --machine-id 41
''', "2\n")
        self.assertIn("uninstall-selected", files["trace"].decode())
        self.assertNotIn("dependencies", files["trace"].decode())
        self.assertNotIn("UNEXPECTED_VALIDATION", output)

    def test_menu_read_uses_dedicated_descriptor_not_script_stdin(self):
        output, _, _ = self.ok(r'''
printf '2\n' > "$TASK_FIXTURE_ROOT/menu-input"
exec 3< "$TASK_FIXTURE_ROOT/menu-input"
MENU_FD=3
management_menu
read -r untouched
[[ "$ACTION" = restart && "$untouched" = SCRIPT_STDIN_SENTINEL ]]
printf 'DESCRIPTORS_SEPARATE\n'
''', "SCRIPT_STDIN_SENTINEL\n")
        self.assertIn("DESCRIPTORS_SEPARATE", output)

    def test_restart_only_uses_existing_service_without_download_or_dependencies(self):
        _, files, _ = self.ok("seed_old\nmain restart\n")
        trace = files["trace"].decode()
        self.assertIn("systemctl restart xboard-node.service", trace)
        self.assertNotIn("dependencies", trace)
        self.assertNotIn("stage-binary", trace)
        self.assert_old_restored(files)

    def test_menu_upgrade_download_failure_and_syntax_failure_do_not_execute(self):
        for curl_body in ("printf 'partial'; return 22", "return 0", "printf 'if then broken script'"):
            with self.subTest(curl_body=curl_body):
                result, files, _ = self.run_fixture("seed_old\ncurl() { " + curl_body + "; }\nupgrade_from_menu\n")
                self.assertNotEqual(result.returncode, 0)
                self.assert_old_restored(files)
                self.assertNotIn("systemctl restart", files.get("trace", b"").decode())

    def test_real_cli_fresh_generation_ignores_old_config_when_available(self):
        configured = os.environ.get("XBOARD_TEST_CLI")
        candidates = ([Path(configured)] if configured else []) + list((harness.ROOT / ".dependency-work").glob("*/xbctl.exe"))
        cli = next((candidate for candidate in candidates if candidate.is_file()), None)
        if cli is None:
            self.skipTest("Native xbctl unavailable; set XBOARD_TEST_CLI for real generator verification")
        _, files, _ = self.ok(r'''
seed_old
TMP_DIR=$(mktemp -d)
printf '#!/usr/bin/env bash\nexec "%s" "$@"\n' "$TASK_REAL_CLI" > "$TMP_DIR/xbctl"
chmod +x "$TMP_DIR/xbctl"
parse_args --yes --panel https://new.example.com --token new-fixture-token --machine-id 41
render_config
cp "$TMP_DIR/config.yml" "$TASK_FIXTURE_ROOT/actual-config.yml"
cp "$TMP_DIR/credentials.env" "$TASK_FIXTURE_ROOT/actual-credentials.env"
cp "$TMP_DIR/install-meta.json" "$TASK_FIXTURE_ROOT/actual-meta.json"
''', env={"TASK_REAL_CLI": cli.resolve().as_posix()})
        cfg = files["actual-config.yml"].decode()
        self.assertEqual(len(re.findall(r"(?m)^\s*-\s+id:", cfg)), 1)
        self.assertEqual(len(re.findall(r"health_port: 65530", cfg)), 1)
        self.assertNotIn("old-machine", cfg)
        self.assertNotIn("old.example.com", cfg)
        self.assertNotIn("OLD_MACHINE", files["actual-credentials.env"].decode())
        self.assertEqual(json.loads(files["actual-meta.json"])["instance_count"], 1)


if __name__ == "__main__":
    if not harness.BASH or not Path(harness.BASH).exists():
        raise SystemExit("Bash missing; set XBOARD_TEST_BASH to a verified Bash executable")
    unittest.main(verbosity=2)
