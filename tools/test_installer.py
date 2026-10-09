"""Safe Bash fixtures: no root, network, package manager or real service mutation."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "install.sh").read_text(encoding="utf-8")
assert SCRIPT.count('\nmain "$@"') == 1
FUNCTIONS = SCRIPT.rsplit('\nmain "$@"', 1)[0] + '\ntrap - ERR EXIT\n'
BASH = os.environ.get("XBOARD_TEST_BASH") or (
    "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash"))
COMMAND = re.search(r"^node_script=.*$", (ROOT / "README.md").read_text(encoding="utf-8"), re.M).group()


class InstallerTests(unittest.TestCase):
    def shell(self, code, data="", env=None):
        task_env = dict(os.environ)
        for key in ("XBOARD_NODE_RELEASE_VERSION", "XBOARD_NODE_DOWNLOAD_BASE", "XBOARD_NODE_ASSET_BASE"):
            task_env.pop(key, None)
        task_env.update(env or {})
        # A file avoids Git Bash's Windows command-line length limit; stdin remains
        # available for the real read builtins used by the interactive menu.
        with tempfile.TemporaryDirectory(prefix="node-bash-fixture-") as directory:
            fixture = Path(directory) / "fixture.sh"
            fixture.write_text(FUNCTIONS + code, encoding="utf-8", newline="\n")
            result = subprocess.run([BASH, "--noprofile", "--norc", fixture.as_posix()],
                                    input=data.encode("utf-8"), capture_output=True,
                                    env=task_env, timeout=15)
            return subprocess.CompletedProcess(result.args, result.returncode,
                                               result.stdout.decode("utf-8"), result.stderr.decode("utf-8"))

    def ok(self, code, data="", env=None):
        result = self.shell(code, data, env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def test_bash_syntax(self):
        result = subprocess.run([BASH, "-n"], input=SCRIPT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_node_menu_hides_token(self):
        output = self.ok('interactive_menu; parse_args; [[ "$TOKEN" == "fixture-token-only" ]]; '
                         'printf "RESULT:%s:%s:%s:%s\\n" "$ACTION" "$MODE" "$NODE_ID" "$KERNEL_TYPE"',
                         "1\n1\nhttps://panel.example.com\n11\nfixture-token-only\n\n")
        self.assertIn("RESULT:install:node:11:singbox", output)
        self.assertNotIn("fixture-token-only", output)

    def test_machine_menu_and_kernel(self):
        output = self.ok('interactive_menu; parse_args; validate_install_request; '
                         'printf "RESULT:%s:%s:%s\\n" "$MODE" "$MACHINE_ID" "$KERNEL_TYPE"',
                         "1\n2\nhttps://panel.example.com\n41\nfixture-token-only\nxray\n")
        self.assertIn("RESULT:machine:41:xray", output)
        self.assertNotIn("fixture-token-only", output)

    def test_management_menu_needs_no_credentials(self):
        for choice, action in (("1", "upgrade"), ("2", "restart"), ("3", "uninstall")):
            output = self.ok('management_menu; [[ -z "$TOKEN$PANEL_URL$NODE_ID$MACHINE_ID" ]]; '
                             'printf "ACTION:%s\\n" "$ACTION"', choice + "\n")
            self.assertIn("ACTION:" + action, output)

    def test_uninstall_menu_needs_no_credentials(self):
        output = self.ok('interactive_menu; printf "ACTION:%s\\n" "$ACTION"', "2\n")
        self.assertIn("ACTION:uninstall", output)

    def test_cancel(self):
        self.assertNotIn("UNREACHABLE", self.ok('interactive_menu; echo UNREACHABLE', "0\n"))

    def test_invalid_choice_mode_and_eof(self):
        for data in ("9\n", "1\n9\n", "", "1\n1\n"):
            self.assertNotEqual(self.shell('interactive_menu; echo UNREACHABLE', data).returncode, 0)

    def test_nonterminal_main_refuses_menu(self):
        result = self.shell("main")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires a Bash terminal", result.stdout)

    def test_yes_arguments_bypass_menu(self):
        output = self.ok('''
check_root() { :; }; detect_arch() { :; }; detect_os() { :; }
ensure_systemd() { :; }; install_dependencies() { :; }
check_owned_paths() { :; }; acquire_install_lock() { :; }; check_node_command() { :; }
interactive_menu() { echo UNEXPECTED_MENU; return 1; }
perform_install() { validate_install_request; printf 'TARGET:%s:%s\n' "$MODE" "$NODE_ID"; }
main --yes --panel https://panel.example.com --token fixture-token-only --node-id 11
''')
        self.assertIn("TARGET:node:11", output)
        self.assertNotIn("UNEXPECTED_MENU", output)
        self.assertNotIn("fixture-token-only", output)

    def test_panel_arguments_still_show_menu(self):
        output = self.ok('''
check_root() { :; }; detect_arch() { :; }; detect_os() { :; }
ensure_systemd() { :; }; install_dependencies() { :; }
check_owned_paths() { :; }; acquire_install_lock() { :; }; check_node_command() { :; }
open_menu_terminal() { echo MENU_OPENED; MENU_FD=0; }
perform_install() { validate_install_request; printf 'TARGET:%s:%s\n' "$MODE" "$MACHINE_ID"; }
main --mode machine --panel https://panel.example.com --token fixture-token-only --machine-id 41
''', "1\n")
        self.assertIn("MENU_OPENED", output)
        self.assertIn("1)", output)
        self.assertIn("TARGET:machine:41", output)
        self.assertNotIn("fixture-token-only", output)

    def test_menu_reads_separate_descriptor(self):
        output = self.ok('''
exec 3<<< '2'
MENU_FD=3
interactive_menu
IFS= read -r remaining
printf 'RESULT:%s:%s\n' "$ACTION" "$remaining"
''', "SCRIPT_STDIN_UNTOUCHED\n")
        self.assertIn("RESULT:uninstall:SCRIPT_STDIN_UNTOUCHED", output)

    def test_fixed_release_urls_and_override(self):
        for arch in ("amd64", "arm64"):
            output = self.ok(f'ARCH={arch}; resolve_download_url "xboard-node-linux-$ARCH"; echo "$DOWNLOAD_URL"')
            self.assertIn(f"/ksr-v/Xboard-Node--Custom-Source/releases/download/v1.13-orphan.4/xboard-node-linux-{arch}", output)
            self.assertNotIn("latest", output)
        output = self.ok('parse_args --version custom --download-base https://assets.example.com/releases; '
                         'resolve_download_url xbctl-linux-amd64; echo "$DOWNLOAD_URL"')
        self.assertIn("https://assets.example.com/releases/download/custom/xbctl-linux-amd64", output)

    def upgrade(self, port, args="", failure=False):
        with tempfile.TemporaryDirectory(prefix="node-installer-test-") as directory:
            config = Path(directory) / "fixture.yml"
            config.write_text(f"health_port: {port}\n", encoding="utf-8")
            code = '''
CONFIG_FILE="$TASK_FIXTURE_CONFIG"; CLI_PATH=/nonexistent-fixture-cli
detect_current_state() { CURRENT_STATE=installed; }
ensure_dirs() { :; }; stage_binary() { :; }; stage_xbctl() { :; }
stage_installer() { :; }; install_management_files() { :; }; stop_existing_service() { :; }
render_service() { :; }; backup_existing_state() { BACKUP_PATH=/nonexistent-fixture-backup; }
mktemp() { printf /nonexistent-fixture-stage; }
install() { :; }; ln() { :; }; systemctl() { :; }
show_recent_logs() { :; }
wait_for_health() { printf 'HEALTH:%s:%s\n' "$HEALTH_PORT" "$HEALTH_ENABLED"; }
'''
            if failure:
                code += '''
wait_for_health() { return 1; }
rollback_install() { echo FIXTURE_ROLLBACK; }
trap 'on_error $LINENO' ERR
'''
            return self.shell(code + f"parse_args upgrade {args}; perform_upgrade", env={"TASK_FIXTURE_CONFIG": config.as_posix()})

    def test_menu_ignores_ambient_old_binaries(self):
        with tempfile.TemporaryDirectory(prefix="node-old-binary-fixture-") as directory:
            for name in ("xboard-node", "xbctl"):
                (Path(directory) / name).write_text("old fixture", encoding="utf-8")
            result = self.shell('''
cd "$TASK_LOCAL_DIR"
ARCH=amd64; INTERACTIVE=1
[[ -z "$(select_binary_source)" ]]
BINARY_SOURCE=./xboard-node
[[ "$(select_binary_source)" == ./xboard-node ]]
TMP_DIR=/nonexistent-fixture-stage
curl() { printf 'DOWNLOAD:%s\n' "$*"; }
chmod() { :; }; cp() { echo UNEXPECTED_LOCAL_COPY; }
# No synthetic executable is created: validation must fail after choosing download.
stage_xbctl
''', env={"TASK_LOCAL_DIR": Path(directory).as_posix()})
            self.assertIn("DOWNLOAD:", result.stdout)
            self.assertIn("/download/v1.13-orphan.4/xbctl-linux-amd64", result.stdout)
            self.assertNotIn("UNEXPECTED_LOCAL_COPY", result.stdout)
            self.assertNotEqual(result.returncode, 0)

    def test_upgrade_preserves_default_custom_and_disabled_health(self):
        for port in (65530, 12345, 0):
            result = self.upgrade(port)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(f"HEALTH:{port}:{int(port != 0)}", result.stdout)

    def test_historical_cli_empty_or_unsupported_health_port(self):
        with tempfile.TemporaryDirectory(prefix="node-old-cli-health-") as directory:
            config = Path(directory) / "config.yml"
            cli = Path(directory) / "xbctl"
            config.write_text("health_port: 0\n", encoding="utf-8")
            for response in ("exit 0", "exit 1"):
                cli.write_text("#!/usr/bin/env bash\n" + response + "\n", encoding="utf-8", newline="\n")
                cli.chmod(0o755)
                output = self.ok('CONFIG_FILE="$TASK_CONFIG"; CLI_PATH="$TASK_CLI"; '
                                 'load_health_port_from_config "$CONFIG_FILE"; '
                                 'printf "HEALTH:%s:%s\\n" "$HEALTH_PORT" "$HEALTH_ENABLED"',
                                 env={"TASK_CONFIG": config.as_posix(), "TASK_CLI": cli.as_posix()})
                self.assertIn("HEALTH:0:0", output)

    def test_explicit_health_override_and_validation(self):
        for port in (0, 23456):
            result = self.upgrade(12345, f"--health-port {port}")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(f"HEALTH:{port}:{int(port != 0)}", result.stdout)
        for port in ("bad", "70000", "-1"):
            self.assertNotEqual(self.upgrade(12345, f"--health-port {port}").returncode, 0)

    def test_upgrade_failure_reaches_existing_rollback(self):
        result = self.upgrade(12345, failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FIXTURE_ROLLBACK", result.stdout)

    def test_partial_install_is_not_overwritten(self):
        result = self.shell('detect_current_state() { CURRENT_STATE=partial; }; '
                            'stage_binary() { echo UNEXPECTED_DOWNLOAD; }; perform_upgrade')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("UNEXPECTED_DOWNLOAD", result.stdout)

    def test_buffered_readme_command(self):
        for behavior, executed in (("printf 'fixture script'", True), ("printf 'partial'; return 22", False),
                                   ("return 22", False), ("return 0", False)):
            result = self.shell(f'curl() {{ {behavior}; }}\nsudo() {{ echo EXECUTED; }}\n' + COMMAND)
            self.assertEqual("EXECUTED" in result.stdout, executed)
            self.assertEqual(result.returncode == 0, executed)

    def test_distribution_copy_and_readme_command_match(self):
        project = ROOT.parents[1]
        mirror = project / "node-installer/install.sh"
        if not mirror.exists():
            self.skipTest("Independent distribution workspace not present")
        self.assertEqual(mirror.read_text(encoding="utf-8"), SCRIPT)
        self.assertNotIn(b"\r", mirror.read_bytes())
        self.assertIn(COMMAND, (project / "README.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    if not BASH or not Path(BASH).exists():
        raise SystemExit("Bash missing; set XBOARD_TEST_BASH to a verified Bash executable")
    unittest.main(verbosity=2)
