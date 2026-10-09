#!/usr/bin/env bash
set -Eeuo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

APP_NAME="xboard-node"
INSTALL_ROOT="/etc/xboard-node"
BACKUP_DIR="${INSTALL_ROOT}/backups"
INSTALL_META="${INSTALL_ROOT}/install-meta.json"
CONFIG_FILE="${INSTALL_ROOT}/config.yml"
CREDENTIALS_FILE="${INSTALL_ROOT}/credentials.env"
BINARY_PATH="/usr/local/bin/xboard-node"
SERVICE_NAME="xboard-node.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
CLI_PATH="/usr/local/bin/xbctl"
CLI_LINK_PATH="/usr/bin/xbctl"
INSTALLER_COPY_PATH="${INSTALL_ROOT}/install.sh"
NODE_COMMAND_PATH="/usr/local/bin/node"
MENU_FD=0
INSTANCES_ARCHIVED=0
CLI_BINARY_SOURCE=""
DEFAULT_HEALTH_PORT=65530
DEFAULT_KERNEL="singbox"
DEFAULT_MODE="node"
DEFAULT_ACTION="install"
DEFAULT_RELEASE_VERSION="${XBOARD_NODE_RELEASE_VERSION:-v1.13-orphan.2}"
DEFAULT_LOG_LEVEL="info"
DEFAULT_KERNEL_LOG_LEVEL="warn"
DEFAULT_DOWNLOAD_BASE="${XBOARD_NODE_DOWNLOAD_BASE:-https://github.com/ksr-v/Xboard-Node--Custom-Source/releases}"
DEFAULT_ASSET_BASE="${XBOARD_NODE_ASSET_BASE:-https://raw.githubusercontent.com/ksr-v/Xboard-Independent/main/node-installer}"

ACTION="${DEFAULT_ACTION}"
MODE=""
PANEL_URL=""
TOKEN=""
NODE_ID=""
NODE_TYPE=""
MACHINE_ID=""
KERNEL_TYPE="${DEFAULT_KERNEL}"
RELEASE_VERSION="${DEFAULT_RELEASE_VERSION}"
HEALTH_PORT="${DEFAULT_HEALTH_PORT}"
HEALTH_ENABLED=1
HEALTH_PORT_SET=0
INTERACTIVE=0
RUNTIME_GOMEMLIMIT=""
RUNTIME_GOGC=""
BINARY_SOURCE=""
CLI_BINARY_SOURCE=""
FORCE_RECONFIGURE=0
PURGE=0
YES=0
ARCH=""
OS=""
DOWNLOAD_URL=""
CURRENT_STATE="fresh"
TMP_DIR=""
BACKUP_PATH=""
SERVICE_EXISTED=0
SERVICE_WAS_ACTIVE=0
SERVICE_WAS_ENABLED=0
CLI_LINK_EXISTED=0
CLEANUP_DONE=0

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${CYAN}[STEP]${NC} ${BOLD}$1${NC}"; }

cleanup_tmp() {
    if [ "$CLEANUP_DONE" -eq 1 ]; then
        return
    fi
    CLEANUP_DONE=1
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

load_health_port_from_config() {
    local cfg_path="$1"
    if [ ! -f "$cfg_path" ]; then
        return
    fi
    local parsed=""
    if [ -x "$CLI_PATH" ]; then
        parsed=$("$CLI_PATH" config health-port --config "$cfg_path" 2>/dev/null) || parsed=""
    fi
    # Historical xbctl emits nothing for disabled/missing health_port or may
    # lack this subcommand. The standard block-YAML fallback must preserve 0.
    if [ -z "$parsed" ]; then
        parsed=$(awk '$1 == "health_port:" { print $2; found=1; exit } END { if (!found) print 0 }' "$cfg_path") || return 1
    fi
    if ! [[ "$parsed" =~ ^[0-9]+$ ]] || [ "$parsed" -gt 65535 ]; then
        log_error 'Cannot determine a valid existing health port; no files changed'
        return 1
    fi
    HEALTH_PORT="$parsed"
    HEALTH_ENABLED=1
    if [ "$HEALTH_PORT" -eq 0 ]; then HEALTH_ENABLED=0; fi
}

restore_backup_file() {
    if [ -f "$BACKUP_PATH/$1" ]; then
        install -m "$3" "$BACKUP_PATH/$1" "$2"
    else
        rm -f "$2"
    fi
}

restore_backup_state() {
    # Every operation is checked explicitly: this function runs in an ERR handler
    # and must not depend on errexit (disabled by the caller's || error handling).
    restore_backup_file xboard-node "$BINARY_PATH" 755 || return 1
    restore_backup_file config.yml "$CONFIG_FILE" 600 || return 1
    restore_backup_file credentials.env "$CREDENTIALS_FILE" 600 || return 1
    restore_backup_file install-meta.json "$INSTALL_META" 644 || return 1
    restore_backup_file xbctl "$CLI_PATH" 755 || return 1
    restore_backup_file "$SERVICE_NAME" "$SERVICE_PATH" 644 || return 1
    if [ "$INSTANCES_ARCHIVED" -eq 1 ]; then
        if [ -e "$INSTALL_ROOT/instances" ]; then
            mv -- "$INSTALL_ROOT/instances" "$BACKUP_PATH/failed-instances" || return 1
        fi
        if [ -d "$BACKUP_PATH/instances" ]; then
            mv -- "$BACKUP_PATH/instances" "$INSTALL_ROOT/instances" || return 1
        fi
        INSTANCES_ARCHIVED=0
    fi
    restore_backup_file install.sh "$INSTALLER_COPY_PATH" 700 || return 1
    if [ -f "$BACKUP_PATH/node-menu" ]; then
        install -m 755 "$BACKUP_PATH/node-menu" "$NODE_COMMAND_PATH" || return 1
    elif owned_node_command; then
        rm -f "$NODE_COMMAND_PATH" || return 1
    fi
    if [ "$CLI_LINK_EXISTED" -eq 1 ]; then
        ln -sf "$CLI_PATH" "$CLI_LINK_PATH" || return 1
    elif owned_cli_link; then
        rm -f "$CLI_LINK_PATH" || return 1
    fi
    return 0
}

rollback_install() {
    log_warn "Rolling back installation"
    if ! stop_existing_service; then
        log_error "Rollback could not stop Node; recovery files remain in ${BACKUP_PATH}"
        return 1
    fi
    # Disable a newly enabled unit while its file still exists; after restoring
    # a fresh (no-unit) state, systemctl disable may no longer find the unit.
    if [ "$SERVICE_WAS_ENABLED" -eq 0 ] && [ -f "$SERVICE_PATH" ]; then
        if ! systemctl disable "$SERVICE_NAME" >/dev/null 2>&1; then
            log_error "Rollback could not disable the replacement unit; inspect ${BACKUP_PATH}"
            return 1
        fi
    fi
    if [ -z "$BACKUP_PATH" ] || [ ! -d "$BACKUP_PATH" ] || ! restore_backup_state; then
        log_error "Rollback restore failed; Node remains stopped. Recover manually from ${BACKUP_PATH}"
        return 1
    fi
    if ! systemctl daemon-reload; then
        log_error "Rollback service reload failed; inspect ${BACKUP_PATH} before starting Node"
        return 1
    fi
    if [ "$SERVICE_EXISTED" -eq 1 ] || [ -f "$SERVICE_PATH" ]; then
        local enable_action=disable
        if [ "$SERVICE_WAS_ENABLED" -eq 1 ]; then enable_action=enable; fi
        if ! systemctl "$enable_action" "$SERVICE_NAME" >/dev/null 2>&1; then
            log_error "Old files restored but service enablement could not be restored; inspect ${BACKUP_PATH}"
            return 1
        fi
        if [ "$SERVICE_WAS_ACTIVE" -eq 1 ]; then
            if ! load_health_port_from_config "$CONFIG_FILE"; then
                log_error 'Old files restored but health settings require manual inspection; Node remains stopped'
                return 1
            fi
            systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1 || true
            if ! systemctl restart "$SERVICE_NAME" || ! wait_for_health; then
                log_error "Old files restored but restored service did not become healthy; inspect ${BACKUP_PATH}"
                show_recent_logs
                return 1
            fi
        fi
    fi
    log_warn "Rollback complete"
}

on_error() {
    local exit_code=$?
    local line_no=${1:-unknown}
    if [ "$exit_code" -ne 0 ]; then
        log_error "Install failed at line ${line_no} (exit=${exit_code})"
        if [ -n "$BACKUP_PATH" ]; then
            rollback_install || true
        fi
    fi
    cleanup_tmp
    exit "$exit_code"
}
trap 'on_error $LINENO' ERR
trap cleanup_tmp EXIT

usage() {
    cat <<'HELP'

  xboard-node Installer

  ACTIONS:
    install      Install or replace ALL existing local bindings (default)
    upgrade      Upgrade binary and restart service
    uninstall    Disconnect/remove Node; retain private recovery backup
    manage       node menu: upgrade / restart / uninstall
    restart      Restart this Node service only
    status       Show current installation status
    help         Show this help

  MODES (auto-detected from --node-id or --machine-id if omitted):
    --mode node      Panel single-node mode (default)
    --mode machine   Panel machine mode

  REQUIRED FOR NODE MODE:
    --panel, -a      Panel URL
    --token, -t      Panel server token
    --node-id, -n    Node ID

  REQUIRED FOR MACHINE MODE:
    --panel, -a       Panel URL
    --token, -t       Machine token
    --machine-id      Machine ID

  OPTIONAL:
    --node-type, -T     Explicit node type for node mode
    --kernel, -k        singbox or xray (default: singbox)
    --version           Fixed release version (default: v1.13-orphan.2)
    --download-base     Release-layout base (default: ksr-v/Xboard-Node--Custom-Source/releases)
    --binary            Use a local xboard-node binary path instead of downloading
    --xbctl-binary      Use a local xbctl binary path instead of downloading
    --health-port       Local health port (default: 65530, use 0 to disable)
    --gomemlimit        Runtime GOMEMLIMIT value, e.g. 256MiB
    --gogc              Runtime GOGC value, e.g. 50
    --force-reconfigure Overwrite an existing install even if mode/target changed
    --purge             Deprecated: recovery backups are retained for manual review
    --yes, -y           Non-interactive confirmation for destructive operations

  EXAMPLES:
    sudo bash install.sh            # interactive install / uninstall menu
    sudo bash install.sh --panel https://panel.example.com --token TOKEN --node-id 1
    sudo bash install.sh --panel https://panel.example.com --token TOKEN --machine-id 1
    sudo bash install.sh upgrade
    sudo bash install.sh uninstall --purge --yes

HELP
}

interactive_menu() {
    local choice target
    printf '\nXboard-Node %s\n1) 安装（替换本机全部旧对接）\n2) 卸载\n0) 退出\n' "$RELEASE_VERSION"
    menu_read -r -p '请选择 [0-2]: ' choice
    case "$choice" in
        0) exit 0 ;;
        2) ACTION=uninstall; return ;;
        1) ACTION=install ;;
        *) log_error '无效选项，未执行操作'; return 1 ;;
    esac
    # Panel-generated commands already contain their target/credential.
    if [ -n "$PANEL_URL" ] && [ -n "$TOKEN" ] && { [ -n "$MACHINE_ID" ] || [ -n "$NODE_ID" ]; }; then
        return
    fi
    menu_read -r -p '对接模式：1) node  2) machine [默认 1]: ' target
    case "${target:-1}" in
        1) MODE=node ;;
        2) MODE=machine ;;
        *) log_error '无效对接模式'; return 1 ;;
    esac
    menu_read -r -p '面板地址（例如 https://panel.example.com）: ' PANEL_URL
    if [ "$MODE" = machine ]; then
        menu_read -r -p 'Machine ID: ' MACHINE_ID
    else
        menu_read -r -p 'Node ID: ' NODE_ID
    fi
    menu_read -r -s -p 'Token（输入不回显）: ' TOKEN
    printf '\n'
    menu_read -r -p '内核 singbox / xray [默认 singbox]: ' KERNEL_TYPE
    KERNEL_TYPE="${KERNEL_TYPE:-singbox}"
}

menu_read() { read "$@" <&"$MENU_FD"; }

open_menu_terminal() {
    # bash -s may be reading a downloaded script on stdin. Never consume that stream.
    if ! { exec 3<>/dev/tty; } 2>/dev/null; then
        log_error 'Interactive menu requires a Bash terminal; automation must use --yes with explicit arguments'
        return 1
    fi
    MENU_FD=3
}

management_menu() {
    local choice
    printf '\nnode 管理\n1) 升级（保留当前绑定）\n2) 重启节点\n3) 卸载\n0) 退出\n'
    menu_read -r -p '请选择 [0-3]: ' choice
    case "$choice" in
        0) exit 0 ;;
        1) ACTION=upgrade ;;
        2) ACTION=restart ;;
        3) ACTION=uninstall ;;
        *) log_error '无效选项，未执行操作'; return 1 ;;
    esac
}

owned_node_command() {
    [ -f "$NODE_COMMAND_PATH" ] && [ ! -L "$NODE_COMMAND_PATH" ] &&
        grep -Fqx '# XBOARD_NODE_MENU_V1' "$NODE_COMMAND_PATH"
}

check_node_command() {
    local existing
    existing=$(command -v node || true)
    if { [ -n "$existing" ] && [ "$existing" != "$NODE_COMMAND_PATH" ]; } ||
       { { [ -e "$NODE_COMMAND_PATH" ] || [ -L "$NODE_COMMAND_PATH" ]; } && ! owned_node_command; }; then
        log_error 'node already belongs to another program (possibly Node.js); refusing to overwrite/shadow it'
        return 1
    fi
}

owned_cli_link() {
    [ -L "$CLI_LINK_PATH" ] && [ "$(readlink "$CLI_LINK_PATH")" = "$CLI_PATH" ]
}

check_owned_paths() {
    local path
    for path in "$INSTALL_ROOT" "$BACKUP_DIR" "$INSTALL_ROOT/instances" "$CONFIG_FILE" "$CREDENTIALS_FILE" "$INSTALL_META" "$INSTALLER_COPY_PATH" "$SERVICE_PATH" "$BINARY_PATH" "$CLI_PATH"; do
        if [ -L "$path" ]; then
            log_error 'Managed path is a symlink; inspect manually before replacing or uninstalling'
            return 1
        fi
    done
    for path in "$CONFIG_FILE" "$CREDENTIALS_FILE" "$INSTALL_META" "$INSTALLER_COPY_PATH" "$SERVICE_PATH" "$BINARY_PATH" "$CLI_PATH"; do
        if [ -e "$path" ] && [ ! -f "$path" ]; then
            log_error 'Managed file is not a regular file; inspect manually before continuing'
            return 1
        fi
    done
    if { [ -e "$CLI_LINK_PATH" ] || [ -L "$CLI_LINK_PATH" ]; } && ! owned_cli_link; then
        log_error 'xbctl command link belongs to another program; refusing to replace/remove it'
        return 1
    fi
    if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$INSTALL_ROOT/instances"; then
        log_error 'Instance directory is a mount point; refusing to move it'
        return 1
    fi
}

acquire_install_lock() {
    command -v flock >/dev/null 2>&1 || { log_error 'flock is required for safe installation'; return 1; }
    exec 9>/run/lock/xboard-node-installer.lock
    flock -n 9 || { log_error 'Another Node installer/manager is running'; return 1; }
}

stage_installer() {
    if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
        cp -- "${BASH_SOURCE[0]}" "$TMP_DIR/install.sh"
    elif [ -n "${BASH_EXECUTION_STRING:-}" ]; then
        printf '%s\n' "$BASH_EXECUTION_STRING" > "$TMP_DIR/install.sh"
    else
        curl -fsSL --max-time 30 --max-filesize 65536 "${DEFAULT_ASSET_BASE%/}/install.sh" -o "$TMP_DIR/install.sh"
    fi
    [ -s "$TMP_DIR/install.sh" ]
    bash -n "$TMP_DIR/install.sh"
    grep -q '^management_menu()' "$TMP_DIR/install.sh"
    cat > "$TMP_DIR/node-menu" <<'NODE_MENU'
#!/usr/bin/env bash
# XBOARD_NODE_MENU_V1
if [ "$(id -u)" -ne 0 ]; then
    exec sudo /bin/bash /etc/xboard-node/install.sh manage
fi
exec /bin/bash /etc/xboard-node/install.sh manage
NODE_MENU
}

install_management_files() {
    install -m 700 "$TMP_DIR/install.sh" "$INSTALLER_COPY_PATH"
    install -m 755 "$TMP_DIR/node-menu" "$NODE_COMMAND_PATH"
}

upgrade_from_menu() {
    local script
    script=$(curl -fsSL --max-time 30 --max-filesize 65536 "${DEFAULT_ASSET_BASE%/}/install.sh")
    [ -n "$script" ]
    bash -n <<< "$script"
    # Run only a complete download; the new maintained script selects its pinned version.
    bash -c "$script" -- upgrade
}

parse_args() {
    local positional=()
    while [ $# -gt 0 ]; do
        case "$1" in
            install|upgrade|uninstall|status|help|manage|restart)
                ACTION="$1"
                shift
                ;;
            --mode)
                MODE="$2"
                shift 2
                ;;
            --panel|-a|--api)
                PANEL_URL="$2"
                shift 2
                ;;
            --token|-t)
                TOKEN="$2"
                shift 2
                ;;
            --node-id|-n)
                NODE_ID="$2"
                shift 2
                ;;
            --node-type|-T)
                NODE_TYPE="$2"
                shift 2
                ;;
            --machine-id)
                MACHINE_ID="$2"
                shift 2
                ;;
            --kernel|-k)
                KERNEL_TYPE="$2"
                shift 2
                ;;
            --version)
                RELEASE_VERSION="$2"
                shift 2
                ;;
            --download-base)
                DEFAULT_DOWNLOAD_BASE="${2%/}"
                shift 2
                ;;
            --binary)
                BINARY_SOURCE="$2"
                shift 2
                ;;
            --xbctl-binary)
                CLI_BINARY_SOURCE="$2"
                shift 2
                ;;
            --health-port)
                HEALTH_PORT="$2"
                HEALTH_PORT_SET=1
                shift 2
                ;;
            --gomemlimit)
                RUNTIME_GOMEMLIMIT="$2"
                shift 2
                ;;
            --gogc)
                RUNTIME_GOGC="$2"
                shift 2
                ;;
            --force-reconfigure)
                FORCE_RECONFIGURE=1
                shift
                ;;
            --purge)
                PURGE=1
                shift
                ;;
            --yes|-y)
                YES=1
                shift
                ;;
            --help|-h)
                ACTION="help"
                shift
                ;;
            *)
                positional+=("$1")
                shift
                ;;
        esac
    done

    if [ ${#positional[@]} -gt 0 ] && [ "$ACTION" = "install" ]; then
        ACTION="${positional[0]}"
    fi

    case "$KERNEL_TYPE" in
        singbox|SingBox|SINGBOX) KERNEL_TYPE="singbox" ;;
        xray|Xray|XRAY) KERNEL_TYPE="xray" ;;
        *) ;;
    esac

    # Auto-detect mode from arguments when --mode is not specified.
    if [ -z "$MODE" ]; then
        if [ -n "$MACHINE_ID" ]; then
            MODE="machine"
        else
            MODE="node"
        fi
    fi

    case "$MODE" in
        node|machine) ;;
        *)
            log_error "Unsupported mode: $MODE"
            usage
            exit 1
            ;;
    esac
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Please run as root or with sudo"
        exit 1
    fi
}

detect_arch() {
    local raw
    raw=$(uname -m)
    case "$raw" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)
            log_error "Unsupported architecture: $raw"
            exit 1
            ;;
    esac
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS="$ID"
    else
        OS="unknown"
    fi
}

ensure_systemd() {
    if ! command -v systemctl >/dev/null 2>&1; then
        log_error "systemd is required for this installer"
        exit 1
    fi
    if [ ! -d /run/systemd/system ]; then
        log_error "This host does not appear to be running systemd"
        exit 1
    fi
}

run_with_retry() {
    local attempts="$1"
    local delay="$2"
    shift 2
    local i=1
    while [ "$i" -le "$attempts" ]; do
        if "$@"; then
            return 0
        fi
        if [ "$i" -lt "$attempts" ]; then
            log_warn "Command failed, retrying in ${delay}s: $*"
            sleep "$delay"
        fi
        i=$((i + 1))
    done
    return 1
}

install_dependencies() {
    case "$OS" in
        ubuntu|debian)
            DEBIAN_FRONTEND=noninteractive run_with_retry 10 3 apt-get update -qq
            DEBIAN_FRONTEND=noninteractive run_with_retry 10 3 apt-get install -y -qq curl wget ca-certificates >/dev/null 2>&1
            ;;
        centos|rhel|rocky|almalinux|fedora)
            if command -v dnf >/dev/null 2>&1; then
                run_with_retry 5 3 dnf install -y -q curl wget ca-certificates >/dev/null 2>&1
            else
                run_with_retry 5 3 yum install -y -q curl wget ca-certificates >/dev/null 2>&1
            fi
            ;;
        *)
            log_warn "OS ${OS} is not in the official support set; continuing best-effort"
            ;;
    esac
}

ensure_dirs() {
    mkdir -p "$INSTALL_ROOT" "$BACKUP_DIR"
    chmod 700 "$INSTALL_ROOT"
}

validate_positive_int() {
    local label="$1"
    local value="$2"
    if ! [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" -le 0 ]; then
        log_error "${label} must be a positive integer, got: ${value}"
        exit 1
    fi
}

validate_install_request() {
    if [ -z "$PANEL_URL" ]; then
        log_error "Panel URL is required"
        exit 1
    fi
    if [ -z "$TOKEN" ]; then
        log_error "Token is required"
        exit 1
    fi
    if ! [[ "$HEALTH_PORT" =~ ^[0-9]+$ ]] || [ "$HEALTH_PORT" -gt 65535 ]; then
        log_error "health-port must be an integer from 0 to 65535"
        exit 1
    fi
    if [ "$HEALTH_PORT" -eq 0 ]; then
        HEALTH_ENABLED=0
    fi
    case "$KERNEL_TYPE" in
        singbox|xray) ;;
        *)
            log_error "Kernel must be singbox or xray"
            exit 1
            ;;
    esac
    case "$MODE" in
        node)
            validate_positive_int "Node ID" "$NODE_ID"
            ;;
        machine)
            validate_positive_int "Machine ID" "$MACHINE_ID"
            ;;
    esac
}

detect_current_state() {
    local has_binary=0 has_config=0 has_service=0
    [ -x "$BINARY_PATH" ] && has_binary=1
    [ -f "$CONFIG_FILE" ] && has_config=1
    [ -f "$SERVICE_PATH" ] && has_service=1

    if [ "$has_binary" -eq 1 ] && [ "$has_config" -eq 1 ] && [ "$has_service" -eq 1 ]; then
        CURRENT_STATE="installed"
    elif [ "$has_binary" -eq 1 ] || [ "$has_config" -eq 1 ] || [ "$has_service" -eq 1 ] ||
         [ -e "$CREDENTIALS_FILE" ] || [ -e "$INSTALL_META" ] || [ -e "$CLI_PATH" ] ||
         [ -e "$INSTALLER_COPY_PATH" ] || [ -e "$INSTALL_ROOT/instances" ] || owned_node_command ||
         systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
        CURRENT_STATE="partial"
    else
        CURRENT_STATE="fresh"
    fi
}

require_reconfigure_confirmation() {
    if [ "$CURRENT_STATE" = fresh ]; then return; fi
    log_warn 'Existing Node detected: installation REPLACES ALL local panel/machine/node bindings'
    log_info "Active config and instance files will be backed up under ${BACKUP_DIR}; panel/collector data is not deleted"
    if [ "$YES" -eq 1 ] || [ "$FORCE_RECONFIGURE" -eq 1 ]; then return; fi
    local answer
    menu_read -r -p '输入 REPLACE 确认替换全部旧对接（其他输入取消）: ' answer
    if [ "$answer" != REPLACE ]; then
        log_warn 'Replacement cancelled; existing installation unchanged'
        exit 0
    fi
}

select_binary_source() {
    if [ -n "$BINARY_SOURCE" ]; then
        if [ ! -f "$BINARY_SOURCE" ]; then
            log_error "Binary source not found: $BINARY_SOURCE"
            exit 1
        fi
        echo "$BINARY_SOURCE"
        return
    fi
    # Never accidentally reuse an old binary in the SSH cwd, including menu upgrades.
    # Offline/local sources must be explicitly selected with --binary.
    echo ""
}

resolve_download_url() {
    local artifact="$1"
    if [ -z "$DEFAULT_DOWNLOAD_BASE" ]; then
        DOWNLOAD_URL="${DEFAULT_ASSET_BASE%/}/${artifact}"
        return 0
    fi
    if [ "$RELEASE_VERSION" = "latest" ]; then
        DOWNLOAD_URL="${DEFAULT_DOWNLOAD_BASE}/latest/download/${artifact}"
    else
        DOWNLOAD_URL="${DEFAULT_DOWNLOAD_BASE}/download/${RELEASE_VERSION}/${artifact}"
    fi
}

stage_binary() {
    local staged="$TMP_DIR/xboard-node"
    local local_src
    local_src=$(select_binary_source)
    if [ -n "$local_src" ]; then
        log_step "Using local binary: ${local_src}"
        cp "$local_src" "$staged"
    else
        resolve_download_url "xboard-node-linux-${ARCH}"
        log_step "Downloading binary: ${DOWNLOAD_URL}"
        if ! curl -fsSL "$DOWNLOAD_URL" -o "$staged"; then
            log_error "Failed to download binary from ${DOWNLOAD_URL}"
            exit 1
        fi
    fi
    chmod +x "$staged"
    if ! "$staged" -v >/dev/null 2>&1; then
        log_error "Downloaded binary failed version check"
        exit 1
    fi
}

stage_xbctl() {
    local staged="$TMP_DIR/xbctl"
    local local_src=""
    if [ -n "$CLI_BINARY_SOURCE" ]; then
        if [ ! -f "$CLI_BINARY_SOURCE" ]; then
            log_error "xbctl binary source not found: $CLI_BINARY_SOURCE"
            exit 1
        fi
        local_src="$CLI_BINARY_SOURCE"
    fi
    if [ -n "$local_src" ]; then
        log_step "Using local xbctl binary: ${local_src}"
        cp "$local_src" "$staged"
    else
        resolve_download_url "xbctl-linux-${ARCH}"
        log_step "Downloading xbctl: ${DOWNLOAD_URL}"
        if ! curl -fsSL "$DOWNLOAD_URL" -o "$staged"; then
            log_error "Failed to download xbctl from ${DOWNLOAD_URL}"
            exit 1
        fi
    fi
    chmod +x "$staged"
    if ! "$staged" version > /dev/null 2>&1; then
        log_error "Downloaded xbctl failed version check"
        exit 1
    fi
}

render_config() {
    local init_args=(
        config init
        --mode "$MODE"
        --panel-url "$PANEL_URL"
        --kernel "${KERNEL_TYPE:-singbox}"
        --health-port "${HEALTH_PORT:-0}"
        --token "$TOKEN"
        --version "$RELEASE_VERSION"
        --output "$TMP_DIR/config.yml"
        --credentials-out "$TMP_DIR/credentials.env"
        --meta "$TMP_DIR/install-meta.json"
        --install-root "$INSTALL_ROOT"
    )
    # Replacement is intentionally fresh: never merge an old binding or credential.
    if [ "$MODE" = "machine" ]; then
        init_args+=(--machine-id "$MACHINE_ID")
    else
        init_args+=(--node-id "$NODE_ID")
        if [ -n "$NODE_TYPE" ]; then
            init_args+=(--node-type "$NODE_TYPE")
        fi
    fi
    if [ -n "$RUNTIME_GOMEMLIMIT" ]; then
        init_args+=(--gomemlimit "$RUNTIME_GOMEMLIMIT")
    fi
    if [ -n "$RUNTIME_GOGC" ] && [ "$RUNTIME_GOGC" -gt 0 ] 2>/dev/null; then
        init_args+=(--gogc "$RUNTIME_GOGC")
    fi

    local output
    output=$("$TMP_DIR/xbctl" "${init_args[@]}") || {
        log_error "xbctl config init failed"
        exit 1
    }

    INSTANCE_ID=$(echo "$output" | grep '^INSTANCE_ID=' | cut -d= -f2-)
    chmod 600 "$TMP_DIR/credentials.env"
}

render_service() {
    cat >"$TMP_DIR/${SERVICE_NAME}" <<EOF_UNIT
[Unit]
Description=Xboard Node Backend
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_ROOT}
EnvironmentFile=-${CREDENTIALS_FILE}
ExecStart=${BINARY_PATH} -c ${CONFIG_FILE}
Restart=always
RestartSec=5
KillMode=control-group
TimeoutStopSec=30
LimitNOFILE=1048576
NoNewPrivileges=true
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF_UNIT
}

backup_existing_state() {
    local pending
    pending=$(mktemp -d "${BACKUP_DIR}/recovery-XXXXXXXX")
    chmod 700 "$pending"
    if [ -x "$BINARY_PATH" ]; then
        cp "$BINARY_PATH" "$pending/xboard-node"
    fi
    if [ -x "$CLI_PATH" ]; then
        cp "$CLI_PATH" "$pending/xbctl"
    fi
    if [ -f "$CONFIG_FILE" ]; then
        cp "$CONFIG_FILE" "$pending/config.yml"
    fi
    if [ -f "$CREDENTIALS_FILE" ]; then
        cp "$CREDENTIALS_FILE" "$pending/credentials.env"
    fi
    if [ -f "$INSTALL_META" ]; then
        cp "$INSTALL_META" "$pending/install-meta.json"
    fi
    if [ -f "$SERVICE_PATH" ]; then
        cp "$SERVICE_PATH" "$pending/${SERVICE_NAME}"
        SERVICE_EXISTED=1
    else
        SERVICE_EXISTED=0
    fi
    if [ -f "$INSTALLER_COPY_PATH" ]; then cp "$INSTALLER_COPY_PATH" "$pending/install.sh"; fi
    if owned_node_command; then cp "$NODE_COMMAND_PATH" "$pending/node-menu"; fi
    SERVICE_WAS_ACTIVE=0
    SERVICE_WAS_ENABLED=0
    if systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then SERVICE_WAS_ACTIVE=1; fi
    if systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; then SERVICE_WAS_ENABLED=1; fi
    CLI_LINK_EXISTED=0
    if owned_cli_link; then CLI_LINK_EXISTED=1; fi
    # Only complete backups are eligible for automatic rollback.
    BACKUP_PATH="$pending"
    log_info "Recovery backup: ${BACKUP_PATH}"
}

stop_existing_service() {
    if [ -f "$SERVICE_PATH" ] || systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
        local kill_mode
        kill_mode=$(systemctl show --property=KillMode --value "$SERVICE_NAME")
        case "$kill_mode" in
            control-group|mixed) ;;
            *)
                log_error 'Old unit cannot guarantee kernel-process cleanup (KillMode must be control-group/mixed); inspect the custom service manually'
                return 1
                ;;
        esac
        if ! systemctl stop "$SERVICE_NAME"; then
            log_error 'Failed to stop old Node service; refusing to replace files'
            return 1
        fi
        if systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
            log_error 'Old Node service is still active; refusing to replace files'
            return 1
        fi
    fi
}

archive_instance_files() {
    if [ -d "$INSTALL_ROOT/instances" ]; then
        mv -- "$INSTALL_ROOT/instances" "$BACKUP_PATH/instances"
    fi
    INSTANCES_ARCHIVED=1
}

install_staged_files() {
    stop_existing_service
    archive_instance_files
    install -m 755 "$TMP_DIR/xboard-node" "$BINARY_PATH"
    install -m 600 "$TMP_DIR/config.yml" "$CONFIG_FILE"
    install -m 600 "$TMP_DIR/credentials.env" "$CREDENTIALS_FILE"
    install -m 644 "$TMP_DIR/install-meta.json" "$INSTALL_META"
    install_management_files
    install -m 755 "$TMP_DIR/xbctl" "$CLI_PATH"
    ln -sf "$CLI_PATH" "$CLI_LINK_PATH"
    install -m 644 "$TMP_DIR/${SERVICE_NAME}" "$SERVICE_PATH"
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" > /dev/null 2>&1
}

wait_for_health() {
    if ! systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
        return 1
    fi
    if [ "$HEALTH_ENABLED" -eq 0 ]; then
        return 0
    fi
    local attempt=0
    local max_attempts=30
    while [ "$attempt" -lt "$max_attempts" ]; do
        if ! systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
            return 1
        fi
        if curl -fsS --connect-timeout 1 --max-time 2 "http://127.0.0.1:${HEALTH_PORT}/healthz" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    return 1
}

show_recent_logs() {
    if command -v journalctl >/dev/null 2>&1; then
        journalctl -u "$SERVICE_NAME" -n 30 --no-pager || true
    fi
}

start_service() {
    if systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; then
        systemctl restart "$SERVICE_NAME"
    else
        systemctl start "$SERVICE_NAME"
    fi
    if ! wait_for_health; then
        log_error "Service failed health check"
        show_recent_logs
        return 1
    fi
}

perform_install() {
    validate_install_request
    detect_current_state
    require_reconfigure_confirmation
    if [ -x "$BINARY_PATH" ]; then
        log_info 'Existing Node detected; migrating to the current single-target configuration'
    fi
    install_dependencies
    TMP_DIR=$(mktemp -d)
    ensure_dirs
    stage_binary
    stage_xbctl
    render_config
    render_service
    stage_installer
    backup_existing_state
    install_staged_files
    start_service

    log_info "Installation succeeded"
    log_info "Service: ${SERVICE_NAME}"
    log_info "Config: ${CONFIG_FILE}"
    log_info "Credentials: ${CREDENTIALS_FILE}"
    if [ "$HEALTH_ENABLED" -eq 1 ]; then
        log_info "Health: http://127.0.0.1:${HEALTH_PORT}/healthz"
    fi
    log_info "CLI: ${CLI_PATH}  (run '${CLI_PATH} list' if xbctl is not in PATH)"
    log_info '管理命令：node（小写）；旧对接及其本地节点已退出，面板数据未删除'
}

perform_upgrade() {
    detect_current_state
    if [ "$CURRENT_STATE" = "fresh" ]; then
        log_warn "No existing install found; falling back to install"
        perform_install
        return
    fi
    if [ "$CURRENT_STATE" != installed ]; then
        log_error 'Incomplete/custom installation; inspect existing config/service before upgrading'
        return 1
    fi
    if [ "$HEALTH_PORT_SET" -eq 0 ]; then
        load_health_port_from_config "$CONFIG_FILE"
    fi
    if ! [[ "$HEALTH_PORT" =~ ^[0-9]+$ ]] || [ "$HEALTH_PORT" -gt 65535 ]; then
        log_error 'Invalid health port; no files changed'
        return 1
    fi
    HEALTH_ENABLED=1
    if [ "$HEALTH_PORT" -eq 0 ]; then HEALTH_ENABLED=0; fi
    install_dependencies
    TMP_DIR=$(mktemp -d)
    ensure_dirs
    stage_binary
    stage_xbctl
    render_service
    stage_installer
    backup_existing_state
    stop_existing_service
    install -m 755 "$TMP_DIR/xboard-node" "$BINARY_PATH"
    install -m 755 "$TMP_DIR/xbctl" "$CLI_PATH"
    ln -sf "$CLI_PATH" "$CLI_LINK_PATH"
    install -m 644 "$TMP_DIR/${SERVICE_NAME}" "$SERVICE_PATH"
    install_management_files
    systemctl daemon-reload
    systemctl restart "$SERVICE_NAME"
    if ! wait_for_health; then
        log_error "Upgrade health check failed"
        show_recent_logs
        return 1
    fi
    log_info "Upgrade succeeded"
}

confirm_uninstall() {
    if [ "$YES" -eq 1 ]; then
        return
    fi
    echo
    menu_read -r -p '将断开本机全部 Node 对接并卸载，保留恢复备份。输入 UNINSTALL 确认: ' answer
    if [ "$answer" != UNINSTALL ]; then
        log_warn "Uninstall cancelled"
        exit 0
    fi
}

perform_uninstall() {
    confirm_uninstall
    check_owned_paths
    ensure_dirs
    backup_existing_state
    stop_existing_service
    archive_instance_files
    if [ -f "$SERVICE_PATH" ]; then
        systemctl disable "$SERVICE_NAME"
        rm -f "$SERVICE_PATH"
        systemctl daemon-reload || true
    fi
    rm -f "$BINARY_PATH"
    rm -f "$CLI_PATH"
    if owned_cli_link; then rm -f "$CLI_LINK_PATH"; fi
    if owned_node_command; then rm -f "$NODE_COMMAND_PATH"; fi
    rm -f "$CONFIG_FILE" "$CREDENTIALS_FILE" "$INSTALL_META" "$INSTALLER_COPY_PATH"
    if [ "$PURGE" -eq 1 ]; then
        log_warn '--purge no longer automatically deletes recovery backups; erase them manually after verification'
    else
        log_info "Old local config/credentials/instances retained only in ${BACKUP_PATH}"
    fi
    log_info "Uninstall complete"
}

perform_status() {
    detect_current_state
    echo
    echo -e "${BOLD}xboard-node install status${NC}"
    echo "  state:   ${CURRENT_STATE}"
    if [ -f "$INSTALL_META" ]; then
        echo "  meta:    ${INSTALL_META}"
        if [ -x "$CLI_PATH" ]; then
            "$CLI_PATH" list 2>/dev/null || true
        else
            # Simple key extraction from JSON (no Python needed)
            local val
            for key in config_mode version latest_instance_id instance_count updated_at; do
                val=$(sed -n "s/.*\"${key}\": *\"\{0,1\}\([^\"]*\)\"\{0,1\}.*/\1/p" "$INSTALL_META" | head -1)
                val="${val%,}"  # strip trailing comma from numeric JSON values
                [ -n "$val" ] && echo "  ${key}: ${val}"
            done
        fi
    fi
    if [ -f "$SERVICE_PATH" ]; then
        echo "  service: ${SERVICE_NAME}"
        systemctl status "$SERVICE_NAME" --no-pager || true
    fi
}

main() {
    parse_args "$@"
    if [ "$ACTION" = install ] && [ "$YES" -eq 0 ]; then
        open_menu_terminal
        INTERACTIVE=1
        interactive_menu
    fi
    if [ "$ACTION" = manage ]; then
        open_menu_terminal
        management_menu
        if [ "$ACTION" = upgrade ]; then
            check_root
            upgrade_from_menu
            return
        fi
    fi
    if [ "$ACTION" = uninstall ] && [ "$YES" -eq 0 ] && [ "$MENU_FD" -eq 0 ]; then open_menu_terminal; fi
    case "$ACTION" in
        help)
            usage
            exit 0
            ;;
        status)
            ensure_systemd
            perform_status
            exit 0
            ;;
    esac

    check_root
    umask 077
    ensure_systemd
    check_owned_paths
    acquire_install_lock
    case "$ACTION" in
        install|upgrade)
            check_node_command
            detect_arch
            detect_os
            ;;
    esac

    case "$ACTION" in
        install)
            perform_install
            ;;
        upgrade)
            perform_upgrade
            ;;
        uninstall)
            perform_uninstall
            ;;
        restart)
            load_health_port_from_config "$CONFIG_FILE"
            systemctl restart "$SERVICE_NAME"
            wait_for_health
            log_info 'Node restarted'
            ;;
        *)
            log_error "Unknown action: $ACTION"
            usage
            exit 1
            ;;
    esac
}

main "$@"
