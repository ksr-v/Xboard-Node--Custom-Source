# xboard-node

Node backend for Xboard. Supports `sing-box` / `xray-core` dual kernels.

> **Disclaimer**: This project is for educational and learning purposes only.

## Features

- Protocols: V2Ray family, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS
- Sync: WebSocket push + REST polling dual channel
- User controls: speed limit, device limit, alive-IP tracking, hot update
- Deploy modes: node mode, machine mode, standalone mode
- Multi-instance: single process binding multiple panels / nodes

## Install

### Installer (Linux systemd)

在服务器的 **Bash SSH 终端**执行一条命令：

```bash
node_script=$(curl -fsS --max-time 30 --max-filesize 65536 https://raw.githubusercontent.com/ksr-v/Xboard-Independent/main/node-installer/install.sh) && [ -n "$node_script" ] && sudo bash -c "$node_script"
```

- 选 **1**：安装／新增对接，按提示输入 node/machine 模式、面板地址、ID、Token 和内核；Token 不回显，不用写入这条命令或 Shell 历史。
- 选 **2**：原地升级，保留配置、Token、绑定及原健康检查端口（包括关闭状态 `0`），无需重新对接或安装采集器。
- 选 **3**：查看状态；选 **0**：退出。失败下载、空响应或无终端时不执行安装。

自动识别 amd64/arm64，默认固定下载本项目 Release **v1.13-orphan.2**，不使用 latest，也不使用仓库中旧版二进制直链。必须信任该仓库：命令完整缓冲 HTTPS 脚本后以 root 执行，入口跟随 main；需要审核／离线部署时使用下方本地文件方式。仅适用于本项目标准 Linux/systemd 安装；Docker、自定义服务或不完整安装请先人工确认。

升级会重启 Node，可能中断连接。安装器会在 /etc/xboard-node/backups 保存旧文件，失败尝试回滚。IPv4 自动展示还需启用 FlowScope 2.4.0，和周期流量开关无关。

检查结果：

```bash
xboard-node -v
sudo systemctl status xboard-node --no-pager
```

### Local / automated installation

Use the maintained installer and version-pinned local binaries. Replace the placeholders below with your deployment settings. Explicit arguments bypass the interactive menu.

```bash
# Node mode
sudo bash install.sh --mode node --panel https://panel.example.com --token YOUR_TOKEN \
  --node-id YOUR_NODE_ID --version YOUR_IMMUTABLE_VERSION --binary ./xboard-node-linux-amd64 \
  --xbctl-binary ./xbctl-linux-amd64

# Machine mode
sudo bash install.sh --mode machine --panel https://panel.example.com --token YOUR_TOKEN \
  --machine-id YOUR_MACHINE_ID --version YOUR_IMMUTABLE_VERSION --binary ./xboard-node-linux-amd64 \
  --xbctl-binary ./xbctl-linux-amd64
```

For arm64, use the matching `*-linux-arm64` binaries. Override the maintained Release base with `--download-base` or `XBOARD_NODE_DOWNLOAD_BASE`; local binary arguments take precedence. Upgrading offline uses `sudo bash install.sh upgrade --version YOUR_IMMUTABLE_VERSION --binary ./xboard-node-linux-amd64 --xbctl-binary ./xbctl-linux-amd64`.

Installer verification (2026-10-09): `python tools/test_installer.py` passed all 16 tests for the menu, secret omission, buffered-download refusal, pinned URLs, ambient old-binary refusal and upgrade health-port preservation in isolated Bash fixtures. No real Linux installation/service upgrade was executed for this script change. The published Node release has local build/test verification; remote CI is currently blocked by a missing historical dependency-snapshot Release (see its release notes).

## xbctl

Run `xbctl` after installation for help. Common commands:

```bash
xbctl list                          # list all instances
xbctl status                        # running status
xbctl bind add-node --panel URL --token YOUR_TOKEN --node-id YOUR_NODE_ID
xbctl bind add-machine --panel URL --token YOUR_TOKEN --machine-id YOUR_MACHINE_ID
xbctl bind remove-node --panel URL --node-id YOUR_NODE_ID
xbctl service restart
```

## Configuration

Legacy single-panel config is fully compatible. Appending bindings auto-migrates to `instances` format. See `config.yml.example`.

## Extensions

- Automatic FlowScope egress IPv4 (no collector required): [中文使用、升级和验证说明](FLOWSCOPE-IPV4.md)

- Custom routes: [docs-custom-routes.md](docs-custom-routes.md)
- Custom outbounds: [docs-custom-outbounds.md](docs-custom-outbounds.md)
- DNS providers (ACME DNS-01): [docs-dns-providers.md](docs-dns-providers.md)

## Dependency maintenance and recovery

- [中文恢复维护指南](DEPENDENCY-RECOVERY.md)
- [中文依赖保护设计](DEPENDENCY-STRATEGY.md)
- [完整风险清单](DEPENDENCY-AUDIT.md)
- [功能验证与未验证范围](DEPENDENCY-TEST-REPORT.md)

Normal Makefile builds require the verified selective Module Proxy snapshot. See the recovery guide for local archive restoration; no dependency proxy service is required on deployed VPS hosts.

## License

MPL-2.0.
