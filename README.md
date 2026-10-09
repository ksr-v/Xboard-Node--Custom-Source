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

- 选 **1 安装**：填写 node/machine 模式、面板地址、ID、Token 和内核；检测到旧安装时，输入 `REPLACE` 确认后替换本机**全部旧对接**，不再追加绑定。Token 输入不回显。
- 选 **2 卸载**：输入 `UNINSTALL` 确认后断开本机全部 Node 对接并卸载，保留私有恢复备份。
- 选 **0 退出**。面板生成的带参数对接指令也会显示此菜单，选择安装时沿用参数中的目标，不重复填写。菜单通过独立终端读取，不占用管道脚本的 stdin；自动化必须显式加 `--yes`。

自动识别 amd64/arm64，默认固定下载本项目 Release **v1.13-orphan.2**，不使用 latest，也不使用仓库中旧版二进制直链。必须信任该仓库：命令完整缓冲 HTTPS 脚本后以 root 执行，入口跟随 main；需要审核／离线部署时使用下方本地文件方式。仅适用于本项目标准 Linux/systemd 安装；Docker、自定义服务或不完整安装请先人工确认。

安装替换、升级和重启均可能中断连接。IPv4 自动展示还需启用 FlowScope 2.4.0，和周期流量开关无关。

### 本机管理命令

安装成功后输入小写 `node`（大小写敏感，`Node` / `NODE` 不适用）：

```text
1) 升级（保留当前绑定）
2) 重启节点
3) 卸载
0) 退出
```

非 root 用户会请求 sudo。升级先完整获取本项目维护的安装脚本，再升级到该脚本固定的版本；保留当前配置、凭据、实例文件和原健康端口（包括 `0`）。重启仅操作 `xboard-node.service`。如果系统已存在 Node.js 或其他程序的 `node` 命令，安装／升级会安全拒绝，不覆盖或遮蔽；需先自行解决命令冲突。

### 旧版检测、覆盖与恢复边界

安装器检查旧二进制、配置、服务及残留凭据／实例目录；版本新旧都走同一安全替换流程：先下载并生成当前 `instances` 格式的新配置，再备份，停止 `xboard-node.service`，归档旧实例目录，最后仅启用此次填写的目标。旧配置及旧凭据不会合并进新文件，避免不同机器共用 `65530` 的冲突；machine 模式会由新目标面板重新下发其节点。

纯**升级**保留旧格式文件，利用 Node 已有的 legacy 配置兼容，不自动重写配置，也不会修复原本无效的多实例布局。需要解除旧绑定／切换机器时，请用**安装**并确认 `REPLACE`。版本以 `xboard-node -v` 为准，纯升级不会重写原安装元数据。

恢复备份位于 `/etc/xboard-node/backups/recovery-*`（目录权限 `700`，含敏感 Token）；旧 `instances` 目录在停服后移入同次备份。安装失败会尝试恢复旧文件并检查服务；恢复失败会明确报错，保留备份，不保证能恢复本来就失效的旧 Token。停止失败、非安全 KillMode、自定义链接／路径等异常会拒绝继续；不会按端口强杀其他程序。

“断开”指本机停止旧对接和释放本服务的全部节点监听，**不删除面板中的服务器／节点记录、历史流量、Python 采集器或外部证书**。卸载只移除本项目活动文件及有归属标记的管理命令；`--purge` 也不自动删除恢复备份，确认无用后自行处理。Docker、自定义 unit、额外独立 Node 服务及管理目录之外的文件需人工处理。

检查结果：

```bash
xboard-node -v
sudo systemctl status xboard-node --no-pager
```

### Local / automated installation

Use the maintained installer and version-pinned local binaries. Replace the placeholders below with your deployment settings. `--yes` bypasses the menu and authorizes replacement of all existing local bindings. Avoid literal tokens in shared command histories/process listings.

```bash
# Node mode
sudo bash install.sh --yes --mode node --panel https://panel.example.com --token YOUR_TOKEN \
  --node-id YOUR_NODE_ID --version YOUR_IMMUTABLE_VERSION --binary ./xboard-node-linux-amd64 \
  --xbctl-binary ./xbctl-linux-amd64

# Machine mode
sudo bash install.sh --yes --mode machine --panel https://panel.example.com --token YOUR_TOKEN \
  --machine-id YOUR_MACHINE_ID --version YOUR_IMMUTABLE_VERSION --binary ./xboard-node-linux-amd64 \
  --xbctl-binary ./xbctl-linux-amd64
```

For arm64, use the matching `*-linux-arm64` binaries. Override the maintained Release base with `--download-base` or `XBOARD_NODE_DOWNLOAD_BASE`; explicit local binary arguments take precedence. Files in the current directory are never selected implicitly. Upgrading offline uses `sudo bash install.sh upgrade --version YOUR_IMMUTABLE_VERSION --binary ./xboard-node-linux-amd64 --xbctl-binary ./xbctl-linux-amd64`. Automated uninstall: `sudo bash install.sh uninstall --yes`.

Installer verification (2026-10-09): `python tools/test_installer.py` passed 20 tests; `python tools/test_replacement.py` passed 27 with 1 skipped (48 total, 47 passed). Isolated Bash/filesystem fixtures cover replacement, stop refusal, rollback including original service state, uninstall and command ownership; a real local `xbctl` generated one new instance from an old dual-65530 fixture. Windows lacks native symlink permission: link creation was explicitly simulated and the real-symlink security case skipped. No real root/network/systemd mutation occurred. Linux service/port release and controlling-terminal pipeline acceptance remain NOT RUN. This change updates the maintained installer, not immutable v1.13-orphan.2 Release assets. The published Node release has local build/test verification; remote CI has a missing historical dependency-snapshot Release (see its release notes).

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

Legacy single-panel config is compatible. Explicit `xbctl bind add-*` still appends/migrates bindings; the installer deliberately replaces them instead. See `config.yml.example`.

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
