# xboard-node

Node backend for Xboard. Supports `sing-box` / `xray-core` dual kernels.

> **Disclaimer**: This project is for educational and learning purposes only.

## Features

- Protocols: V2Ray family, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS
- Sync: WebSocket push + REST polling dual channel
- User controls: speed limit, device limit, alive-IP tracking, hot update
- Deploy modes: node mode, machine mode, standalone mode
- Multi-instance: single process binding multiple panels / nodes

本发行版修复 nftables 1.0.6 遗漏旧 inet NAT 表 JSON 注释而阻止 HY2 启动的问题，增加严格归属校验后的自动迁移。保留旧 nftables 空规则集兼容与 ACME 域名规范化。保留 [HY2 UDP INPUT 自动管理](HY2_PORT_HOPPING.md)：标准安装在支持的 iptables 后端放行实际监听端口，每30秒检查 INPUT 与跳跃 NAT，另计串行命令耗时。在线 IP 集中准入仍需配套独立后端 `v2026.10.28.1` 或兼容版本。[完整 node 管理菜单](NODE_MANAGEMENT.zh-CN.md)支持修改面板地址／Token、查看日志、重启及更新。

## Install

本发行版本：**v1.13-orphan.10**。已有机器按[更新教程](UPGRADE-v1.13-orphan.10.zh-CN.md)配套升级 Node、xbctl 和管理脚本，保留绑定和私有 CA；以后输入 `node` 选 **1** 更新。仅更新面板插件不会替换已部署的 Node。自动 INPUT 由节点本地权限决定，面板不能开启该权限，详见[本版说明与验证范围](RELEASE-v1.13-orphan.10.md)。

在线设备按账号与来源 IP 去重，不是硬件设备数。同账号同 IP 的多个节点连接共用一个 IP 额度，同一 NAT 内的多台设备无法区分。正常断开会尽快释放；完全断网需 TCP 检测，Node 整体失联需租约过期。配套后端与本版协商集中准入后，心跳5秒，连续55秒未收到成功报告 ACK 时主动关闭有限额在线连接；不限额和旧后端保留兼容行为。具体边界见发行说明。

### NodeEndpoint 独立 IP 自动对接

面板安装 NodeEndpoint 1.1.3，完成独立 HTTPS 入口和本机公共 CA 同步后，在原生“机器管理”新建机器或复制安装命令，在新的 Node 服务器执行并选择 1 安装。新节点入口查询本仓库最新稳定 Node；独立页面的 prepare 流程校验所选程序后固定该版本，后续 latest 变化不会替换已准备的程序。旧插件生成的固定版本命令需改用匹配的 v10 安装器，不能据此认定已部署的 Node 已更新。命令自动带入通讯 IP/端口、机器身份、公共 CA PEM 与指纹，无需逐机手工上传 CA。

安装器校验公共 CA 的 SHA-256、用途、自签名和强度，实际预检 HTTPS 身份/主机名；Node 与 xbctl 固定使用本仓库 v1.13-orphan.10 Release，域名和私有 CA 两种模式都在执行前核对 AMD64/ARM64 资产摘要。本版安装器只接受 v1.13-orphan.10，下载镜像和本地文件也必须匹配固定摘要。构建使用固定 Go 1.26.8 和版本元数据。依赖为 curl、wget、ca-certificates、python3、openssl、nftables、iptables；启用 INPUT 管理或跳跃 NAT 需要足够的网络管理权限。

公共 CA、合并系统根的 bundle、归属摘要写入 /etc/xboard-node/node-endpoint-{ca.pem,trust.pem,trust.json}，Root 0600，服务通过 SSL_CERT_FILE 使用；升级保留，失败恢复，卸载移除活动文件并保留私有恢复备份。已运行实例不会因面板 CA 变化自动更新，CA 轮换仍需安排双信任更新。

原生机器命令沿用 --token 参数，命令和 Shell 历史属于敏感内容；CA 与指纹同来自已信任的管理员面板，不构成额外带外信任。该流程用于新机器，旧安装的 REPLACE 会替换全部本机旧绑定，已有生产实例请按 NodeEndpoint 的迁移流程处理。关闭 TLS 验证不能作为 IP 对接方式。

历史 IP/私有 CA 安装验证见[原生安装报告](https://github.com/ksr-v/Xboard-Independent-NodeEndpoint/blob/main/NATIVE_MACHINE_TEST_REPORT.md)，v5 限速／路由证据见[修复报告](https://github.com/ksr-v/Xboard-Independent-NodeEndpoint/blob/main/docs/RATE_ROUTE_FIX_REPORT.md)。这些历史证据不等于本次发行字节验收；本版源码、兼容性与正式资产核验见[发行说明](RELEASE-v1.13-orphan.10.md)及同版 `VERIFICATION.json`。

### Installer (Linux systemd)

在服务器的 **Bash SSH 终端**执行一条命令：

```bash
node_script=$(curl -fsS --proto '=https' --max-time 30 --max-filesize 65536 https://raw.githubusercontent.com/ksr-v/Xboard-Node--Custom-Source/v1.13-orphan.10/install.sh) && [ -n "$node_script" ] && sudo bash -c "$node_script"
```

- 选 **1 安装**：填写 node/machine 模式、面板地址、ID、Token 和内核；检测到旧安装时，输入 `REPLACE` 确认后替换本机**全部旧对接**，不再追加绑定。Token 输入不回显。
- 选 **2 卸载**：输入 `UNINSTALL` 确认后断开本机全部 Node 对接并卸载，保留私有恢复备份。
- 选 **0 退出**。面板生成的带参数对接指令也会显示此菜单，选择安装时沿用参数中的目标，不重复填写。菜单通过独立终端读取，不占用管道脚本的 stdin；自动化必须显式加 `--yes`。

自动识别 amd64/arm64，默认固定下载本项目 Release **v1.13-orphan.10**。上方脚本和二进制均固定版本；后续小写 `node` 菜单选 **1**，查询本仓库最新正式 Release，完整下载并校验安装器，再使用该脚本固定的二进制版本；不再执行 `dev` 分支脚本。需要审核／离线部署时使用下方本地文件方式。仅适用于本项目标准 Linux/systemd 安装；Docker、自定义服务或不完整安装请先人工确认。

安装替换、升级和重启均可能中断连接。标准 unit 设置 `XBOARD_NODE_MANAGED_INPUT=1`；`upgrade --skip-firewall` 改为 `0`，以后升级保留该关闭设置。本地 `firewall.managed_input: false` 也可关闭自动 INPUT。自定义部署无环境授权时默认关闭，面板配置不能授权。INPUT 仅覆盖实际 HY2 UDP 监听端口；额外原生 nftables/firewalld INPUT base chain 不受支持。nft 0.9.0 仅在没有活动 nft INPUT 且规则可完整读取时使用显式 legacy 工具，不切换系统 alternatives；已有 nft INPUT 或不可安全读取时拒绝自动放行。云安全组仍需自行放行。每个网络命名空间只运行一个启用管理的 Node 进程，同进程可含多个节点。详见[权限和范围](HY2_PORT_HOPPING.md)。IPv4 自动展示还需启用 FlowScope 2.4.0。

### 本机管理命令

[完整 node 管理菜单](NODE_MANAGEMENT.zh-CN.md)提供修改面板地址／Token、查看日志、重启、状态及在线更新。首次从旧版升级可用下方固定 v10 安装器，配套更新菜单、Node 和 xbctl；已有新版菜单也可输入 `node` 选 **1**，确认目标正式版本后更新。

已有标准安装也可直接使用同一维护入口的 `upgrade` 动作，保留配置和绑定，不进入安装／卸载菜单：

```bash
node_script=$(curl -fsS --proto '=https' --max-time 30 --max-filesize 65536 https://raw.githubusercontent.com/ksr-v/Xboard-Node--Custom-Source/v1.13-orphan.10/install.sh) && [ -n "$node_script" ] && sudo bash -c "$node_script" -- upgrade
```

安装成功后输入小写 `node`（大小写敏感，`Node` / `NODE` 不适用）：

```text
1) 在线更新到最新正式版本（保留绑定）
2) 重启节点
3) 卸载
4) 修改对接面板地址 / Token
5) 查看最近日志
6) 查看状态
0) 退出
```

非 root 用户会请求 sudo。新版菜单从本项目 latest 正式 Release 完整获取并校验安装器，再升级到该脚本固定的版本，保留当前配置、凭据、实例文件和原健康端口（包括 `0`）；历史 v1.13-orphan.5 菜单仍使用其原来的维护脚本入口，因此首次请执行上方明确的 v10 `upgrade`。重启仅操作 `xboard-node.service`。如果系统已存在 Node.js 或其他程序的 `node` 命令，安装／升级会安全拒绝，不覆盖或遮蔽；需先自行解决命令冲突。

### 旧版检测、覆盖与恢复边界

安装器检查旧二进制、配置、服务及残留凭据／实例目录；版本新旧都走同一安全替换流程：先下载并生成当前 `instances` 格式的新配置，再备份，停止 `xboard-node.service`，归档旧实例目录，最后仅启用此次填写的目标。旧配置及旧凭据不会合并进新文件，避免不同机器共用 `65530` 的冲突；machine 模式会由新目标面板重新下发其节点。

纯**升级**保留旧格式文件，利用 Node 已有的 legacy 配置兼容，不自动重写配置，也不会修复原本无效的多实例布局。仅修改同一绑定的面板地址／Token，使用 `node` 选 **4**，保留原 machine/node ID；编辑器会验证真实 API 认证，发现自定义 unit 或 drop-in 时拒绝。需要更换机器身份／全部绑定时，再使用安装与 `REPLACE`。版本以 `xboard-node -v` 为准，纯升级不会重写原安装元数据。

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
  --node-id YOUR_NODE_ID --version v1.13-orphan.10 --binary ./xboard-node-linux-amd64 \
  --xbctl-binary ./xbctl-linux-amd64

# Machine mode
sudo bash install.sh --yes --mode machine --panel https://panel.example.com --token YOUR_TOKEN \
  --machine-id YOUR_MACHINE_ID --version v1.13-orphan.10 --binary ./xboard-node-linux-amd64 \
  --xbctl-binary ./xbctl-linux-amd64
```

For arm64, use the matching `*-linux-arm64` binaries. Override the maintained Release base with `--download-base` or `XBOARD_NODE_DOWNLOAD_BASE`; explicit local binary arguments take precedence. Both must match this installer's pinned v1.13-orphan.10 hashes; other release versions are refused. Files in the current directory are never selected implicitly. Upgrading offline uses `sudo bash install.sh upgrade --version v1.13-orphan.10 --binary ./xboard-node-linux-amd64 --xbctl-binary ./xbctl-linux-amd64`. Automated uninstall: `sudo bash install.sh uninstall --yes`.

本版的固定依赖、证书回归、旧版 nftables 兼容、隔离 netns、程序构建及公开下载结果记录于[发行说明](RELEASE-v1.13-orphan.10.md)与同版 `VERIFICATION.json`，以其中实际执行范围为准。2026-10-30 的 [v8 说明](RELEASE-v1.13-orphan.8.md)记录此前 INPUT 和正式资产验收；[v7 说明](RELEASE-v1.13-orphan.7.md)与 [v6 说明](RELEASE-v1.13-orphan.6.md)保留更早证据，历史数量不计入本版。

Historical verification (2026-10-09): the original installer suite had 48 checks, with 47 passed and one Windows native-symlink case skipped. v1.13-orphan.4 included trimpath builds and the corrected native-symlink fixture. v1.13-orphan.3 remained an unpublished candidate; historical tags and assets are preserved. The missing dependency-snapshot Release reported by that version was a separate distribution issue; current CI still requires the exact asset pinned in `dependency-snapshot.json`.

### 发布与脱敏

本项目公开仓库仅发布受 Git 管理的源码；实际 `config.yml`、`.env`、凭据、私钥、测试运行产物及 `.dependency-work` 不进入源码包。发布前对导出的源码树和新增提交执行敏感信息扫描，人工区分测试假值与真实凭据，并检查 Release 附件。固定依赖构建启用 Go `-trimpath`，避免二进制暴露构建机绝对源码路径。扫描是已知模式检查，不是不存在任何敏感信息的绝对保证；详见 [本版发布说明](RELEASE-v1.13-orphan.10.md)。

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
- Hysteria2 自动 UDP 范围转发：[配置、权限及验证](HY2_PORT_HOPPING.md)
- node 管理菜单：[对接修改、日志、重启及在线更新](NODE_MANAGEMENT.zh-CN.md)

- Custom routes: [docs-custom-routes.md](docs-custom-routes.md)
- Custom outbounds: [docs-custom-outbounds.md](docs-custom-outbounds.md)
- DNS providers (ACME DNS-01): [docs-dns-providers.md](docs-dns-providers.md)

## Dependency maintenance and recovery

- [中文恢复维护指南](DEPENDENCY-RECOVERY.md)
- [中文依赖保护设计](DEPENDENCY-STRATEGY.md)
- [完整风险清单](DEPENDENCY-AUDIT.md)
- [功能验证与未验证范围](DEPENDENCY-TEST-REPORT.md)

Normal Makefile builds require the verified selective Module Proxy snapshot. See the recovery guide for local archive restoration; no dependency proxy service is required on deployed VPS hosts.

Formal v10 builds use Go 1.26.8 and the fixed `release-build.json` metadata, with `-trimpath -buildvcs=false`. `VERSION=v1.13-orphan.10 make build-all` produces the four Linux assets; CI rebuilds and verifies installer pins before publication and compares byte-for-byte when the Release already exists. Git provenance is recorded separately so the later installer-pin commit cannot change the binary bytes.

## License

MPL-2.0.
