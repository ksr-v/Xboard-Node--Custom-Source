# 更新至 v1.13-orphan.9：旧 nftables 与 ACME 域名修复

本版配套更新 Node、xbctl 和安装器，保留已有绑定、Token、私有 CA、实例文件及健康端口（包括 `0`）。修复旧 nftables 空规则集和跳跃 NAT 兼容，以及 ACME 域名大小写导致的 Order / CSR 不一致。仅更新面板插件不会更新已部署的 Node。

## 标准 Linux/systemd 升级

先更新一台测试节点，在 Bash SSH 终端执行：

```bash
node_script=$(curl -fsS --proto '=https' --max-time 30 --max-filesize 65536 https://raw.githubusercontent.com/ksr-v/Xboard-Node--Custom-Source/v1.13-orphan.9/install.sh) && [ -n "$node_script" ] && sudo bash -c "$node_script" -- upgrade
```

使用 `upgrade` 保留绑定，普通升级不要执行安装菜单的 `REPLACE`。服务重启会中断已有代理连接；恢复备份位于 `/etc/xboard-node/backups/recovery-*`，目录权限700，含敏感凭据。已有新版 `node` 菜单也可选 **1**，确认目标正式版本后更新。

标准安装启用本地授权的 HY2 INPUT 管理，已设置环境值 `0` 或本地 `firewall.managed_input: false` 的关闭选择保持不变。希望继续手动管理时在上方命令的 `upgrade` 后追加 `--skip-firewall`；该开关只关闭 INPUT，不关闭端口跳跃 NAT。自定义服务和 Docker 按原部署方式更新，不借此获得新的网络权限。

每个网络命名空间只启用一个受管 Node 进程，同进程可含多个节点。额外原生 nftables/firewalld INPUT base chain 仍不受支持；云安全组仍需自行放行。完整范围见 [HY2 文档](HY2_PORT_HOPPING.md)。

使用 nft 0.9.0 时，自动 INPUT 只在没有活动 nft INPUT、规则可完整读取且显式 legacy IPv4/IPv6 工具可用时启用，不切换系统 alternatives。已有 nft INPUT 或 JSON 读取不可靠时会拒绝自动放行；先升级防火墙工具，或用 `--skip-firewall` 保留手动管理。不能通过剥离错误输出或清空现有规则处理此限制。

## 审核后或离线升级

从[固定 v9 Release](https://github.com/ksr-v/Xboard-Node--Custom-Source/releases/tag/v1.13-orphan.9)取得 `install.sh`、`SHA256SUMS` 和本机架构两个程序，在新建 Root 私有目录核对来源和摘要后执行：

```bash
sha256sum --ignore-missing -c SHA256SUMS &&
sudo bash install.sh upgrade --version v1.13-orphan.9 \
  --binary ./xboard-node-linux-amd64 --xbctl-binary ./xbctl-linux-amd64
```

ARM64 将两处 `amd64` 改为 `arm64`；关闭管理时追加 `--skip-firewall`。镜像和本地文件均须匹配安装器固定摘要，摘要校验不替代可信来源。

## 升级后检查

```bash
xboard-node -v
xbctl version
sudo systemctl status xboard-node --no-pager
```

两个程序应显示 `v1.13-orphan.9`。再用真实客户端验证实际 HY2 单端口、跳跃范围和其他协议。进程 active 或 `/healthz` 成功不代表内核已启动或 UDP 已放行；规则暂时失败时每30秒重试，另计串行命令耗时。

ACME 配置可保留原域名大小写，Node 在申请和指纹计算时统一处理；无需删除证书缓存、私钥或关闭校验。先前申请因域名大小写失败的节点可在更新后按正常启动流程重试。该修复不替代 DNS、挑战端口、提供商凭据、CA 限流或证书身份检查。

v9 以严格归属检查迁移旧 v8 owned `inet` NAT 表；存在未知附加内容时拒绝变更并重试，不自动删除管理员添加的规则。若仍失败，保留日志中的固定阶段信息并检查实际工具、权限和布局，不执行全局防火墙 flush。

## 失败恢复与回退

安装失败会尝试恢复旧文件和服务，恢复失败明确报错并保留备份。不要清空绑定、重建 CA 或执行 `REPLACE` 处理普通升级失败。

v8 不能识别 v9 的 `ip` / `ip6` NAT 归属格式。回退到 v8 或更早程序前，先正常停止 v9 并确认 owned INPUT/NAT 已清理，再替换程序。强制退出或断电后的遗留规则由管理员核查；不要让旧二进制在未清理的新格式规则上直接接管。

本版固定源码、依赖、正式资产和实际回归结果见 [v9 发行说明](RELEASE-v1.13-orphan.9.md)与同版 `VERIFICATION.json`；旧版验证不计入本次验收。
