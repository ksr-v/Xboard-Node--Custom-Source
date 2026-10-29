# 更新至 v1.13-orphan.8：Hysteria2 UDP INPUT 自动管理

本版配套更新 Node、xbctl 和安装器，保留已有绑定、Token、私有 CA、实例文件及健康端口（包括 `0`）。仅更新面板插件不会更新已部署的 Node。原有在线 IP 集中准入仍需兼容后端；本次 INPUT 授权只来自节点本地。

## 标准 Linux/systemd 升级

先更新一台测试节点，在 Bash SSH 终端执行：

```bash
node_script=$(curl -fsS --proto '=https' --max-time 30 --max-filesize 65536 https://raw.githubusercontent.com/ksr-v/Xboard-Node--Custom-Source/v1.13-orphan.8/install.sh) && [ -n "$node_script" ] && sudo bash -c "$node_script" -- upgrade
```

使用 `upgrade`，不要为普通升级执行安装菜单的 `REPLACE`。升级重启会中断已有代理连接，恢复备份位于 `/etc/xboard-node/backups/recovery-*`，权限700，包含敏感凭据。标准安装将启用 `XBOARD_NODE_MANAGED_INPUT=1`，为实际 HY2 UDP 监听端口管理受支持的 INPUT 规则；没有跳跃范围的 HY2 节点也适用。

每个网络命名空间只启用一个受管 Node 进程；该进程可以包含多个节点。额外原生 nftables/firewalld INPUT base chain 不受支持，云安全组仍需手动放行。[完整权限和数据路径](HY2_PORT_HOPPING.md)。

## 保留手动防火墙管理

如果使用不支持的布局或希望继续手动管理，首次升级时加关闭参数：

```bash
node_script=$(curl -fsS --proto '=https' --max-time 30 --max-filesize 65536 https://raw.githubusercontent.com/ksr-v/Xboard-Node--Custom-Source/v1.13-orphan.8/install.sh) && [ -n "$node_script" ] && sudo bash -c "$node_script" -- upgrade --skip-firewall
```

标准 unit 写入环境值 `0`，以后升级保留该值。也可在本地配置设置 `firewall: {managed_input: false}`；YAML 文件重新加载会重启进程内服务。此开关不关闭既有跳跃 NAT。自定义服务无环境授权默认不改 INPUT，面板不能授权；Docker 与自定义服务按原部署方式更新，标准安装器不会代为推断其布局。

## 审核后或离线升级

从[固定 v8 Release](https://github.com/ksr-v/Xboard-Node--Custom-Source/releases/tag/v1.13-orphan.8)取得 `install.sh`、`SHA256SUMS` 和本机架构两个程序，在新建 Root 私有目录核对来源和摘要后执行：

```bash
sha256sum --ignore-missing -c SHA256SUMS &&
sudo bash install.sh upgrade --version v1.13-orphan.8 \
  --binary ./xboard-node-linux-amd64 --xbctl-binary ./xbctl-linux-amd64
```

ARM64 将两处 `amd64` 改为 `arm64`；需要关闭管理时追加 `--skip-firewall`。本地文件和镜像也必须匹配安装器固定摘要。摘要校验不是发行签名，首次入口仍依赖可信来源与 HTTPS。

## 验证和失败恢复

```bash
xboard-node -v
xbctl version
sudo systemctl status xboard-node --no-pager
```

两个程序应显示 `v1.13-orphan.8`。随后用真实客户端验证实际 HY2 单端口、跳跃范围和其他协议，并检查日志。进程 active 或 `/healthz` 成功不能代替 UDP 业务验收。规则暂时失败时保留待应用配置，每30秒修复或重试；外部防火墙 reload 后可能有恢复窗口。

升级失败会尝试恢复旧文件和服务，恢复失败明确报错并保留备份。不要通过清空绑定、重建 CA 或 `REPLACE` 处理普通失败；不要执行全局防火墙 flush。回退到旧程序前应确认新版正常停止并清理 owned INPUT，强制退出留下的资源需要管理员检查。

## 本版验收状态

本版 Linux 单元599项、INPUT/NAT race129项、私有 netns 真实 UDP 9场景通过；构建/安装升级等 Python 夹具94通过、1个可选副本检查跳过。四个程序已按固定 Go 1.26.8 构建，AMD64 在 Windows/Linux 逐字节复现；ARM64 为交叉构建。公开下载结果见同版 `VERIFICATION.json`，测试边界见 [v8 发行说明](RELEASE-v1.13-orphan.8.md)；历史 v6/v7 结果不作为本版功能或正式字节验收。
