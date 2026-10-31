# 更新至 v1.13-orphan.10：HY2 旧 NAT 表迁移兼容

本版配套更新 Node、xbctl 和安装器，修复 nftables 1.0.6 的旧 `inet` 表注释在 JSON 输出中缺失，导致 HY2 无法启动的问题。已有绑定、Token、证书、私有 CA、实例目录及健康端口保持原值。

## 标准 Linux/systemd 升级

确认 [v10 正式 Release](https://github.com/ksr-v/Xboard-Node--Custom-Source/releases/tag/v1.13-orphan.10)已经发布后，在 Bash SSH 终端执行：

```bash
node_script=$(curl -fsS --proto '=https' --max-time 30 --max-filesize 65536 https://raw.githubusercontent.com/ksr-v/Xboard-Node--Custom-Source/v1.13-orphan.10/install.sh) && [ -n "$node_script" ] && sudo bash -c "$node_script" -- upgrade
```

已有新版小写 `node` 菜单也可选 **1**，更新到本仓库最新稳定发行。NodeEndpoint 1.1.3 的新节点安装入口已支持最新稳定 Node；已部署的 Node 仍需单独执行升级。普通升级使用 `upgrade`，不要执行 `REPLACE`。

升级会重启 Node，同进程代理连接会短暂中断。安装器的私有恢复备份位于 `/etc/xboard-node/backups/recovery-*`。标准安装保留 `XBOARD_NODE_MANAGED_INPUT=0` 和本地 `firewall.managed_input: false` 的关闭选择；继续手动管理 INPUT 时可在命令末尾追加 `--skip-firewall`。该开关不关闭跳跃 NAT。

## 审核后或离线升级

从同一固定 Release 下载 `install.sh`、`SHA256SUMS` 和本机架构的两个程序，在新建 Root 私有目录中核对来源后执行：

```bash
sha256sum --ignore-missing -c SHA256SUMS &&
sudo bash install.sh upgrade --version v1.13-orphan.10 \
  --binary ./xboard-node-linux-amd64 --xbctl-binary ./xbctl-linux-amd64
```

ARM64 将两处 `amd64` 改成 `arm64`。安装器固定四个程序的实际摘要，本地文件和镜像也必须匹配。摘要验证不能替代可信来源。

## 升级后检查

```bash
xboard-node -v
xbctl version
sudo systemctl status xboard-node --no-pager
sudo journalctl -u xboard-node --since '-5 minutes' --no-pager
sudo ss -lunp
```

两个程序应显示 `v1.13-orphan.10`。以面板当前服务监听口核对 `ss` 输出，并用真实客户端验证单端口、跳跃范围和其他协议。服务 active 或健康接口成功不能证明 HY2 已启动；本地规则正常也不能证明云安全组已经放行。

v10 会兼容读取并迁移**当前实例**的旧表。定向文本读取必须给出完整匹配的所有权 marker，重读 JSON 时还要确认同一 handle 和完整结构。无法证明归属或内容安全时仍停止迁移，不放宽为按表名前缀删除。

本版已在 Debian 12、nftables 1.0.6 的授权测试节点执行标准升级：安装器返回 0，当前实例旧表自动迁移，HY2 与其余三个协议恢复监听，配置、凭据、私有 CA bundle 和 unit 字节摘要保持不变。使用节点原有 Salamander 混淆与证书信任，实际监听口和跳跃范围内两个端口均通过 TLS 校验及 QUIC `h3` 握手。该结果只证明公网 QUIC/TLS 握手，不包含认证后的代理流量。未启用混淆的普通探测会与实际协议不匹配，不能据其超时认定升级失败。

## 仍有重叠旧规则时

如果日志改为 `conflicts with a possibly overlapping existing NAT rule`，说明当前阻塞点是另一张重叠 NAT 表。先记录日志给出的表名、地址族、链名以及面板当前端口，使用 `nft -a list table` 与 `nft -j list table` 定向读取该表，并在 Root 私有目录保存这张表的文本和 JSON 备份。

将完整 marker 对照原实例 ID、节点 ID 和配置目录的 SHA-256，并核查历史安装备份、已移除绑定及是否仍有进程使用旧端口。不能仅凭 `xbnode_hop_` 前缀认定它已废弃。只有在归属、结构和废弃用途都确认后，才定向清理这一张表，让 Node 按当前配置恢复规则。

不要执行 `nft flush ruleset`、`iptables -F` 或清空其他表来处理单节点冲突。未知归属、附加规则或仍在使用的旧绑定应保留，由管理员先协调配置。不要把完整配置、Token、用户凭据、私钥或原始业务日志放入公开问题单。

## 失败恢复

安装失败时按安装器输出检查恢复结果和私有备份，先恢复原服务文件与程序，保留现有绑定及 CA。回退到 v8 或更早版本之前，正常停止新版并核实新版拥有的规则已清理；旧版不能接管新版的 `ip` / `ip6` 所有权格式。

本版实际测试环境、固定源码与资产校验见 [发行说明](RELEASE-v1.13-orphan.10.md)和同版 `VERIFICATION.json`。
