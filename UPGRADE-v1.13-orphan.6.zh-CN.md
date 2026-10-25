# 更新至 v1.13-orphan.6：自动端口转发与 node 菜单

本次配套版本为 **独立后端 v2026.10.25.2、NodeEndpoint 1.0.9、Node v1.13-orphan.6**。后端校验并下发 Hysteria2 跳跃范围，Node 自动维护 UDP 转发；插件让新机器的安装命令使用 v6。新菜单可修改对接地址／Token、查看日志、重启和在线更新。

已有机器首次用下方固定 v6 `upgrade`，同时获得 Node、xbctl 和菜单；以后输入 `node` 选 **1** 更新。无需卸载其他插件、重建 CA、清空配置或重新初始化数据库。新机安装菜单的 `REPLACE` 会替换全部旧绑定，不用于本次普通升级。

## 1. 更新面板

Hysteria2 自动转发需要后端和 Node 配套。先按[后端更新说明](https://github.com/ksr-v/Xboard-Custom-Source/blob/v2026.10.25.2/docs/installation/upgrade-2026.10.25.2.zh-CN.md)备份数据库与程序，更新后端并重启该部署原有的 NodeWorker／队列。沿用 `.env`、`APP_KEY`、机器记录、Token、NodeEndpoint 设置和 CA。

全插件后端包含 NodeEndpoint 1.0.9，不必再次上传。仅上传插件不会给旧后端添加跳跃范围 API，也不会替旧 Node 更新程序。只使用管理菜单的新功能不依赖新的面板字段，但 Node、xbctl 和安装器仍需配套升级。

## 2. 节点首次升级

以 Root 登录**节点服务器**，在 Bash SSH 终端执行：

```bash
node_script=$(curl -fsS --proto '=https' --max-time 30 --max-filesize 65536 https://raw.githubusercontent.com/ksr-v/Xboard-Node--Custom-Source/v1.13-orphan.6/install.sh) && [ -n "$node_script" ] && bash -c "$node_script" -- upgrade
```

普通用户将最后的 `bash -c` 改为 `sudo bash -c`。完整下载后才执行固定版本安装器；需要事先审核入口时，使用下方离线流程。升级重启服务会中断本机代理连接，先处理一台测试节点，确认后再逐台更新。

安装器固定校验两个架构的 Node／xbctl 摘要，准备 nftables、暂存程序后才备份和停服。它保留配置、machine/node ID、Token、实例文件、健康端口和现有私有 CA；配置0600、恢复目录0700。失败尝试恢复同次备份，若恢复失败会单独报错。备份位于 `/etc/xboard-node/backups/recovery-*`，含敏感凭据。

仅适用于标准 Linux/systemd 安装。Docker、自定义 unit、多套独立服务或未知布局按原部署方式更新匹配程序并保留配置卷；配置编辑器会拒绝自定义 unit 与 drop-in，不能通过它修改不明确的实际服务配置。

## 3. 后续一键管理

首次升级后执行：

```bash
node
```

```text
1) 在线更新到最新正式版本（保留绑定）
2) 重启节点
3) 卸载
4) 修改对接面板地址 / Token
5) 查看最近日志
6) 查看状态
0) 退出
```

以后选 **1** 即从本仓库最新正式 Release 完整下载并校验安装器，更新 Node、xbctl 和本地菜单；不再手写下载地址，也不执行 dev 脚本。没有正式 Release、下载中断或摘要不符会停止，保留原安装。下载入口及 GitHub API 不可达时稍后重试。

选 **4** 修改同一绑定的面板地址／Token，多实例先选择目标，留空保留原值。Token 隐藏输入；先校验真实 API 认证和证书，成功后保存并恢复原服务状态。原 machine/node ID、其他绑定、自定义配置与私有 CA保留；换面板后新地址仍须受现有 CA 信任且原 ID 有效。要更换 CA 或机器身份，先按对应迁移流程准备，不能仅改地址。

选 **5** 显示本服务最近100行日志，日志分享前由管理员脱敏；选 **2** 重启并检查原健康端口。系统的 `node` 若已属于 Node.js／其他程序，安装器会拒绝覆盖或遮蔽，需先人工解决命令冲突。完整行为见[node 使用说明](NODE_MANAGEMENT.zh-CN.md)。

## 4. 验证 Hysteria2

```bash
xboard-node -v
xbctl version
systemctl is-active xboard-node
```

前两项应显示 `v1.13-orphan.6`，服务应为 `active`。在面板确认机器在线、CPU／内存和节点状态继续更新。

Hysteria 节点选择版本 **2**，例如连接端口 `42450-42453`、监听端口 `42443`、跳跃间隔 `5` 秒。保存后 Node 自动建立范围到实际监听口的 UDP 转发；修改范围会替换自己的规则，连接端口恢复单端口会撤销。用支持端口跳跃的真实客户端更新订阅、连接并持续传输，再验证范围变更后的重连。

**仍需网络放行：云安全组／外部防火墙允许广告 UDP 范围，主机 INPUT 允许转发后的实际 UDP 监听端口。** 自动转发不改变这些允许策略。节点需有 nft、`CAP_NET_ADMIN`、Linux NAT 和可写 `/run`；权限不足、已有 UDP 服务或 NAT 冲突时明确报错并保留原配置，不能以关闭 TLS 或清空防火墙处理。

范围或内核变更可能关闭该节点已有流，客户端需重连；Go 主进程和面板控制连接保持。正常停服清理自身规则，异常退出由同实例下次启动核对接管。[完整配置与边界](HY2_PORT_HOPPING.md)

## 5. 下载审核后／离线升级

从[固定 v6 Release](https://github.com/ksr-v/Xboard-Node--Custom-Source/releases/tag/v1.13-orphan.6)下载 `install.sh`、`SHA256SUMS` 和本机架构的 `xboard-node-linux-*`、`xbctl-linux-*`。核对校验清单来源，在新建的 Root 私有目录检查并执行：

```bash
sha256sum --ignore-missing -c SHA256SUMS &&
bash install.sh upgrade --version v1.13-orphan.6 \
  --binary ./xboard-node-linux-amd64 --xbctl-binary ./xbctl-linux-amd64
```

ARM64 将两处 `amd64` 改为 `arm64`。首次入口仍需要信任固定仓库标签和 GitHub HTTPS；摘要不等同于签名。失败后保留安装器输出与备份，不要清空绑定或通过 `REPLACE` 处理普通升级失败。

## 验证范围

候选源码已完成47项自动转发 VM 检查、13项真实菜单／对接编辑 VM 检查、12项后端校验与下发检查，相关 Linux Go 竞态测试通过。正式发行程序、架构与公开下载核验另见同次 `VERIFICATION.json`，详见[发行说明](RELEASE-v1.13-orphan.6.md)。

菜单在线更新实测使用受控测试 Release；日志菜单只验证调用范围，没有读取 Root 私有运行日志。公网生产升级、IPv6、商业客户端、原生 ARM64 代理流量、新 Node Docker 镜像运行和长期压力未完成验收，部署后仍需针对实际网络验证。
