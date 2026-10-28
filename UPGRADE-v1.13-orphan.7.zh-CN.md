# 更新至 v1.13-orphan.7：在线统计与跨节点 IP 限额

先更新配套独立后端 **v2026.10.28.1**，再逐台升级 Node。NodeEndpoint 1.0.10 让新机安装命令使用 v7；仅更新插件不会替已有节点更新程序。Node、xbctl 和安装器需配套，不需要重建 CA 或重置 Token。完整变更和统计边界见[发行说明](RELEASE-v1.13-orphan.7.md)。

## 标准 systemd 安装升级

以 Root 登录节点服务器，在 Bash 终端执行：

```bash
node_script=$(curl -fsS --proto '=https' --max-time 30 --max-filesize 65536 https://raw.githubusercontent.com/ksr-v/Xboard-Node--Custom-Source/v1.13-orphan.7/install.sh) && [ -n "$node_script" ] && bash -c "$node_script" -- upgrade
```

普通用户将最后的 `bash -c` 改为 `sudo bash -c`。先更新一台测试节点，确认后再逐台升级。安装器保留配置、machine/node ID、Token、实例文件、原健康端口（包括0）和私有 CA，先暂存并校验程序，再备份和重启；重启会中断本机连接。恢复备份含敏感凭据，位于 `/etc/xboard-node/backups/recovery-*`，目录权限0700。

使用 `upgrade`，不进入新机安装或 `REPLACE`。Docker、自定义 unit、独立多服务按原部署方式替换对应程序、保留配置卷；标准安装器不处理未知服务布局。后续输入小写 `node` 选 **1**，即可校验并更新到本项目最新正式 Release。系统已有其他 `node` 命令时会安全拒绝，不覆盖。

## 验证

```bash
xboard-node -v
xbctl version
systemctl is-active xboard-node
```

前两项应显示 `v1.13-orphan.7`，服务应为 `active`。在配套面板查看机器与节点状态，并用测试账号验证正常连接、正常断开和跨节点限额。在线设备按来源 IP 去重，同账号同 IP 的多台物理设备无法区分。正常断开通常在中心释放后、下一次列表刷新内消失；断网需等待 TCP 检测，Node 整体失联需等待租约过期。未配套更新的旧后端沿用兼容行为，不能据此承诺新的清理时间。

## 审核后／离线升级

从[固定 v7 Release](https://github.com/ksr-v/Xboard-Node--Custom-Source/releases/tag/v1.13-orphan.7)下载 `install.sh`、`SHA256SUMS` 和本机架构的两个程序。核对清单来源，在新建 Root 私有目录执行：

```bash
sha256sum --ignore-missing -c SHA256SUMS &&
bash install.sh upgrade --version v1.13-orphan.7 \
  --binary ./xboard-node-linux-amd64 --xbctl-binary ./xbctl-linux-amd64
```

ARM64 将两处 `amd64` 改为 `arm64`。安装器拒绝不匹配的版本或摘要，下载镜像和本地文件也必须通过固定摘要。失败时保留输出和备份；不要通过清空绑定或 `REPLACE` 处理普通升级失败。首次入口依赖固定标签与 HTTPS，摘要不是发布签名。

候选源码、候选二进制的功能验收和正式资产验收分别记录，见发行说明及 Release 的 `VERIFICATION.json`；正式 ARM64 仅验证 ELF 架构和 QEMU 版本运行，不代表原生 ARM64 代理流量已验收。
