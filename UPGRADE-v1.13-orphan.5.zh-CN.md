# v1.13-orphan.5 更新教程

本版修复限速启用、变更与取消，以及路由顺序、精确域名匹配、出口替换和失败恢复。要让面板保存后及时通知节点，需同时使用 [独立 Xboard 后端 v2026.10.25.1](https://github.com/ksr-v/Xboard-Custom-Source/releases/tag/v2026.10.25.1)。只更新 NodeEndpoint 插件 ZIP 不包含这些后端和 Node 修复。

## 1. 更新面板后端

先按 [后端更新教程](https://github.com/ksr-v/Xboard-Custom-Source/blob/v2026.10.25.1/docs/installation/upgrade-2026.10.25.zh-CN.md) 备份数据库和程序，再更新后端、重启 NodeWorker／队列进程。保留现有数据库、Token、机器记录、NodeEndpoint 配置和 CA。本版 Node 不要求重建 CA、重新绑定机器或卸载其他插件。

完成面板更新后，再逐台升级 Node。重启 Node 服务会断开该机器的现有代理连接，安排可接受的维护时间。

## 2. 已有标准 Linux/systemd 节点：一条命令升级

以 root 登录节点服务器，在 Bash SSH 终端执行：

```bash
node_script=$(curl -fsS --proto '=https' --max-time 30 --max-filesize 65536 https://raw.githubusercontent.com/ksr-v/Xboard-Node--Custom-Source/v1.13-orphan.5/install.sh) && [ -n "$node_script" ] && bash -c "$node_script" -- upgrade
```

普通用户把最后的 `bash -c` 改为 `sudo bash -c`。脚本完整下载成功后才执行，固定安装 v1.13-orphan.5；这是 `upgrade` 动作，不进入重新绑定菜单。

升级保留 `/etc/xboard-node/config.yml`、机器／节点绑定、Token、实例文件和健康端口；已有 NodeEndpoint 的公共 CA、合并信任 bundle 与归属摘要继续使用。新程序和 xbctl 暂存并检查后才停服替换，失败尝试恢复私有备份。备份在 `/etc/xboard-node/backups/recovery-*`，含敏感凭据，勿上传到公开仓库。

检测到不完整安装、异常所有权或自定义 unit 时会停止。Docker、自定义服务和多套独立进程需按现有部署方式替换匹配架构的程序、保留配置卷并重建服务；不要把 systemd 安装器用于这些部署。

已有私有 CA 的升级必须使用完整的本版固定安装脚本；旧面板复制出来的旧版安装指令仍可能固定旧版本。全新机器请从已更新的面板复制新的对接命令。安装菜单的 `REPLACE` 用于替换全部旧绑定，升级当前机器无需使用它。

## 3. 检查结果

```bash
xboard-node -v
xbctl version
systemctl is-active xboard-node
```

前两项应显示 `v1.13-orphan.5`，服务应显示 `active`。在面板确认机器在线、CPU／内存更新和节点状态正常，再用测试账号验证代理。

- 更改测试账号的限速并保存：已有 TCP 连接支持从不限速变为限速、调整正值、恢复不限速；面板的 `0` 表示不限速。
- 更改测试节点的路由顺序、精确域名或出口并保存：已接受的新策略会关闭该节点旧 TCP／UDP 流，客户端需重连；新连接按新规则执行。
- sing-box 用户增删、UUID／密码等身份变化也会关闭该节点旧流，以安全替换内核；仅限速变更继续沿用连接。Node 进程和机器控制连接保持运行。
- 配置生成失败保留正在运行的配置；启动新内核失败时尝试恢复最后成功配置，并保留最新用户。面板的“保存成功”表示已保存和发出通知，不是每台 Node 已应用的确认。

## 4. 离线／审核后更新

从 [固定 Release](https://github.com/ksr-v/Xboard-Node--Custom-Source/releases/tag/v1.13-orphan.5) 下载 `install.sh`、`SHA256SUMS` 和本机架构的 `xboard-node-linux-*`、`xbctl-linux-*`，核对校验文件来源并校验下载文件。在下载目录执行：

```bash
sha256sum --ignore-missing -c SHA256SUMS
bash install.sh upgrade --version v1.13-orphan.5 \
  --binary ./xboard-node-linux-amd64 --xbctl-binary ./xbctl-linux-amd64
```

ARM64 把两处 `amd64` 改为 `arm64`。更新失败后先看安装器报告和备份位置，保留当前配置，不要通过重新安装或清空绑定来处理失败。

## 验证范围

候选版完成 80 项 TCP 联测检查（含配置载荷核对），覆盖两个内核独立运行与机器管理模式、正值限速、同用户共享桶、不同用户隔离、原连接限速变化和路由更新。已有连接启用／调整限速后，保存返回后的首个匹配速率采样窗口约 0.6–1.3 秒完成，取消限速后的窗口约数毫秒完成；路由保存返回后约 2–106 毫秒用新连接验证到新策略。测量包含采样窗口的实际传输时间，不能等同于真实推送延迟，也不是公网时延保证。最终源码还通过 Linux 竞态检查、身份变化与失败恢复测试。

完整 UDP／QUIC 限速、长期压力、原生 ARM64 和所有代理协议的真实业务连续性未穷尽验证。详见 [完整测试证据](https://github.com/ksr-v/Xboard-Independent-NodeEndpoint/blob/main/docs/RATE_ROUTE_FIX_REPORT.md)。
