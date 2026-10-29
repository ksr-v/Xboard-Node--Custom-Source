# Xboard-Node v1.13-orphan.8

日期：2026-10-30。此版解决受支持的主机 INPUT 拒绝规则阻断 Hysteria2 实际 UDP 监听端口的问题，保留端口跳跃、在线 IP 限额、限速、路由和本机管理菜单。

## 变更

- 新增本地授权的 HY2 INPUT 管理，覆盖可识别的 iptables-nft / iptables-legacy、IPv4 / IPv6，只开放实际 UDP 监听端口。同进程多节点各有 owned chain，不清空外来规则、不改默认 policy。
- 标准安装器设置 `XBOARD_NODE_MANAGED_INPUT=1`；`--skip-firewall` 写为 `0`，升级保留关闭选择。本地 `firewall.managed_input: false` 可关闭；自定义运行无环境授权默认关闭，面板配置不能授予此权限。
- Service 协调 NAT、INPUT 与内核启动/配置更新，失败尝试恢复旧状态，保留未接受配置重试。独立30秒检查修复当前成功应用配置的规则，WS 连接与否均适用。
- 初始网络规则暂时失败时保留 Service 和待应用配置，避免 machine 模式永久漏掉节点重试。正常退出先停内核，再清理 owned 规则。
- sing-box 尊重本地/面板节点 `listen_ip`，与 Xray 一致；空值仍为 `::`。
- 安装器依赖增加 iptables，与 nftables 一起预检。两个标准 unit 模板和本地绑定配置写回均保留 INPUT 策略。

## 使用范围

每个网络命名空间只运行一个启用 INPUT 管理的 Node 进程，同进程可包含多个节点。额外原生 nftables/firewalld INPUT base chain 不受支持；不能靠独立 nft chain 的 ACCEPT 绕过其他 DROP。使用这些布局时关闭本功能并通过原管理器放行。iptables 形式的 UFW 按实际后端处理，reload 后存在一个检查周期及操作耗时的恢复窗口。

Node 不修改云安全组、上游路由或外部防火墙；跳跃范围仍需外部放行。管理只作用于 Node 所在网络命名空间，不写全局规则持久文件。多后端失败恢复是补偿操作，不保证整套原子回滚。强制退出无法执行清理，关闭管理或回退旧版前须确认 owned 规则状态。

更新保留绑定、Token、私有 CA、实例文件和原健康端口；按 [v8 更新教程](UPGRADE-v1.13-orphan.8.zh-CN.md)执行，完整配置与边界见 [HY2 文档](HY2_PORT_HOPPING.md)。进程 active 或 `/healthz` 成功不代表 UDP 已可用，需实际客户端验证。

## 构建与验收

固定 Go 1.26.8，版本和构建时间由 `release-build.json` 指定，使用 `-trimpath -buildvcs=false`。正式 Node/xbctl AMD64、ARM64 摘要及源码来源以同版 `VERIFICATION.json` 和 `SHA256SUMS` 为准；安装器执行前核对固定摘要。

| 项目 | 本版状态 |
| --- | --- |
| 本地配置、Service、sing-box、xbctl 回归 | 已通过；最终源码和总数待统一报告 |
| 本地 Bash 安装器回归 | 29通过、1跳过；独立发行工作区缺失，待最终发行副本检查 |
| Linux 单元/race 回归 | 待结果 |
| 隔离 netns：REJECT、双后端、IPv4/IPv6、真实 UDP | 待结果 |
| 重启/reload、周期修复、多实例、升级/回滚 | 待结果 |
| 正式资产重建、架构/版本、公开下载核验 | 待结果 |

验收未完成的项目不计为通过。公网生产升级、原生 ARM64 代理流量、商业客户端、任意防火墙管理器和长期负载没有由本地测试证明。

历史证据：2026-10-25 的 [v6 说明](RELEASE-v1.13-orphan.6.md)记录端口跳跃验证；2026-10-28 的 [v7 说明](RELEASE-v1.13-orphan.7.md)记录在线 IP/限额验证。它们不包含本版 INPUT 行为，不计入本版测试总数，历史标签和资产保持原样。
