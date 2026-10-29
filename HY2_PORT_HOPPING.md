# Hysteria2 端口跳跃与 UDP INPUT 自动管理

Node **v1.13-orphan.8** 保留端口跳跃 NAT，并增加实际 HY2 UDP 监听端口的 INPUT 管理。标准安装默认启用 INPUT 管理；本地管理员可以关闭。只更新面板插件不会更新已部署的 Node，已有机器按 [v8 更新教程](UPGRADE-v1.13-orphan.8.zh-CN.md)执行 `upgrade`。

## 配置与数据路径

面板节点配置示例：

```json
{
  "protocol": "hysteria",
  "version": 2,
  "listen_ip": "0.0.0.0",
  "server_port": 42443,
  "port_hopping": {"start": 42450, "end": 42453}
}
```

内核只监听 `server_port`。PREROUTING NAT 将范围内、发往本机的 UDP 流量重定向到该端口；INPUT 看到的是重定向后的端口，所以只允许范围、却拒绝 `42443/udp`，仍会阻断连接。启用管理后，Node 为实际 `42443/udp` 创建自己的 INPUT 放行规则，放在该后端 INPUT 的外来拒绝规则之前，不在 INPUT 中开放整个跳跃范围。未配置跳跃的 HY2 单端口节点也可使用 INPUT 管理。

`port_hopping: null` 或删除该字段只关闭 NAT，不关闭仍在运行的 HY2 监听端口的 INPUT 放行。端口须在 `1..65535`，范围须满足 `start <= end`，仅适用于 `protocol=hysteria`、`version=2`。`listen_ip` 为 IP 字面量或空值；sing-box 与 Xray 均按该地址监听，空值为 `::`，规则按相应地址族及指定目标地址约束。

standalone 模式在 `standalone.node` 使用相同配置。客户端必须支持跳跃，例如 sing-box 的 `server_ports: ["42450:42453"]`；跳跃间隔由客户端决定。TLS 校验和用户认证仍需正常配置。

## 本地授权与关闭方法

标准安装器安装 `nftables` 和 `iptables`，unit 设置：

```ini
Environment=XBOARD_NODE_MANAGED_INPUT=1
```

自定义服务、手动运行或容器没有该环境授权时，INPUT 管理默认关闭。设置本地 YAML `true` 或面板下发配置均不能替代环境授权。管理员可在节点配置中关闭：

```yaml
firewall:
  managed_input: false
```

该设置可作为多实例顶层默认值或实例本地配置。文件监视器会重新加载配置并重启进程内服务，现有代理连接需要重连。也可用 v8 安装器升级并关闭：

```bash
sudo bash install.sh upgrade --skip-firewall
```

这会把标准 unit 的环境值写为 `0`，后续升级保留 `0`；已有本地 YAML opt-out 同样保留。此开关只关闭自动 INPUT，端口跳跃 NAT 仍按 `port_hopping` 独立工作。手动管理防火墙时，须自行放行实际监听端口。

节点需 Linux、足够的网络管理权限、可写的受保护 `/run`，以及相应工具和内核支持。标准服务保持 `NoNewPrivileges=true`。规则只作用于 Node 所在网络命名空间；容器中的规则不会自动开放宿主机端口或云安全组。

## 支持范围和规则归属

INPUT 管理覆盖可识别的 **iptables-nft / iptables-legacy、IPv4 / IPv6** 后端，使用每实例的 `XB_IN_<摘要>` chain 和完整归属注释。NAT 继续使用 `inet xbnode_hop_<摘要>`。不把 Token、用户 UUID、私钥写入规则；不修改默认 policy，不清空外来规则，不写全局 `rules.v4` / `rules.v6`，不启动 `nftables.service` 加载系统规则。

**额外原生 nftables/firewalld INPUT base chain 不受支持。** 独立 nft base chain 的 ACCEPT 不能保证覆盖另一个 chain 的 DROP。检测依据是实际规则布局，不是 firewalld 服务是否运行。Node 检测到不支持的布局会拒绝应用新的自动 INPUT 配置，保留待重试状态，不改写该管理器的规则；请关闭本功能并用该管理器配置监听端口。iptables 形式的 UFW 规则可随实际后端处理，但 reload 后可能有短暂阻断，仍需在自己的环境验证。

启用 INPUT 管理时，每个网络命名空间只运行**一个 Node 进程**；同一进程可管理多个实例和节点。进程生命周期锁避免另一个启用管理的进程接管规则，锁保留到进程退出。各节点使用不同稳定 owner，停止一个节点不会删除同进程其他节点的规则。不要通过复制锁目录来绕过该约束。

NAT 仍会检查现有 UDP socket、重复范围及不明转发冲突，避免截获 DNS、WireGuard 等其他服务。复杂规则无法安全判断时会拒绝；INPUT 支持两种 iptables 后端不代表旧 legacy NAT 冲突也会自动转换。

云安全组、上游路由和外部防火墙仍须放行客户端访问的 UDP 端口或跳跃范围；Node 不调用云平台 API，也不修改外部规则。

## 更新、恢复与持久性

启动、REST/WS 配置更新时，Service 协调 NAT、INPUT 和内核。规则失败不接受新配置；内核候选失败时尝试恢复旧规则和旧运行配置。多后端恢复属于补偿操作，无法承诺整体原子回滚；补偿失败会单独报错并继续重试。初始网络规则暂时失败时保留待应用配置进入主循环，不因 machine 节点已登记而永久停止重试。

独立的 **30 秒**检查在 WS 连接或断开时都运行，修复当前成功应用配置的 INPUT 与 NAT；不会把已拒绝的待应用配置当成当前规则。仅内核运行且存在用户时保留规则，否则清理。防火墙 reload 后的恢复属于周期修复，等待30秒检查周期之外还包括串行命令执行耗时，期间可能暂时无法连接；不是写入全局保存文件后的即时持久化。

正常停止、重启、卸载先停内核，再清理 owned INPUT/NAT；配置文件重新加载等待旧 Service 清理后再启动。SIGKILL、断电无法执行退出清理；后续启用管理的进程会在严格核对归属后回收旧 INPUT 资源，NAT 按稳定实例核对。关闭管理或回退到不认识 INPUT 的旧程序，不能保证回收此前强制退出留下的资源；先确认正常停止清理，异常时由管理员检查，不要 flush 整套规则。

## 验证范围

先确认实际单端口 HY2 代理可用，再检查跳跃范围、其他端口仍被拒绝，以及正常停止后的清理。`systemctl is-active` 或 `/healthz` 成功只说明进程级状态，不证明内核已启动或 UDP 已放行；初始规则失败重试期间进程可以保持运行。

v8 Linux/netns、重启/reload、多实例、双后端拒绝规则和正式发行资产验收：**待本轮结果填写**，见 [v8 发行说明](RELEASE-v1.13-orphan.8.md)及同版 `VERIFICATION.json`。

历史验证（2026-10-25，v6 候选）：专用 Linux VM 共47项检查，包含双内核 standalone、machine、权限与冲突，使用隔离 IPv4、真实 TLS/QUIC 和45秒会话；详见[历史报告](https://github.com/ksr-v/Xboard-Independent-NodeEndpoint/blob/main/docs/HYSTERIA2_AUTO_FORWARDING_REPORT.md)。这些结果不包含 v8 INPUT 功能，也不计入 v8 总数。公网、原生 ARM64、商业客户端和长期负载不能由本地测试推定。
