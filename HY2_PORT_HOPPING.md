# Hysteria2 端口跳跃与 UDP INPUT 自动管理

Node **v1.13-orphan.10** 兼容读取 nftables 1.0.6 在 JSON 中遗漏的旧 inet 表注释，经完整归属和结构校验后自动迁移。继续按 IPv4/IPv6 建立 NAT 表，以完整规则 marker 确认归属，并保留实际 HY2 UDP 监听端口 INPUT 管理。标准安装默认启用，本地管理员可以关闭。只更新面板插件不会更新已部署的 Node，已有机器按 [v10 更新教程](UPGRADE-v1.13-orphan.10.zh-CN.md)执行 `upgrade`。

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

该设置可作为多实例顶层默认值或实例本地配置。文件监视器会重新加载配置并重启进程内服务，现有代理连接需要重连。也可用 v10 安装器升级并关闭：

```bash
sudo bash install.sh upgrade --skip-firewall
```

这会把标准 unit 的环境值写为 `0`，后续升级保留 `0`；已有本地 YAML opt-out 同样保留。此开关只关闭自动 INPUT，端口跳跃 NAT 仍按 `port_hopping` 独立工作。手动管理防火墙时，须自行放行实际监听端口。

节点需 Linux、足够的网络管理权限、可写的受保护 `/run`，以及相应工具和内核支持。标准服务保持 `NoNewPrivileges=true`。规则只作用于 Node 所在网络命名空间；容器中的规则不会自动开放宿主机端口或云安全组。

## 支持范围和规则归属

INPUT 管理覆盖可识别的 **iptables-nft / iptables-legacy、IPv4 / IPv6** 后端，使用每实例的 `XB_IN_<摘要>` chain 和完整归属注释。v9/v10 NAT 使用相应地址族的 `ip xbnode_hop_<摘要>` / `ip6 xbnode_hop_<摘要>`，以非 hook 的 `__xbnode_owner` chain 内完整 marker 规则确认归属，不依赖 table comment。旧 v8 的 `inet` 表仅在完整归属和内容检查通过后迁移；归属不符或出现未知附加对象时拒绝删除。不把 Token、用户 UUID、私钥写入规则；不修改默认 policy，不清空外来规则，不写全局 `rules.v4` / `rules.v6`，不启动 `nftables.service` 加载系统规则。

旧 nftables 的空规则集可能输出空文本或 `{"nftables":null}`。v9 仅在 JSON 命令成功、输出符合受支持的空形式，且独立执行的 `nft list tables` 成功并确认为空时按空规则集处理；权限错误、畸形或有表输出不能借此忽略。逐地址族 NAT、规则注释和 fib 查询降低了最低功能需求，不代表任意旧发行版或防火墙布局都兼容；实际版本和场景见同版验证记录。

**额外原生 nftables/firewalld INPUT base chain 不受支持。** 独立 nft base chain 的 ACCEPT 不能保证覆盖另一个 chain 的 DROP。检测依据是实际规则布局，不是 firewalld 服务是否运行。Node 检测到不支持的布局会拒绝应用新的自动 INPUT 配置，保留待重试状态，不改写该管理器的规则；请关闭本功能并用该管理器配置监听端口。iptables 形式的 UFW 规则可随实际后端处理，但 reload 后可能有短暂阻断，仍需在自己的环境验证。

**nft 0.9.0 的 INPUT 支持进一步受限。** 该 CLI 读取某些 iptables-nft 的 xt 兼容表达式会崩溃，或把警告混入 JSON，不能安全剥离后继续。v9 对确认为 0.9.0 的工具，仅在没有活动 nft INPUT 且规则集能完整读取时选择显式 `iptables-legacy` / `ip6tables-legacy`，不修改系统 alternatives。已有 nft INPUT、缺少必需 legacy 工具或规则不可安全读取时拒绝自动放行；应升级系统防火墙工具，或关闭自动 INPUT 后手动管理。现代工具保持按实际后端处理，不因此强制改用 legacy。NAT 使用原生逐地址族 nft 规则，旧工具限制不等同禁止所有 nft NAT。

启用 INPUT 管理时，每个网络命名空间只运行**一个 Node 进程**；同一进程可管理多个实例和节点。进程生命周期锁避免另一个启用管理的进程接管规则，锁保留到进程退出。各节点使用不同稳定 owner，停止一个节点不会删除同进程其他节点的规则。不要通过复制锁目录来绕过该约束。

NAT 仍会检查现有 UDP socket、重复范围及不明转发冲突，避免截获 DNS、WireGuard 等其他服务。复杂规则无法安全判断时会拒绝；INPUT 支持两种 iptables 后端不代表旧 legacy NAT 冲突也会自动转换。

云安全组、上游路由和外部防火墙仍须放行客户端访问的 UDP 端口或跳跃范围；Node 不调用云平台 API，也不修改外部规则。

## 更新、恢复与持久性

启动、REST/WS 配置更新时，Service 协调 NAT、INPUT 和内核。规则失败不接受新配置；内核候选失败时尝试恢复旧规则和旧运行配置。多后端恢复属于补偿操作，无法承诺整体原子回滚；补偿失败会单独报错并继续重试。初始网络规则暂时失败时保留待应用配置进入主循环，不因 machine 节点已登记而永久停止重试。

独立的 **30 秒**检查在 WS 连接或断开时都运行，修复当前成功应用配置的 INPUT 与 NAT；不会把已拒绝的待应用配置当成当前规则。仅内核运行且存在用户时保留规则，否则清理。防火墙 reload 后的恢复属于周期修复，等待30秒检查周期之外还包括串行命令执行耗时，期间可能暂时无法连接；不是写入全局保存文件后的即时持久化。

正常停止、重启、卸载先停内核，再清理 owned INPUT/NAT；配置文件重新加载等待旧 Service 清理后再启动。SIGKILL、断电无法执行退出清理；后续启用管理的进程会在严格核对归属后回收旧 INPUT 资源，NAT 按稳定实例核对。v8 不能识别 v9/v10 的逐地址族 NAT 归属格式，回退前须让新版正常停止并确认清理，再运行旧二进制。关闭管理或回退旧版，不能保证回收此前强制退出留下的资源；异常时由管理员检查，不要 flush 整套规则。

## 验证范围

先确认实际单端口 HY2 代理可用，再检查跳跃范围、其他端口仍被拒绝，以及正常停止后的清理。`systemctl is-active` 或 `/healthz` 成功只说明进程级状态，不证明内核已启动或 UDP 已放行；初始规则失败重试期间进程可以保持运行。

v10 的旧表注释兼容、严格归属迁移和正式资产验收范围记录于 [v10 发行说明](RELEASE-v1.13-orphan.10.md)及同版 `VERIFICATION.json`；记录区分解析夹具、实际 CLI/内核和真实 UDP 验证，不把其中一项等同全部环境可用。[v9 说明](RELEASE-v1.13-orphan.9.md)保留旧空规则集和逐地址族 NAT 验证，[v8 说明](RELEASE-v1.13-orphan.8.md)保留此前 INPUT 验收；历史数量不计入 v10 总数。

历史验证（2026-10-25，v6 候选）：专用 Linux VM 共47项检查，包含双内核 standalone、machine、权限与冲突，使用隔离 IPv4、真实 TLS/QUIC 和45秒会话；详见[历史报告](https://github.com/ksr-v/Xboard-Independent-NodeEndpoint/blob/main/docs/HYSTERIA2_AUTO_FORWARDING_REPORT.md)。这些结果不包含 v8 INPUT 或 v9 兼容修复，也不计入本版总数。公网、原生 ARM64、商业客户端和长期负载不能由本地测试推定。

## nft 1.0.6 旧表迁移

v10 在 JSON 遗漏旧 inet 表注释时，定向读取同一张表的文本注释，并重新读取 JSON 核对 handle、完整归属和表内对象。只迁移当前实例且结构完整的旧表；未知实例、缺失或不符的 marker、附加对象、并发替换及重叠外来 NAT 均拒绝自动清理。排查和人工恢复步骤见 [v10 升级说明](UPGRADE-v1.13-orphan.10.zh-CN.md)。
