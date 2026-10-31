# 运行入站防火墙管理与诊断

本次源码实现从双内核已经成功应用的 `activeConfig` 读取入站监听，不从面板期望值推测端口。根因、旧架构和实施前方案见 [审计报告](FIREWALL-AUDIT.zh-CN.md)。本文件对应 v1.13-orphan.11；四个二进制及安装器摘要已配套固定，旧版安装器下载的二进制不包含本功能。

## 使用

标准服务需保留 `Environment=XBOARD_NODE_MANAGED_INPUT=1`。本地配置 `firewall.managed_input: false` 可关闭自动 INPUT；面板不能开启这项本机权限。自定义部署默认关闭，需管理员显式授权。自动管理范围要求每个网络命名空间只运行一个 Node 进程，进程内支持多个实例和节点；跨进程的非管理实例无法参与进程内存活 owner 保护，不应与自动清理共享旧版自有链。

服务运行后以 root 执行：

```bash
sudo xboard-node firewall status
sudo xboard-node firewall ports
sudo xboard-node firewall check
sudo xboard-node firewall diagnose --output json
sudo xboard-node firewall repair
# xbctl firewall 支持相同子命令
```

`status/check/ports/diagnose` 都只读。`check` 在发现未解决问题时返回非零；`repair` 只修复已经获得本地授权的实例，修后仍有问题也返回非零。`--json` 等价于 `--output json`。未运行、非 root 或控制接口不可用时，明确报告 unavailable；CLI 不读取历史端口快照，不启动第二个规则写入进程。

控制端点为 `/run/xboard-node-firewall/control.sock`，父目录 root 0700、socket 0600，双向检查 Unix peer 身份，使用有所有权标记的独占锁。保留未知对象，拒绝抢占活动端点，可恢复本模块留下的已停止端点。原 HTTP `/healthz` 不承载防火墙修改权限，也不代表外部入站健康。

## 端口与状态

每项记录含 `instance_id/node_id/protocol/transport/listen_address/listen_port/runtime_status/rule_status/effective_status/managed`。`transport` 指宿主监听 socket 的 TCP/UDP，不是代理隧道内承载的流量。

- VLESS、VMess、Trojan：读取生成配置里的底层传输；TCP/WS/gRPC/XHTTP 等使用 TCP，内核支持的 KCP/QUIC/Hysteria 传输使用 UDP。
- Shadowsocks：读取已应用的 network 设置，默认 TCP 与 UDP 均登记。
- Hysteria/Hysteria2、TUIC：UDP。
- HTTP、AnyTLS：TCP。SingBox SOCKS 固定监听仅为 TCP；UDP ASSOCIATE 动态 socket 不误放同号 UDP。Xray SOCKS 按实际设置登记 UDP。
- Mieru：按实际传输登记。未知协议/传输明确报告未支持，避免猜测权限。
- Naive 的 HTTP/3 可能独立绑定失败而总体启动成功，单靠成功配置不能证明 UDP 已启动，当前保守报告未支持，需管理员管理该协议的防火墙。

`rule_status` 表示 Node 自有权限的完整性；缺失自有权限不等同于宿主机已经阻断。`effective_status` 表示能否证明当前本地 INPUT 路径允许/阻断：复杂外部链或无法确定的条件报告 unknown。即使本地允许，也不能据此证明云安全组、上游网络或认证代理会话正常。

`::` 按现有双栈监听语义协调可用地址族，`0.0.0.0` 为 IPv4，具体地址使用精确目标地址匹配。未成功启动、已停止、无效配置不会产生候选端口放行；用户列表变为空但内核仍监听时，依据真实内核运行状态保留登记。

## 自愈与后端

生命周期为：保留 HY2 NAT 预检 → 内核成功启动/更新 → 读取成功快照 → 同步 INPUT → 重读验证。INPUT 失败记明确警告，内核继续运行并周期重试。NAT 的原有配置预检和回滚语义保持。运行切换与 CLI repair 共用每实例锁，防止旧快照在停服后重新开端口；所有 INPUT 写入还受进程串行锁、跨进程 flock 和 xtables 事务锁保护。

独立30秒 ticker 不依赖面板 WS 连接。启动、配置变更、端口变更、实例停止与删除都会同步；检测到缺失 ACCEPT、RETURN、jump、错误端口/协议、重复或移位 jump 时，依据完整所有权证据修复。周期包括实际规则读取/命令耗时，不是外部 reload 后零延迟恢复；宿主防火墙反复重载时可能有短暂不可达窗口。

规则继续使用原 `XB_IN_<owner摘要>` 链和 `xboard-node-input:v1:<完整摘要>` comment。仅修改严格验证的自有链和 INPUT jump，使用 `restore --noflush`，不声明或清空宿主链、不改默认策略。自有 jump 位于 INPUT 连续自有前缀，所有放行都精确限定 TCP/UDP、端口及适用地址，末尾 RETURN。不生成 ACCEPT ALL。

后端选择依据实际活动过滤 hook；工具已安装与实际活动分别报告。legacy-only 不额外激活 nft；nft-only 不激活 legacy；均未活动时选择一种可用后端。若 nft 与 legacy 均活动，两套 hook 都可能丢包，因此在两套已活动路径中协调自有权限，并显示实际选择。不开全局 alternatives。

原生 nft INPUT base chain、UFW、firewalld 或不明确所有权的规则报告冲突，拒绝接管；需要管理员在对应管理工具中放行，或统一管理结构。额外 raw/mangle/上游链等超出 INPUT 协调范围，不能用本模块证明端到端可达。旧 nft 0.9.0 保留现有保守兼容策略。规则中途变动或写后校验失败会报告错误并保留重试，不输出可能包含隐私的任意命令 stderr。

查询和修复按实例串行执行，单个外部命令有2/5秒超时；CLI连接30秒后超时并不取消已经开始的协调。大量节点或异常工具环境下，应检查服务日志和后续 status，避免把 CLI 超时当成已回滚。

## 持久化与 netfilter-persistent

不运行 `iptables-save > /etc/iptables/rules.v4`，不改宿主保存文件，不注册额外恢复守护进程。systemd unit 添加 `After=netfilter-persistent.service nftables.service ufw.service firewalld.service`，同时保留 network-online；仅声明顺序，不强制启动这些宿主服务。

系统启动时宿主恢复服务先恢复自己的规则，Node 成功启动实际入站后重建自有权限。运行中 netfilter-persistent reload 移除或重排规则时，由周期协调恢复。检测到的安装程序和 `rules.v4/v6` 文件存在状态仅作为诊断线索，不冒充服务已启用或规则已成功持久化。若持久化文件含旧 Node 链，按严格所有权及存活 owner 检查协调；未知资源保留并报错。

## 升级与回滚

先备份当前二进制、配置、unit 与自己的宿主持久化配置，记录 `firewall diagnose --json` 和二进制摘要。在隔离环境验证本次候选源码/二进制后，由正式发布流程更新固定版本及下载摘要；使用正式v11安装器及其固定摘要匹配的二进制，不能混用旧安装器。

升级需先干净停止旧 Node，替换新 Node/xbctl 及对应 unit，再启动并运行 `firewall check`。实例 ID、节点 ID、内核目录和 owner 哈希保持稳定；新解析器兼容旧单 UDP + RETURN 的 v1 链。不会改变面板协议、同步、流量统计、证书和 HY2 NAT。

回滚必须先用新版干净停服并确认已清理自有链，再恢复原二进制和 unit。旧版 INPUT 解析器不认识 TCP 或多条 ACCEPT，不能直接在保留新链时启动旧版。恢复旧版后 HY2 按旧策略重建，其他协议的端口由管理员管理；不要清空 INPUT 或全局恢复旧规则覆盖宿主其他程序的更新。清理失败时先保存 diagnose 输出，按完整 owner 标记核对，仅处理对应自有资源。

自动化测试范围、执行环境和未完成的现场验收见 [测试报告](FIREWALL-TEST-REPORT.zh-CN.md)。
