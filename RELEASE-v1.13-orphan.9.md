# Xboard-Node v1.13-orphan.9

日期：2026-10-30。本版修复旧 nftables 的空规则集读取和跳跃 NAT 兼容问题，以及 ACME 域名大小写导致的 Order / CSR 不一致。保留 v8 的本地授权 HY2 INPUT 管理、周期修复及既有节点功能。

## 变更

- 旧 nftables 在空规则集时可能返回空文本或 `{"nftables":null}`。只有 JSON 命令成功、输出符合受支持的空形式，且独立 `nft list tables` 成功确认为空，才接受为空规则集；不忽略权限错误、畸形输出或实际存在的表。
- 跳跃 NAT 统一按地址族使用 `ip` / `ip6` 表，以非 hook 的 owner chain 内完整 marker 规则确认归属，不再依赖 inet NAT 或 table comment。迁移旧 v8 `inet` 表时核对完整旧 marker 和表内对象；未知附加对象或归属不符时拒绝删除。两地址族和已验证的旧表由同一次 nft 批处理协调，不清空外来规则。
- nft 0.9.0 对某些 iptables-nft 兼容表达式不能可靠输出 JSON。本版对确认的该版本，仅在没有活动 nft INPUT 且规则可完整读取时使用显式 legacy IPv4/IPv6 工具，不改系统 alternatives；已有 nft INPUT 或不可安全读取时在写入放行规则前拒绝。现代工具的后端选择保持不变，不通过剥离警告绕过解析。
- ACME 域名在申请、存储读取和配置指纹处统一去除首尾空白并转小写，避免 DNS Order 已转小写而 CSR 保留大写造成不匹配。大小写或首尾空白的单独变化不触发重新申请；沿用现有证书、私钥与存储，不删除缓存，不跳过 TLS 校验。通配符和 IP 的既有校验继续适用，不扩展为任意 IDN 或尾点形式的兼容承诺。

## 部署和边界

按 [v9 更新教程](UPGRADE-v1.13-orphan.9.zh-CN.md)使用 `upgrade`，保留绑定、Token、私有 CA、实例文件和健康端口。仅更新面板插件不会替换 Node；旧插件生成的固定 v8 命令也不会自动变为 v9。

标准 unit 继续使用 `XBOARD_NODE_MANAGED_INPUT=1`；`--skip-firewall` 写为 `0`，后续升级保留关闭选择。本地 `firewall.managed_input: false` 优先关闭 INPUT，自定义服务无环境授权默认关闭。面板不能授予该权限。每个网络命名空间只启用一个受管 Node 进程，同进程可包含多个节点。

INPUT 仍只支持可识别的 iptables-nft / iptables-legacy 布局，并受上述 nft 0.9.0 限制；额外原生 nftables/firewalld INPUT base chain 不受支持，检测依据是规则而不是服务状态。云安全组和外部防火墙仍需放行。30秒周期修复另计串行命令时间；多后端失败恢复是补偿操作，不保证整体原子回滚。详见 [HY2 权限与数据路径](HY2_PORT_HOPPING.md)。

v8 不能识别 v9 的逐地址族 NAT 归属格式。回退前先让 v9 正常停止并确认 owned INPUT/NAT 已清理，再运行旧程序；SIGKILL 或断电留下的规则需管理员核查，不要 flush 全局规则。

## 构建和验证记录

使用固定 Go 1.26.8、`release-build.json` 元数据和 `-trimpath -buildvcs=false`。正式源码来源、四个 Node/xbctl 资产、安装器摘要、Linux/race/解析夹具、旧 nftables CLI/内核、隔离 netns 与公开下载结果记录在同版 `VERIFICATION.json` 和 `SHA256SUMS`，以记录中的实际环境和执行范围为准。

空规则集夹具不能单独证明旧内核上的真实转发；现代内核运行旧 CLI 也不能证明 Linux 4.19。证书回归不需要向生产 ACME CA 申请证书。公网生产升级、原生 ARM64 代理流量、商业客户端、任意防火墙布局和长期负载不能由本地测试推定。

2026-10-30 的 [v8 说明](RELEASE-v1.13-orphan.8.md)保留此前 INPUT 与正式资产验收；v6/v7 及旧面板报告均为历史证据，不计入 v9 总数。旧标签和资产保持原样。
