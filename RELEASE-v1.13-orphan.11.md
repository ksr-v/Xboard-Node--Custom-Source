# v1.13-orphan.11：运行入站防火墙管理与自愈

日期：2026-11-01（Asia/Shanghai）。状态：正式发行，最终发布字节已通过专用本地虚拟机验证。源码基于正式 v10，保留其 nftables 1.0.6 旧 NAT 归属兼容修复。

## 修复的问题与新行为

旧 INPUT 模块只接受 HY2，并固定生成 UDP 规则。VLESS 虽可正常启动 TCP 监听，却没有相应放行路径，遇宿主 INPUT 的 REJECT/DROP 时外部连接被阻断。v11 从 sing-box / Xray **已经成功应用**的配置读取实际监听地址、端口与 socket 协议，不把面板期望值当成运行状态，也不硬编码443。

VLESS、VMess、Trojan 按实际底层传输生成 TCP 或 UDP 权限；Shadowsocks 支持同端口 TCP/UDP；HY2、TUIC 使用 UDP。VLESS 使用25444等有效端口时走相同路径，修改端口后同步新权限并清理不再使用的旧权限。失败候选不会先被放行。未知协议或不能证明监听成功的情况明确报告，不猜测开放；SingBox SOCKS 的动态 UDP ASSOCIATE 不误放固定同号端口，Naive 的可独立失败 HTTP/3 监听暂不自动管理。

## 管理、诊断与恢复

- 继续复用每节点 `XB_IN_<owner摘要>` 链和完整所有权标记，只维护精确 TCP/UDP、端口及适用地址的 ACCEPT，末尾 RETURN。自有 jump 保持在 INPUT 连续自有前缀，优先于宿主终止规则。
- 新增运行注册表、逐端口诊断和写后验证。`rule_status` 表示 Node 自有权限，`effective_status` 表示可证明的本地 INPUT 判定；复杂规则或信息不足时为 unknown。
- 生命周期变化及每30秒独立检查协调规则。缺失、重复、端口/协议错误或移位规则在所有权可证明时修复；停止、删除、改端口只调整对应权限。存活的禁用实例也参与 owner 保护。
- INPUT 失败明确告警并重试，不因此关闭其他节点或阻止已经成功启动的内核运行。HY2 NAT 仍独立执行其原有预检与回滚。
- `xboard-node firewall status|check|ports|diagnose|repair` 与 `xbctl firewall` 查询同一运行进程；前四项只读，仅 repair 写入已获本地授权的实例。`check/repair` 未解决问题时返回非零。控制端点是 root 私有 Unix socket，不扩展未鉴权健康 HTTP 接口。
- 不写宿主 `rules.v4/v6`，不新增恢复常驻服务。unit 仅通过 `After=` 晚于 netfilter-persistent/nftables/UFW/firewalld，Node 从成功运行快照重建，运行中 reload 由周期协调恢复。

详见[实施前审计](FIREWALL-AUDIT.zh-CN.md)、[运行与回滚说明](FIREWALL-MANAGER.zh-CN.md)、[测试报告](FIREWALL-TEST-REPORT.zh-CN.md)及[修改清单](FIREWALL-CHANGES.txt)。

## 兼容性与升级注意

本地授权方式保持：标准 unit 的 `XBOARD_NODE_MANAGED_INPUT=1` 才授予自动管理权限，`firewall.managed_input: false` 可关闭；面板不能授予这项权限。启用管理时每个网络命名空间只运行一个 Node 进程，进程内可以有多个节点或实例。

工具安装与后端活动分开检测：legacy-only 不额外激活 nft，nft-only 不激活 legacy；两套过滤 hook 都活动时按两套已活动路径协调，不改系统 alternatives。UFW、firewalld、额外原生 nft INPUT 或未知所有权冲突明确报告并拒绝接管。若旧版本曾在 UFW 前自动插入权限，升级前应先在 UFW 中配置实际端口，不能依赖绕过其策略的旧行为。云安全组和上游网络仍由管理员管理。

保留 v10 的逐地址族 NAT、旧表归属确认和 nft1.0.6注释兼容，保留旧 nft0.9保守策略、ACME 域名规范化、面板通信、数据同步、流量统计、证书和集中在线IP准入逻辑。

新解析器兼容旧单 UDP + RETURN 链；旧二进制不认识新增 TCP 或多条 ACCEPT。回滚前必须先让新版干净停服并确认自有链清理，再恢复旧程序；恢复旧版后 TCP 等权限需管理员管理。不要用 flush 或全局规则覆盖进行回滚。[升级与回滚步骤](UPGRADE-v1.13-orphan.11.zh-CN.md)

## 构建与验证记录

固定 Go **1.26.8**，固定 `build_time=2026-10-31T16:00:00Z`，生产 tags 为 `with_quic,with_utls,with_wireguard,with_acme,with_clash_api`。维护内核 modfile、固定依赖快照、`CGO_ENABLED=0`、`-trimpath -buildvcs=false` 保持。四个 Linux Node/xbctl 的实际 SHA256 在最终构建后写入安装器，`SHA256SUMS` 与源码/构建提交证明另行核验。

发布前使用授权的本地虚拟机 Debian **12**、内核6.1、nftables **1.0.6**、iptables **1.8.9** 测试最终发布字节，包括任意 VLESS TCP25444端口及端口变更。该环境不等于 Debian13，实际完成项目、数量、跳过项及原生/交叉编译范围以同版 `VERIFICATION.json` 和测试报告为准；本次实际通过18个Linux包、460项顶层测试，12个INPUT实包场景及两轮各9项实际Node端到端场景；3包75项race测试通过。旧版数量不累加。

standalone 连通测试不等于真实 Xboard 面板迁移；VLESS TCP 握手不等于 Reality/TLS/认证代理业务，HY2 QUIC版本协商不等于认证业务流量。公网、云安全组、商业客户端、长期负载及原生ARM64不能从本地AMD64测试推定。公开源码及附件不包含真实配置、Token、私钥或依赖缓存；发布后须重新下载公开附件核对完整摘要和 tag 指向。
