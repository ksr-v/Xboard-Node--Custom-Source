# Firewall Manager 测试与交付报告

日期：2026-10-31（Asia/Shanghai）。实现位于独立维护仓库 `node-reference`。审计先于代码修改完成，见 [审计与方案](FIREWALL-AUDIT.zh-CN.md)；架构、命令、自愈、持久化和升级回滚见 [运维说明](FIREWALL-MANAGER.zh-CN.md)。[完整修改清单](FIREWALL-CHANGES.txt)区分于下述已有改动。

## 本次结论

源码实现、自动化单测和隔离 Linux 实包验证已完成。最终候选的实际 Node 进程能够在 nft/legacy 同时活动、INPUT 默认 DROP 且存在终止 REJECT 的环境中，根据真实成功运行的入站自动放行 VLESS TCP 443 与 HY2 UDP 17443；规则被删除后可以检测并修复，热更新到 8443 后清理旧权限。停止及重新启动不会改变测试宿主原有规则和策略。

尚未在原始 Debian 13 服务器执行“全新安装＋真实 Xboard 面板＋系统重启”最终现场验收。本次没有访问生产面板、使用生产凭据或部署生产服务；后续v11正式字节VM验收见下文补充。不能把以下 standalone、网络命名空间结果称为公网或真实面板验收。

## 工具链与环境

- 固定 Go **1.26.8**，使用现有维护内核 `.dependency-work/kernel-build.mod`，保留固定依赖及本地维护补丁；未增加第三方依赖。
- 依赖快照通过仓库 `dependencies.py verify`，校验 **582** 个模块。
- Linux：Ubuntu WSL2，内核 `6.18.33.2-microsoft-standard-WSL2`，nftables **1.1.6**，iptables **1.8.11**，IPv4/IPv6 的 nft 和 legacy 四套工具。
- 防火墙工具通过 apt **download-only** 到任务目录，没有安装到 WSL，没有切换系统 alternatives。工具仅复制到私有 mount namespace 的 tmpfs；服务器和客户端分别使用全新 netns，`/run` 为私有 tmpfs。
- Linux 测试及候选使用生产 tags：`with_quic,with_utls,with_wireguard,with_acme,with_clash_api`。Windows 全仓回归使用项目 HOST_TAGS，随后受影响包按最终修改重测。

## 实际执行结果

| 验证 | 结果与证据 |
| --- | --- |
| Windows 全部 `./internal/... ./cmd/...` | 通过，`all-host-tests.log`；后续 runtime、registry 改动的定向回归也通过 |
| 最终 Linux 内部与 CLI 单测 | **18 个测试包，462 个顶层测试通过**；2 个原有外部 FlowScope 实时环境用例跳过，逐包日志及 `linux-unit-results.json` |
| 防火墙实包集成 | **12 场景通过**，`inputfirewall-netns.test.wsl-all.netns.json` |
| 实际 Node 进程端到端 | **9 场景通过**，`xboard-node-linux-amd64.wsl-runtime.runtime-netns.json` |
| 安装器安全模拟 | 30 项运行，29 通过、1 个既有环境用例跳过；包含生成 unit 的启动顺序与不强拉防火墙服务检查 |
| 候选构建 | Linux AMD64/ARM64 的 Node、xbctl 共4个构建成功；AMD64 实际运行，ARM64仅交叉编译 |
| 静态检查 | `git diff --check`、安装器 Bash 语法通过；新增 Go 文件已 gofmt |

Linux socket 集成不是跳过：真实执行了 root 私有 socket 的权限、锁、重复端点拒绝、已知陈旧端点恢复、未知文件/符号链接保留、只读与显式修复分派。Registry 测试包含100次并发 Repair、生命周期与修复互斥、disabled owner 保护、重复 owner、失败候选、零用户但仍运行监听等。

执行器定向测试覆盖超时、输出上限、退出码、程序不存在和权限拒绝；错误仅保留固定分类，验证不输出私密路径、参数或 stderr。未运行 Go race detector：WSL 没有 C 编译器；显式并发锁与生命周期测试已运行。

## A—I 场景对应

| 场景 | 本次证据 |
| --- | --- |
| A：TCP 443 缺失，HY2 已放行，SSH/REJECT 保留 | 真实 Node+四后端规则，外部 TCP 443 与真实 HY2 QUIC 响应通过；另有单测区分宿主 UDP 已允许和 TCP 已阻断 |
| B：默认 DROP | 实包与 Node 端到端均使用 DROP，未授权端口阻断，外来规则/策略哈希保留 |
| C：中间 REJECT/自有 jump 被移位 | 单测修复被遮挡/重复/丢失 jump，实包删除 jump 后恢复；不依赖固定 REJECT 行号 |
| D：多个实例 | 双实例实际 Node、多个 Manager、关闭 owner 不影响兄弟实例、disabled owner 保留测试通过 |
| E：443 → 8443 | 实际配置 watcher 热更新，新端口可连接，旧 443 不可连接且无旧自有 dport 残留 |
| F：nft/legacy 并存 | 四后端同时活动的真实报文通过；单测另验证 legacy-only 不激活 nft、空环境只选择一种 hook |
| G：重启恢复 | 干净停止后启动新 Node 进程，依据成功 runtime 重建；并有 stale owner/服务启动清理单测。没有执行整机重启或真实 netfilter-persistent boot |
| H：100 次 | 单测及双栈实包100次 check/repair，不产生重复规则；另有100次并发 Registry 修复 |
| I：宿主已有管理器 | UFW/firewalld/原生 nft INPUT 检测及无写入冲突测试通过；真实额外 native INPUT chain 的拒绝测试通过。未对真实 UFW 守护进程启停做集成 |

iptables 默认策略没有 REJECT，相关需求按中间/终止 REJECT 规则验证。

## 实际 Node 端到端的9项

1. 建立双栈 nft/legacy、SSH 22、REJECT、默认 DROP 的合成宿主规则。
2. 实际 VLESS 运行快照进入注册表，外部客户端 netns 可连接 TCP 443。
3. xbctl 与 xboard-node CLI 查询同一运行注册表。
4. 实际 HY2 服务返回外部 UDP QUIC 版本协商响应。
5. 删除自有 TCP ACCEPT 后，check 返回失败且完整规则哈希不变。
6. repair 恢复外部 TCP 连接。
7. 原地修改配置触发 watcher，443 迁移到 8443并清理旧权限。
8. SIGTERM 干净停止后所有外来规则/策略完整哈希与基线一致，CLI 报 unavailable。
9. 新 Node 进程重新启动，自动重建8443及HY2权限，再停服仍保持基线。

VLESS fixture 使用 TLS=0，验证监听与防火墙连通性，没有声称验证 Reality/TLS 或代理认证。HY2 Version Negotiation 是实际 UDP 服务响应，没有声称验证认证业务流量。

## 交付文件及复现

候选、摘要、源码清单和全部日志位于工作区 `release-work/firewall-manager-20261031/`：

- `verification.json`：本次验证汇总及证据摘要。
- `production-source-manifest.json`：当前构建输入的 SHA-256。
- `xboard-node-linux-amd64`、`xbctl-linux-amd64`、`xboard-node-linux-arm64`、`xbctl-linux-arm64`：`firewall-manager-dev` 候选，`SHA256SUMS` 校验。
- `linux-unit-results.json`、逐包 `.linux.log`、上述两个 netns JSON/日志。
- `wsl_netns.py`：本次 download-only 工具包装器；不修改宿主防火墙。`make_evidence.py` 可重新汇总已完成结果。

在具有所需工具的隔离 Linux 测试机，先按仓库维护内核流程准备 modfile，再执行：

```bash
go test -modfile=.dependency-work/kernel-build.mod -tags with_quic,with_utls,with_wireguard,with_acme,with_clash_api ./internal/... ./cmd/...
GOOS=linux CGO_ENABLED=0 go test -c -tags netns -o /absolute/inputfirewall.test ./internal/inputfirewall
sudo python3 tools/test_inputfirewall_netns.py --binary /absolute/inputfirewall.test
sudo python3 tools/test_firewall_runtime_netns.py --binary /absolute/xboard-node --xbctl /absolute/xbctl --label candidate
```

代码入口：`internal/kernel/runtime.go` 与双内核 `runtime.go`；`internal/firewall` 注册表/控制/CLI；`internal/inputfirewall` 规则与诊断；`internal/service/service.go` 生命周期；两 CLI main 和安装器 unit 顺序。新增端到端脚本为 `tools/test_firewall_runtime_netns.py`。

工作区原有 portforward nft 1.0.6 兼容改动、snapshot及service backoff测试均保留，不算本次重新开发。`service.go` 兼有本次修改与原 `delayTicks` 修复，未撤销原修改。v11安装器已固定本次通过VM测试的发行资产摘要；Debian 13真实面板与开机恢复仍需独立现场终验。

## v11 最终字节：指定本地虚拟机验收（2026-11-01）

正式构建基于 v10，固定 Go1.26.8 和维护内核；用户指定VM为 Debian12 / kernel6.1.0-54 / nftables1.0.6 / iptables1.8.9。18包460项顶层单测通过（2个依赖外部FlowScope环境的旧用例跳过），12个INPUT实包场景通过；实际Node分别以443→8443、25444→25445运行，两轮各9项全部通过，外来规则哈希保持一致。三包75项Go race测试全部通过，无跳过或数据竞争。VM实际执行的AMD64二进制SHA与发行附件逐字节一致，ARM64仅交叉编译。

VM首次发现测试fixture受umask022影响，已显式Chmod0777并重跑全套；只修测试，不改通过验证的生产二进制。原开发目录的独立backoff修改没有混入本次发布，因此VM数量与此前开发工作区462项不同。完整机器可读证据见 [VERIFICATION-v1.13-orphan.11.json](VERIFICATION-v1.13-orphan.11.json) 和 [VM报告](verification/firewall-v11/vm-firewall-final-verification.json)。本次不是Debian13、真实面板、Reality认证业务或整机重启验收。

最终安装器pin回填后，在同一Debian VM执行全部102项Python依赖工具、安装器替换/回滚、菜单与Release元数据模拟测试：100项通过、2项环境用例跳过。五项发布资产与安装器固定摘要校验通过。
