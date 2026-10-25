# Xboard-Node v1.13-orphan.6

本版增加 Hysteria2 自动 UDP 范围转发，以及 `node` 管理菜单中的面板地址／Token 修改、最近日志、状态和按最新正式 Release 在线更新。配套版本为独立后端 **v2026.10.25.2**、NodeEndpoint **1.0.9**；后端负责校验和下发跳跃范围，插件让以后复制的新机安装命令使用 v6。

正式v6资产17项检查全部通过：13项真实PTY/systemd/SQLite面板管理和4个程序版本smoke（amd64原生、arm64 QEMU）。实际执行同版正式v6升级，绑定、健康端口和CA保留，篡改拒绝、失败恢复及权限通过；下载运输使用受控Release，不是公网Root更新执行。最终源码摘要和完整结果由同次 `VERIFICATION.json` 记录。以下另列候选源码功能测试，保持两类证据的范围。

## 变更

- Node 按面板 `port_hopping` 范围建立、更新和撤销 nftables UDP 转发，支持 sing-box、Xray 和 standalone／machine 模式。仅管理带 owner 摘要的自身表，使用原子更新与生命周期锁；拒绝端口、外部 NAT、同实例进程和其他节点规则冲突。正常停服清理；异常退出后同实例重启核对自身遗留规则。
- 标准安装器补装 `nftables`，在替换程序前检查工具可用。服务仍保留 `NoNewPrivileges=true`；启用跳跃需要 `CAP_NET_ADMIN`、Linux NAT 和可写 `/run`，权限不足明确报错，更新失败保留原配置并重试。不会清空全局规则、改 INPUT 默认策略或开启云安全组。
- SSH 输入 `node`，可修改选定实例的面板地址／Token，保留 machine/node ID、实例身份、数据目录、私有 CA 和其他绑定。Token 隐藏输入，先通过新地址的真实 API 认证与 TLS 验证，再备份、提交和恢复原服务状态；失败尝试回退。
- 配置编辑器拒绝自定义 unit、drop-in、standalone 和无法安全编辑的 YAML，避免写入服务实际未使用的文件。多个绑定共用旧 Token 引用时，新 Token 单独隔离。
- 菜单选1从本项目最新正式 Release 下载安装器与校验清单；核对仓库／tag／资产摘要、完整字节和 Bash 语法后才执行 `upgrade`。不执行 dev 脚本，不自动退回旧源。每个正式安装器仍固定本版四个二进制摘要。
- 菜单选5只显示 `xboard-node.service` 最近100行日志，选2重启并检查原健康端口。系统已有其他 `node` 命令时不覆盖。v5 的限速、路由与维护内核修复继续保留，固定依赖版本、来源和许可证不变。

## 安装与更新

旧节点首次按[本版更新教程](UPGRADE-v1.13-orphan.6.zh-CN.md)执行固定 v6 `upgrade`，配套替换 Node、xbctl 和菜单。以后直接输入 `node` 选 **1**。不要用新机安装或 `REPLACE` 来升级已有绑定。

Hysteria2 自动转发须先更新配套后端，再逐台升级 Node。主机 INPUT 需允许转发后的实际监听端口，云安全组／外部防火墙需允许广告 UDP 范围；自动 NAT 不能替代这些允许策略。范围或内核更新会使该节点已有连接重连；升级与服务重启也会中断连接。

无需卸载插件、重建 NodeEndpoint CA 或重置 Token。只升级插件不能替换旧后端或节点程序。Docker／自定义服务按其原部署方式替换程序并处理网络命名空间，不套用 systemd 菜单安装器。

本 Release 需提供两个架构的 Node／xbctl、匹配的 `install.sh`、`SHA256SUMS`、更新教程和脱敏验证记录。历史 tag、Release 与资产保留，不覆盖旧版。首次执行入口仍需信任固定仓库标签和 GitHub HTTPS，摘要校验不等同于发布签名。

## 验证与限制

- 自动转发候选源码：专用 Linux VM **47/47**，包括两内核真实 TLS/QUIC、5秒跳跃持续45秒的同一 TCP／UDP 会话字节校验，真实后端／NodeWorker 保存通知、范围更换／撤销、规则冲突、权限拒绝、退出清理及异常退出接管。后端另有12项新增校验与下发检查，原13项限速／路由回归通过。[完整报告](https://github.com/ksr-v/Xboard-Independent-NodeEndpoint/blob/main/docs/HYSTERIA2_AUTO_FORWARDING_REPORT.md)
- 菜单候选源码：**13/13** 真实 PTY/systemd/Node/SQLite 面板检查，涵盖隐藏输入、绑定修改、认证失败不变更、实际重启、失败恢复、停止状态和权限。在线更新使用受控、固定摘要的 `v9.99.0` 测试 Release 验证实际替换和篡改拒绝，没有执行公网下载的 Root 更新器。日志菜单用哨兵检查调用范围，没有读取 Root 私有运行日志。[完整报告](https://github.com/ksr-v/Xboard-Independent-NodeEndpoint/blob/main/docs/NODE_MANAGEMENT_TEST_REPORT.md)
- 安装器26项中25通过、1项外部分发镜像路径跳过；新菜单7项隔离测试通过。相关 Go 包的生产 tags、Linux `-race` 通过。正式程序与发布资产验收以本 Release 的 `VERIFICATION.json` 为准。

公网生产升级、跨公网 NAT、实际 IPv6、商业客户端、原生 ARM64 代理流量、新 Node Docker 镜像运行及长期压力未完成验收。本地通过不表示远程 Actions 已通过；查看本次提交实际 CI 状态。公开包不包括实际配置、Token、CA 私钥、原始诊断日志或依赖工作目录，程序使用 `-trimpath`。
