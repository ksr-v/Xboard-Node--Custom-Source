# Xboard-Node 依赖恢复验证范围

本报告涵盖当前 Node 仓库的依赖保护、构建和部署验证，不代表整个 Xboard 面板系统已经完成从零灾难恢复。

## 恢复资产

- MVS 选中模块 582 个，当前构建与测试范围使用 179 个。风险分布为 A 114、B 46、C 5、review_required 417；完整清单见 [DEPENDENCY-AUDIT.md](DEPENDENCY-AUDIT.md)。
- 完整保护 127 个模块，保留原始 ZIP、`.mod`、`.info`、Go h1、SHA256 和发现的许可证原文。其他图依赖及历史 go.sum 元数据按审计范围保留。
- 快照为 `module-proxy-d2ab7c680c219e58.zip`，74,065,932 字节，SHA256 为 `32ba04a05003d9f11cac5959bcfe310f82879eaf52b2b81903b7f43a53dfad5f`，可信 pin 见 [dependency-snapshot.json](dependency-snapshot.json)。
- 原 `go-vendor-fea5732.zip` 为 427,225,962 字节，新快照减少 **82.66%**。旧包保留；体积差异及保护范围见 [dependency-size-comparison.json](dependency-size-comparison.json)。

## 构建与恢复

| 验证范围 | 结果 | 边界 |
| --- | --- | --- |
| Windows 构建与受保护上游失效模拟 | PASS | 未在 Windows 执行 Linux 二进制 |
| Linux AMD64 构建、空缓存恢复和版本执行 | PASS | AMD64 原生运行 |
| Linux ARM64 交叉构建与版本执行 | PASS | ARM64 通过 QEMU 运行 |
| 原始与生产 tags 单元测试、Linux race 检查 | PASS | 以当前审计范围为准 |
| 快照损坏、路径安全、覆盖拒绝及依赖文件意外改写门槛 | PASS | 损坏仅注入可丢弃副本 |
| GitHub Actions 构建、恢复、完整性检查和双架构产物 | PASS | artifact 的 ELF、SHA256 和版本已独立核验 |

受保护模块通过临时网关限定为只读本地快照，缺失即失败，不能回退公共代理或 direct。未保护的已审计模块及 checksum database 允许联网。因此验证的是受保护上游全部失效后的恢复能力，不是完全断网恢复。

原始与生产 tags、CGO 测试包图均已核对，未发现当前范围漏保护的模块。更改平台、tags、依赖或测试范围后须重新审计。`go.mod`、`go.sum`、业务代码和安装器保持原版本。

## 面板通信与部署

| 架构与内核 | 机器认证、VLESS TCP/TLS、设备限制、撤销恢复 | 部署方式 |
| --- | --- | --- |
| AMD64 / sing-box、Xray | PASS | 原安装器与持久 systemd 服务 |
| ARM64 QEMU / sing-box、Xray | PASS | QEMU 节点进程 |

验证涵盖机器 token 获取所属节点、握手、配置与用户列表；错误 token、跨机器节点访问及错误 UUID 拒绝；使用受信测试证书并校验 hostname 的 TLS 通信；设备限制、释放后恢复、面板禁用与恢复用户。用户与节点流量核对一致，心跳及统计入库已验证。演练通过限定的临时数据与原始任务处理逻辑完成，原有配置未变，临时数据和私密运行资料已清理。

AMD64 已通过原 `install.sh` 的持久安装、升级、故意失败后的自动回滚和卸载。回滚后程序、配置及部署文件恢复，健康检查和 TLS 通信再次通过。`xbctl config init` 的 node、machine 配置生成已验证。

## Docker

AMD64、ARM64 镜像构建及镜像内程序的 ELF、版本检查通过；sing-box、Xray 的 standalone 连接就绪与优雅停止检查通过。当前 Dockerfile 的双架构构建已在 CI 验证。

连接就绪检查不等于只绑定 loopback；演练使用临时双栈端口隔离并完成清理。Docker 内的真实面板与 TLS 数据流尚未验证，面板通信验证发生在原生 AMD64 和 ARM64 QEMU 节点进程中。

## 未验证范围

- 原生 ARM64 硬件及 ARM64 原生安装器：NOT RUN。
- 旧 node 模式全局 token 认证实联：NOT RUN；node 配置生成已验证。
- WebSocket 推送及跨节点设备数全局协同：NOT RUN；实联覆盖 REST 拉取、上报与撤销恢复。
- Docker 内真实面板和 TLS 端到端数据流：NOT RUN。
- 全新机器从零恢复面板数据库、前端及完整系统：NOT RUN。
- 其他协议组合、TLS 模式、长期生产负载及完全离线恢复：不在本次范围。

当前受保护依赖失效后的双架构构建与上述部署路径已经验证。整个项目的 `INDEPENDENTLY RECOVERABLE` 状态仍需全系统从零恢复验收。
