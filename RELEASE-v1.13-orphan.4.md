# Xboard-Node v1.13-orphan.4

v1.13-orphan.3 未公开发布：Linux CI 发现外来文件测试夹具沿已有符号链接写入目标，没有实际创建外来文件，产生错误断言。本版先移除夹具链接再创建外来普通文件，保留生产所有权检查；不改写已推送的候选标签。

本版发布新的安装器及同源重建的 Node / xbctl；沿用 v1.13-orphan.2 的 FlowScope 出口 IPv4 功能，不修改代理协议、依赖版本或计量逻辑。

## 安装与管理

- 安装脚本菜单：`1 安装 / 2 卸载 / 0 退出`。面板带参数指令也会显示菜单，通过独立终端 FD 读取；无终端的自动化必须显式 `--yes`。
- 安装检测旧二进制、服务、配置及残留凭据／实例目录，先暂存新文件并完成私有备份，停止 `xboard-node.service` 后归档旧实例目录，再生成仅包含本次目标的当前格式配置。旧绑定及凭据不再合并，避免重复健康端口。
- 已有对接需输入 `REPLACE` 确认；卸载需 `UNINSTALL`。备份位于 `/etc/xboard-node/backups/recovery-*`，含敏感凭据，权限 `700`；`--purge` 也保留备份。
- 安装成功后，小写 `node` 唤出 `1 升级 / 2 重启节点 / 3 卸载 / 0 退出`。升级保留绑定、凭据、实例文件及健康端口（包括 `0`），不重写旧安装元数据。兼容的 legacy 配置不强制重写；无效多实例布局需安装替换。
- 停服失败、异常路径、已有 Node.js／其他程序的 `node` 命令、外来 `xbctl` 链接均拒绝覆盖。仅停止本项目服务，不按端口强杀其他程序，不删除面板记录、历史流量、Python 采集器或外部证书。
- 恢复步骤显式检查失败，恢复不完整时不重启部分配置；回滚恢复原服务启停及启用状态。旧凭据已失效时不能保证旧服务恢复正常。

安装、升级和重启可能中断连接。标准 Linux/systemd 安装以外（Docker、自定义 unit、额外独立服务）需人工确认。

从本 Release 下载 `install.sh` 及对应架构两个二进制，按 `SHA256SUMS` 校验后升级：

```bash
sudo bash install.sh upgrade --version v1.13-orphan.4 \
  --binary ./xboard-node-linux-amd64 --xbctl-binary ./xbctl-linux-amd64
```

ARM64 替换两处 `amd64`。首次安装运行 `sudo bash install.sh`；需要覆盖旧对接时选择安装并确认 `REPLACE`。

## 脱敏与构建

- 源码附件从 Git 提交导出，不包含 `.git`、实际配置、`.env`、凭据、私钥、运行日志、测试产物、备份或 `.dependency-work`。仅测试假值和占位符保留在示例／测试中。
- 发布前对导出的受控源码树、新增 Git 提交及附件执行敏感信息检查；保留 License、上游来源和 Git 历史。已知模式扫描不能绝对保证不存在任何敏感信息，也不代表第三方依赖的全面安全审计。
- 四个 Linux amd64/arm64 二进制使用固定的 582 模块依赖和 Go `-trimpath` 重建，移除本机绝对源码路径，不复用旧 Release 的二进制。
- 已有 v1.13-orphan.2 Release 不覆盖。旧二进制没有启用 trimpath，仍可能含旧构建机路径；本次仅清理新版附件，不改写历史 Release 或 Git 历史。

## 验证边界

回归命令：`python tools/test_dependencies.py`、`python tools/test_installer.py`、`python tools/test_replacement.py`。前一轮安装器 48 项隔离测试中 47 通过、1 因 Windows 无原生符号链接权限跳过；真实链接生命周期不以模拟结果替代。

发布页记录本次构建、扫描、ELF 架构／内嵌版本／提交和附件校验结果。真实 Linux/systemd 安装升级、cgroup／端口释放、管道控制终端验收、原生 ARM64 运行、生产面板和客户端连续性仍未验证。用户此前选择不执行的真实客户端流量验证不会自动恢复。

远程 CI 的固定依赖 `dependencies-d2ab7c680c219e58` Release 在公开仓库缺失，恢复依赖阶段仍可能失败；不把本地构建或测试描述为远程 CI 通过。本次不额外公开依赖快照，不修改生产环境，也不主动额外发布 Docker 镜像；既有工作流仍按其规则触发。
