# 升级到 v1.13-orphan.11

本说明对应正式 v11；使用下列固定 tag 命令前，核对同版验证记录和资产摘要。版本说明见 [v11](RELEASE-v1.13-orphan.11.md)，完整防火墙权限和边界见 [Firewall Manager](FIREWALL-MANAGER.zh-CN.md)。

## 升级前

备份现有 Node、xbctl、配置、凭据、unit 及管理员自己的宿主持久化规则。配置和恢复备份可能包含Token，使用原有受保护目录和权限，分享诊断前脱敏。已有实例升级使用 `upgrade`；新安装的 `REPLACE` 会替换全部旧对接，不能当成普通升级。

检查本机实际防火墙管理关系。v11 会对成功运行的 TCP/UDP 入站自动创建自有权限，例如 VLESS TCP25444，无需端口专用配置；但 UFW、firewalld、额外原生 nft INPUT 或未知归属冲突会拒绝自动接管。此类机器应先在对应管理器中放行实际端口，或明确采用手工管理；不要依赖旧版在 UFW 前插规则的行为。

每个网络命名空间只运行一个启用自动管理的 Node 进程，同进程可含多个实例。跨进程禁用实例不能参与同一内存注册表，不能与自动清扫共享旧自有链。云安全组、路由和外部端口范围仍需管理员放行。升级、配置重载和重启可能中断连接，请安排维护窗口。

## 标准 Linux/systemd 安装

在 Bash SSH 终端执行：

```bash
node_script=$(curl -fsS --proto '=https' --max-time 30 --max-filesize 65536 https://raw.githubusercontent.com/ksr-v/Xboard-Node--Custom-Source/v1.13-orphan.11/install.sh) && [ -n "$node_script" ] && sudo bash -c "$node_script" -- upgrade
```

此流程保留配置、绑定、实例目录、私有CA和健康端口，同时配套更新 Node、xbctl 和管理菜单。安装器只接受 v11 的四个固定二进制摘要；镜像和本地文件也必须匹配，不能混用旧版程序。首次配套更新后，后续可输入小写 `node` 选 **1**，由菜单查询并校验最新正式 Release。

离线升级时，把同版已校验的安装器和对应架构二进制放在受保护目录：

```bash
sudo bash install.sh upgrade --version v1.13-orphan.11 \
  --binary ./xboard-node-linux-amd64 --xbctl-binary ./xbctl-linux-amd64
```

ARM64 使用同版 `*-linux-arm64`。先校验公开 Release 的 `SHA256SUMS`，安装器执行前还会逐个核对固定 pin。Docker、自定义unit、额外独立Node进程或不完整安装需按实际部署处理，不能套用标准安装器。

## 管理开关与开机恢复

标准 unit 默认 `XBOARD_NODE_MANAGED_INPUT=1`。已有关闭设置在升级时保留；本地 YAML `firewall.managed_input: false` 同样保留。需要明确关闭自动 INPUT 时，在上述命令末尾增加 `--skip-firewall`，或使用离线命令的同名选项；这不关闭 HY2 `port_hopping` 的独立 NAT 管理。

Node 不覆盖 `/etc/iptables/rules.v4/v6`，不写全局快照，也不注册额外恢复守护进程。unit 仅声明晚于宿主防火墙恢复服务的顺序；启动后依据成功运行的入站重建，运行中规则丢失/移位由独立30秒检查修复，另计命令执行耗时。不能把这一机制当作云端或防火墙reload后的零延迟可达保证。

## 升级后验证

```bash
xboard-node -v
xbctl version
sudo systemctl status xboard-node --no-pager
sudo xboard-node firewall ports
sudo xboard-node firewall check
sudo xboard-node firewall diagnose --output json
```

两个程序都应显示 v1.13-orphan.11。`ports` 应列出实际成功运行的监听，包含正确 TCP/UDP、地址、端口和实例。`check` 只读，未解决问题返回非零。区分 `rule_status` 自有权限完整性和 `effective_status` 可证明的本地 INPUT 结果；unknown 不等于已放行，也不表示可以安全自动接管。

对可自动修复的已授权实例执行：

```bash
sudo xboard-node firewall repair
sudo xboard-node firewall check
```

原生 nft/UFW/firewalld/未知所有权冲突先由管理员处理，不能通过关闭整个防火墙解决。`systemctl active` 或 `/healthz` 不能证明外部端口可达，还需从外部客户端验证实际代理业务。发布测试使用本地 Debian12（kernel6.1、nft1.0.6、iptables1.8.9），不能声称覆盖原始Debian13、真实面板或公网；以最终验证记录为准。

## 回滚

1. 先用仍在运行的 v11 干净停止服务，检查自有 INPUT/NAT 是否清理。不要先覆盖二进制再用旧版尝试解释新规则。
2. 恢复同次备份的旧 Node、xbctl 和unit，保留原配置/私有CA。旧版本不认识 v11 的 TCP/多条 ACCEPT 链，旧 v8 也不认识新版 NAT 归属格式，必须先确认清理。
3. 重新加载unit并启动旧服务。旧版HY2按其原策略重建，TCP等权限由管理员明确管理；再从外部验证业务。

清理或回滚失败时保留本地诊断和恢复材料，仅按完整 owner 标记核对对应自有资源；不要清空INPUT、删除其他程序链或全局恢复旧规则覆盖宿主后续更新。安装器升级失败会尝试恢复同次备份并检查服务，恢复失败会明确报错，不保证修复原先已经失效的面板Token或配置。
