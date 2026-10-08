# Xboard-Node 依赖维护与恢复

本指南只修改和构建当前 Node 仓库。不要将 Module Proxy、Go 缓存、Token 或运行配置提交 Git。Python 3.9+ 为日常工具依赖；Go 版本至少满足 go.mod（当前 1.26），安装器仍使用原来的 systemd 和本地二进制方式。

## 已保护与仍需联网的内容

完整清单见 `DEPENDENCY-AUDIT.md`、`dependency-lock.json`。当前完整保护 127 个模块，包含 5 个 C 类、当前可达中风险和待复核模块。114 个 A 类模块默认源码联网，其中实际当前构建/测试使用 52 个；其他未使用平台/功能的图依赖只保存元数据，扩展构建范围前须重新审计。

分类依据、128 个仓库的维护证据、许可证及范围限制见 `DEPENDENCY-STRATEGY.md` 和 `dependency-evidence.json`。完整历史 checksum 仍在 go.sum；不自动升级、删掉或重写它们。

## 从本地备份恢复

需要同时保存：项目源码与当前 lock/policy/snapshot pin，以及 `.dependency-work/exports/` 中 pin 指定的 ZIP 和 SHA256 文件。把这些复制到独立磁盘或独立存储；同一磁盘的暂存目录不能视作防硬盘故障的第二份备份。GitHub Release 只是分发渠道，本地归档可以完全替代它。

源码可在提交后通过 `git bundle create /your/backup/xboard-node-source.bundle --all` 保存完整本地历史，再用 `git bundle verify /your/backup/xboard-node-source.bundle` 检查。新机器使用 `git clone --branch dev /your/backup/xboard-node-source.bundle Xboard-Node` 恢复源码；同时保留 bundle 的 SHA256 并从可信位置核对。bundle 不包含未提交内容、Go 工具链或 `.dependency-work`，因此依赖 ZIP 必须另存。

Windows PowerShell 示例（Linux 使用 python3 并将 pin 的 archive、sha256 填入命令）：

```powershell
$pin = Get-Content dependency-snapshot.json -Raw | ConvertFrom-Json
python tools/dependencies.py restore --archive "/your/backup/$($pin.archive)" --sha256 $pin.sha256
python tools/dependencies.py verify
python tools/dependencies.py build --arch amd64
python tools/dependencies.py build --arch arm64
python tools/dependencies.py test --host
```

恢复目标默认为 `.dependency-work/snapshot`，必须为空或不存在。已有暂存数据时请通过 `--snapshot` 指定一个新目录，手动核对后再决定保留方式，不要清空历史备份。非默认目录构建时也传同一个 `--snapshot`。

如果当前仓库的固定依赖 Release 已发布且 gh 已登录，可运行 `python tools/ci_snapshot.py`；它只下载 pin 指定的 tag/asset，按源码固定的 SHA256 校验。也可以 `python tools/ci_snapshot.py /absolute/path/to/archive.zip`，完全不访问 GitHub。

## 日常维护

```sh
# 新增/更新依赖或改变策略后先审计，建立当前可达图；未知依赖先保守保护
python3 tools/dependencies.py audit
# 重新收集官方维护证据（需要 gh 登录，只读；不访问原维护者仓库）
python3 tools/dependency_evidence.py
# 将新证据重新用于风险分类；两架构包图、测试依赖与固定清单再次生成
python3 tools/dependencies.py audit
# 备份默认覆盖所有实际可达的待复核/中高风险源码及全部图元数据
python3 tools/dependencies.py backup
python3 tools/dependencies.py verify
python3 tools/dependencies.py export
python3 tools/dependencies.py report
```

首次审计没有足够 GitHub 证据时全部不明确依赖保守分类；收集证据后应再次 audit/backup/export。新增依赖或改变 tags 时，也按此顺序执行。工具不自动执行 go get、tidy 或版本升级。
维护活跃度窗口按执行审计当天的前 365 天判断；旧证据不自动续期。现有 lock 固定当次审计结果，重新收集证据后须重新审计并生成匹配快照。

手动强制备份示例（实际下载路径，包括 replace 后的路径）：

```json
"github.com/example/module/v2": {
  "risk": "C",
  "backup": true,
  "reason": "自定义审计理由和证据"
}
```

需要免责时明确设置 A/B、backup false 和理由；C 禁止免责。未知风险应保留保护。重新 backup 不覆盖已有不同字节，export 以内容标识生成新包，旧归档不会被删除。更新依赖时，保留旧源码/lock/pin 对应的历史 ZIP 和 checksum。

当前两个定制内核仅从可信已有 Go 下载缓存备份。如果本地缓存丢失，应先恢复已导出的精确 Module Proxy；不要重新连接原维护者或用官方内核代替。对于旧版本，可以在匹配源码 checkout 中将恢复出的 proxy 配成 GOPROXY，再进行维护。

## 故障模拟与校验

```sh
python3 tools/test_dependencies.py
python3 tools/corruption_test.py
python3 tools/dependencies.py recovery-test
```

恢复测试创建新的源码副本、GOMODCACHE、GOCACHE 和 GOPATH，完全不用已有缓存。临时网关对受保护模块禁止公共代理/direct 回退，逐条记录请求来源。它下载全部保护模块并构建四个 Linux 程序，检查 ELF 架构，执行原始与生产 tags 的测试，并在可执行环境中检查版本。ARM64 smoke test 需要 native ARM64 或 qemu-aarch64/qemu-aarch64-static；缺少时必须记录 NOT RUN。

恢复工具将诊断日志写入本地运行目录。corruption-test 只破坏可丢弃副本中的一个真实 C 模块，必须得到 SHA256 拒绝并证明原快照未变。SHA256 文件与 pin 应从可信源码或独立存储取得，不能只信任同一个可疑下载站提供的 ZIP 和 checksum。

## 新 VPS 部署

通常在可信构建机恢复依赖并编译，VPS 只接收自己架构的两个二进制、install.sh 和必要的 Geo 资产，不需要 Go、Python 或依赖代理服务器。现有 node/machine/standalone 模式均保留。

```sh
chmod +x xboard-node-linux-amd64 xbctl-linux-amd64
./xboard-node-linux-amd64 -v
./xbctl-linux-amd64 version
sudo bash install.sh --mode machine --panel https://panel.example.com \
  --token YOUR_MACHINE_TOKEN --machine-id YOUR_MACHINE_ID \
  --version YOUR_IMMUTABLE_VERSION \
  --binary ./xboard-node-linux-amd64 --xbctl-binary ./xbctl-linux-amd64
```

ARM64 更换两个文件后缀即可；node 模式使用原有 `--mode node --node-id` 参数。Token 仅在目标机器按现有安装流程输入，不放进备份或 Git。Geo 数据按现有本地资产路径/`XBOARD_GEO_DATA_SOURCE` 准备，依赖源码备份不会替代 Geo 数据及面板配置备份。

上面的持久安装命令沿用原安装器。机器模式及 TLS 客户端通信已验证；AMD64 通过原 `install.sh` 完成持久安装、升级、失败回滚和卸载。ARM64 运行验证使用 QEMU，原生 ARM 硬件仍需目标环境验收。验证范围与边界见 [DEPENDENCY-TEST-REPORT.md](DEPENDENCY-TEST-REPORT.md)。

## CI 与分发准备

CI 使用 `dependency-snapshot.json` 固定的新依赖 tag。发布时必须先校验最终 ZIP，将它和对应 checksum 作为**新的**当前仓库依赖 Release 上传，并保留本地独立副本。不要覆盖同名资产，也不要修改历史 `go-vendor-fea5732` 或 `dev` Release。

依赖快照已发布为 pin 指定的独立预发布，并回下载核对 SHA256；本地 ZIP、checksum 和源码 Git bundle 同时保留。历史 Release、tag 和完整 vendor 不被覆盖或删除；依赖预发布不设为 latest。

构建脚本本身不会上传依赖或推送源码。当前 CI 在普通 dev push/默认手动运行时只构建镜像；正式 `v*` tag 或显式 `workflow_dispatch publish_images=true` 才发布 GHCR 镜像。正式二进制 Release 只允许新的 `v*` tag，发现同名 Release 就拒绝覆盖。真实 Actions 结果见测试报告，后续依赖变更仍须重新导出、发布对应新快照并验收。

## 可选完整离线模式

保留原 `go-vendor-fea5732.zip` 作为额外冷备。在匹配的干净源码副本中解压成完整 vendor 后，可按原记录使用 `go build -mod=vendor`。不要把部分 ZIP 拼成不完整 vendor，也不要让日常 Makefile 依赖旧 Vendor。此旧包不等于已验证的新版本全测试离线能力；需要完全离线时应另外固定工具链、OS、完整模块及必要校验缓存，并独立验收。

## 部署演练资料

部署演练应使用独立临时数据及明确配置的目标环境。安装和卸载前核对已有部署及操作范围，完成后检查进程、临时规则和私密配置是否清理。认证资料、私钥、运行目录及原始统计不进入源码或公开归档。
