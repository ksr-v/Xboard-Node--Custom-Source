# Xboard-Node 选择性依赖保护设计

本次改造只涉及当前 Node 仓库的依赖工具、构建、CI 和文档。`go.mod`、`go.sum`、代理内核实现、节点 API、流量计费、设备限制和安装器业务逻辑保持原版本。两套内核仍编译进同一个 `xboard-node`，同时生成独立的 `xbctl`。

## 恢复目标

保护当前 Linux AMD64/ARM64 静态构建（`CGO_ENABLED=0`），以及原有单元测试、生产 tags 和审计主机测试所需源码。假设全部受保护模块的原作者仓库和公共源码缓存不可用，受保护模块仍只能从本地备份恢复；其余已接受联网风险的源码与 Go 校验数据库可以联网。

这不是整个 Go 生态的完全离线保证，也不是真实 VPS 已重新安装的证明。更改平台、构建 tags、测试范围或依赖后必须重新审计。工具链、操作系统、CA、Git/Python、公共低风险依赖、sum.golang.org 仍是外部前提。

## 现状与体积来源

旧 `go-vendor-fea5732.zip` 实测为 427,225,962 bytes，SHA256 为 `904779a08edefd57b24fa66e303f1134fad2e65e8d20dd5f333db22eb7749a3a`。它有 10,782 个 ZIP 条目、255 个 modules.txt 模块头，解压内容约 1.63 GB。

最大来源是 `github.com/sagernet/cronet-go` 的跨平台内容：未压缩 1,554,329,136 bytes，ZIP 条目压缩大小合计 404,293,619 bytes，约占旧 ZIP 的 94.6%。当前生产 tags 不含 `with_naive_outbound`，包图确认当前目标不使用这些 Cronet 平台二进制。它们不能简单被认为“因为 indirect 所以不重要”：如果将来启用相关 tags，必须重新纳入保护。

新快照保存原始完整 Module ZIP，所以包含模块的完整源码和测试，而非 vendor 裁剪过的包。新旧体积同时受到风险选择与实际构建可达性影响，不能把全部缩减都解释成低风险模块免备份。详见 `dependency-size-comparison.json`。

## 审计与分类

`dependency-lock.json` 保存 582 个 MVS 选定模块，记录逻辑路径、replace 后实际路径、固定版本、checksum、风险理由、许可证识别和包图使用情况。实际 Linux 构建/测试加审计主机测试使用 179 个模块。`dependency-graph.txt` 保存实际模块图；另保留 443 条非当前选定版本的 go.sum 校验记录及相应历史 `.mod`，防止空缓存下版本选择需要旧元数据却无法恢复。

`dependency-evidence.json` 保存 128 个实际可达 GitHub 仓库的官方 API 证据：归档状态、提交时间、贡献者样本、近期 Release、许可证元数据。原维护者仓库按既有孤儿策略不再查询。贡献者样本最多 20 人，Release 最多 5 条，不能视作完整维护者审计；Stars 仅作为记录，不参与分类。

| 分类 | 当前数量 | 处理方式 |
|---|---:|---|
| A | 114 | 成熟机构/生态模块；源码允许联网，保留精确图元数据；发现已归档时提升为 C |
| B | 46 | 官方证据满足多贡献者、持续提交及近期发布；当前可达模块仍备份 |
| C | 5 | 原维护者定制内核或已归档模块；完整源码必须备份 |
| review_required | 417 | 证据不足；当前构建/测试可达时保守备份，不能解释为低风险 |

完整源码保护集是 127 个模块，包含全部 C、当前可达 B 和待复核模块。所有 582 个选定模块都保存 `.mod`、`.info`；仅模块图可达、其他平台或未启用功能的待复核模块不保存源码 ZIP。其风险和范围排除明确写入清单，未来可通过 overrides 强制保护。任何 C 类均不得配置 `backup: false`。

五个 C 类实际下载路径：

- `github.com/cedar2025/sing-box`：定制 sing-box，replace 后的精确伪版本。
- `github.com/cedar2025/Xray-core`：定制 Xray-core，replace 后的精确伪版本。
- `github.com/PuerkitoBio/urlesc`：官方 API 确认归档。
- `github.com/google/btree`：机构维护也不能忽略官方归档事实。
- `github.com/mitchellh/mapstructure`：官方 API 确认归档。

手动覆盖在 `dependency-policy.json` 的 `overrides` 配置，以实际下载模块路径为键，可设置 risk、backup、reason。未确认风险时不自动免责；显式 B/A 免备份会将该源码的恢复责任转回互联网，必须写清理由。

## 文件型 Module Proxy

按 Go 官方 Module Proxy 协议保存：`proxy/<escaped-module>/@v/<escaped-version>.zip/.mod/.info`，以及版本 `list`。大写字母使用 `!` 加小写转义；伪版本和 replace 的实际模块身份保持不变。不使用不完整 vendor，也不添加新的 replace。

正常构建的 `GOPROXY` 是 `file:///.../proxy,https://proxy.golang.org`。先验证快照再构建，完整保留 go.sum、启用 `sum.golang.org`、使用 `-mod=readonly`；不默认启用 direct，避免意外连接已禁止的原维护者。公共代理无法提供低风险源码时应明确失败，或经审查后配置受控替代公共代理。

故障模拟的 GOPROXY 则只有一个临时 loopback 网关。它对 protected 路径只读本地，缺失返回 503，不能回退公共代理；只允许未保护的已审计路径访问公共代理。所有请求记录来源、状态和字节数，保护集每个 ZIP 都必须出现本地请求。网关不是部署依赖，测试结束即关闭，VPS 不需要安装它。

## 完整性与版本保留

备份优先读取现有 Go 下载缓存，缺失公共模块才通过公共代理获取；原维护者路径缺失时直接失败。ZIP 和 go.mod 采用 Go dirhash h1 与原 go.sum 对照，另保存原文件 SHA256；缺少根 go.sum 校验的保护版本必须在临时模块中由正常 checksum database 认证，绝不改写根 go.sum 或全局关闭校验。

Manifest 记录所有文件的长度、SHA256、原始模块身份、固定版本和许可证原文；源码中的 `dependency-snapshot.json` 固定 Manifest hash、lock hash、归档 SHA256 和不可变分发 tag。恢复要求可信 SHA256，拒绝路径穿越、重复条目、软链接和覆盖非空目标。校验失败立即停止。

归档名称取自全部导出文件内容的摘要。相同文件不重复归档，不同字节不覆盖旧文件；导出只包含已审计文件，避免将暂存目录的无关内容打包。旧版本通过旧的不可变归档及其匹配源码/lock 保留；日常工具不删除任何历史 ZIP、Release 或 tag。

## 许可证边界

所有 127 个受保护模块 ZIP 都检查到了 LICENSE/COPYING/NOTICE 类文本，并将原文与 hash 放入 Manifest。识别结果是审计辅助，不是法律授权结论；低风险和图元数据模块缺少本地许可证时明确标记 review_required。

定制 sing-box 的许可证是 GPLv3 系列并包含名称/关联声明限制，Xray-core 是 MPL-2.0。不能用根 README 的 MPL-2.0 概括整个组合，也不能因为上游删除就认为可以任意公开再发布。当前备份保留原始许可和声明；已发布快照包含原始精确模块源码与许可证，没有替换为根仓库许可证。分发源码/二进制时仍须保留对应源码、版权、NOTICE、修改声明及适用附加条款。工具不会自动发布第三方备份。

## 构建与 CI

Makefile 的 build/build-linux/build-linux-arm64/test 均通过验证后的文件代理。输出名称保持 `xboard-node-linux-amd64`、`xboard-node-linux-arm64`、`xbctl-linux-amd64`、`xbctl-linux-arm64`。生产 tags 保持 QUIC、uTLS、WireGuard、ACME、Clash API。原有未加 tags 测试与生产 tags 测试在恢复验证中分别执行，Linux 的 make test 还保留原 race 检查。

GitHub Actions 使用 `go-version-file: go.mod`，保持工具链与模块要求一致；恢复验证使用独立空缓存。CI 包含正常构建、双架构、测试、真实 C 模块损坏拒绝、空缓存恢复及 QEMU ARM64 smoke test。Docker 构建使用同一快照，并同时保留两个程序。多架构 builder 固定使用 `BUILDPLATFORM`，显式把 `TARGETOS/TARGETARCH` 传给 Go，从本机交叉编译目标架构；避免通过 QEMU 运行整个 Go 编译过程。

源码中的快照 pin 必须对应已上传的当前仓库不可变依赖 Release，或由操作者直接提供本地归档。远端尚未发布时 CI 应失败，不能退回原作者下载。正式二进制 Release 仅从 `v*` 版本 tag 发布；已有 Release 拒绝覆盖，保留历史 dev Release，不再由 dev 分支反复覆盖。镜像使用 SHA/版本 tag，不新增 latest 发布。普通分支 push、PR 和默认手动运行验证双架构镜像但不上传；`v*` tag 或显式手动勾选 `publish_images` 才登录并发布 GHCR。依赖快照的公开发布已得到用户单独授权，第三方原始源码和许可证随快照完整保留；本地独立资产仍是恢复路径之一。

## 旧 Vendor 包退役条件

当前保留旧包及远端 Release。新方案即使编译通过，也建议至少保留一个稳定维护周期，直到本地第二份独立备份、CI 运行、真实目标 VPS 安装/回滚检查均完成。然后可以停止日常重复生成完整 vendor，将旧包保留为冷归档。删除任何旧远端资产需要明确授权，工具不会自动执行。

协议依据：[Go Modules Reference](https://go.dev/ref/mod#module-proxy)。功能验证结果与未验证范围见 `DEPENDENCY-TEST-REPORT.md`；公开文档不保存运行环境标识或原始统计。
