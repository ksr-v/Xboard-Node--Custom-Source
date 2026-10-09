# FlowScope 出口 IPv4 自动报告

本地构建标识：v1.13-orphan.2；兼容 FlowScope 2.4.0。此功能不要求 Python 采集器、周期流量、额外 Token、重绑或新增配置。

## 实现

internal/panel/address.go 使用 Go 标准库直接访问 https://api-ipv4.ip.sb/ip：tcp4、正常 TLS 验证、3 秒期限、拒绝跳转、无环境代理及节点转发链路，响应限制 64 字节并排除非公网 IPv4。第三方请求没有面板 Token 或身份。每进程共享一份宿主机缓存（多实例共享，不包括独立的其他 Node 进程），成功 12 小时刷新、失败 5 分钟后再试；24 小时后不再上报过期缓存。地址代表 IP.SB 看到的宿主机出口，不保证等于监听 IP 或用户代理出口。

client.go 复用已有 Client、transport、JSON 凭据注入和认证成功请求。首次对接、已有绑定重启/升级、REST/WS 报告、连接恢复均可驱动异步 IP 报告。无新增定时器循环、进程、服务、监听端口或依赖。machine orchestrator 的 child Client 不重复报告。

POST /api/v2/flowscope/node-address 包含 ipv4、age_seconds 和现有绑定凭据；凭据不进 URL，5 秒期限，拒绝重定向。面板沿用已有 HTTP/HTTPS 连接；HTTPS 验证不被关闭。每个 Client 独立维护能力/失败缓存，面板间不共享 Token。成功每小时刷新，404/405/501/未知 ACK 缓存 10 分钟，401/403 为 15 分钟，429 使用限制后的 Retry-After，网络/5xx 指数退避 1..15 分钟。Node 原功能不依赖可选接口成功。

machine mode 使用专属机器 Token；FlowScope 只接受该机器及其真实子节点。legacy node mode 原凭据是面板级 server token，不能证明逐节点独立身份。FlowScope 使用有期限的节点级兼容结果，按服务端数据库关系显示，不允许共享 Token 直接更新机器地址表；无绑定时只显示节点结果。没有引入手工配置凭据，也不声称提供原本不存在的逐节点密码隔离。

## 升级与回滚

先后升级 Node/FlowScope 均可，后安装/启用插件会自动重新发现；不需要重绑。已有采集器不用动，Token、身份、序号、outbox、历史流量不变；停止或用户主动卸载采集器也不影响新 Node 的 IP。

使用固定依赖构建（不发布、不访问原维护者路径）：

~~~powershell
$env:VERSION='v1.13-orphan.2'
python tools/dependencies.py build --arch amd64
python tools/dependencies.py build --arch arm64
~~~

现有机器上使用本地可信二进制走原升级流程：

~~~sh
sudo bash install.sh upgrade --version v1.13-orphan.2 \
  --binary ./xboard-node-linux-amd64 --xbctl-binary ./xbctl-linux-amd64
~~~

ARM64 替换文件后缀。原 upgrade 保留 config.yml 和绑定，不执行重新配置。先保存旧二进制及配置；失败使用既有安装器回滚或已保存二进制回退。升级会重启 Node，可能中断连接，不能承诺零中断。未创建远程 Release，现有 xbctl 私有升级源只有自行准备相应资产后才可使用。

## 本次验证（2026-10-09）

VERIFIED：固定依赖的原有 internal/... 套件；检测缓存/超时/TLS/代理/非法值；两种模式已有凭据、跨面板、404 后恢复、重定向不泄漏；实际 Go HTTPS Client 与 FlowScope PHP 原生路由及模型（隔离 SQLite）联调；工作站直连 IP.SB；Linux amd64/arm64 的 Node 和 xbctl 构建。

重跑集成与直连测试：

~~~powershell
$env:FLOWSCOPE_TEST_RECEIVER='D:/xb-flowscope/tests/node-receiver.php'
$env:FLOWSCOPE_TEST_LIVE_IP='1'
python tools/dependencies.py test --host
~~~

普通单元测试不会隐式联系 IP.SB；未设置上述选项时这两类测试明确跳过。测试凭据为 fixture，不读取生产 .env/配置。NOT RUN：新版 Linux/原生 ARM64 实机安装升级、真实代理客户端连续性、生产面板/MySQL/Octane/Nginx 和裸机网络。现有安装器及代理代码未改，其旧验证不替代本次生产验收。
