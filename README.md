# DraFRP

DraFRP 是包含云控、共享出口节点和客户端的内网映射服务。云控保存账号、客户端、规则、套餐和审计；出口节点接入公网流量；客户端主动建立出站加密承载并访问本地目标。三个角色分别编译为 `drafrp-cloud`、`drafrp-edge`、`drafrp-client`。只有云控依赖 MySQL、可选 Redis 和 Web 控制台。

当前可运行 TCP、UDP 和 HTTP(S) 映射，QUIC 优先、TLS/yamux 回退。已完成真实 MySQL 和三端网络联调；验证范围、尚未完成的设计项在 [IMPLEMENTATION.md](IMPLEMENTATION.md)。七份设计文档仍是目标规格，不代表每项均已交付。

MySQL 的外键、删除动作、历史账本和升级恢复策略见 [SCHEMA-INTEGRITY.md](SCHEMA-INTEGRITY.md)。

## 构建

需要 Go 1.26.10 或更新的安全补丁版本、Node.js 24 和 npm；go.mod 固定当前验证的工具链。正式构建将 Vite 产物嵌入云控，出口节点和客户端不携带前端资源。

```powershell
# Windows；也可 -TargetOS linux -TargetArch arm64
./scripts/build.ps1 -Version 0.1.0 -TargetOS windows -TargetArch amd64
```

```bash
# Linux / macOS；输出 bin/0.1.0/linux-amd64/
bash scripts/build.sh 0.1.0 linux amd64
```

目录内包含三个可执行文件、示例配置、说明和 SHA256SUMS。`--version` 显示版本和 Git revision。单独执行 `go build` 得到开发版；正式云控需要 `-tags release` 与 `internal/webui/dist`，缺失前端时构建失败。

## 首次运行

1. 创建专用 MySQL 8 数据库和账号。复制 `examples/cloud.json`，填写 DSN、初始管理员密码与持久的 AES 存储密钥。密钥为 16/24/32 字节随机值的标准 Base64 编码，例如 `openssl rand -base64 32`。妥善保存密钥，数据库中的证书私钥依赖它解密。首次空库才创建管理员；修改配置不会重置现有密码。
2. 运行 `drafrp-cloud --config cloud.json`，访问 `/console/` 登录。云控可直接设置 `tls_cert`、`tls_key` 提供 HTTPS。示例默认只监听本地地址；公网入口应使用 HTTPS。若在 TLS 反向代理后运行，设置 `secure_cookies: true`，保留请求 Host，并禁止绕过代理直连后端；不要依赖任意来访的 X-Forwarded-Proto 决定 cookie 安全属性。
3. 在控制台创建出口节点，设置公网地址、业务端口池、共享 HTTP/HTTPS 端口和承载 endpoint。例如 QUIC UDP 8443 与 TLS TCP 8443 可共用端口号。设置证书的 `server_name`、可选 CA PEM，以及随机出口节点 token。业务端口不应与承载或共享站点端口重叠。
4. 复制 `examples/edge.json`，填写云控 URL、出口节点 ID、token 和承载 TLS 证书路径，运行 `drafrp-edge --config edge.json`。证书必须匹配 endpoint 的 `server_name`；私有 CA 应写入出口节点的 CA 配置，云控私有 CA 则使用 `ca_file`。
5. 复制 `examples/client.json` 到目标机器。Windows 使用可写的绝对 `state_dir`，如 `C:/ProgramData/DraFRP/device-a`。运行 `drafrp-client --config client.json`，打开日志给出的绑定地址，核对客户端指纹后确认。每个独立进程使用独立状态目录；复制同一身份同时运行会发生会话冲突。
6. 在控制台创建映射，选择绑定客户端和出口节点。TCP/UDP 目标为 `host:port`，HTTP(S) 目标为 `http://host:port/base` 或 `https://host:port/base`。客户端的本地目标允许列表限制云端规则能访问的地址和端口；示例仅允许 loopback。`allowed_target_cidrs`/`allowed_target_ports` 缺省为不额外限制，显式空数组拒绝所有目标。

配置是严格 JSON：未知字段报错，时长接受 `"20s"` 等 Go duration 字符串，也兼容数值纳秒。正常同步间隔默认 20 秒、授权期限默认 3 分钟；断开云控超过期限后现有转发停止。客户端进程重启后，新会话须等旧租约到期后才可接管身份，或重新绑定独立客户端。

### 注册与验证码

登录页提供“创建账号”。注册需用户名、10–72 UTF-8 字节密码、确认密码和图形验证码；新账号取得独立空间和普通用户权限，注册后再登录。登录与注册默认使用本地生成的六位图片验证码，可“换一张”，两分钟有效，不区分大小写。一次提交即消费，错误后自动换图；从客户端绑定地址进入时，注册和登录会保留该地址。

云控配置 `registration_disabled: true` 可关闭公开注册，只保留管理员创建账号；`captcha_disabled: true` 可显式关闭图形校验，主要用于隔离自动化测试。新空间使用管理员设置的默认套餐；没有默认套餐时，不能创建端口服务或网站。已有账号升级时保留原权限，并生成迁移套餐。验证码不依赖外部服务或 Redis；云控重启会使尚未提交的验证码失效。

### 控制台导航

侧栏按“连接管理”“网络资源”“我的账户”“平台管理”分组。仪表盘显示客户端、服务、套餐和流量；“我的账户”包含账户与套餐、流量用量；管理员在“平台管理”中维护用户、套餐、出口节点、ACL 与审计。分组按当前页面展开，手机端选择页面后关闭侧栏。

### HTTP(S) 站点

先在“网络资源 → 域名与证书”注册域名，在 DNS 添加返回的 `_drafrp-challenge.<domain>` TXT 值，然后验证所有权。上传与域名匹配且未过期的叶证书后创建 HTTPS 站点。HTTPS 在出口节点终止，HTTP 请求重定向到该 HTTPS 站点；回源可独立选择 HTTP/HTTPS。客户端默认校验回源证书，私有 CA 使用 `origin_ca_file`，`server_name` 可显式设置回源 SNI。

客户端根据已认证的逐请求元数据生成 `X-Forwarded-For`、`X-Real-IP`、`X-Forwarded-Proto`、`X-Forwarded-Host`、`X-Forwarded-Port`。来访的同名头和 `Forwarded` 被移除，目标 socket 对端仍为客户端。目标应用应只信任客户端的实际地址。支持流式正文与 WebSocket；回源当前使用 HTTP/1.1 连接池，按规则版本隔离。

### 套餐与 ACL

管理员在“平台管理 → 套餐管理”创建套餐，设置**可用出口节点、基础带宽、突发开关与峰值/时长、端口总数、网站数、流量计费与超额策略**，再在“用户管理”分配。带宽界面单位为 Mbps，API 单位为 bit/s；带宽和端口总数由全部出口节点共享。TCP、UDP 同号端口分别计数；HTTP(S) 每条网站配置计一个网站，使用共享监听，不占端口数。`-1` 表示不限，`0` 表示不可用。

流量计费可配置周期额度（界面 GiB）、周期天数（0 不重置），超额选择拒绝连接或限速。上传与下载合计，超额限速期间继续计量；信用续发后已有流继续传输，拒绝策略关闭已有流并阻止新流。突发预算与流量均由全部出口节点共享，未用预留流量不会提前触发超额。修改套餐保留当期用量，周期到期恢复速率与额度；旧离线授权最迟在租约到期失效。当前不包含价格、订单或支付。

一个空间使用一个套餐，同空间用户共享客户端、服务与资源。新注册或管理员新建空间使用默认套餐；没有默认套餐或明确选择“未分配”时，没有可用节点和服务容量。首次管理员有独立管理套餐。已有账号迁移为各自的套餐并保留原配置，升级不会将未分配账号变为不限。

新增服务、改节点、TCP/UDP 转为网站都由 MySQL 事务检查套餐。禁用、等待删除的网站和未释放的旧端口仍计入使用量，迁移端口也需要余量。降低数量上限不会删除现有资源，仍可编辑或删除；移出套餐的节点停止获得转发授权，在线节点同步后关闭监听和已有流，离线节点最迟在原租约到期时停止。收紧带宽时，旧节点的未过期份额保守保留到结算或到期，避免跨节点超发。

仪表盘和“账户与套餐”显示当前套餐与实际用量；服务列表支持节点/状态筛选、25/50/100 条分页、复制入口和快捷启停。创建表单按常用与高级配置折叠；所有界面对外使用“出口节点”和“客户端”，协议和配置字段保持兼容。用户可在账户页修改密码，其他登录会话随之退出。流量页按出口节点汇总完整累计报告，不受原始授权记录列表的 1000 条上限影响，并提供最近 30 天的分钟级流量历史折线图。出口节点在内存中按 UTC 分钟累加上传/下载，随现有定时同步统一发送；云控按 grant、分钟和报告来源幂等落入 MySQL，按时间范围返回流量与平均带宽。短暂离线期间保留有限分钟窗口，超出窗口的累计差额会标记为收到报告时汇总；这类数据仍计入总流量但不伪装成原始分钟采样。

用户与管理员控制台采用独立导航，可通过管理入口切换。用户流量页仅看当前空间，管理员后台的“全平台流量”查看所有空间。顶部默认汇总全部节点，选择后只显示该节点的一条曲线；流量与带宽共用筛选，数据点支持悬停吸附与点击/触摸固定详情。升级时先更新云控，再更新出口节点；记录从升级起采集，不能补出更早的分钟历史。

ACL 只应用于 TCP/UDP。模板草稿和已发布版本分离；可配置来源 CIDR、来源端口、协议、优先级及生效/到期时间。发布或到期收紧后会重新判定现有流。默认模板和 mandatory 模板由管理员明确设置，仓库不预置地理区域放行列表。HTTP(S) 站点采用独立来源头机制。

ACL 页可模拟未保存草稿和已发布模板；TCP/UDP 规则详情可模拟包括 mandatory 模板的有效策略链。填写访客 IP、来源端口及协议后，可查看命中条目、默认动作和各层版本。地域由手动假设输入，模拟结果仅解释云端期望 ACL，不代表配置已应用或服务可达，也不会修改或发布策略。

规则详情的“实际访问观测”显示出口节点真实 ACL 命中，TCP 按新连接、UDP 按入站报文计数；按启动、规则版本与策略摘要区分当前和历史记录。规则合计与各策略层不能相加。模板页的应用反馈按出口节点列出实际 ACK，明确等待确认、失败、过期和停用；保存或下发成功不会直接显示已应用。统计有容量与七天保留期限，未观测不等于没有访问。

地域条件使用管理员提供的前缀数据库；出口节点配置 `geoip_file` 指向 UTF-8 JSON：`{"version":"operator-version","records":[{"cidr":"…","country":"AA","region":"AA-X"}]}`。示意代码不是内置地区数据。国家为两位大写码，地区前缀必须与国家一致，IPv4/IPv6 按最长前缀匹配。数据上限 64 MiB / 25 万条。规则必须明确未知地域 `deny` 或 `no_match`；数据库缺失/损坏时，地域规则关闭并报告错误。通过原子替换文件更新，下一次同步会重新判定已有连接。控制台显示加载状态、版本和错误。

### Linux 原生源 IP 和端口

普通 socket 模式下目标看到客户端的地址。严格 `native` 规则当前支持 Linux IPv4 TCP/UDP 透明 socket：目标真实 socket 对端为出口节点观察到的访客 IP 和端口，不注入业务前缀。它与设计中的原始 IP 包/TUN 路径不同；`tun`、Windows native 和 IPv6 native 尚不支持。

在专用 Linux 网络命名空间或经过规划的主机上，给客户端配置 `network_mode: "transparent"`、私有且持久的 `state_dir`、`native_flow_limit`（默认 128，上限 1024）。需要 `ip`、`iptables` 和 CAP_NET_ADMIN。启动时分别实际验证 TCP/UDP 透明回流，再上报对应能力；控制台只允许匹配能力的规则。普通 socket 规则仍可使用。

本机目标会安装精确五元组的回流标记和策略路由。远程 LAN 目标还需管理员事先确保**回复访客地址的路由经过客户端**，并在 `native_return_cidrs` 声明允许的目标网段；这个字段不代替目标端路由配置。源元组冲突、权限不足或回流不可用时明确失败，不自动改端口。已有 NAT 后的不可见原始地址无法恢复。客户端仅维护带私有所有权标记的网络对象，正常退出清理，崩溃后依赖同一状态目录恢复。

### 出口节点物理出口整形

账户限额始终按业务 payload 计量。默认 `capacity_enforcement=payload` 不能当作网卡硬上限。Linux 可另外配置 `wire_shaping`，见 `examples/edge-wire.json`：必须明确指定专用非 loopback 接口、`dedicated_interface: true`、私有持久状态目录和独立 `rate_bps`。需要 `tc`（iproute2）和 CAP_NET_ADMIN。

该模式用 TBF 约束指定接口的**全部出站流量**，包括隧道封装；不限制入站，不代表以太网 L1 精确线速。不要选择承载其他项目的共享接口。已有未知 root qdisc 时拒绝覆盖。运行中独立检查 qdisc；被删除或篡改后关闭数据面并报告 wire_failed。云控 CapacityBPS 与本地 wire rate 分别配置，控制台同时显示实施模式和真实网卡累计 TX/RX（包含该接口其他流量，不归属于某个租户）。

### 运行状态

保存成功表示配置已持久化。`pending` 等待下发，`waiting_for_agent` 表示没有可用承载，`listening` 表示监听/承载存在，`ready` 仅在实际目标连接或响应被观测后上报。UDP 的 ready 需要目标回包。`ready` 是最近一次观测，不是持续目标健康检查；客户端离线、预算耗尽和授权过期会使状态失效。

客户端详情每 10 秒刷新客户端实际传输采样，显示活动流、QUIC/TLS 承载、端点连接失败分类、重试时间和最近握手耗时。支持的新对端每五秒进行一次已认证承载控制流回显，显示最多 64 次的 RTT、成功/超时/失败窗口；旧对端或无成功样本时明确显示未观测。QUIC 另显示真实 ACK RTT 和连接期包统计，当前判丢数可因迟到包下降，探测超时率不等于 IP 丢包率。握手、控制 RTT 与目标业务响应分开，承载存在不保证目标健康。缺少或过期采样时明确提示。控制台“公网端口”可按出口节点查询业务池和系统保留端口；跨空间占用仅显示通用状态，候选空闲端口仍需创建时原子分配。

## 容器和服务

`Dockerfile` 提供非特权的 `cloud`、`edge`、`client` target；另有带所需网络工具的 `edge-wire`、`client-native` target，需在专用网络命名空间显式授予 NET_ADMIN。`examples/compose.yaml` 可启动专用 MySQL 和只绑定宿主 loopback 的云控：

```bash
export DRAFRP_DB_PASSWORD='replace-with-random-db-password'
export DRAFRP_DB_ROOT_PASSWORD='replace-with-separate-root-password'
export DRAFRP_STORAGE_KEY="$(openssl rand -base64 32)"
export DRAFRP_ADMIN_PASSWORD='replace-with-random-admin-password'
docker compose -f examples/compose.yaml up -d --build
```

保存上述存储密钥以供重启恢复。Redis 为可选临时缓存，可在 cloud 配置的 `redis.address` 指定。不可用时自动切换有容量上限的进程内缓存；恢复后经过连续探测切回。身份、会话、套餐和绑定结果以 MySQL 为准，不依赖 Redis 成功。

Linux systemd 示例位于 `examples/systemd`。先创建 `drafrp` 系统用户/组，将二进制安装到 `/usr/local/bin`、配置与证书安装到 `/etc/drafrp`，配置和私钥由 root 持有并仅允许 drafrp 组读取（0640）。客户端的 `StateDirectory` 由 systemd 创建。示例客户端 unit 面向普通 socket 模式。

`/healthz` 为进程探针，`/readyz` 实际检查 MySQL。关停使用 SIGTERM。备份需同时保存 MySQL、AES 存储密钥、出口节点凭据/证书和客户端状态目录；不要将客户端私钥或实际配置提交到仓库。

## 验证

```bash
go vet ./...
go test -race ./... -count=1 -timeout=5m
cd web
npm ci --no-audit --no-fund
npm test
npm run build
```

没有 MySQL DSN 时，数据库与全栈测试会明确 skip。完整验证需要一个有建库/删库权限的**专用测试 MySQL**，测试自动创建 `drafrp_cloud_test_*` / `drafrp_system_test_*` 隔离数据库并在退出时删除：

```bash
DRAFRP_TEST_MYSQL_DSN='root:test-password@tcp(127.0.0.1:3306)/' \
  go test -race ./... -count=1 -timeout=5m
```

`internal/systemtest` 通过真实 HTTP API 绑定客户端、创建规则，运行真实出口节点和客户端，分别验证 QUIC/TLS 上的 TCP、UDP、HTTPS、可信来源头、落库用量/状态和撤销活跃流。前端 fixture/browser QA 单独记录在 `web/README.md`，不作为真实数据库端到端证据。

`scripts/smoke.py` 还可对三个正式可执行文件进行 API 联调。提供独立空数据库和尚不存在的 `--work-dir`，需要 Python 3、openssl：`DRAFRP_SMOKE_MYSQL_DSN='…/dedicated_empty_db' python3 scripts/smoke.py --bin-dir bin/0.1.0/linux-amd64 --work-dir /private/new-run`。目录中配置含测试凭据，应按私密状态保存；result.json 不含凭据。它不会改宿主路由或防火墙。原生模式与整形的特权验证只在明确指定的隔离容器运行，见 IMPLEMENTATION.md。

更多接口与兼容约定见 [API-CONTRACT.md](API-CONTRACT.md)。
