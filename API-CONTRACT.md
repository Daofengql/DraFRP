# DraFRP 当前接口契约

本文件描述当前实现；七份设计文档描述完整目标。共享 Go JSON 类型以 `internal/model/model.go` 为准。浏览器 API 与运行时 API 共用云控监听端口；数据承载使用独立的 QUIC/TLS endpoint。

## 通用约定

- JSON 使用 snake_case，错误形如 `{"error":{"code":"version_conflict","message":"…"}}`。列表返回 `{"items":[],"total":0}`；当前不支持游标分页，用量与审计最多返回最近 1000 条。
- 浏览器使用 HttpOnly、SameSite=Lax cookie 登录。已认证写操作要求 `X-CSRF-Token` 并检查 Origin；token 来自登录或 `/me`。登录和公开注册检查 Origin，不要求预先登录或 CSRF token。前端不把凭据写入 localStorage。
- 浏览器写操作可带最多 128 字节的 `Idempotency-Key`。同一账号、key、方法、路径和原始正文重放已提交结果；key 用于另一请求返回 409。业务写入、审计、revision 和幂等响应在一个 MySQL 事务提交。
- 规则、ACL 草稿和配额编辑提交当前 `version`；冲突返回 409。边缘编辑当前没有 version 字段；存在规则时拒绝改变其监听配置。
- 普通资源限定于登录用户的固定 `tenant_id`。角色为 `admin` / `user`；当前每账号一个空间，没有多空间切换或细粒度成员 capabilities。
- 速率为 bit/s，信用、突发和流量为 byte；配额 `-1` 为无限，`0` 为拒绝。时间使用 UTC RFC3339。保存、监听和目标成功观测是三个不同状态。

## 浏览器端点

除 `/auth/*` 外，以下路径都带 `/api/v1` 前缀。

| 方法与路径 | 作用和主要输入 |
| --- | --- |
| GET `/auth/options` | `{registration_enabled,captcha_required}`；前端据此显示注册和验证码 |
| GET `/auth/captcha` | `{captcha_id,image,expires_at}`；image 为 PNG data URL，绝不返回答案 |
| POST `/auth/register` | `{username,password,captcha_id,captcha_answer}` → 201 `{user}`；创建独立空间的普通用户，不自动登录 |
| POST `/auth/login` | `{username,password,captcha_id,captcha_answer}` → `{user,csrf_token}` |
| POST `/auth/logout` | 撤销当前会话 |
| GET `/me` | `{user,csrf_token,build_id}` |
| GET `/overview` | 当前空间设备、在线数、规则、ready 数、边缘数、累计流量、观测时间；管理员可带 `scope=platform` |
| GET `/devices` | 设备列表；设备只能通过绑定创建 |
| PATCH `/devices/{id}` | `{name}` 重命名 |
| DELETE `/devices/{id}` | 撤销身份、递增 generation、禁用关联规则；同步后关闭已有流 |
| GET `/bind/{user_code}` | 待绑定名称、公钥指纹、状态、到期时间；需先登录 |
| POST `/bind/confirm` | `{user_code,name?}` → `{device_id,ok:true}`；只能批准一次 |
| GET/POST `/rules` | 列表 / 创建 Rule |
| GET/PUT/DELETE `/rules/{id}` | 读取 / 带 version 完整编辑 / 标记删除；撤销确认或授权过期后释放资源 |
| GET/POST `/edges` | 已登录用户可读；管理员创建 `{...Edge,token}`，token 至少 24 字符且只写不读 |
| GET/PUT/DELETE `/edges/{id}` | 管理员读取、编辑、删除；有规则时拒绝编辑、删除 |
| GET `/port-resources?edge_id=…` | 业务池与系统保留端口实时列表；可带 protocol=tcp\|udp、offset、limit（1..500，默认100） |
| GET/POST `/acl-templates` | 已登录用户可读；管理员创建具名空草稿，明确 default_action，无预置条目 |
| PUT/DELETE `/acl-templates/{id}` | 管理员修改草稿、默认/mandatory 标记或删除；引用中的模板不可删除 |
| POST `/acl-templates/{id}/publish` | 管理员发布，可提交 `{version}`；保存草稿不等于发布 |
| POST `/acl/simulate` | 登录后诊断指定来源的 ACL 判定；要求 CSRF/Origin，不发布或写入配置 |
| GET `/acl/observations?rule_id={id}&cursor={key?}&limit=100` | 当前空间规则的真实 ACL 命中与边缘应用 ACK；管理员可读任意规则 |
| GET `/acl/applications?template_id={id}` | 管理员按边缘汇总模板相关规则的期望版本与实际 ACK |
| GET/POST `/certificates` | 列出元信息 / 上传 `{name,cert_pem,key_pem}`；私钥不返给浏览器 |
| DELETE `/certificates/{id}` | 未引用时删除 |
| GET/POST `/domains` | 列表 / `{domain}` 注册 DNS 所有权挑战 |
| GET/DELETE `/domains/{id}` | 查看 TXT 信息 / 未被站点引用时释放所有权 |
| POST `/domains/{id}/verify` | 查询 `_drafrp-challenge.<domain>` TXT，精确匹配随机值后取得全局唯一所有权 |
| GET `/quotas` | 用户读取自己配额；管理员读取所有配额 |
| PUT `/quotas/{tenant_id}` | 管理员带 version 编辑运行预算、周期长度和配置资源数量上限 |
| GET `/usage` | 当前空间按 grant 的累计字节快照；记录是累计值，不可逐行求和 |
| GET `/audit` | 管理员读取近期审计 |
| GET `/system` | MySQL、临时缓存后端与统计、版本、启动时间 |
| GET/POST `/users` | 管理员读取 / 创建 `{username,password,role,tenant_id?}`；省略 tenant_id 创建空间 |
| PATCH `/users/{id}` | 管理员修改 `{disabled?,password?,role?}`，保留至少一个启用管理员；改密码或禁用撤销会话 |
| GET `/events` | 会话认证的 SSE，命名事件 `invalidate` 提示重新读取，15 秒心跳并重查会话 |

`GET/HEAD /healthz` 返回 204；`GET/HEAD /readyz` 实际探测 MySQL，失败返回 503。`/console/` 为嵌入 SPA，缺失静态资产返回 404，不回退成 HTML。

注册和图形验证码默认开启。云控 `registration_disabled: true` 关闭公开注册，管理员创建用户仍可用；`captcha_disabled: true` 显式关闭登录与注册验证码校验，此时可省略两个验证码字段，发图接口返回 404。验证码为六位字符、不区分大小写，TTL 两分钟，一次尝试即消费（含错误答案或正确答案但错误密码），刷新、重启后须重新获取。无效/过期/重复答案返回 400 `captcha_invalid`；重复用户名返回 409 `username_exists`；关闭注册返回 403 `registration_disabled`。注册用户名 trim 后 1–64 个 Unicode 字符且最多 255 字节，密码 10–72 UTF-8 字节；不接受 role、tenant_id 等额外字段。账号、空间、默认配额与审计在同一事务内提交。每来源 IP 每分钟发图最多 30 次、登录 20 次、注册 10 次，超限返回 429。验证码仅保存在有界进程内存，数据库不保存答案。

## 配置资源数量配额

Quota 的 `max_devices`、`max_rules`、`max_ports`、`max_domains` 默认 `-1`（不限），可设置为 `0..1000000`，其中 0 禁止继续新增。PUT 省略某个新字段会保留已保存的值，兼容旧控制台。`resources` 为服务端只读统计，含 `devices`、`rules`、`ports`、`domains` 和 `observed_at`；客户端提交的统计不参与额度判断。

设备统计未撤销身份；规则包括 HTTP(S) 站点、禁用和等待释放项；域名包括待验证项。公网端口按 TCP/UDP 分别计数，相同端口号使用两种协议占两份，HTTP(S) 共享监听不占业务端口额度。规则迁移后，仍有效的旧端口保留继续归属原空间，直到删除确认或保留到期。规则记录删除和旧端口释放可能发生在不同时间。

设备绑定批准、域名创建和规则/端口新增在同一 MySQL 事务内锁定空间配额、检查数量并写入资源；跨边缘并发也共享该锁。降低上限不会删除现有配置，仍可进行不增加数量的编辑或删除；移动端口需要为尚未释放的旧端口保留额外余量。达限返回 409 `resource_quota_exceeded`，绑定请求仍保持待批准状态。无法恢复归属的历史有效端口保留会暂缓有限额端口新增，返回 409 `resource_quota_pending`，需等待到期或修复归属。数据库检查失败返回 503，不按空闲资源处理。

## 规则和 ACL

端口列表返回 `{edge_id,port_min,port_max,items,total,offset,limit,observed_at}`。每项有 protocol、port、in_business_pool、status（available/reserved/occupied/releasing）、可选 reservations、release_at 和 rule。系统保留用途为 carrier_tls/carrier_quic/http/https；total 包括池外固定保留端口。仅管理员或资源所属空间可见 rule 的 id/name/tenant_id/current_claim，其他用户只见通用占用状态。移动/删除后的旧 claim 在授权释放前仍占用。该 GET 不修改资源，候选 available 不等于已预留；创建仍由 MySQL 写事务仲裁。列表按端口升序、同号 TCP 在 UDP 前，省略 protocol 返回两者。

Rule 使用 `name`、`protocol`、`device_id`、`edge_id`、`target`、`source_mode`、`transport`、`enabled`。TCP/UDP 设置 `public_port`；HTTP(S) 使用已验证的 `domain`，HTTPS 另需 `certificate_id`。设备、证书和域名必须属于当前空间。端口和域名占用通过数据库唯一资源声明约束；TCP/UDP 可使用相同数字端口。

| 字段 | 当前支持值 |
| --- | --- |
| `protocol` | tcp、udp、http、https |
| `source_mode` | TCP/UDP：socket、native；HTTP(S)：forwarded_headers |
| `transport` | auto（QUIC 优先、TLS 回退）、quic_only、tls_only |
| `target` | TCP/UDP 为 host:port；HTTP(S) 为带可选 base path 的 URL |
| `host` / `server_name` | 回源 Host / TLS SNI；Agent 仍校验回源证书 |
| `timeout_seconds` | 规则超时设置，0 使用默认值 |

native 要求设备当前签名能力包含 `native_tcp_ipv4_ip_port` / `native_udp_ipv4_ip_port`。实现为 Linux 透明 socket；IPv6 native 不支持。保留边缘观察到的源 IP 和源端口，冲突时失败，不更换源端口或添加 PROXY 前缀。

ACL 仅作用于 TCP/UDP。规则可绑定已发布模板或内联策略；mandatory 策略与规则策略共同约束。条目按较小 priority 优先，支持 action=allow/deny、cidrs、来源 ports、protocol、not_before、expires_at；default_action 必须显式声明。省略集合为任意，显式空 CIDR/端口集合无效。

地域条件为 countries（两位大写码）、regions（如 AA-X 格式），并明确 geo_unknown_action=deny|no_match。数据来自边缘的管理员 geoip_file，无内置地域数据库。缺失或损坏会关闭依赖地域能力的规则；文件更新后的同步重新编译并重新判定已有流。

`POST /acl/simulate` 输入 `source_ip`、访客的 `source_port`（1..65535）、`protocol`（tcp/udp）和可选 `at`（RFC3339）。必须且只能选择 `rule_id`、`template_id` 或管理员专用的原始 `policy`；模板另指定 `template_revision: "published"|"draft"`。普通用户只能模拟本空间 TCP/UDP 规则或已发布模板；管理员可预览草稿和任意规则。规则模式按同一数据库快照组合已发布 mandatory 与规则实际策略。地域输入 `geo.state` 为 unavailable/unknown/known；known 可带 country/region，所有地域均为手动假设，不查询真实边缘 GeoIP。unavailable 时，任何地域策略整层拒绝，与运行时能力检查一致。

模拟响应含 `scope`、`observed_at`、`evaluated_at`、`source`、`geo`、`allowed`、`action`、`reason` 和按次序的 `chain`；每层包括策略版本及 `decision`（命中条目或默认动作）。规则模式另含规则版本和 enabled/deleting。`acl_only: true`、`desired_snapshot: true` 表示只解释云端期望策略，不表示边缘已经应用、端口可用或目标可达。此诊断不写审计、revision 或幂等记录，每 IP 每分钟上限 60 次。

`GET /acl/observations` 返回真实入口判定的累计允许/拒绝计数。TCP 按进入 ACL 的新连接计，UDP 按进入 ACL 的入站报文计；模拟、后台重查和 HTTP(S) 不计入。每条计数以 boot、规则版本、有效策略摘要及首条命中/默认动作区分；`kind=rule_total` 与 `kind=policy` 为不同层次，不能相加。标签不保存访客 IP/端口，条目文本最多 128 字节并另保留身份摘要。`current` 只标识当前配置，历史计数不代表当前生效。

响应另含 `application`：期望规则版本、边缘当前 boot，以及实际 `ack` 的规则/策略版本、摘要、应用时间、授权期限和活动流采样。state 为 pending/applied/error/inactive/expired；未收到实际 ACK、boot 或配置不匹配时不能显示已应用，stale 表示反馈超过一分钟。模板 applications 端点按边缘汇总这些状态，最多 4096 条受影响规则，并显式返回 truncated。普通用户不能读取跨空间计数或平台汇总。

边缘通过 `EdgeSyncRequest.acl` 可选字段上报 boot 内单调 sequence、累计 rows 与实际 ACKs；重复/乱序不重复计数。每批最多 256 个计数、16 个 ACK、128 KiB；边缘计数标签最多 4096，云端每 edge 最多 8192 个计数、保留 7 天。达到容量时记录丢弃数；平台级 `collection_loss` 仅向管理员提供，统计不承诺穷尽所有访问。应用 ACK 在策略应用及旧流取消后产生，观测不授予转发权限。

status 可为 pending、waiting_for_agent、listening、ready、error、disabled、quota_exhausted、deleted。applied_version 表示边缘报告版本；ready 需实际目标成功（UDP 需回包），不是持续主动健康检查。新版本不能沿用旧 ready。

## 运行时同步

全部使用 POST，前缀 `/api/v1/runtime`；不使用浏览器 cookie/CSRF。

| 路径 | 身份和请求 → 响应 |
| --- | --- |
| `/client/bind` | BindRequest{name,public_key} → BindResponse{id,user_code,poll_token,verification_uri,expires_at,status} |
| `/client/bind/poll` | `{id,poll_token}` → 状态；批准后含 device_id，绝不发浏览器会话 |
| `/client/sync` | ClientSyncRequest 的 Ed25519 签名 → ClientSnapshot |
| `/edge/sync` | Bearer 边缘 token，EdgeSyncRequest → EdgeSnapshot |

Agent 在绑定前本地生成并保存 Ed25519 私钥。同步签名为标准 Base64，签名输入通过 `model.ClientSyncPayload` 生成：清空 signature，按 Go 类型字段顺序序列化整个请求，加前缀 `drafrp-client-sync-v2\n`（实际为换行）。包含 device_id、session_id、timestamp（Unix 秒）、capabilities、applied_revision、nonce 和可选 runtime。runtime 缺省时省略该字段，保留旧客户端签名字节。最大时钟偏差 60 秒，nonce 防重放；旧 SyncPayload v1 不用于当前同步。跨语言实现须对照 Go 序列化和测试。

每次 Agent 启动使用新 session_id；有效租约内另一 session 被拒绝，不反复驱逐旧进程。边缘每次启动使用新 boot_id；退休 boot 不能重新接管。snapshot/device/grant 到期均限制转发授权，云控失联超过期限后关闭已有流和监听。

EdgeSyncRequest 包括 edge_id、boot_id、applied_revision、statuses、usage、可选 runtime。usage 为每 grant 单调累计的 sequence、upload_bytes、download_bytes、closed；重复上报幂等，回退或超额使整个批次回滚。grant 与 tenant/edge/boot/period 绑定；重复同步不充值。跨周期迟到报告只结算原周期；失联边缘无法核实的预留保守结算。

EdgeSnapshot 包含 revision、expires_at、edge、devices、rules、grants、certificates、mandatory_acls。证书私钥仅经认证的边缘同步发放。ClientSnapshot 包含 revision、expires_at、device、edges、rules。

runtime 为边缘实测：endpoint 监听/错误、活跃流、QUIC/TLS 承载数、UDP 映射数、授权期限、容量实施模式、可选物理网卡计数和 GeoIP 状态。云控保存报告，前端结合 last_seen 判断过时状态。

ClientSyncRequest.runtime 为 Agent 签名采样，包含 reported_at、snapshot_expires_at、preferred_transport、active_flows、active_carriers、quic_carriers、tls_carriers、carriers、endpoints 和 truncated。carriers 记录 edge_id/transport/address/server_name、active_flows、established_at 与 handshake_ms；endpoints 记录连接尝试/成功时间、连续失败数、retry_at、handshake_ms、probing 与分类 error_code，绝不上报原始错误文本。两种数组各限 128 条，超出时确定性截断并标记 truncated。

云控为设备观测设置 received_at、session_id 和 generation，仅保留当前设备有效规则授权的端点。`GET /devices` 仅暴露当前未过期会话的 runtime；撤销、新会话或不带 runtime 的旧客户端同步会清除旧观测。观测不授予转发权限。控制台每 10 秒刷新设备页；握手耗时是连接建立与认证时间，与持续控制流 RTT 分开显示。

carrier 的可选 `quality` 使用 `source=carrier_probe_v1`，包括窗口起止、最近成功时间、`interval_ms=5000`、`timeout_ms=2000`、`window_limit=64`，以及 samples/successes/timeouts/errors 和 latest/mean/min/max_rtt_ms。每承载一个在途、最多保留 320 秒，取消、撤销和退出不作为网络超时；无成功样本时不把 0 当 RTT。旧对端不支持或还无样本时省略 quality，保持旧签名字节。

QUIC 的 quality 还可携带 `quic`，来源 `quic_go_rfc9002`，显示真实 ACK latest/smoothed/min_rtt_ms、连接期 packets/bytes_sent/received 和当前 packets/bytes_lost。判丢数可因迟到包下降，不是单调累计重传次数，不据此计算 IP 丢包率。TLS 不填这些 QUIC 字段。控制流往返包含承载排队与对端处理，不等于目标健康或业务响应时间。

## 数据承载

TLS 默认严格校验证书，支持私有 CA。ALPN 为 `drafrp/1`；QUIC 使用原生 stream，TLS 使用 yamux。Agent 主动出站；先发送版本 Hello，再接收随机 nonce，使用绑定私钥签名 ProofPayload。边缘核对公钥、session、generation、expiry；业务 stream 只能由边缘发起。

控制帧为 4 字节大端长度加 JSON，最大 64 KiB。Flow 元数据含规则/version、flow ID、协议、peer、generation 和 HTTP Host/scheme/ingress_port。TCP 保持原始业务字节和半关闭；UDP 使用 2 字节长度封帧，支持零长度，最大 65507 byte。QUIC datagram 仅用于可承载大小，较大包走可靠 stream，保留边界。

Hello 与 challenge 使用可选 `probe_version=1` 协商承载探测，认证成功后才启用，不改变 ProofPayload。Agent 发起的控制 stream 仅接受固定 24 字节请求及原样回显（8 字节版本 magic 与 16 字节随机 nonce），不能用于业务 Flow。每承载同步处理一个，服务端至少间隔一秒，读写两秒超时，并在读取前后验证当前 snapshot/device 授权；探测不占业务流许可、信用或目标连接。

HTTP(S) 由边缘路由，Agent 根据认证元数据重建来源头，移除来访同名头与 Forwarded。流式请求/响应和 WebSocket 使用相同计费与撤销生命周期。
