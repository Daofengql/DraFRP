# 来源信息传递与客户端 TUN 设计

设计边界（2026-11-01）：服务器端固定 Linux，使用普通监听；TCP/UDP 业务入口和目标仅为 IPv4，TUN 仅属于 Linux 客户端；HTTP(S) 入口与客户端—服务器承载可为 IPv4/IPv6。Windows 不支持源 IP/端口透传，普通转发和 HTTP(S) 可信来源头仍可使用。新增双栈设计不等于已验收，当前实现与差异见 [实现记录](../reference/IMPLEMENTATION.md)，TUN 配置与验收见 [Linux TUN 指南](../guides/LINUX-TUN.md)。2026-10-31 双端 TUN 方案已移除。

## 1. 来源语义

TCP/UDP 的 `source_mode: native` 要求目标 socket 真实对端为出口观察到的访客 IP 和端口，不插入 PROXY 前缀，不改源端口，不降级普通转发。出口之前的 NAT 已隐藏的来源无法恢复。HTTP(S) 使用 `source_mode: forwarded_headers`，按请求传递可信元数据。

TCP/UDP 的普通 socket 与 native 模式均仅支持 IPv4 访客和 IPv4 目标。关闭 TUN 后，socket 规则由主程序直接连接目标；已配置的严格 native 规则不能自动变成 socket 规则，需显式切换来源模式。原生保源的“无损”指访客 IPv4/端口及业务载荷，不要求保留公网 TCP 的握手、序列号或选项。

外层承载可经 IPv6 传输 IPv4 TCP/UDP 的业务载荷与可信来源元数据；访客来源始终取自业务入口，不取自承载的 IPv6 对端。本轮不提供 IPv6 四层业务转发、IPv6 TUN、NAT64 或通用 IPv4-in-IPv6 包隧道。

## 2. 角色职责

出口普通 accept/read UDP，按真实访客执行 ACL、资源准入，再通过认证且绑定规则/设备/代次的业务流发送 `peer`。出口没有 TUN、DNAT、虚拟地址池或保源网络规则。

Linux 客户端使用 gVisor 用户态 TCP/IP 协议栈，绑定访客 IPv4/端口，连接本地白名单内目标；生成的 IP 包直接写入客户端 TUN。目标看到访客元组，回包经精确策略路由送入 TUN，再交给协议栈还原为业务数据。

TCP 公网侧和目标侧是两条独立连接，握手、序列、窗口与重传独立维护。隧道传业务字节，不传原始公网 SYN 或 IP 包。UDP 在隧道中保留应用报文边界。TUN 提供本地内核投递和回流接口，不负责隧道加密或业务认证。

## 3. 网络模式与能力

客户端可选 `socket`、`transparent`、`tun`。后两者只支持 Linux IPv4。TUN 启动实际完成 TCP 双向载荷与 UDP 回流验证后，报告 `native_tcp_ipv4_ip_port` / `native_udp_ipv4_ip_port` 以及 `tun_client_tcp_ipv4_ip_port` / `tun_client_udp_ipv4_ip_port`。

控制台仅允许匹配当前签名能力的 native 规则；Windows 明确显示不支持。旧双端 TUN 请求的非空 `data_path` / `ip_destination` 被拒绝。网络模式配置不等同于已验证能力，接口故障会撤回能力并关闭相应流。

## 4. 正反向路径与边界

```text
IPv4 访客 → Linux 出口 IPv4 socket → IPv4/IPv6 上的 QUIC/TLS 业务流与可信 peer
          → Linux 客户端协议栈（绑定访客 IPv4/端口）→ 客户端 TUN → IPv4 目标
IPv4 访客 ← 出口原 socket ← IPv4/IPv6 上的 QUIC/TLS 业务数据
          ← 客户端协议栈 ← 客户端 TUN ← 精确回流路由 ← IPv4 目标
```

仅客户端需要 CAP_NET_ADMIN、/dev/net/tun、策略路由与 filter guard。每流由内核 socket 独占来源元组，冲突失败。严格校验回流协议、目标与访客 IP/端口；UDP 通配绑定目标的不同源地址回复被丢弃，保护规则阻止目标回包绕过隧道。

目标可以是本机 IPv4、127.0.0.1 或 LAN 机器。LAN 目标必须事先配置到访客网段的回程经客户端，并在客户端 return_cidrs 声明；仅能拨通目标不代表回流可用。访客地址不能等于客户端自身地址。

客户端 MTU=1500，IPv4 分片有界重组；隧道 UDP 载荷上限65507字节，QUIC DATAGRAM 分段与本地 IP 分片分开管理。TCP 支持半关闭。撤销、ACL 收紧或接口失效及时取消业务和握手；退出和崩溃恢复只管理自身标记的对象。

## 5. HTTP(S)：边缘提供来源，Agent 封装回源

### 5.1 职责与请求路径

公网 HTTP(S) 入口支持 IPv4/IPv6，HTTPS 在边缘终止 TLS。边缘按域名定位站点和设备，取得实际网络对端的源 IP/端口，再将请求和可信元数据发给 Agent。Agent 是实际访问 HTTP/HTTPS 目标的回源客户端。IPv6 访客可访问单栈 IPv4 目标，真实 IPv6 来源写入 HTTP 头；HTTP 不使用 TUN 绑定访客来源，不要求跨地址族模拟 socket 对端。

~~~text
IPv4/IPv6 浏览器 → 边缘双栈 HTTPS / HTTP 入口
              ↓
逐请求隧道消息：方法、路径、请求头、流式请求体、可信来源元数据
              ↓
Agent 按已授权规则构造 HTTP(S) 请求并设置来源头
              ↓
单栈 IPv4 目标 HTTP(S) 服务
              ↓
响应经 Agent 和边缘流式返回浏览器
~~~

回源地址、Host 覆盖、HTTPS SNI 和信任材料来自云控下发到该 Agent 的站点配置。不能让来访 URL 或来源元数据任意指定一个本地目标。HTTPS 回源由 Agent 发起并默认校验证书。

### 5.2 逐请求来源元数据

每个请求至少关联：

~~~text
request_id
tenant_id / device_id / device_session_generation
rule_id / rule_version
client_ip / client_port
ingress_scheme / ingress_host / ingress_port
~~~

来源身份由边缘从实际连接读取。元数据与对应请求流通过已认证的加密隧道传递；Agent 校验设备、规则版本和会话，不接受来自浏览器的同名头作为内部元数据。

HTTP 多路复用时，元数据属于每一个逻辑请求，不作为整条隧道或连接池的共享变量。请求 ID 仅用来关联，不代替隧道认证或规则授权。

### 5.3 Agent 设置回源头

默认的受管头包括：

| 回源头 | 来源与含义 |
| --- | --- |
| X-Forwarded-For | 边缘观测到的访客 IP；默认一个可信 IP，不拼接来访头 |
| X-Real-IP | 同一访客 IP |
| X-Forwarded-Proto | 公网访问协议，例如 https；与回源协议不同 |
| X-Forwarded-Host | 已匹配站点的公网 Host；与回源 Host 覆盖不同 |
| X-Forwarded-Port | 公网入口端口，例如 443；不是访客源端口 |

边缘移除来访的这些头及 Forwarded 等受管来源头；Agent 在构造回源请求时再次按元数据覆盖，防止重复字段、大小写变体或用户自定义回源头绕过可信值。第一阶段不信任外部代理链；若后续支持多层可信代理，须显式配置可信上游并重新定义链处理策略。

XFF 写入经过 IP 地址解析后的值，不混入源端口。访客源端口可留在元数据和日志中；需要交给应用时用单独约定的头，不能冒充 X-Forwarded-Port。IPv6 的编码按所选头的语法处理，不直接拼接未经校验的字符串；例如 IPv6 访客 2001:db8::10 访问 IPv4 回源时，X-Forwarded-For 与 X-Real-IP 均保留 2001:db8::10。

示例：访客 203.0.113.10:54321 通过 HTTPS 访问 app.example.com，Agent 以 HTTP 回源并覆盖 Host：

~~~http
GET / HTTP/1.1
Host: internal.example.local
X-Forwarded-For: 203.0.113.10
X-Real-IP: 203.0.113.10
X-Forwarded-Proto: https
X-Forwarded-Host: app.example.com
X-Forwarded-Port: 443
~~~

目标 socket 的对端仍是 Agent。应用按自身框架将 Agent 的实际回源地址设为可信代理后，从这些头获取访客来源，不要求 PROXY Protocol v2。回源服务若同时允许不可信网络直连，不能把所有直接请求的转发头都视为可信。

### 5.4 连接复用与错误行为

来源头逐请求独立生成，因此可以复用同一站点的回源连接，不必按访客源 IP/端口拆分连接池。连接池仍按租户、规则版本、目标和 TLS 配置隔离，不能把某个请求的身份留在共享连接或可变请求模板里。

HTTP/2、HTTP/3、HTTP/1.1 之间的协议转换不再受原生源端口四元组限制。具体支持的 HTTP 版本、WebSocket 和流式转发仍需实现验证，但不得因未开启 TUN 而拒绝 HTTP(S) 来源头传递。

Agent 规范化构造 HTTP 请求，按协议处理逐跳头和消息分帧，流式传输正文并关联取消信号。正常目标响应原样代理其状态和内容；连接失败、回源 TLS 失败和超时以结构化结果返回边缘，由边缘在尚未发送响应时生成 502/504，设备离线时生成 503。响应已提交后失败只能结束该流，不能改写已经发出的状态。

## 6. 平台、效率与验证

出口部署在 Linux，无需保源网络权限。Windows 客户端明确不支持源 IP/端口透传，暂不开发 Wintun/WFP 路径。客户端 TUN 依赖和权限见 LINUX-TUN.md。

出站直接 writev 协议栈包视图；入站校验授权后为异步处理保留一份副本。生产路径无逐流包队列、整包改写或二次校验和；普通包跳过分片器与时间读取，取消仅保存固定 RST 头。资源计量统一为应用载荷，物理封装和重传单独统计。

Hyper-V 分别验证本机普通地址、loopback 与独立 LAN 目标，覆盖 QUIC/TLS × TCP/UDP、访客 IP/端口、大载荷/空报文、半关闭、取消、ACL、撤销、故障与所有权恢复。优化仅测本地包准备成本，不作吞吐或生产稳定性结论。

IPv6 TCP/UDP 业务转发及保源、通用 IP/ICMP 不在本轮范围。HTTP 双栈入口和双栈承载自动选择属于待补充实现/验收的设计目标；需验证 IPv6 HTTP 访客到 IPv4 目标的来源头、防伪造和连接池身份隔离，以及经 IPv6 承载的 IPv4 socket/native 转发。动态 PMTU 和跨失效承载迁移未实现。公网 NAT、高丢包、大并发、长期稳定性及 frp 对比测试暂缓。
