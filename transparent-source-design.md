# 来源信息传递与 TUN 设计

## 1. 目标与支持状态

TCP/UDP 透明保源要求目标通过 socket 识别公网源 IP、源端口，无需解析 PROXY Protocol v2。HTTP(S) 则采用应用层来源头：边缘提供可信逐请求元数据，Agent 构造回源请求并写入类似 X-Forwarded-For 的头。

本方案把 Agent 的 TUN 设计为 TCP/UDP 的可选网络模式。已确认 Linux 具备 TUN、透明套接字和策略路由等基础机制，但本项目尚无原型，具体平台和网络条件仍需验证。HTTP(S) 使用普通回源连接即可传递来源头，不要求 TUN 或透明 socket。

“公网源地址”以边缘入口实际观测到的网络对端为准。访问者经过 NAT 或其他代理时，无法据此恢复不可见的内网地址；未经信任的转发头不能提升为网络层真实身份。

## 2. TUN 解决什么

TUN 是三层虚拟网络接口：

- Agent 向 TUN 写入 IP 包，操作系统将其视为从该接口收到的包。
- 系统将路由到 TUN 的包交给 Agent 读取，再经隧道发往边缘。
- TUN 不要求目标应用理解额外协议头。
- TUN 本身不完成加密、鉴权、NAT、路由配置或 TCP 协议状态维护。

因此，TCP/UDP 路径优先隧道转发原始 IP 包，由内核路由与 conntrack/NAT 处理转发，访问者与目标服务的协议栈维护连接状态。不能把已 accept 的 TCP 字节流随意填上 IP/TCP 头就称为原始连接；那还需要正确的握手、序列号、确认、重传和窗口状态。

若继续复用基于 TCP 字节流的转发内核，需要额外的透明连接机制或用户态 TCP/IP 协议栈来构造独立连接，不能仅加一个 TUN 接口就获得原始包转发能力。

IP 包在加密隧道内仍有封装开销。这里取消的是对目标业务流的 PROXY 头要求，不是取消隧道封装。

## 3. 网络模式与能力

Agent 本地可设置：

~~~yaml
network_mode: socket  # 或 tun
~~~

TCP/UDP 规则分别声明所需的原生身份信息：

~~~yaml
source_identity_mode: native
native_source_identity:
  require_ip: true
  require_port: true
~~~

HTTP(S) 规则使用 source_identity_mode: forwarded_headers，不依赖设备启用 TUN，也不声明 native_source_identity。

匹配规则：

- socket 模式用于不要求原生保源的规则；目标通常看到 Agent 的地址和临时源端口。
- tun 模式只有在接口、权限、路由、回流和对应协议能力检查通过后，才宣告保源可用。
- 同时要求 IP 与端口时，不能只保留 IP，也不能自动用 PROXY v2 或 HTTP 头降级。
- 不满足条件时返回明确原因，如 capability_missing、return_path_unavailable、source_tuple_conflict。
- 关闭 TUN 后，相关严格保源规则停止转发并显示原因；其他规则可继续使用独立的 socket 能力。
- IPv4、IPv6、TCP、UDP 原生保源的能力分别报告，不用一个 tun_enabled 布尔值代表全部就绪。HTTP 回源与可信头传递属于独立能力。

“tun”是选择的数据路径；“原生保源就绪”是经过验证的运行能力，两者不能混为同一个状态。

## 4. TCP/UDP：按规则转发 IP 包

### 4.1 正向路径

建议原型验证以下结构：

~~~text
公网访问者 client_ip:client_port
    ↓
边缘公网入口 public_ip:public_port
    ↓
边缘匹配已批准规则，以原始公网五元组执行来源 ACL，再映射目的地址
    ↓
经带身份校验的 IP 包隧道发送给指定 Agent
    ↓
Agent 校验流授权与最终目标后注入 TUN，内核按规则 DNAT 到目标地址
    ↓
目标服务看到 client_ip:client_port
~~~

公网源地址保持不变，不对该方向做源地址伪装。内部服务地址仅用于隧道路由和规则映射，分配时避免与宿主机、目标网络地址冲突。

边缘的透明 TCP/UDP 入口执行包级转发，不先通过普通 TCP accept/UDP 代理替换掉原连接身份。边缘内部接口、策略路由和 NAT 是这一模式的组成部分。

### 4.2 返回路径

~~~text
目标服务响应到 client_ip:client_port
    ↓
回包被导回 Agent 的对应 TUN 数据路径
    ↓
Agent 侧 conntrack 执行反向目的转换
    ↓
隧道返回原边缘
    ↓
边缘 conntrack 恢复公网入口身份
    ↓
原访问者收到响应
~~~

每个方向必须通过对应的 NAT/conntrack 域，才能完成反向映射。不能只验证目标收到了第一包就宣告透传成功。

若目标在另一台局域网机器，回程必须经过 Agent 或受控路由器。仅仅满足“Agent 能访问目标”不保证保源可用；目标把回包直接交给自己的默认网关时，这条路径不能成立。

若目标在本机，尤其是 127.0.0.1，还需验证本机回流、loopback 地址限制、策略路由和连接跟踪。具体策略按最小范围应用，不能假设 loopback 与普通 LAN 目标行为相同。

### 4.3 TCP/UDP 边界

- 映射关联设备身份、会话代次、规则版本、协议和原始五元组。
- UDP 保留报文边界，对每个来源维持双向映射及空闲超时。
- 同一客户端可能通过不同公网入口访问同一个内部服务。DNAT 后若得到重复的 TCP 四元组或 UDP 流身份，须检测冲突。
- 严格保留端口时不能用自动改写源端口掩盖冲突；应拒绝冲突流，或采用经过验证的额外隔离结构。
- MTU、PMTU/ICMP、分片重组、乱序及映射过期必须纳入原型。
- IP 包承载优先验证 QUIC DATAGRAM 等加密数据报通道；控制同步独立使用可靠通道。TCP/TLS 兜底承载 IP 包时，要评估 TCP 套 TCP、排队和队头阻塞，不能将兜底等同于低延迟保证。
- 数据报大小受承载协商与外层 MTU 约束；隧道分段/重组与业务 IP 分片分开处理。IPv6 TUN MTU 等协议要求不能为适配外层包容量而被忽略，具体见 [传输协议与承载设计](transport-protocol-design.md)。

## 5. HTTP(S)：边缘提供来源，Agent 封装回源

### 5.1 职责与请求路径

公网 HTTPS 在边缘终止 TLS。边缘按域名定位站点和设备，取得实际网络对端的源 IP/端口，再将请求和可信元数据发给 Agent。Agent 是实际访问 HTTP/HTTPS 目标的回源客户端。

~~~text
浏览器 → 边缘 HTTPS / HTTP 入口
              ↓
逐请求隧道消息：方法、路径、请求头、流式请求体、可信来源元数据
              ↓
Agent 按已授权规则构造 HTTP(S) 请求并设置来源头
              ↓
目标 HTTP(S) 服务
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

XFF 写入经过 IP 地址解析后的值，不混入源端口。访客源端口可留在元数据和日志中；需要交给应用时用单独约定的头，不能冒充 X-Forwarded-Port。IPv6 的编码按所选头的语法处理，不直接拼接未经校验的字符串。

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

## 6. 平台与权限

### Linux

TCP/UDP 原生保源的基础机制包括 /dev/net/tun、策略路由、conntrack/NAT；若采用透明 socket 的替代路径，还需验证相应的非本地地址绑定权限。TUN 创建与路由管理需要 CAP_NET_ADMIN 或预配置的受控权限。HTTP(S) 来源头回源使用普通 socket，不需要这些网络管理权限。

Agent 可保持单个分发可执行文件，但启用 TUN 会产生系统网络配置和权限需求。接口、路由、NAT 和流状态需有明确归属标记，支持启动时核对、关闭时清理和崩溃后的恢复。

### Windows 与其他平台

Windows 可评估 Wintun，官方提供三层包读写接口及已签名 DLL/驱动分发。启用时需要相应安装和网络管理权限；单二进制分发与运行时驱动依赖需分别说明。

Wintun 的存在只证明能读写 IP 包，不证明本项目已完成本机投递、源身份保留和回流捕获。Windows 网络过滤、路由和 loopback 路径需独立原型验证，必要时评估 WFP 等机制。

其他平台也按实际能力开放，不把 Linux 的验证结果当成跨平台保证。

## 7. 隔离与运行要求

- 内部隧道和路由只服务已批准规则，不接管普通网络流量的默认路由，也不开放设备间组网；专用策略路由表只匹配批准的业务流量。
- 边缘与 Agent 均校验报文所属设备、规则、版本、目标和活动流。
- 目标 Agent 只能为自己的授权流返回报文，不能借 TUN 伪造任意网络流量。
- TCP/UDP 的来源 ACL 使用目的转换前的公网五元组，Agent 目标限制使用最终目标；socket 与 TUN 路径执行相同语义。管理员模板仅提供机制，具体条目后续由管理员配置。
- 加密承载连接与保源业务路由分离，避免隧道把自己的传输包再次送回 TUN。
- 设备撤销、规则停用或会话换代时清理对应 NAT/流状态，不误删其他设备的状态。
- UDP/TUN 跨承载改绑需先确认映射、授权和流代次，拒绝旧代次迟到数据；原生保源能力不能因传输回退而自动降级，内层 TCP 是否可继续需要独立验证。
- ACL 收紧、模板发布、地址组/地区库更新和条目到期后重新判断关联流；不允许通用 ESTABLISHED 放行绕过撤销。内核对象仅在本项目拥有的范围内管理。
- 网络分区时按短期租约停止过期流量；本机转发路径也必须执行过期限制，不能只停止控制连接。
- 设置并发连接、UDP 映射、分片重组和内存上限，避免单台设备占尽共享边缘资源。

来源策略、目标边界、分片检查与状态撤销详见 [TCP/UDP ACL、模板与防火墙设计](tcp-udp-acl-firewall-design.md)；HTTP(S) 不接入该方案的 ACL。

## 8. 原型验收要求

以下为后续实现的验收条件，当前尚未执行：

1. Linux 上分别覆盖本机普通地址、127.0.0.1 和另一台 LAN 目标；不能仅验证 TUN 创建成功。
2. TCP 服务通过 getpeername() 核对源 IP/端口，确认业务流没有 PROXY 前缀；完成双向传输与关闭。
3. UDP 服务通过 recvfrom() 核对来源，覆盖多个客户端、多个规则、超时清理与返回路径。
4. 同账号多 Agent 与不同租户并发，确认规则、流量和源地址映射互不串用。
5. 不同公网入口映射到同一目标，验证源四元组冲突能被明确识别且不会偷偷改端口。
6. HTTP(S) 验证来源元数据、Agent 生成的 XFF 等头、Host、SNI、证书校验与错误页；确认目标 socket 对端为 Agent 且应用读取到正确的来源头。
7. 伪造来访 XFF、Forwarded、重复或不同大小写的来源头；多个访客在 keep-alive、HTTP 多路复用和并发回源下不能串用来源。关闭 TUN 后 HTTP(S) 仍正常工作。
8. 验证 MTU、分片、包乱序、回流路由缺失、权限不足、TUN 关闭及进程崩溃。
9. 验证断线重连、旧设备会话、旧规则版本和租约到期后不会遗留继续转发的内核流。
10. 对 Windows 独立验证驱动、权限、目标投递与回包，不依据接口存在就通过验收。

## 9. 机制依据

- [Linux TUN/TAP 官方文档](https://docs.kernel.org/networking/tuntap.html)：TUN 读写 IP 包，以及创建网络接口的权限要求。
- [Linux 透明代理官方文档](https://docs.kernel.org/networking/tproxy.html)：IP_TRANSPARENT、非本地地址绑定及策略路由。
- [NGINX TCP/UDP 透明绑定](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_bind)：非本地源地址代理及截获回包所需路由。
- [Wintun 官方文档](https://www.wintun.net/)：Windows 三层虚拟网卡、包读写和已签名分发形式。
