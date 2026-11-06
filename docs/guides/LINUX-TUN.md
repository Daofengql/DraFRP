# Linux 客户端 TUN

TUN 只属于 Linux 客户端。出口边缘固定支持 Linux，使用普通 TCP accept 和 UDP socket 监听，不创建 TUN、DNAT、地址池或保源策略路由，也不需要为保源授予 CAP_NET_ADMIN。出口从真实网络对端读取访客 IP/端口，经认证的 QUIC/TLS 承载将来源元数据和业务数据交给客户端。

客户端使用 gVisor netstack 绑定访客 IPv4 和端口，建立到获准目标的独立 TCP/UDP 连接。协议栈产生的包写入客户端 TUN，目标内核接收；精确策略路由将回包送回 TUN，再由协议栈还原业务数据。TCP 公网侧与目标侧分别握手、确认和重传，目标保留访客 IP/端口，不保留公网 SYN、序列号或 TCP options。

2026-11-01 设计范围为 IPv4 TCP/UDP 业务；服务器—客户端外层 QUIC/TLS 可经 IPv4/IPv6 传输业务载荷和来源元数据，目标侧仍使用原访客 IPv4，不需要 IPv6 TUN。HTTP(S) 入口保留双栈，IPv6 访客到 IPv4 回源使用逐请求可信来源头及普通连接池，不经 TUN 模拟来源。双栈承载及普通 socket 的 IPv4 范围收紧已实现，验证范围见 [实现与验收记录](../reference/IMPLEMENTATION.md)。

关闭 TUN 后，普通 socket 规则由主程序直接连接 IPv4 目标；已有严格 native 规则不能静默降级，需显式改选 socket。HTTP(S) 的来源头与回源能力独立于 TUN 开关。

Windows 支持普通 socket 转发和 HTTP(S) 来源头，不支持源 IP/端口透传；`network_mode: tun/transparent` 会在创建设备状态前明确拒绝。IPv6 TCP/UDP 业务及保源、通用 VPN、ICMP 转发不在本轮范围，动态 PMTU 通告和已有流跨失效承载迁移未支持。公网 NAT、高丢包、大并发、长期稳定性和 frp 对比测试暂缓。

## 环境与配置

出口使用普通 [edge.json](../../examples/edge.json)，旧出口 `tun` 配置会被拒绝。普通 Docker `edge` target 以非 root 用户、无网络管理能力、无 `/dev/net/tun` 运行；物理出口整形的 `edge-wire` target 单独以 root 运行并需 NET_ADMIN。

仅客户端需要专用 Linux 网络命名空间、`/dev/net/tun`、CAP_NET_ADMIN、`ip` 和 `iptables`。管理员须事先设置 IPv4 forwarding=1、全局 rp_filter=0 或 loose=2，并允许 TUN 接口 route_localnet=1、accept_local=1、rp_filter=0。Docker 示例参数：

```sh
--cap-add NET_ADMIN --device /dev/net/tun \
--sysctl net.ipv4.ip_forward=1 \
--sysctl net.ipv4.conf.all.rp_filter=0 \
--sysctl net.ipv4.conf.default.rp_filter=0 \
--sysctl net.ipv4.conf.default.route_localnet=1 \
--sysctl net.ipv4.conf.default.accept_local=1
```

这些设置用于专用命名空间。Docker 使用 `client-tun` target；该 target 包含网络工具，创建容器时仍需提供上述权限和设备。

客户端配置见 [client-tun.json](../../examples/client-tun.json)：

| 配置 | 说明 |
| --- | --- |
| network_mode | `tun`；`socket` 为普通转发，`transparent` 为另一条 Linux 保源路径 |
| state_dir | 私有、持久、绝对路径，0700，同一命名空间的独立进程不能共享 |
| tun.max_flows | 默认 128，上限 1024；达到限制拒绝新流 |
| tun.return_cidrs | 允许已配置回程的远程目标 IPv4 网段；本机地址无需声明 |
| allowed_target_cidrs / allowed_target_ports | 限制最终目标，不因启用 TUN 放宽 |

未提供 `tun` 对象时，可沿用根级 `native_return_cidrs` / `native_flow_limit`。目标可为 127.0.0.1、本机普通 IPv4 或独立 LAN 机器。LAN 目标必须事先配置到访客网段的回程经客户端，配置声明不能替代路由。访客 IP 不能是客户端自身地址。来源 IP/端口已有占用时失败，不改端口。

启动实际完成 TCP 握手、双向载荷和 UDP 回流后，才上报 `native_tcp_ipv4_ip_port` / `native_udp_ipv4_ip_port` 及 `tun_client_tcp_ipv4_ip_port` / `tun_client_udp_ipv4_ip_port`。控制台仍选择 `source_mode: native`。平台和网络模式包含在设备签名运行报告中，Windows 明确显示能力限制。

先升级云控，再更新出口和客户端。2026-10-31 双端 TUN 预览的包协议已移除；新客户端拒绝旧 `data_path` / `ip_destination` 请求，旧配置不可直接沿用。

## 包处理与计量

客户端 TUN MTU=1500。TCP 由协议栈分段；UDP 最大应用载荷 65507 字节。目标内核产生的 IPv4 分片在客户端有界重组：最多 64 个未完成包、每包最多 64 片、两秒到期，约 4 MiB 数据缓存；重叠片段、IP options、非法长度和校验和被拒绝。隧道仅传 TCP 业务字节或 UDP 载荷，QUIC DATAGRAM 有界分段重组，TLS 保留 UDP 长度封帧。

出站借用协议栈包视图，以一次 writev 写入 TUN，不经过包队列、整包拼接、地址改写或第二次校验和计算。入站在校验及精确回流元组匹配后，为异步协议栈保留一份拥有所有权的副本，不使用每流包队列。普通未分片包不经过分片器或读取时间；取消只保存固定 40 字节 RST 头，不保留最后一整个载荷。

ACL 在出口按实际访客身份执行。客户端独立检查设备/规则/会话代次、承载、协议、目标白名单和保源能力；只为获准流安装精确 filter / policy route，并通过内核 socket 独占来源元组。未知回流包丢弃。共享连接数、PPS、带宽、流量额度继续使用原业务转发机制。

所有网络模式统一按**应用载荷字节**消费额度并汇总累计和分钟历史。TUN/IP/TCP/UDP 头、ACK、目标侧重传不额外计入；隧道封装和外层重传只进入独立物理统计。旧双端 TUN 预览的内层 IP 计量记录属于历史口径。

## 生命周期与验证

TCP 支持半关闭。取消、撤销、ACL 收紧、授权失效或额度失效会关闭对应流；UDP 按空闲超时回收。接口删除、down 或 MTU 改变时撤回能力、关闭活动连接并取消进行中的握手。回流保护规则阻止已授权元组绕过 TUN 从普通接口发出。

正常退出清理私有网络对象；崩溃后使用同一命名空间、同一状态目录精确恢复。所有权不匹配时保留记录并失败，不清空系统路由表或防火墙。更换命名空间应使用新的状态目录。

`DRAFRP_TUN_TEST=1` 仅在专用 NET_ADMIN 命名空间开启特权内核测试，覆盖真实 TCP/UDP、来源身份、大载荷、半关闭、取消、故障、占用、恢复与清理。`DRAFRP_TUN_LOCAL_IP` 增加本机普通地址测试。`BenchmarkTUNPacketPreparation` 对同样的协议栈包比较拼接副本与 writev 视图的本地准备成本，不代表吞吐或 frp 对比。

`scripts/tun_smoke.py` 验证独立无特权出口、客户端和本机/LAN 目标的三程序链路，包含 QUIC/TLS × TCP/UDP、128 KiB TCP、60 KB/空 UDP、访客 IP/端口、半关闭、UDP 停用重启、ACL 收紧、撤销、应用计量和清理。原始验证材料未纳入文档发布。
