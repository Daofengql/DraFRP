# 文档

[简体中文](README.md) | [English](README.en.md)

## 使用与部署

- [项目概览](../README.md)：支持范围、构建与快速开始。
- [部署指南](guides/DEPLOYMENT.md)：Compose、HTTPS 代理、独立出口/客户端、升级与备份。
- [Linux TUN 指南](guides/LINUX-TUN.md)：客户端 TUN 保源、权限、故障处理与边界。
- [示例配置](../examples/)：JSON、Compose、Caddy 与 systemd。

## 开发与运维

- [实现与验收记录](reference/IMPLEMENTATION.md)：已交付行为、验证范围与已知缺口。
- [测试说明](guides/TESTING.md)：本地检查、数据库要求与特权 Linux 测试边界。
- [性能记录](performance/2026-11-06.md)：Linux TUN 微基准与 VM loopback QUIC/TLS 测量及限制。
- [API 合约](reference/API-CONTRACT.md) 与 [数据库关系和删除策略](reference/SCHEMA-INTEGRITY.md)。
- [贡献指南](../CONTRIBUTING.md)、[安全报告](../SECURITY.md) 与 [第三方声明](../THIRD-PARTY-NOTICES.md)。

## 设计文档

以下文档描述目标规格，不代表所有功能均已交付；请先查阅[实现与验收记录](reference/IMPLEMENTATION.md)。

- [内网穿透服务设计](design/tunnel-service-design-notes.md)
- [传输协议、双栈承载与 UDP 优先](design/transport-protocol-design.md)
- [连接复用与资源控制](design/multiplexing-and-resource-control-design.md)
- [来源信息传递与客户端 TUN](design/transparent-source-design.md)
- [TCP/UDP ACL、模板与防火墙](design/tcp-udp-acl-firewall-design.md)
- [运行与存储](design/storage-and-runtime-design.md)
- [前端与二进制嵌入](design/frontend-and-embed-design.md)
