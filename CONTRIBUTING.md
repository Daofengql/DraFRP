# 贡献指南

[English](CONTRIBUTING.en.md) | 简体中文

DraFRP 由 Go 服务和 React/TypeScript 控制台组成。欢迎提交问题报告、针对性修复、文档
改进和经过验证的功能变更。

## 提交前

- 阅读[实现状态](docs/reference/IMPLEMENTATION.md)了解已交付行为，并查看[文档索引](docs/README.md)。
  设计文档描述目标行为，可能领先于当前实现。
- 不要提交凭据、私钥、真实服务地址或运行时输出；配置示例使用 `examples/` 中的占位值。
- 保持改动聚焦，行为变更需附带测试。
- 修改 Go 文件后运行 `gofmt`；修改控制台后运行 `npm run format:check`。

## 本地检查

```bash
go vet ./...
go test -race ./... -count=1 -timeout=5m
cd web
npm ci --no-audit --no-fund
npm test
npm run build
```

数据库集成测试需要专用 MySQL 实例，详见[测试说明](docs/guides/TESTING.md)。不要对含有用户数据
的数据库运行测试。Linux TUN 和 native 模式测试需要隔离的 Linux 网络命名空间及额外网络
权限。

## Pull request

请说明用户可见行为、限制和执行过的检查，并指出配置或 API 兼容性变化。不要附带包含
运行时凭据或私有网络信息的日志。
