# 测试说明

[English](../en/guides/TESTING.md) | 简体中文

## 本地检查

```bash
go vet ./...
go test -race ./... -count=1 -timeout=5m
cd web
npm ci --no-audit --no-fund
npm test
npm run build
```

云控与系统集成测试仅在 `DRAFRP_TEST_MYSQL_DSN` 指向专用 MySQL 实例时运行；测试用户
需要创建和删除临时数据库的权限。Redis 集成测试可通过 `DRAFRP_TEST_REDIS_ADDRESS`
选用。不要对生产或个人数据运行这些测试。

Linux native 和 TUN 测试需要临时 Linux 虚拟机或隔离网络命名空间。测试会在该命名空间
内创建路由、策略规则、TUN 设备和防火墙对象。不要在通用主机上启用特权测试环境。


使用 `scripts/browser_e2e.py` 进行浏览器端到端测试时，操作者必须显式提供 SSH 目标、SSH
密钥和远端测试数据库 DSN。仅使用隔离测试虚拟机和专用空数据库；不要提供生产凭据，也不要
将这些值提交到仓库。

## Linux VM 性能测试

在隔离 Linux VM 中用 release 构建的 cloud、edge、client 二进制运行 `scripts/smoke.py --performance`。每次运行都需要新的专用空 MySQL 数据库、私有且不存在的 `--work-dir`，以及有效的二进制目录。使用隐藏输入或受保护的环境管理器设置 DSN，避免将其写入 shell 历史：

```bash
export BIN_DIR=bin/0.1.0/linux-amd64
read -r -s -p 'Disposable MySQL DSN: ' DRAFRP_SMOKE_MYSQL_DSN; printf '\n'
export DRAFRP_SMOKE_MYSQL_DSN
python3 scripts/smoke.py --bin-dir "$BIN_DIR" --work-dir "/var/tmp/drafrp-perf-quic-$(date +%s)" --performance --transport quic_only
```

为 TLS-only 测试另建空数据库和工作目录，再以 `--transport tls_only` 重跑。输出 `result.json` 包含持久 TCP echo RTT 的 p50/p95/p99、1/4/16 并发 TCP goodput、128 B/1400 B/48000 B UDP 窗口回显的延迟/丢失/goodput，以及 cloud/edge/client 进程的 CPU 和 200 ms 间隔采样 RSS。测试只覆盖 VM loopback 上的普通 socket 转发，不测 TUN、WAN 或跨项目性能。工作目录包含临时凭据，保存结果后应删除；结果文件不含 DSN。

## 已有验证范围

此前验证使用 Windows 和 Ubuntu 虚拟机，搭配隔离 MySQL 与专用 Docker 网络。仓库保留可
复现的测试摘要，不发布临时原始日志、私有测试地址、本地路径和运行凭据。

性能记录包括 Linux TUN 包路径微基准，以及隔离 VM 上 QUIC/TLS 普通 socket loopback 的 TCP 延迟/吞吐、UDP 窗口回显和进程 CPU/RSS。
测试不代表 WAN、TUN 端到端吞吐、生产容量或跨项目比较。该 VM 的 UDP 接收缓冲上限为 425984 字节；高窗口测试报告的是 harness 未收到的 echo，不能当成 WAN/NIC 丢包率。
