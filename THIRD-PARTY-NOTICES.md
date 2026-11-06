# Third-party notices

English legal and component details are followed by a Chinese summary below.

DraFRP is licensed under GPL-3.0-only; see [LICENSE](LICENSE). This file lists
the third-party components included in the Go programs and production console.
License texts are included in `licenses/`. Exact Go versions are locked in
`go.mod` and `go.sum`; the production JavaScript inventory is in
`licenses/npm-production/manifest.json`.

## Go dependencies

| Component | Version | License |
| --- | --- | --- |
| filippo.io/edwards25519 | v1.1.1 | BSD-3-Clause |
| github.com/cespare/xxhash/v2 | v2.3.0 | MIT |
| github.com/dgryski/go-rendezvous | v0.0.0-20200823014737-9f7001d12a5f | MIT |
| github.com/go-sql-driver/mysql | v1.9.3 | MPL-2.0 |
| github.com/google/btree | v1.1.2 | Apache-2.0 |
| github.com/hashicorp/yamux | v0.1.2 | MPL-2.0 |
| github.com/quic-go/quic-go | v0.59.1 | MIT |
| github.com/redis/go-redis/v9 | v9.17.0 | BSD-2-Clause |
| golang.org/x/crypto | v0.56.0 | BSD-3-Clause |
| golang.org/x/net | v0.57.0 | BSD-3-Clause |
| golang.org/x/sync | v0.16.0 | BSD-3-Clause |
| golang.org/x/sys | v0.47.0 | BSD-3-Clause |
| golang.org/x/time | v0.15.0 | BSD-3-Clause |
| gvisor.dev/gvisor | v0.0.0-20250503011706-39ed1f5ac29c | Apache-2.0 |

The Go license inventory was generated for Linux release targets, including the
Linux-only TUN implementation. The Go module source and license files are
available from the upstream repositories at these locked versions.

## Production console dependencies

The production dependency inventory currently contains 92 packages: 87 MIT,
3 BSD-3-Clause, and 2 ISC. Each package's declared license and upstream
repository are listed in `licenses/npm-production/manifest.json`; the matching
license text files are stored beside that manifest. The package lockfile also
contains development dependencies, which are not part of the deployed console.

## Container images used by examples

The Docker build uses Node.js 24 Alpine, Go 1.26.10 Alpine, and Alpine Linux
3.22 as build/runtime images. The Compose examples also pull MySQL 8.4 and,
optionally, Caddy 2 Alpine. These upstream images are not copied into the
repository's source distribution. Image publishers should retain upstream
notices and security update information when redistributing derived images.

## 中文说明

DraFRP 自身按 GPL-3.0-only 授权。`licenses/go/` 收录 Go 构建目标依赖的
许可证文本；Linux 客户端包含 gVisor TUN 网络栈。前端生产依赖目前共 92
项，按包名、版本、许可证和上游仓库列于
`licenses/npm-production/manifest.json`，对应许可证文本也随仓库和二进制包
提供。精确 Go 版本见 `go.mod` 与 `go.sum`。

Docker 构建使用 Node.js 24 Alpine、Go 1.26.10 Alpine 和 Alpine Linux 3.22。
Compose 示例会从上游拉取 MySQL 8.4；可选 HTTPS 反向代理还会拉取 Caddy 2
Alpine。这些基础镜像不会被复制进源码包。重新分发派生容器镜像时，请同时
遵守上游镜像的许可证与安全更新要求。
