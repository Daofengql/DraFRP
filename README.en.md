# DraFRP

[English](README.en.md) | [简体中文](README.md)

DraFRP is a self-hosted port and website forwarding platform with three
separately built services: a cloud control plane, shared edge nodes, and
outbound-connected clients. The cloud stores accounts, clients, rules, plans,
and audit data. Only the cloud service requires MySQL; Redis is optional.

The current implementation supports TCP, UDP, and HTTP(S) forwarding. Clients
prefer QUIC and can fall back to TLS over TCP with yamux. See the [implementation
status](docs/reference/IMPLEMENTATION.md) for delivered behavior and known gaps.
Design documents describe target specifications and do not imply that every
feature has shipped.

This is an early preview. Linux client TUN has been exercised in an isolated
environment, but public NAT, high packet loss, large-scale concurrency, and
long-duration stability have not been validated. Performance results apply
only to the benchmark scope stated in the report.

## Capabilities and limits

- TCP, UDP, and HTTP(S) forwarding through a shared edge fleet.
- MySQL-backed accounts, service plans, traffic accounting, ACLs, and audit
  history; optional Redis cache.
- Dual-stack HTTP entry points and carrier connection selection. TCP/UDP
  business forwarding and source preservation currently use IPv4.
- Linux client modes for transparent IPv4 source IP/port preservation, including
  a TUN-based path. These require an isolated Linux network namespace and
  additional privileges. Windows supports ordinary socket forwarding only.
- No general-purpose VPN, IPv6 TCP/UDP forwarding, hole punching, or
  STCP/SUDP/XTCP support in this release.

## Build

Use Go 1.26.10 or a newer security patch in that toolchain line, Node.js 24, and
npm. The release scripts build the web console and embed it in the cloud binary.

```powershell
./scripts/build.ps1 -Version 0.1.0 -TargetOS windows -TargetArch amd64
```

```bash
bash scripts/build.sh 0.1.0 linux amd64
```

Each output directory contains the role binaries, example configurations,
documentation, license texts, and SHA256 checksums. The edge binary is built for
Linux only.

## Quick deployment

The base Compose file starts MySQL and a cloud service bound to host loopback.
Generate unique secrets before starting it:

```bash
export DRAFRP_DB_PASSWORD="$(openssl rand -hex 24)"
export DRAFRP_DB_ROOT_PASSWORD="$(openssl rand -hex 24)"
export DRAFRP_STORAGE_KEY="$(openssl rand -base64 32)"
export DRAFRP_ADMIN_PASSWORD="$(openssl rand -hex 24)"
docker compose -f examples/compose.yaml up -d --build
```

Preserve the storage key separately from the database backup. For public HTTPS,
use the optional Caddy profile:

```bash
DRAFRP_DOMAIN=control.example.com docker compose \
  -f examples/compose.yaml -f examples/compose.proxy.yaml \
  --profile proxy up -d --build
```

Deploy the Linux edge and ordinary socket-mode client with
`examples/compose.edge.yaml` and `examples/compose.client.yaml`. The
[`deployment guide`](docs/en/guides/DEPLOYMENT.md) explains required files,
networking, firewall ports, upgrades, and backups. Do not use the ordinary
client example for privileged native or TUN modes.

## Documentation

- [Documentation index](docs/README.en.md) | [中文索引](docs/README.md)
- [Deployment guide](docs/en/guides/DEPLOYMENT.md)
- [Testing guide](docs/en/guides/TESTING.md)
- [Linux TUN guide](docs/guides/LINUX-TUN.md) (Chinese)
- [Implementation status](docs/reference/IMPLEMENTATION.md) (Chinese)
- [API contract](docs/reference/API-CONTRACT.md) and [schema integrity](docs/reference/SCHEMA-INTEGRITY.md)
  (Chinese)
- [Performance report](docs/performance/2026-11-06.md) (Chinese)
- [Contributing](CONTRIBUTING.en.md) and [security reporting](SECURITY.en.md)

Detailed architecture specifications are maintained in Chinese under
[`docs/design/`](docs/README.en.md#design-documents). Check the implementation
status before treating a design item as available behavior.


## License and security

DraFRP is distributed under GPL-3.0-only. Third-party dependency license texts
and the production console inventory are included in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) and `licenses/`.

Report suspected vulnerabilities privately using GitHub Security Advisories
when private reporting is available. Do not post exploit details in public
Issues or Discussions before a fix is available.
