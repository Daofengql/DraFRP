# Testing

[English](TESTING.md) | [简体中文](../../guides/TESTING.md)

## Local checks

```bash
go vet ./...
go test -race ./... -count=1 -timeout=5m
cd web
npm ci --no-audit --no-fund
npm test
npm run build
```

Cloud and system integration tests skip unless `DRAFRP_TEST_MYSQL_DSN` points
to a dedicated MySQL instance where the test user can create and drop temporary
databases. Redis integration is optional through
`DRAFRP_TEST_REDIS_ADDRESS`. Never use production or personal data for these
tests.

Linux native and TUN tests need a disposable Linux VM or isolated network
namespace. They can create routes, policy rules, TUN devices, and firewall
objects inside that namespace. Do not enable privileged test settings against a
general-purpose host.

Browser end-to-end runs using `scripts/browser_e2e.py` require the operator to
provide the SSH target, SSH key, and remote test database DSN explicitly. Use
only an isolated test VM and dedicated empty database; never provide production
credentials or commit these values to the repository.

## Linux VM performance run

Run the release cloud, edge, and client binaries in an isolated Linux VM with `scripts/smoke.py --performance`. Each run requires a fresh dedicated empty MySQL database, a private `--work-dir` path that does not exist, and the release binary directory. Set the DSN through hidden input or a protected environment manager rather than shell history:

```bash
export BIN_DIR=bin/0.1.0/linux-amd64
read -r -s -p 'Disposable MySQL DSN: ' DRAFRP_SMOKE_MYSQL_DSN; printf '\n'
export DRAFRP_SMOKE_MYSQL_DSN
python3 scripts/smoke.py --bin-dir "$BIN_DIR" --work-dir "/var/tmp/drafrp-perf-quic-$(date +%s)" --performance --transport quic_only
```

For TLS-only, provision another empty database and use a new work directory with `--transport tls_only`. `result.json` reports persistent TCP echo RTT p50/p95/p99, TCP goodput at 1/4/16 concurrent flows, RTT/loss/goodput for 128 B/1400 B/48000 B UDP windowed echo, and CPU plus RSS sampled every 200 ms for cloud/edge/client processes. Scope: ordinary socket forwarding over VM loopback; not TUN, WAN, or cross-project performance. The work directory contains temporary credentials; delete it after retaining the result. The result file excludes the DSN.

## Scope of available evidence

Past validation used Windows and an Ubuntu VM with isolated MySQL and dedicated
Docker networks. The published test guidance is intentionally a reproducible
summary; transient raw logs, private test addresses, local paths, and runtime
credentials are excluded from the source distribution.

The report includes Linux TUN packet-path microbenchmarks and QUIC/TLS ordinary
socket loopback TCP latency/goodput, UDP windowed echo, and process CPU/RSS.
It does not establish WAN behavior, end-to-end TUN throughput, production
capacity, or comparative performance. This VM capped the UDP receive socket at
425,984 bytes; high-window counts are harness echo losses, not WAN/NIC loss rates.
