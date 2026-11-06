# Documentation

[English](README.en.md) | [简体中文](README.md)

## Use and deploy

- [Project overview](../README.en.md): supported scope, build, and quick start.
- [Deployment guide](en/guides/DEPLOYMENT.md): Compose cloud, optional HTTPS
  proxy, standalone edge/client containers, upgrades, and backups.
- [Linux TUN guide](guides/LINUX-TUN.md) (Chinese): client source preservation,
  required permissions, failure handling, and supported scope.
- [Examples](../examples/): JSON configurations, Compose, Caddy, and systemd.

## Development and operations

- [Implementation status](reference/IMPLEMENTATION.md) (Chinese): delivered
  behavior, validation scope, and known gaps.
- [Testing guide](en/guides/TESTING.md): local checks, database requirements,
  and privileged Linux test boundaries.
- [Performance report](performance/2026-11-06.md) (Chinese): Linux TUN microbenchmarks
  and VM loopback QUIC/TLS TCP/UDP and process-resource measurements, with limits.
- [API contract](reference/API-CONTRACT.md) and [schema integrity](reference/SCHEMA-INTEGRITY.md)
  (Chinese).
- [Contributing](../CONTRIBUTING.en.md), [security reporting](../SECURITY.en.md),
  and [third-party notices](../THIRD-PARTY-NOTICES.md).

## Design documents

The detailed architecture specifications are maintained in Chinese under
[`design/`](design/). They describe target specifications, not a checklist of
features that have shipped. Check the implementation-status document before
relying on a behavior.
