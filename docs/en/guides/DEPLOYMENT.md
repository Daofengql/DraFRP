# Deployment guide

[English](DEPLOYMENT.md) | [简体中文](../../guides/DEPLOYMENT.md)

The Compose examples target Linux Docker Engine. Keep the cloud service behind
HTTPS, store credentials outside the repository, and take a database backup
before upgrades.

## Cloud and MySQL

From the repository root, generate unique secrets and start the cloud plus its
dedicated MySQL 8.4 instance:

```bash
export DRAFRP_DB_PASSWORD="$(openssl rand -hex 24)"
export DRAFRP_DB_ROOT_PASSWORD="$(openssl rand -hex 24)"
export DRAFRP_STORAGE_KEY="$(openssl rand -base64 32)"
export DRAFRP_ADMIN_PASSWORD="$(openssl rand -hex 24)"
docker compose -f examples/compose.yaml up -d --build
```

The cloud port is published only on host loopback (`127.0.0.1:8080`). MySQL
data is stored in a named volume. Preserve `DRAFRP_STORAGE_KEY` separately from
the database backup; encrypted credentials cannot be recovered without it. Do
not commit shell history, `.env` files, certificates, or rendered Compose
configuration containing secrets.

## HTTPS with Caddy

Point public DNS to the cloud host, then start the optional proxy profile:

```bash
DRAFRP_DOMAIN=control.example.com docker compose \
  -f examples/compose.yaml \
  -f examples/compose.proxy.yaml \
  --profile proxy up -d --build
```

Caddy obtains and renews certificates and forwards to `cloud:8080`. The overlay
sets `DRAFRP_SECURE_COOKIES=true`. Keep the cloud's loopback-only port mapping;
do not publish the backend port to the Internet or trust forwarded headers from
untrusted clients. See `examples/Caddyfile` for the proxy rule.

## Edge container

An edge needs the public service ports configured in the console, which can
include a port pool and TCP/UDP carrier endpoints. On Linux, host networking
avoids incomplete static port mappings. The ordinary `edge` target runs as a
non-root user and drops all capabilities. Only `edge-wire` runs as root and
requires an explicit `NET_ADMIN` grant for physical-interface shaping. Never
use Docker `privileged`; deploy `edge-wire` only with a dedicated interface in
a planned, dedicated network namespace.

```bash
export DRAFRP_EDGE_CONFIG=/etc/drafrp/edge.json
export DRAFRP_EDGE_CERT=/etc/drafrp/carrier.crt
export DRAFRP_EDGE_KEY=/etc/drafrp/carrier.key
docker compose -f examples/compose.edge.yaml --profile edge up -d --build
```

The JSON must use `/etc/drafrp/carrier.crt` and `/etc/drafrp/carrier.key` for
its certificate paths. Open only the carrier and business ports configured for
the node in the host firewall.

## Client container

The ordinary socket-mode client can run with a persistent identity volume:

```bash
export DRAFRP_CLIENT_CONFIG=/etc/drafrp/client.json
docker compose -f examples/compose.client.yaml --profile client up -d --build
```

Use `/var/lib/drafrp-client` as `state_dir`. New client-state volumes use UID
10001; existing volumes may need ownership corrected to UID 10001 before
startup. The ordinary `client` target runs as a non-root user. The sample uses
host networking so loopback targets refer to the Linux host.

The `client-native` and `client-tun` targets run as root because these modes
modify routes/firewall state. Use them only in a dedicated Linux network
namespace, never host networking or Docker `privileged`. Grant only the
required `NET_ADMIN` capability (for example, `--cap-add NET_ADMIN`). TUN mode
also requires `/dev/net/tun` (for example, `--device
/dev/net/tun:/dev/net/tun`). Do not grant these permissions to ordinary socket
mode.

## Upgrades and backups

Back up MySQL, its named volume, the storage key, TLS materials, edge
credentials, and client state directories. Keep backups encrypted and test a
restore before upgrading. Rebuild images from a reviewed source revision,
update cloud first, then update edge and client nodes. Keep prior image tags
until health checks and a real forwarding path succeed.

For systemd deployments, see `examples/systemd/`. Run cloud and edge under
dedicated unprivileged accounts and restrict configuration and key file
permissions.
