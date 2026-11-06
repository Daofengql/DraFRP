# 部署指南

[English](../en/guides/DEPLOYMENT.md) | 简体中文

Compose 示例面向 Linux Docker Engine。云控应通过 HTTPS 提供服务；凭据应放在仓库之外，
升级前先备份数据库。

## 云控与 MySQL

在仓库根目录生成独立密钥，并启动云控与专用 MySQL 8.4：

```bash
export DRAFRP_DB_PASSWORD="$(openssl rand -hex 24)"
export DRAFRP_DB_ROOT_PASSWORD="$(openssl rand -hex 24)"
export DRAFRP_STORAGE_KEY="$(openssl rand -base64 32)"
export DRAFRP_ADMIN_PASSWORD="$(openssl rand -hex 24)"
docker compose -f examples/compose.yaml up -d --build
```

云控端口只绑定宿主机 loopback（`127.0.0.1:8080`）。MySQL 数据存放在命名 volume 中。
请在数据库备份之外单独保存 `DRAFRP_STORAGE_KEY`；没有该密钥无法恢复加密凭据。
不要提交 shell 历史、`.env`、证书或含有密钥的 Compose 展开配置。

## 使用 Caddy 提供 HTTPS

将公网 DNS 指向云控主机，然后启动可选反向代理 profile：

```bash
DRAFRP_DOMAIN=control.example.com docker compose \
  -f examples/compose.yaml \
  -f examples/compose.proxy.yaml \
  --profile proxy up -d --build
```

Caddy 会申请并续期证书，再将流量转发到 `cloud:8080`。Compose overlay 会设置
`DRAFRP_SECURE_COOKIES=true`。保留云控仅绑定 loopback 的端口配置；不要将后端端口暴露到
公网，也不要信任不可信客户端提供的转发头。代理规则见 `examples/Caddyfile`。

## Edge 容器

普通 `edge` target 以非 root 用户运行并丢弃全部 capabilities；只有 `edge-wire` target 以 root
运行，并需额外授予 `NET_ADMIN` 才能整形物理网卡流量。不要使用 Docker `privileged`。仅在
专用接口及规划好的独立网络命名空间中部署 `edge-wire`。

JSON 中的证书路径需为 `/etc/drafrp/carrier.crt` 和 `/etc/drafrp/carrier.key`。宿主防火墙
只开放该节点实际配置的承载端口和业务端口。

## Client 容器

普通 socket 模式客户端可使用持久身份 volume 运行：

```bash
export DRAFRP_CLIENT_CONFIG=/etc/drafrp/client.json
docker compose -f examples/compose.client.yaml --profile client up -d --build
```

配置中的 `state_dir` 应设为 `/var/lib/drafrp-client`。新建 volume 使用 UID 10001；如果沿用
旧 volume，启动前可能需要将目录所有权更正为 UID 10001。普通 `client` target 以非 root 用户
运行。样例使用 host 网络，因此 loopback 目标指向 Linux 宿主机。

`client-native` 和 `client-tun` target 以 root 运行；它们修改路由/防火墙状态，只能在专用
Linux 网络命名空间中使用，不能使用 host 网络，也不能使用 Docker `privileged`。按目标所需
显式授予 `NET_ADMIN`（例如 `--cap-add NET_ADMIN`），不要添加其他能力；TUN 还必须提供
`/dev/net/tun`（例如 `--device /dev/net/tun:/dev/net/tun`）。普通 socket 模式不要授予这些权限。

## 升级与备份

备份 MySQL 数据库与命名 volume、存储密钥、TLS 材料、edge 凭据和客户端状态目录。加密
保存备份，并在升级前测试恢复。从已审查的源码版本重新构建镜像，先升级云控，再升级 edge
和 client。健康检查和真实转发链路确认成功前，保留旧镜像标签。

systemd 部署见 `examples/systemd/`。云控和 edge 应使用独立非特权账号运行，并限制配置与
密钥文件权限。
