// Isolated browser QA fixture. This is deliberately not a production cloud or a
// substitute for the repository's MySQL/edge/client integration tests.
import { createServer } from "vite";

const at = new Date().toISOString();
const user = {
  id: "qa-user",
  username: "qa-admin",
  role: "admin",
  tenant_id: "qa-space",
  disabled: false,
};
const session = { user, csrf_token: "qa-csrf", build_id: "development" };
const device = {
  id: "qa-device",
  name: "QA Agent",
  tenant_id: user.tenant_id,
  revoked: false,
  generation: 1,
  last_seen: at,
  capabilities: ["socket", "tcp", "udp", "native_tcp_ipv4_ip_port"],
  applied_revision: 9,
};
const edge = {
  id: "qa-edge",
  name: "QA Edge",
  endpoints: [
    { transport: "quic", address: "edge.test:9443", server_name: "edge.test" },
    { transport: "tls", address: "edge.test:9444", server_name: "edge.test" },
  ],
  ca_cert: "",
  public_host: "edge.test",
  listen_host: "",
  http_port: 8080,
  https_port: 8443,
  port_min: 20000,
  port_max: 21000,
  max_carriers: 64,
  capacity_bps: -1,
  last_seen: at,
  applied_revision: 9,
  runtime: {
    reported_at: at,
    snapshot_expires_at: new Date(Date.now() + 60_000).toISOString(),
    endpoints: [
      { transport: "quic", address: "edge.test:9443", listening: true },
      {
        transport: "tls",
        address: "edge.test:9444",
        listening: false,
        error: "QA: address already in use",
      },
    ],
    active_flows: 3,
    active_carriers: 2,
    quic_carriers: 2,
    tls_carriers: 0,
    udp_mappings: 1,
    capacity_enforcement: "payload",
    geoip_state: "error",
    geoip_error: "QA: invalid database",
  },
};
let rules = [
  {
    id: "qa-rule",
    tenant_id: user.tenant_id,
    name: "QA TCP",
    protocol: "tcp",
    device_id: device.id,
    edge_id: edge.id,
    public_port: 20001,
    target: "127.0.0.1:8080",
    source_mode: "socket",
    transport: "auto",
    enabled: true,
    deleting: false,
    version: 3,
    status: "pending",
    applied_version: 0,
    timeout_seconds: 30,
  },
];
const domains = [
  {
    id: "qa-domain",
    domain: "app.example.test",
    status: "verified",
    txt_name: "_drafrp-challenge.app.example.test",
    txt_value: "qa-challenge",
    created_at: at,
    verified_at: at,
  },
];
const certificates = [
  {
    id: "qa-cert",
    tenant_id: user.tenant_id,
    name: "QA Certificate",
    domains: ["app.example.test"],
    expires_at: "2030-01-01T00:00:00Z",
  },
];
const quotas = [
  {
    tenant_id: user.tenant_id,
    base_bps: 8_000_000,
    peak_bps: -1,
    burst_bytes: 1024,
    max_connections: 0,
    new_flows_per_second: -1,
    period_bytes: -1,
    used_bytes: 0,
    reserved_bytes: 0,
    version: 2,
    period_seconds: 0,
    period_id: "qa-period",
    period_started_at: at,
  },
];
let templates = [],
  edges = [edge],
  signedIn = false,
  firstConflict = true,
  next = 1;
const requests = [];
const server = await createServer({
  configFile: "./vite.config.ts",
  server: { host: "127.0.0.1", port: 5173, strictPort: true, proxy: {} },
  plugins: [
    {
      name: "isolated-qa-api",
      configureServer(vite) {
        vite.middlewares.use(async (req, res, nextMiddleware) => {
          if (!req.url.startsWith("/api/") && !req.url.startsWith("/auth/"))
            return nextMiddleware();
          const path = new URL(req.url, "http://127.0.0.1").pathname,
            method = req.method;
          const chunks = [];
          for await (const chunk of req) chunks.push(chunk);
          const body = chunks.length
            ? JSON.parse(Buffer.concat(chunks).toString())
            : {};
          requests.push({
            path,
            method,
            body,
            key: req.headers["idempotency-key"],
          });
          const json = (data, status = 200) => {
            res.statusCode = status;
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify(data));
          };
          const list = (items) => json({ items, total: items.length });
          if (path === "/auth/options")
            return json({
              registration_enabled: false,
              captcha_required: false,
            });
          if (path === "/auth/login") {
            signedIn = true;
            res.setHeader(
              "Set-Cookie",
              "qa-session=1; HttpOnly; SameSite=Lax; Path=/",
            );
            return json(session);
          }
          if (path === "/auth/logout") {
            signedIn = false;
            return json({ ok: true });
          }
          if (!signedIn)
            return json(
              { error: { code: "unauthorized", message: "sign in required" } },
              401,
            );
          if (path === "/api/v1/me") return json(session);
          if (path === "/api/v1/qa/requests") return json(requests);
          if (path === "/api/v1/events") {
            res.setHeader("Content-Type", "text/event-stream");
            res.setHeader("Cache-Control", "no-cache");
            res.flushHeaders();
            const timer = setInterval(
              () => res.write(": heartbeat\n\n"),
              10000,
            );
            req.on("close", () => clearInterval(timer));
            return;
          }
          if (path === "/api/v1/bind/TESTCODE")
            return json({
              user_code: "TESTCODE",
              name: "QA Agent",
              public_key_fingerprint: "SHA256:qa-fingerprint",
              status: "pending",
              expires_at: "2030-01-01T00:00:00Z",
            });
          if (path === "/api/v1/bind/confirm")
            return json({ device_id: device.id, ok: true });
          if (path === "/api/v1/devices") return list([device]);
          if (path === "/api/v1/domains") return list(domains);
          if (path === "/api/v1/certificates") return list(certificates);
          if (path === "/api/v1/quotas") return list(quotas);
          if (path === "/api/v1/users") return list([user]);
          if (path === "/api/v1/usage" || path === "/api/v1/audit")
            return list([]);
          if (path === "/api/v1/system")
            return json({
              mysql: "healthy",
              cache: { backend: "memory" },
              build_id: "development",
              started_at: at,
            });
          if (path === "/api/v1/overview")
            return json({
              devices: 1,
              online_devices: 1,
              rules: rules.length,
              ready_rules: 0,
              edges: edges.length,
              usage_upload_bytes: 0,
              usage_download_bytes: 0,
            });
          if (path === "/api/v1/edges") {
            if (method === "POST") {
              const { token, ...data } = body;
              if (token.length < 24 || !data.endpoints.length)
                return json(
                  {
                    error: {
                      code: "invalid_edge",
                      message: "endpoint and random token required",
                    },
                  },
                  400,
                );
              const result = { ...edge, ...data, id: `qa-edge-${next++}` };
              edges.push(result);
              return json(result, 201);
            }
            return list(edges);
          }
          if (path === "/api/v1/acl-templates") {
            if (method === "POST") {
              const result = {
                ...body,
                id: `qa-template-${next++}`,
                policy: { ...body.policy, version: 0 },
                version: 1,
                default: false,
                mandatory: false,
              };
              templates.push(result);
              return json(result, 201);
            }
            return list(templates);
          }
          if (/\/acl-templates\/[^/]+\/publish$/.test(path)) {
            const t = templates.find((t) => path.includes(t.id));
            t.version++;
            t.published = { ...t.policy, version: t.version };
            return json(t);
          }
          if (/\/acl-templates\/[^/]+$/.test(path) && method === "PUT") {
            const t = templates.find((t) => path.endsWith(t.id));
            Object.assign(t, body, { version: t.version + 1 });
            return json(t);
          }
          if (path === "/api/v1/rules") {
            if (method === "POST") {
              const result = {
                ...body,
                id: `qa-rule-${next++}`,
                tenant_id: user.tenant_id,
                public_port: body.public_port || 20002,
                version: 1,
                applied_version: 0,
                deleting: false,
                status: "pending",
              };
              rules.push(result);
              return json(result, 201);
            }
            return list(rules);
          }
          if (path.startsWith("/api/v1/rules/")) {
            const rule = rules.find((r) => path.endsWith(r.id));
            if (method === "PUT") {
              if (firstConflict) {
                firstConflict = false;
                rule.version++;
                return json(
                  {
                    error: {
                      code: "version_conflict",
                      message: "changed by QA concurrent editor",
                    },
                  },
                  409,
                );
              }
              if (body.version !== rule.version)
                return json(
                  {
                    error: {
                      code: "version_conflict",
                      message: "stale version",
                    },
                  },
                  409,
                );
              Object.assign(rule, body, { version: body.version + 1 });
            }
            return json(rule);
          }
          return json({ error: { code: "not_found", message: path } }, 404);
        });
      },
    },
  ],
});
await server.listen();
console.log(
  "Isolated console QA fixture: http://127.0.0.1:5173/console/bind/TESTCODE",
);
