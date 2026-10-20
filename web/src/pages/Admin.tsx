import { useState } from "react";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  MenuItem,
  Paper,
  Stack,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import {
  fmtBytes,
  fmtDate,
  fmtLimit,
  fmtRate,
  observedOnline,
} from "../format";
import {
  Confirm,
  Empty,
  Load,
  MutationError,
  PageTitle,
  Status,
  TableFrame,
  invalidate,
  useDraftGuard,
  useResource,
  useSessionContext,
  useWriter,
} from "../ui";
import type { Edge, Endpoint, Quota, Rule, User } from "../types";
import EdgeDetails from "./EdgeDetails";

function UserForm({
  initial,
  tenants,
  onClose,
}: {
  initial?: User;
  tenants: string[];
  onClose: () => void;
}) {
  const [form, setForm] = useState({
    username: initial?.username || "",
    password: "",
    role: initial?.role || "user",
    tenant_id: "",
    disabled: initial?.disabled || false,
  });
  const [validation, setValidation] = useState("");
  const [dirty, setDirty] = useState(false);
  const canClose = useDraftGuard(dirty);
  const m = useWriter(() => {
    setForm((f) => ({ ...f, password: "" }));
    invalidate("users", "quotas", "me");
    m.reset();
    onClose();
  });
  const set = <K extends keyof typeof form>(
    key: K,
    value: (typeof form)[K],
  ) => {
    setDirty(true);
    setForm((f) => ({ ...f, [key]: value }));
  };
  const close = () => {
    if (!m.isPending && canClose()) {
      setForm((f) => ({ ...f, password: "" }));
      m.reset();
      onClose();
    }
  };
  const submit = () => {
    const bytes = new TextEncoder().encode(form.password).length;
    if ((!initial || form.password) && (bytes < 10 || bytes > 72)) {
      setValidation("密码必须为 10–72 字节（中文等字符占多个字节）。");
      return;
    }
    const data = initial
      ? {
          role: form.role,
          disabled: form.disabled,
          ...(form.password ? { password: form.password } : {}),
        }
      : {
          username: form.username,
          password: form.password,
          role: form.role,
          tenant_id: form.tenant_id,
        };
    m.mutate({
      path: initial ? `/users/${initial.id}` : "/users",
      method: initial ? "PATCH" : "POST",
      data,
    });
  };
  return (
    <Dialog open onClose={close} fullWidth maxWidth="sm">
      <DialogTitle>
        {initial ? `编辑用户 ${initial.username}` : "创建用户"}
      </DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {!initial && (
            <TextField
              label="用户名"
              value={form.username}
              onChange={(e) => set("username", e.target.value)}
              autoComplete="off"
              required
              autoFocus
            />
          )}
          <TextField
            label={initial ? "重置密码（留空保留）" : "初始密码"}
            type="password"
            value={form.password}
            onChange={(e) => set("password", e.target.value)}
            autoComplete="new-password"
            required={!initial}
            helperText="10–72 字节"
          />
          <TextField
            select
            label="角色"
            value={form.role}
            onChange={(e) => set("role", e.target.value)}
          >
            <MenuItem value="user">普通用户</MenuItem>
            <MenuItem value="admin">平台管理员</MenuItem>
            {form.role === "platform_admin" && (
              <MenuItem value="platform_admin">
                平台管理员 (platform_admin)
              </MenuItem>
            )}
          </TextField>
          {!initial && (
            <TextField
              select
              label="归属空间"
              value={form.tenant_id}
              onChange={(e) => set("tenant_id", e.target.value)}
              helperText="同空间用户共享设备、规则与账号配额"
            >
              <MenuItem value="">为此用户创建新空间</MenuItem>
              {tenants.map((t) => (
                <MenuItem key={t} value={t}>
                  {t}
                </MenuItem>
              ))}
            </TextField>
          )}
          {initial && (
            <>
              <FormControlLabel
                control={
                  <Checkbox
                    checked={form.disabled}
                    onChange={(e) => set("disabled", e.target.checked)}
                  />
                }
                label="停用账号"
              />
              <Alert severity="warning">
                停用用户或重置密码会撤销已有登录会话。角色变更会由服务端重新校验权限。
              </Alert>
            </>
          )}
          {validation && <Alert severity="error">{validation}</Alert>}
          <MutationError error={m.error} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={close} disabled={m.isPending}>
          取消
        </Button>
        <Button
          variant="contained"
          onClick={submit}
          disabled={
            m.isPending ||
            (!initial && (!form.username.trim() || !form.password))
          }
        >
          {m.isPending ? "提交中…" : "保存"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export function UsersPage() {
  const q = useResource<User>("/users", "users");
  const { user } = useSessionContext();
  const [editing, setEditing] = useState<User | "new">();
  return (
    <>
      <PageTitle
        title="用户与空间"
        detail="同一空间共享资源和配额；平台角色独立于资源归属"
        action={
          <Button variant="contained" onClick={() => setEditing("new")}>
            创建用户
          </Button>
        }
      />
      <Load loading={q.isLoading} error={q.error}>
        {!q.data?.items.length ? (
          <Empty title="暂无用户" />
        ) : (
          <TableFrame>
            <TableHead>
              <TableRow>
                <TableCell>用户名</TableCell>
                <TableCell>角色</TableCell>
                <TableCell>空间</TableCell>
                <TableCell>状态</TableCell>
                <TableCell>操作</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {q.data.items.map((u) => (
                <TableRow key={u.id}>
                  <TableCell>
                    {u.username}
                    {u.id === user.id ? "（当前账号）" : ""}
                  </TableCell>
                  <TableCell>{u.role}</TableCell>
                  <TableCell className="mono">{u.tenant_id}</TableCell>
                  <TableCell>
                    <Status value={u.disabled ? "disabled" : "active"} />
                  </TableCell>
                  <TableCell>
                    <Button onClick={() => setEditing(u)}>编辑 / 停用</Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </TableFrame>
        )}
      </Load>
      {editing && (
        <UserForm
          initial={editing === "new" ? undefined : editing}
          tenants={[...new Set(q.data?.items.map((u) => u.tenant_id))]}
          onClose={() => setEditing(undefined)}
        />
      )}
    </>
  );
}

function randomToken() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)), (x) =>
    x.toString(16).padStart(2, "0"),
  ).join("");
}
function EdgeForm({
  initial,
  onClose,
}: {
  initial?: Edge;
  onClose: () => void;
}) {
  const [form, setForm] = useState({
    name: initial?.name || "",
    public_host: initial?.public_host || "",
    listen_host: initial?.listen_host || "",
    http_port: initial?.http_port ?? 80,
    https_port: initial?.https_port ?? 443,
    port_min: initial?.port_min ?? 10000,
    port_max: initial?.port_max ?? 20000,
    max_carriers: initial?.max_carriers ?? 64,
    capacity_bps: initial?.capacity_bps ?? -1,
    ca_cert: initial?.ca_cert || "",
    endpoints: initial?.endpoints || [
      { transport: "quic", address: "", server_name: "" },
    ],
    token: initial ? "" : randomToken(),
  });
  const [dirty, setDirty] = useState(false),
    [validation, setValidation] = useState(""),
    [created, setCreated] = useState<Edge>();
  const [reveal, setReveal] = useState(false),
    [copyMessage, setCopyMessage] = useState("");
  const canClose = useDraftGuard(dirty);
  const m = useWriter<Edge>((edge) => {
    invalidate("edges", "overview");
    if (initial) onClose();
    else {
      setCreated(edge);
      setDirty(false);
      m.reset();
    }
  });
  const set = <K extends keyof typeof form>(
    key: K,
    value: (typeof form)[K],
  ) => {
    setDirty(true);
    setValidation("");
    setForm((f) => ({ ...f, [key]: value }));
  };
  const endpoint = (index: number, key: keyof Endpoint, value: string) =>
    set(
      "endpoints",
      form.endpoints.map((e, i) => (i === index ? { ...e, [key]: value } : e)),
    );
  const close = () => {
    if (!m.isPending && canClose()) {
      setForm((f) => ({ ...f, token: "" }));
      m.reset();
      onClose();
    }
  };
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(form.token);
      setCopyMessage("令牌已复制");
    } catch {
      setReveal(true);
      setCopyMessage("浏览器不允许自动复制，请选中令牌手动复制。");
    }
  };
  const submit = () => {
    if (
      form.endpoints.some(
        (e) =>
          !/^(\[[0-9a-fA-F:]+\]|[^\s:]+):\d+$/.test(e.address) ||
          !e.server_name.trim(),
      )
    ) {
      setValidation("每个承载入口必须有 host:port 地址及 TLS server_name。");
      return;
    }
    if (
      form.port_min < 1024 ||
      form.port_max > 65535 ||
      form.port_max < form.port_min ||
      form.max_carriers < 1 ||
      form.max_carriers > 1024 ||
      form.capacity_bps < -1
    ) {
      setValidation(
        "业务端口池须为 1024–65535，承载数须为 1–1024，容量须 ≥ -1。",
      );
      return;
    }
    const { token, ...edge } = form;
    m.mutate({
      path: initial ? `/edges/${initial.id}` : "/edges",
      method: initial ? "PUT" : "POST",
      data: initial ? edge : form,
    });
  };
  return (
    <Dialog open onClose={close} fullWidth maxWidth="md">
      <DialogTitle>
        {created ? "边缘已登记" : initial ? "编辑边缘节点" : "登记边缘节点"}
      </DialogTitle>
      <DialogContent>
        <Stack spacing={2.5} sx={{ mt: 1 }}>
          {created ? (
            <>
              <Alert severity="success">
                已登记 {created.name}。请在边缘服务配置对应 ID
                和令牌，启动后等待实际同步。
              </Alert>
              <TextField
                label="边缘 ID"
                value={created.id}
                slotProps={{ input: { readOnly: true } }}
              />
            </>
          ) : (
            <>
              <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
                <TextField
                  label="节点名称"
                  value={form.name}
                  onChange={(e) => set("name", e.target.value)}
                  required
                  fullWidth
                />
                <TextField
                  label="公网主机"
                  value={form.public_host}
                  onChange={(e) => set("public_host", e.target.value)}
                  required
                  fullWidth
                  helperText="用户访问业务入口时使用的主机名 / IP"
                />
              </Stack>
              <TextField
                label="业务监听地址（可选）"
                value={form.listen_host}
                onChange={(e) => set("listen_host", e.target.value)}
                helperText="留空由边缘使用默认监听地址；不含端口"
              />
              <Typography variant="h6">承载入口（Agent → 边缘）</Typography>
              {form.endpoints.map((ep, i) => (
                <Paper variant="outlined" key={i} sx={{ p: 2 }}>
                  <Stack spacing={2}>
                    <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
                      <TextField
                        select
                        label="传输"
                        value={ep.transport}
                        onChange={(e) =>
                          endpoint(i, "transport", e.target.value)
                        }
                        sx={{ minWidth: 120 }}
                      >
                        <MenuItem value="quic">QUIC / UDP</MenuItem>
                        <MenuItem value="tls">TLS / TCP</MenuItem>
                      </TextField>
                      <TextField
                        label="入口地址 host:port"
                        value={ep.address}
                        onChange={(e) => endpoint(i, "address", e.target.value)}
                        fullWidth
                        required
                      />
                      <TextField
                        label="TLS server_name"
                        value={ep.server_name}
                        onChange={(e) =>
                          endpoint(i, "server_name", e.target.value)
                        }
                        fullWidth
                        required
                      />
                    </Stack>
                    <Button
                      color="error"
                      disabled={form.endpoints.length === 1}
                      onClick={() =>
                        set(
                          "endpoints",
                          form.endpoints.filter((_, n) => n !== i),
                        )
                      }
                    >
                      移除此入口
                    </Button>
                  </Stack>
                </Paper>
              ))}
              <Button
                variant="outlined"
                disabled={form.endpoints.length >= 16}
                onClick={() =>
                  set("endpoints", [
                    ...form.endpoints,
                    { transport: "tls", address: "", server_name: "" },
                  ])
                }
              >
                添加承载入口
              </Button>
              <TextField
                label="承载 TLS CA PEM（可选）"
                value={form.ca_cert}
                onChange={(e) => set("ca_cert", e.target.value)}
                multiline
                minRows={3}
                helperText="留空使用系统可信证书；自签证书必须配置其 CA，Agent 不会跳过 TLS 校验"
              />
              <Typography variant="h6">公网业务端口池</Typography>
              <Alert severity="info">
                公网业务端口与承载入口独立。共享 HTTP(S) 端口填写 0
                可关闭；端口冲突由服务端事务校验。
              </Alert>
              <Box className="form-grid">
                {(
                  [
                    ["port_min", "业务端口起点"],
                    ["port_max", "业务端口终点"],
                    ["http_port", "HTTP 共享端口"],
                    ["https_port", "HTTPS 共享端口"],
                    ["max_carriers", "最大活动承载数"],
                    ["capacity_bps", "节点容量（bit/s）"],
                  ] as const
                ).map(([key, label]) => (
                  <TextField
                    key={key}
                    type="number"
                    label={label}
                    value={form[key]}
                    onChange={(e) => set(key, Number(e.target.value))}
                    helperText={
                      key === "capacity_bps" ? "-1 = 不限，0 = 禁止" : undefined
                    }
                  />
                ))}
              </Box>
              {initial && (
                <Alert severity="warning">
                  存在关联规则或仍在释放的资源时，服务端拒绝修改入口。请先迁移 /
                  删除规则并等待资源释放。
                </Alert>
              )}
            </>
          )}
          {!initial && (
            <>
              <TextField
                label="边缘令牌（仅本次显示与提交）"
                type={reveal ? "text" : "password"}
                value={form.token}
                onChange={(e) => set("token", e.target.value)}
                autoComplete="off"
                required
                slotProps={{ input: { readOnly: !!created } }}
                helperText="使用密码学随机值；至少 24 字符，务必保存到边缘配置。关闭后不再显示。"
              />
              <Stack direction="row" spacing={1}>
                <Button onClick={() => setReveal(!reveal)}>
                  {reveal ? "隐藏" : "显示"}令牌
                </Button>
                <Button onClick={copy}>复制令牌</Button>
                {!created && (
                  <Button onClick={() => set("token", randomToken())}>
                    重新生成
                  </Button>
                )}
              </Stack>
              {copyMessage && <Alert severity="info">{copyMessage}</Alert>}
            </>
          )}
          {validation && <Alert severity="error">{validation}</Alert>}
          <MutationError error={m.error} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={close} disabled={m.isPending}>
          {created ? "完成" : "取消"}
        </Button>
        {!created && (
          <Button
            variant="contained"
            disabled={
              m.isPending ||
              !form.name.trim() ||
              !form.public_host.trim() ||
              (!initial && form.token.length < 24)
            }
            onClick={submit}
          >
            {m.isPending ? "保存中…" : "保存节点"}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
}

export function EdgesPage() {
  const q = useResource<Edge>("/edges", "edges"),
    rules = useResource<Rule>("/rules", "rules");
  const [editing, setEditing] = useState<Edge | "new">(),
    [deleting, setDeleting] = useState<Edge>(),
    [details, setDetails] = useState<string>();
  const del = useWriter(() => {
    setDeleting(undefined);
    invalidate("edges", "overview");
  });
  return (
    <>
      <PageTitle
        title="边缘与端口池"
        detail="承载入口、业务监听及节点容量；连接状态来自实际心跳"
        action={
          <Button variant="contained" onClick={() => setEditing("new")}>
            登记边缘
          </Button>
        }
      />
      <Load loading={q.isLoading} error={q.error}>
        {!q.data?.items.length ? (
          <Empty
            title="暂无边缘节点"
            detail="登记节点身份与 Agent 可达的 QUIC / TLS 承载入口，再启动边缘服务。"
          />
        ) : (
          <TableFrame>
            <TableHead>
              <TableRow>
                <TableCell>名称 / 公网主机</TableCell>
                <TableCell>Agent 承载入口</TableCell>
                <TableCell>业务端口池</TableCell>
                <TableCell>容量</TableCell>
                <TableCell>观测 / 修订</TableCell>
                <TableCell>操作</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {q.data.items.map((e) => (
                <TableRow key={e.id}>
                  <TableCell>
                    <Typography fontWeight={700}>{e.name}</Typography>
                    <Typography className="mono">{e.public_host}</Typography>
                    <Typography className="mono">{e.id}</Typography>
                  </TableCell>
                  <TableCell>
                    {e.endpoints.map((ep) => (
                      <Typography
                        className="mono"
                        key={`${ep.transport}/${ep.address}`}
                      >
                        {ep.transport} · {ep.address}
                        <br />
                        TLS: {ep.server_name}
                      </Typography>
                    ))}
                  </TableCell>
                  <TableCell>
                    {e.port_min}–{e.port_max}
                    <Typography variant="caption" display="block">
                      HTTP {e.http_port || "关闭"} / HTTPS{" "}
                      {e.https_port || "关闭"}
                    </Typography>
                    <Typography variant="caption" display="block">
                      当前空间规则{" "}
                      {rules.data?.items.filter((r) => r.edge_id === e.id)
                        .length ?? "未知"}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    {e.max_carriers} 承载
                    <br />
                    {fmtRate(e.capacity_bps)}
                  </TableCell>
                  <TableCell>
                    <Status
                      value={observedOnline(e.last_seen) ? "online" : "offline"}
                    />
                    <Typography variant="caption" display="block">
                      {fmtDate(e.last_seen)} · 修订{" "}
                      {e.applied_revision || "未确认"}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Button onClick={() => setDetails(e.id)}>运行详情</Button>
                    <Button onClick={() => setEditing(e)}>编辑</Button>
                    <Button
                      color="error"
                      onClick={() => {
                        del.reset();
                        setDeleting(e);
                      }}
                    >
                      删除
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </TableFrame>
        )}
      </Load>
      {editing && (
        <EdgeForm
          initial={editing === "new" ? undefined : editing}
          onClose={() => setEditing(undefined)}
        />
      )}
      {details && q.data?.items.find((e) => e.id === details) && (
        <EdgeDetails
          edge={q.data.items.find((e) => e.id === details)!}
          onClose={() => setDetails(undefined)}
        />
      )}
      {deleting && (
        <Confirm
          title={`删除边缘 ${deleting.name}`}
          onClose={() => setDeleting(undefined)}
          onConfirm={() =>
            del.mutate({ path: `/edges/${deleting.id}`, method: "DELETE" })
          }
          error={del.error}
          busy={del.isPending}
        >
          <Typography>
            所有空间的关联规则和释放中的资源都会阻止删除。请先处理关联资源；当前页面规则计数仅包含当前空间。
          </Typography>
        </Confirm>
      )}
    </>
  );
}

const quotaFields = [
  ["base_bps", "基准速率（bit/s）"],
  ["peak_bps", "峰值速率（bit/s）"],
  ["burst_bytes", "突发信用（byte）"],
  ["max_connections", "最大并发连接"],
  ["new_flows_per_second", "每秒新流"],
  ["period_bytes", "周期流量（byte）"],
] as const;
const resourceQuotaFields = [
  ["max_devices", "设备数量", "devices"],
  ["max_rules", "规则数量（含站点）", "rules"],
  ["max_ports", "公网 TCP/UDP 端口数量", "ports"],
  ["max_domains", "域名数量", "domains"],
] as const;
const allQuotaFields = [...quotaFields, ...resourceQuotaFields];
function QuotaForm({
  initial,
  latest,
  reload,
  onClose,
}: {
  initial: Quota;
  latest?: Quota;
  reload: () => void;
  onClose: () => void;
}) {
  const [form, setForm] = useState(initial),
    [dirty, setDirty] = useState(false),
    [validation, setValidation] = useState(""),
    [compare, setCompare] = useState(false);
  const canClose = useDraftGuard(dirty);
  const m = useWriter(() => {
    invalidate("quotas");
    onClose();
  });
  const submit = () => {
    if (
      form.period_seconds !== undefined &&
      (!Number.isSafeInteger(form.period_seconds) ||
        form.period_seconds < 0 ||
        form.period_seconds > 31622400 ||
        (form.period_seconds > 0 && form.period_seconds < 60))
    ) {
      setValidation("流量周期填写 0（不限期）或 60–31622400 秒。");
      return;
    }
    if (
      allQuotaFields.some(
        ([k]) =>
          !Number.isSafeInteger(form[k] ?? -1) ||
          (form[k] ?? -1) < (k === "burst_bytes" ? 0 : -1),
      )
    ) {
      setValidation("请填写有效整数。突发信用 ≥ 0，其他上限 ≥ -1。");
      return;
    }
    if (resourceQuotaFields.some(([k]) => (form[k] ?? -1) > 1000000)) {
      setValidation("配置资源上限填写 -1（不限）或 0–1000000。");
      return;
    }
    if (
      form.base_bps >= 0 &&
      form.peak_bps >= 0 &&
      form.peak_bps < form.base_bps
    ) {
      setValidation("峰值速率不能低于基准速率。");
      return;
    }
    m.mutate({
      path: `/quotas/${initial.tenant_id}`,
      method: "PUT",
      data: { ...form, version: form.version },
    });
  };
  return (
    <Dialog
      open
      onClose={() => !m.isPending && canClose() && onClose()}
      fullWidth
      maxWidth="sm"
    >
      <DialogTitle>编辑账号配额</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Typography className="mono">{initial.tenant_id}</Typography>
          <Alert severity="info">
            速率使用 bit/s；流量与信用使用 byte。-1 = 不限，0 = 禁止；突发信用的
            0 表示无额外信用。
          </Alert>
          <Typography variant="h6">运行预算</Typography>
          {quotaFields.map(([key, label]) => (
            <TextField
              key={key}
              type="number"
              label={label}
              value={form[key]}
              onChange={(e) => {
                setDirty(true);
                setForm((f) => ({ ...f, [key]: Number(e.target.value) }));
              }}
              slotProps={{
                htmlInput: { min: key === "burst_bytes" ? 0 : -1, step: 1 },
              }}
            />
          ))}
          <TextField
            type="number"
            label="流量周期（秒）"
            value={form.period_seconds ?? 0}
            onChange={(e) => {
              setDirty(true);
              setForm((f) => ({
                ...f,
                period_seconds: Number(e.target.value),
              }));
            }}
            helperText="0 = 不限期；自动切期为 60–31622400 秒。变更周期会由服务端校验。"
          />
          <Typography variant="body2">
            当前周期：{form.period_id || "未记录"} · 到期：
            {form.period_seconds ? fmtDate(form.period_ends_at) : "不限期"}
          </Typography>
          <Typography variant="h6">配置资源上限</Typography>
          {resourceQuotaFields.map(([key, label]) => (
            <TextField
              key={key}
              type="number"
              label={label}
              value={form[key] ?? -1}
              onChange={(e) => {
                setDirty(true);
                setForm((f) => ({ ...f, [key]: Number(e.target.value) }));
              }}
              slotProps={{ htmlInput: { min: -1, max: 1000000, step: 1 } }}
              helperText="-1 = 不限；0 = 不再允许新增"
            />
          ))}
          <Typography variant="body2" color="text.secondary">
            设备按未撤销数量计；规则包含站点与等待释放的规则；端口按 TCP/UDP
            分别计数，等待撤销确认或到期的旧端口继续占额；域名包含待验证记录。
            降低上限会阻止继续增加资源，现有资源仍可编辑和删除。
          </Typography>
          <Alert severity="warning">
            缩减预算可能限制新连接、后续流量和授权续期；用量与已预留份额由服务端维护。
          </Alert>
          {validation && <Alert severity="error">{validation}</Alert>}
          <MutationError
            error={m.error}
            reload={() => {
              reload();
              setCompare(true);
            }}
          />
          {compare && latest && (
            <Paper variant="outlined" sx={{ p: 2 }}>
              <Typography>最新版本 v{latest.version}</Typography>
              {allQuotaFields.map(([k, label]) => (
                <Typography key={k} variant="body2">
                  {label}：{latest[k] ?? -1}
                </Typography>
              ))}
              <Button
                onClick={() => {
                  setForm((f) => ({ ...f, version: latest.version }));
                  setCompare(false);
                  m.reset();
                }}
              >
                已比较，保留输入并使用最新版本
              </Button>
            </Paper>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button disabled={m.isPending} onClick={() => canClose() && onClose()}>
          取消
        </Button>
        <Button variant="contained" onClick={submit} disabled={m.isPending}>
          {m.isPending ? "保存中…" : "保存配额"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export function QuotasPage() {
  const q = useResource<Quota>("/quotas", "quotas");
  const [editing, setEditing] = useState<Quota>();
  return (
    <>
      <PageTitle
        title="账号配额"
        detail="同空间共享运行预算，以及设备、规则、端口和域名数量上限"
      />
      <Load loading={q.isLoading} error={q.error}>
        {!q.data?.items.length ? (
          <Empty
            title="暂无账号配额"
            detail="创建用户与空间后由服务端生成配额记录。"
          />
        ) : (
          <TableFrame>
            <TableHead>
              <TableRow>
                <TableCell>空间 / 版本</TableCell>
                <TableCell>基准 / 峰值</TableCell>
                <TableCell>突发信用</TableCell>
                <TableCell>并发 / 每秒新流</TableCell>
                <TableCell>周期用量 / 上限</TableCell>
                <TableCell>预留份额</TableCell>
                <TableCell>配置资源占用 / 上限</TableCell>
                <TableCell>操作</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {q.data.items.map((x) => (
                <TableRow key={x.tenant_id}>
                  <TableCell>
                    <Typography className="mono">{x.tenant_id}</Typography>v
                    {x.version}
                  </TableCell>
                  <TableCell>
                    {fmtRate(x.base_bps)}
                    <br />
                    {fmtRate(x.peak_bps)}
                  </TableCell>
                  <TableCell>{fmtBytes(x.burst_bytes)}</TableCell>
                  <TableCell>
                    {fmtLimit(x.max_connections)} /{" "}
                    {fmtLimit(x.new_flows_per_second)}
                  </TableCell>
                  <TableCell>
                    {fmtBytes(x.used_bytes)} /{" "}
                    {x.period_bytes === 0
                      ? "禁止 (0 B)"
                      : fmtBytes(x.period_bytes)}
                  </TableCell>
                  <TableCell>{fmtBytes(x.reserved_bytes)}</TableCell>
                  <TableCell>
                    {resourceQuotaFields.map(([key, label, usageKey]) => {
                      const count = x.resources?.[usageKey];
                      return (
                        <Typography key={key} variant="body2" noWrap>
                          {label}：{count ?? "未统计"} /{" "}
                          {x[key] === undefined ? "未上报" : fmtLimit(x[key]!)}
                        </Typography>
                      );
                    })}
                  </TableCell>
                  <TableCell>
                    <Button onClick={() => setEditing(x)}>编辑</Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </TableFrame>
        )}
      </Load>
      {editing && (
        <QuotaForm
          initial={editing}
          latest={q.data?.items.find((x) => x.tenant_id === editing.tenant_id)}
          reload={() => void q.refetch()}
          onClose={() => setEditing(undefined)}
        />
      )}
    </>
  );
}
