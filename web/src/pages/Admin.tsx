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
import { request } from "../api";
import { fmtDate, fmtRate, observedOnline } from "../format";
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
import type { Edge, Endpoint, Plan, Quota, Rule, User, List } from "../types";
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
  const plans = useResource<Plan>("/plans", "plans", !initial);
  const [form, setForm] = useState({
    plan_id: "default",
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
    invalidate("users", "quotas", "account", "me");
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
      setValidation("密码长度须为 10–72 字节");
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
          ...(!form.tenant_id && form.plan_id !== "default"
            ? { plan_id: form.plan_id }
            : {}),
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
              helperText="同空间用户共享客户端、服务与套餐"
            >
              <MenuItem value="">新建空间</MenuItem>
              {tenants.map((t) => (
                <MenuItem key={t} value={t}>
                  {t}
                </MenuItem>
              ))}
            </TextField>
          )}
          {!initial && !form.tenant_id && (
            <TextField
              select
              label="套餐"
              disabled={plans.isPending || plans.isError}
              value={form.plan_id}
              onChange={(e) => set("plan_id", e.target.value)}
            >
              <MenuItem value="default">
                {plans.isPending
                  ? "读取中…"
                  : plans.data?.items.find((p) => p.default)?.name || "未分配"}
                （默认）
              </MenuItem>
              <MenuItem value="">未分配</MenuItem>
              {plans.data?.items.map((p) => (
                <MenuItem key={p.id} value={p.id}>
                  {p.name}
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
                停用账号或重置密码将使该用户退出登录。
              </Alert>
            </>
          )}
          <MutationError error={!initial ? plans.error : null} />
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
            (!initial &&
              (!form.username.trim() ||
                !form.password ||
                (!form.tenant_id && (plans.isPending || plans.isError))))
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
  const [editing, setEditing] = useState<User | "new">(),
    [assigning, setAssigning] = useState<User>();
  const [search, setSearch] = useState("");
  const quotas = useResource<Quota>("/quotas", "quotas");
  const rows =
    q.data?.items.filter((u) =>
      `${u.username} ${u.plan_name || ""}`
        .toLowerCase()
        .includes(search.toLowerCase()),
    ) || [];
  return (
    <>
      <PageTitle
        title="用户管理"
        action={
          <Button variant="contained" onClick={() => setEditing("new")}>
            创建用户
          </Button>
        }
      />
      <TextField
        label="搜索用户或套餐"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        sx={{ mb: 1.5 }}
      />
      <Load loading={q.isLoading} error={q.error}>
        {!rows.length ? (
          <Empty title="暂无用户" />
        ) : (
          <TableFrame>
            <TableHead>
              <TableRow>
                <TableCell>用户名</TableCell>
                <TableCell>角色</TableCell>
                <TableCell>套餐</TableCell>
                <TableCell>端口 / 网站</TableCell>
                <TableCell>注册时间</TableCell>
                <TableCell>状态</TableCell>
                <TableCell>操作</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.map((u) => (
                <TableRow key={u.id}>
                  <TableCell>
                    {u.username}
                    {u.id === user.id ? "（当前账号）" : ""}
                  </TableCell>
                  <TableCell>
                    {u.role === "admin" ? "管理员" : "用户"}
                  </TableCell>
                  <TableCell>{u.plan_name || "未分配"}</TableCell>
                  <TableCell>
                    {quotas.data?.items.find((q) => q.tenant_id === u.tenant_id)
                      ?.resources?.ports ?? "—"}{" "}
                    /{" "}
                    {quotas.data?.items.find((q) => q.tenant_id === u.tenant_id)
                      ?.resources?.sites ?? "—"}
                  </TableCell>
                  <TableCell>{fmtDate(u.created_at)}</TableCell>
                  <TableCell>
                    <Status value={u.disabled ? "disabled" : "active"} />
                  </TableCell>
                  <TableCell>
                    <Stack direction="row">
                      <Button onClick={() => setAssigning(u)}>分配套餐</Button>
                      <Button onClick={() => setEditing(u)}>编辑</Button>
                    </Stack>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </TableFrame>
        )}
      </Load>
      {assigning && (
        <AssignPlan
          user={assigning}
          quota={quotas.data?.items.find(
            (q) => q.tenant_id === assigning.tenant_id,
          )}
          onClose={() => setAssigning(undefined)}
        />
      )}
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

function AssignPlan({
  user,
  quota,
  onClose,
}: {
  user: User;
  quota?: Quota;
  onClose: () => void;
}) {
  const plans = useResource<Plan>("/plans", "plans");
  const [planID, setPlanID] = useState(user.plan_id || "");
  const [version, setVersion] = useState<number | undefined>(quota?.version);
  const [readError, setReadError] = useState<unknown>();
  const m = useWriter(() => {
    invalidate(
      "users",
      "quotas",
      "account",
      "plans",
      "edges",
      "overview",
      "rules",
    );
    onClose();
  });
  return (
    <Dialog
      open
      fullWidth
      maxWidth="xs"
      onClose={() => !m.isPending && onClose()}
    >
      <DialogTitle>分配套餐 · {user.username}</DialogTitle>
      <DialogContent>
        <Stack spacing={1.5} sx={{ pt: 1 }}>
          <Load loading={plans.isLoading} error={plans.error}>
            <TextField
              select
              fullWidth
              label="套餐"
              value={planID}
              onChange={(e) => setPlanID(e.target.value)}
            >
              <MenuItem value="">未分配</MenuItem>
              {plans.data?.items.map((p) => (
                <MenuItem key={p.id} value={p.id}>
                  {p.name}
                </MenuItem>
              ))}
            </TextField>
          </Load>
          <Typography variant="caption" color="text.secondary">
            空间：{user.tenant_id}
          </Typography>
          <Typography variant="body2">
            同空间用户共享套餐。变更后更新该空间的节点与资源权限。
          </Typography>
          <MutationError
            error={m.error}
            reload={async () => {
              try {
                const list = await request<List<Quota>>("/quotas");
                setVersion(
                  list.items.find((q) => q.tenant_id === user.tenant_id)
                    ?.version,
                );
                m.reset();
                setReadError(undefined);
                invalidate("quotas");
              } catch (e) {
                setReadError(e);
              }
            }}
          />
          <MutationError error={readError} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={m.isPending}>
          取消
        </Button>
        <Button
          variant="contained"
          disabled={!quota || plans.isError || m.isPending}
          onClick={() =>
            m.mutate({
              path: `/users/${user.id}/plan`,
              method: "PUT",
              data: { plan_id: planID, version: version ?? quota?.version },
            })
          }
        >
          保存
        </Button>
      </DialogActions>
    </Dialog>
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
      setCopyMessage("复制失败，可选中令牌复制");
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
        {created ? "出口节点已登记" : initial ? "编辑出口节点" : "登记出口节点"}
      </DialogTitle>
      <DialogContent>
        <Stack spacing={2.5} sx={{ mt: 1 }}>
          {created ? (
            <>
              <Alert severity="success">
                {created.name} 已登记，等待节点连接。
              </Alert>
              <TextField
                label="出口节点 ID"
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
                  helperText="业务入口的主机名或 IP"
                />
              </Stack>
              <TextField
                label="业务监听地址（可选）"
                value={form.listen_host}
                onChange={(e) => set("listen_host", e.target.value)}
                helperText="不含端口；留空使用默认地址"
              />
              <Typography variant="h6">
                承载入口（客户端 → 出口节点）
              </Typography>
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
                helperText="留空使用系统信任库；自签证书需提供 CA"
              />
              <Typography variant="h6">公网业务端口池</Typography>
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
                      key === "capacity_bps"
                        ? "-1 = 不限，0 = 禁止"
                        : key === "http_port" || key === "https_port"
                          ? "0 = 关闭"
                          : undefined
                    }
                  />
                ))}
              </Box>
              {initial && (
                <Alert severity="warning">
                  关联规则及资源全部释放后，才能修改入口。
                </Alert>
              )}
            </>
          )}
          {!initial && (
            <>
              <TextField
                label="出口节点令牌"
                type={reveal ? "text" : "password"}
                value={form.token}
                onChange={(e) => set("token", e.target.value)}
                autoComplete="off"
                required
                slotProps={{ input: { readOnly: !!created } }}
                helperText="至少 24 字符，用于节点认证；仅本次显示"
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
        title="出口节点与端口池"
        detail="节点入口、业务端口池与容量配置"
        action={
          <Button variant="contained" onClick={() => setEditing("new")}>
            登记出口节点
          </Button>
        }
      />
      <Load loading={q.isLoading} error={q.error}>
        {!q.data?.items.length ? (
          <Empty title="暂无出口节点" />
        ) : (
          <TableFrame>
            <TableHead>
              <TableRow>
                <TableCell>名称 / 公网主机</TableCell>
                <TableCell>客户端 承载入口</TableCell>
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
          title={`删除出口节点 ${deleting.name}`}
          onClose={() => setDeleting(undefined)}
          onConfirm={() =>
            del.mutate({ path: `/edges/${deleting.id}`, method: "DELETE" })
          }
          error={del.error}
          busy={del.isPending}
        >
          <Typography>删除条件：所有空间的关联规则及资源均已释放。</Typography>
        </Confirm>
      )}
    </>
  );
}
