import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { z } from "zod";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Collapse,
  IconButton,
  Snackbar,
  Switch,
  Tooltip,
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
  TablePagination,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { request } from "../api";
import { nativeSourceCapability, observedOnline, ruleState } from "../format";
import {
  Confirm,
  DetailField,
  Empty,
  Load,
  MutationError,
  PageTitle,
  Status,
  TableFrame,
  invalidate,
  useDraftGuard,
  useResource,
  useWriter,
} from "../ui";
import type {
  ACLTemplate,
  Certificate,
  Device,
  Domain,
  Edge,
  Rule,
} from "../types";
import EditOutlinedIcon from "@mui/icons-material/EditOutlined";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import { useAccount } from "./Account";
import ACLSimulation from "./ACLSimulation";
import ACLObservations from "./ACLObservations";

const isSite = (protocol: string) => ["http", "https"].includes(protocol);
const supportsEntry = (edge: Edge, protocol: string) =>
  protocol === "http"
    ? edge.http_port > 0
    : protocol === "https"
      ? edge.https_port > 0
      : edge.port_min > 0 && edge.port_max >= edge.port_min;
function publicEntry(rule: Rule, edge?: Edge) {
  if (isSite(rule.protocol)) {
    const port =
      rule.public_port === (rule.protocol === "https" ? 443 : 80)
        ? ""
        : `:${rule.public_port}`;
    return `${rule.protocol}://${rule.domain}${port}`;
  }
  const host = edge?.public_host || rule.edge_id;
  return `${host.includes(":") && !host.startsWith("[") ? `[${host}]` : host}:${rule.public_port}`;
}
const formSchema = z.object({
  name: z.string().trim().min(1, "请输入名称").max(255),
  device_id: z.string().min(1, "请选择客户端"),
  edge_id: z.string().min(1, "请选择出口节点"),
  protocol: z.enum(["tcp", "udp", "http", "https"]),
  target: z.string().min(1, "请输入目标"),
  public_port: z.number().int().min(0).max(65535),
  timeout_seconds: z.number().int().min(1).max(600),
});

function RuleForm({
  initial,
  sites,
  onClose,
}: {
  initial?: Rule;
  sites: boolean;
  onClose: () => void;
}) {
  const account = useAccount();
  const [advanced, setAdvanced] = useState(false);
  const [form, setForm] = useState({
    name: initial?.name || "",
    protocol: initial?.protocol || (sites ? "http" : "tcp"),
    device_id: initial?.device_id || "",
    edge_id: initial?.edge_id || "",
    public_port: initial?.public_port || 0,
    target: initial?.target || "",
    domain: initial?.domain || "",
    host: initial?.host || "",
    server_name: initial?.server_name || "",
    certificate_id: initial?.certificate_id || "",
    source_mode:
      initial?.source_mode || (sites ? "forwarded_headers" : "socket"),
    transport: initial?.transport || "auto",
    acl_template_id: initial?.acl_template_id || "",
    enabled: initial?.enabled ?? true,
    timeout_seconds: initial?.timeout_seconds || 30,
  });
  const [version, setVersion] = useState(initial?.version || 0),
    [latest, setLatest] = useState<Rule>(),
    [validation, setValidation] = useState("");
  const [dirty, setDirty] = useState(false);
  const canClose = useDraftGuard(dirty);
  const devices = useResource<Device>("/devices", "devices"),
    edges = useResource<Edge>("/edges", "edges");
  const certificates = useResource<Certificate>(
      "/certificates",
      "certificates",
      sites,
    ),
    templates = useResource<ACLTemplate>("/acl-templates", "acl", !sites),
    domains = useResource<Domain>("/domains", "domains", sites);
  const [notice, setNotice] = useState("");
  const m = useWriter<Rule>(() => {
    invalidate("rules", "overview", "account", "quotas");
    onClose();
  });
  const availableEdges =
    edges.data?.items.filter(
      (e) =>
        (account.data?.quota.allowed_edge_ids === null ||
          account.data?.quota.allowed_edge_ids.includes(e.id)) &&
        supportsEntry(e, form.protocol),
    ) || [];
  const selectedDevice = devices.data?.items.find(
      (d) => d.id === form.device_id,
    ),
    selectedEdge = edges.data?.items.find((e) => e.id === form.edge_id);
  useEffect(() => {
    if (initial) return;
    const clients = devices.data?.items.filter((d) => !d.revoked) || [];
    const exits =
      edges.data?.items.filter(
        (e) =>
          (account.data?.quota.allowed_edge_ids === null ||
            account.data?.quota.allowed_edge_ids.includes(e.id)) &&
          supportsEntry(e, form.protocol),
      ) || [];
    setForm((f) => {
      const device = f.device_id || (clients.length === 1 ? clients[0].id : "");
      const edge = exits.some((e) => e.id === f.edge_id)
        ? f.edge_id
        : exits.length === 1
          ? exits[0].id
          : "";
      return device === f.device_id && edge === f.edge_id
        ? f
        : { ...f, device_id: device, edge_id: edge };
    });
  }, [initial, devices.data, edges.data, account.data, form.protocol]);
  const nativeAvailable = nativeSourceCapability(
    form.protocol,
    selectedDevice?.capabilities,
  );
  const nativeUnavailableReason =
    selectedDevice?.runtime?.platform === "windows"
      ? "Windows 不支持源 IP/端口透传，请使用普通转发。"
      : "客户端未上报当前协议的原生保源能力。";
  const set = <K extends keyof typeof form>(
    key: K,
    value: (typeof form)[K],
  ) => {
    setDirty(true);
    setValidation("");
    setForm((f) => ({ ...f, [key]: value }));
  };
  const close = () => {
    if (!m.isPending && canClose()) onClose();
  };
  const submit = () => {
    const parsed = formSchema.safeParse(form);
    if (!parsed.success) {
      setValidation(parsed.error.issues.map((i) => i.message).join("；"));
      return;
    }
    if (form.enabled && form.source_mode === "native" && !nativeAvailable) {
      setValidation(nativeUnavailableReason);
      return;
    }
    if (sites) {
      try {
        const url = new URL(form.target);
        if (
          !["http:", "https:"].includes(url.protocol) ||
          url.username ||
          url.password ||
          url.search ||
          url.hash
        )
          throw Error();
      } catch {
        setValidation(
          "回源 URL 必须使用 http:// 或 https://，不可含凭据、查询参数或片段。",
        );
        return;
      }
      if (
        !form.domain.trim() ||
        /[\s/:]/.test(form.domain) ||
        (form.protocol === "https" && !form.certificate_id)
      ) {
        setValidation("请填写入口域名；HTTPS 入口必须选择有效证书。");
        return;
      }
    } else if (
      !/^[^\s:%\[\]]+:\d+$/.test(form.target) ||
      Number(form.target.split(":").at(-1)) < 1 ||
      Number(form.target.split(":").at(-1)) > 65535
    ) {
      setValidation(
        "TCP/UDP 目标应为 IPv4 地址或域名加端口；域名仅使用 IPv4 解析结果。",
      );
      return;
    }
    const data = {
      ...form,
      version,
      source_mode: sites ? "forwarded_headers" : form.source_mode,
      ...(initial?.acl && initial.acl_template_id === form.acl_template_id
        ? { acl: initial.acl }
        : {}),
      ...(sites ? { acl_template_id: "", acl: undefined } : {}),
    };
    m.mutate({
      path: initial ? `/rules/${initial.id}` : "/rules",
      method: initial ? "PUT" : "POST",
      data,
    });
  };
  const reload = async () => {
    try {
      const current = await request<Rule>(`/rules/${initial!.id}`);
      setLatest(current);
    } catch (e) {
      setNotice(e instanceof Error ? e.message : "读取失败");
    }
  };
  return (
    <Dialog open onClose={close} fullWidth maxWidth="md">
      <DialogTitle>
        {initial ? "编辑" : "创建"}
        {sites ? " HTTP(S) 站点" : " TCP/UDP 隧道"}
      </DialogTitle>
      <DialogContent>
        <Stack spacing={1.5} sx={{ mt: 1 }}>
          <Load
            loading={
              devices.isLoading ||
              edges.isLoading ||
              account.isPending ||
              (sites ? certificates.isLoading : templates.isLoading)
            }
            error={
              devices.error ||
              edges.error ||
              account.error ||
              (sites ? certificates.error : templates.error)
            }
          >
            {account.data && (
              <Stack
                direction="row"
                spacing={2}
                sx={{ color: "text.secondary" }}
              >
                <Typography variant="caption">
                  {account.data.plan?.name || "未分配套餐"}
                </Typography>
                <Typography variant="caption">
                  {sites ? "网站" : "端口"}{" "}
                  {sites
                    ? account.data.quota.resources?.sites
                    : account.data.quota.resources?.ports}{" "}
                  /{" "}
                  {(sites
                    ? account.data.quota.max_sites
                    : (account.data.quota.max_ports ?? 0)) < 0
                    ? "不限"
                    : sites
                      ? account.data.quota.max_sites
                      : account.data.quota.max_ports}
                </Typography>
              </Stack>
            )}
            <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
              <TextField
                label="名称"
                value={form.name}
                onChange={(e) => set("name", e.target.value)}
                fullWidth
                required
                autoFocus
              />
              <TextField
                select
                label="入口协议"
                value={form.protocol}
                fullWidth
                onChange={(e) => {
                  setDirty(true);
                  setForm((f) => ({
                    ...f,
                    protocol: e.target.value,
                    public_port: 0,
                    source_mode: sites ? "forwarded_headers" : "socket",
                    acl_template_id: "",
                  }));
                }}
              >
                {(sites ? ["http", "https"] : ["tcp", "udp"]).map((p) => (
                  <MenuItem key={p} value={p}>
                    {p.toUpperCase()}
                  </MenuItem>
                ))}
              </TextField>
            </Stack>
            <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
              <TextField
                select
                label="客户端"
                value={form.device_id}
                fullWidth
                required
                onChange={(e) => {
                  set("device_id", e.target.value);
                  if (!sites) set("source_mode", "socket");
                }}
                helperText={
                  selectedDevice
                    ? `控制会话：${observedOnline(selectedDevice.last_seen) ? "近期在线" : "离线或未上报"}`
                    : "回源客户端"
                }
              >
                {devices.data?.items
                  .filter((d) => !d.revoked || d.id === form.device_id)
                  .map((d) => (
                    <MenuItem key={d.id} value={d.id} disabled={d.revoked}>
                      {d.name}
                      {d.revoked ? "（已撤销）" : ""}
                    </MenuItem>
                  ))}
              </TextField>
              <TextField
                select
                label="出口节点"
                value={form.edge_id}
                fullWidth
                required
                onChange={(e) => {
                  set("edge_id", e.target.value);
                  set("public_port", 0);
                }}
                helperText={
                  selectedEdge
                    ? sites
                      ? `${form.protocol.toUpperCase()} 监听端口 ${form.protocol === "https" ? selectedEdge.https_port : selectedEdge.http_port}`
                      : `业务端口池 ${selectedEdge.port_min}–${selectedEdge.port_max}`
                    : undefined
                }
              >
                {form.edge_id &&
                  !availableEdges.some((e) => e.id === form.edge_id) && (
                    <MenuItem value={form.edge_id} disabled>
                      {selectedEdge?.name || form.edge_id}（入口不可用）
                    </MenuItem>
                  )}
                {availableEdges.map((e) => (
                  <MenuItem key={e.id} value={e.id}>
                    {e.name} · {e.public_host}
                  </MenuItem>
                ))}
              </TextField>
            </Stack>
            {(!devices.data?.items.some((d) => !d.revoked) ||
              !availableEdges.length) && (
              <Alert severity="warning">
                无可用客户端或对应协议的套餐出口节点。
                <Button component={Link} to="/devices" size="small">
                  客户端
                </Button>
              </Alert>
            )}
            {sites ? (
              <>
                <TextField
                  select
                  label="入口域名"
                  value={form.domain}
                  onChange={(e) => set("domain", e.target.value)}
                  required
                  helperText="已通过归属验证的域名"
                >
                  {form.domain &&
                    !domains.data?.items.some(
                      (d) =>
                        d.domain === form.domain && d.status === "verified",
                    ) && (
                      <MenuItem value={form.domain} disabled>
                        {form.domain}（未验证）
                      </MenuItem>
                    )}
                  {domains.data?.items
                    .filter((d) => d.status === "verified")
                    .map((d) => (
                      <MenuItem key={d.id} value={d.domain}>
                        {d.domain}
                      </MenuItem>
                    ))}
                </TextField>
                {!domains.isLoading &&
                  !domains.data?.items.some((d) => d.status === "verified") && (
                    <Alert severity="warning">
                      暂无已验证域名。
                      <Button component={Link} to="/certificates">
                        前往域名验证
                      </Button>
                    </Alert>
                  )}
                <MutationError error={domains.error} />
                {form.protocol === "https" && (
                  <TextField
                    select
                    label="公网证书"
                    value={form.certificate_id}
                    required
                    onChange={(e) => set("certificate_id", e.target.value)}
                    helperText="须覆盖入口域名且在有效期内"
                  >
                    {certificates.data?.items.map((c) => (
                      <MenuItem
                        key={c.id}
                        value={c.id}
                        disabled={Date.parse(c.expires_at) <= Date.now()}
                      >
                        {c.name} · {c.domains.join("、")}
                      </MenuItem>
                    ))}
                  </TextField>
                )}
                <TextField
                  label="回源地址"
                  value={form.target}
                  onChange={(e) => set("target", e.target.value)}
                  required
                  placeholder="https://10.0.0.2:8443"
                  helperText="支持 HTTP / HTTPS；HTTPS 回源验证证书"
                />
                <Collapse in={advanced} unmountOnExit>
                  <Stack spacing={1.5}>
                    <Stack
                      direction={{ xs: "column", sm: "row" }}
                      spacing={1.5}
                    >
                      <TextField
                        label="回源 Host（可选）"
                        value={form.host}
                        onChange={(e) => set("host", e.target.value)}
                        fullWidth
                      />
                      <TextField
                        label="回源 TLS Server Name（可选）"
                        value={form.server_name}
                        onChange={(e) => set("server_name", e.target.value)}
                        fullWidth
                      />
                    </Stack>
                    <Typography variant="body2" color="text.secondary">
                      来源模式：可信来源头
                    </Typography>
                  </Stack>
                </Collapse>
              </>
            ) : (
              <>
                <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
                  <TextField
                    type="number"
                    label="公网业务端口"
                    value={form.public_port}
                    onChange={(e) => set("public_port", Number(e.target.value))}
                    fullWidth
                    helperText="0 = 保存时自动分配"
                    slotProps={{ htmlInput: { min: 0, max: 65535 } }}
                  />
                  <TextField
                    label="目标地址"
                    value={form.target}
                    onChange={(e) => set("target", e.target.value)}
                    required
                    fullWidth
                    helperText="客户端可达的 IPv4 地址或域名；仅转发 IPv4 TCP/UDP，承载链路可使用 IPv6"
                  />
                </Stack>
                <Collapse in={advanced} unmountOnExit>
                  <Stack spacing={1.5}>
                    <TextField
                      select
                      label="来源模式"
                      value={form.source_mode}
                      onChange={(e) => set("source_mode", e.target.value)}
                    >
                      <MenuItem value="socket">普通转发</MenuItem>
                      <MenuItem value="native" disabled={!nativeAvailable}>
                        原生保源（Linux IPv4）
                        {nativeAvailable
                          ? ""
                          : selectedDevice?.runtime?.platform === "windows"
                            ? " · Windows 不支持"
                            : " · 能力未上报"}
                      </MenuItem>
                    </TextField>
                    {form.source_mode === "native" && (
                      <Alert severity={nativeAvailable ? "warning" : "error"}>
                        {nativeAvailable
                          ? "保留来源 IP 和端口，需配置目标网络回程与策略路由。"
                          : nativeUnavailableReason}
                      </Alert>
                    )}
                    <TextField
                      select
                      label="已发布 ACL 模板"
                      value={form.acl_template_id}
                      onChange={(e) => set("acl_template_id", e.target.value)}
                      helperText={
                        templates.data?.items.length
                          ? "强制父策略同时生效"
                          : "暂无已发布模板"
                      }
                    >
                      <MenuItem value="">
                        {initial ? "无模板（保留独立策略）" : "平台默认"}
                      </MenuItem>
                      {templates.data?.items
                        .filter((t) => t.published || t.policy.version > 0)
                        .map((t) => (
                          <MenuItem key={t.id} value={t.id}>
                            {t.name}
                            {t.default ? " · 默认" : ""}
                            {t.mandatory ? " · 强制" : ""}
                          </MenuItem>
                        ))}
                    </TextField>
                    {templates.data?.items
                      .filter(
                        (t) =>
                          t.mandatory && (t.published || t.policy.version > 0),
                      )
                      .map((t) => (
                        <Alert key={t.id} severity="info">
                          强制父策略：{t.name} · 已发布 v
                          {t.published?.version || t.policy.version}
                        </Alert>
                      ))}
                  </Stack>
                </Collapse>
              </>
            )}
            <Button
              sx={{ alignSelf: "flex-start" }}
              onClick={() => setAdvanced(!advanced)}
              aria-expanded={advanced}
            >
              {advanced ? "收起高级配置" : "高级配置"}
            </Button>
            <Collapse in={advanced} unmountOnExit>
              <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
                <TextField
                  select
                  label="传输偏好"
                  value={form.transport}
                  onChange={(e) => set("transport", e.target.value)}
                  fullWidth
                >
                  <MenuItem value="auto">自动（QUIC 优先，TLS 备用）</MenuItem>
                  <MenuItem value="quic_only">仅 QUIC</MenuItem>
                  <MenuItem value="tls_only">仅 TLS</MenuItem>
                </TextField>
                <TextField
                  type="number"
                  label="超时（秒）"
                  value={form.timeout_seconds}
                  onChange={(e) =>
                    set("timeout_seconds", Number(e.target.value))
                  }
                  fullWidth
                  slotProps={{ htmlInput: { min: 1, max: 600 } }}
                />
              </Stack>
            </Collapse>
            <FormControlLabel
              control={
                <Checkbox
                  checked={form.enabled}
                  onChange={(e) => set("enabled", e.target.checked)}
                />
              }
              label="启用规则"
            />
            {initial && (
              <Alert severity="warning">修改或停用规则可能中断现有连接。</Alert>
            )}
            {validation && <Alert severity="error">{validation}</Alert>}
            <MutationError
              error={m.error}
              reload={initial ? reload : undefined}
            />
            {notice && <Alert severity="error">{notice}</Alert>}
            {latest && (
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Typography fontWeight={700}>
                  最新配置 v{latest.version}
                </Typography>
                <Box
                  component="pre"
                  sx={{ overflow: "auto", maxHeight: 230, fontSize: 12 }}
                >
                  {JSON.stringify(latest, null, 2)}
                </Box>
                <Alert severity="info">当前输入已保留。</Alert>
                <Button
                  onClick={() => {
                    setVersion(latest.version);
                    setLatest(undefined);
                    m.reset();
                  }}
                >
                  保留输入，使用 v{latest.version}
                </Button>
              </Paper>
            )}
          </Load>
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
            !form.name.trim() ||
            !form.device_id ||
            !form.edge_id ||
            (form.enabled &&
              !availableEdges.some((e) => e.id === form.edge_id)) ||
            !form.target ||
            devices.isError ||
            edges.isError
          }
        >
          {m.isPending ? "保存中…" : initial ? "保存" : "创建"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export function RulesPage({ sites = false }: { sites?: boolean }) {
  const q = useResource<Rule>("/rules", "rules"),
    devices = useResource<Device>("/devices", "devices"),
    edges = useResource<Edge>("/edges", "edges");
  const [params, setParams] = useSearchParams(),
    [form, setForm] = useState<Rule | "new" | undefined>(() =>
      params.get("create") === "1" ? "new" : undefined,
    ),
    [deleting, setDeleting] = useState<Rule>();
  const search = params.get("q") || "",
    filter = params.get("protocol") || "",
    page = Math.max(0, Number(params.get("page")) || 0),
    pageSize = [25, 50, 100].includes(Number(params.get("size")))
      ? Number(params.get("size"))
      : 25,
    edgeFilter = params.get("edge") || "",
    stateFilter = params.get("state") || "";
  const [notice, setNotice] = useState("");
  const updateParams = (values: Record<string, string>) =>
    setParams(
      (p) => {
        const next = new URLSearchParams(p);
        next.delete("create");
        next.delete("page");
        for (const [k, v] of Object.entries(values))
          v ? next.set(k, v) : next.delete(k);
        return next;
      },
      { replace: true },
    );
  const toggle = useWriter(() => {
    invalidate("rules", "overview");
  });
  const remove = useWriter(() => {
    setDeleting(undefined);
    invalidate("rules", "overview", "account", "quotas");
  });
  const rows =
    q.data?.items.filter(
      (r) =>
        isSite(r.protocol) === sites &&
        (!filter || r.protocol === filter) &&
        (!edgeFilter || r.edge_id === edgeFilter) &&
        (!stateFilter ||
          (stateFilter === "enabled"
            ? r.enabled && !r.deleting
            : stateFilter === "disabled"
              ? !r.enabled
              : ruleState(r) === stateFilter)) &&
        `${r.name} ${r.target} ${r.domain || ""}`
          .toLowerCase()
          .includes(search.toLowerCase()),
    ) || [];
  const activePage = Math.min(
    page,
    Math.max(0, Math.ceil(rows.length / pageSize) - 1),
  );
  const title = sites ? "HTTP(S) 站点" : "TCP / UDP 隧道";
  return (
    <>
      <PageTitle
        title={title}
        action={
          <Button
            variant="contained"
            onClick={() => {
              toggle.reset();
              setForm("new");
            }}
          >
            创建{sites ? "站点" : "隧道"}
          </Button>
        }
      />
      <Stack
        direction="row"
        useFlexGap
        flexWrap="wrap"
        spacing={1.5}
        alignItems="center"
        sx={{ mb: 1.5 }}
      >
        <TextField
          label="搜索名称或目标"
          size="small"
          value={search}
          onChange={(e) => updateParams({ q: e.target.value })}
        />
        <TextField
          select
          label="协议"
          size="small"
          value={filter}
          onChange={(e) => updateParams({ protocol: e.target.value })}
          sx={{ minWidth: 105 }}
        >
          <MenuItem value="">全部</MenuItem>
          {(sites ? ["http", "https"] : ["tcp", "udp"]).map((p) => (
            <MenuItem key={p} value={p}>
              {p.toUpperCase()}
            </MenuItem>
          ))}
        </TextField>
        <TextField
          select
          label="出口节点"
          value={edgeFilter}
          onChange={(e) => updateParams({ edge: e.target.value })}
          sx={{ minWidth: 140 }}
        >
          <MenuItem value="">全部</MenuItem>
          {edges.data?.items.map((e) => (
            <MenuItem key={e.id} value={e.id}>
              {e.name}
            </MenuItem>
          ))}
        </TextField>
        <TextField
          select
          label="状态"
          value={stateFilter}
          onChange={(e) => updateParams({ state: e.target.value })}
          sx={{ minWidth: 105 }}
        >
          <MenuItem value="">全部</MenuItem>
          <MenuItem value="enabled">已启用</MenuItem>
          <MenuItem value="disabled">已停用</MenuItem>
          <MenuItem value="error">应用失败</MenuItem>
          <MenuItem value="plan_restricted">套餐不可用</MenuItem>
          <MenuItem value="deleting">正在释放</MenuItem>
        </TextField>
        <Typography variant="body2" color="text.secondary">
          {rows.length} 项
        </Typography>
      </Stack>
      <MutationError error={toggle.error} />
      <Load loading={q.isLoading} error={q.error}>
        {!rows.length ? (
          <Empty
            title={
              q.data?.items.some((r) => isSite(r.protocol) === sites)
                ? "没有匹配规则"
                : sites
                  ? "暂无站点"
                  : "暂无隧道"
            }
          />
        ) : (
          <>
            <Box className="service-table">
              <TableFrame>
                <TableHead>
                  <TableRow>
                    <TableCell>名称 / 协议</TableCell>
                    <TableCell>公网入口</TableCell>
                    <TableCell>客户端 → 目标</TableCell>
                    <TableCell>状态</TableCell>
                    <TableCell>启用</TableCell>
                    <TableCell>操作</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {rows
                    .slice(
                      activePage * pageSize,
                      activePage * pageSize + pageSize,
                    )
                    .map((r) => {
                      const edge = edges.data?.items.find(
                        (e) => e.id === r.edge_id,
                      );
                      return (
                        <TableRow key={r.id} hover>
                          <TableCell>
                            <Button
                              component={Link}
                              to={`/${sites ? "sites" : "rules"}/${r.id}`}
                              sx={{ p: 0 }}
                            >
                              {r.name}
                            </Button>
                            <Typography variant="caption" display="block">
                              {r.protocol.toUpperCase()} ·{" "}
                              {r.source_mode === "socket"
                                ? "普通转发"
                                : r.source_mode === "native"
                                  ? "原生保源"
                                  : "可信来源头"}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography className="mono">
                              {publicEntry(r, edge)}
                            </Typography>
                            <Typography variant="caption">
                              {edge?.name || r.edge_id}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography>
                              {devices.data?.items.find(
                                (d) => d.id === r.device_id,
                              )?.name || r.device_id}
                            </Typography>
                            <Typography className="mono">{r.target}</Typography>
                          </TableCell>
                          <TableCell>
                            <Status value={ruleState(r)} />
                            <Typography
                              variant="caption"
                              display="block"
                              color="text.secondary"
                            >
                              v{r.applied_version} / {r.version}
                            </Typography>
                            {r.plan_restricted && (
                              <Typography
                                variant="caption"
                                color="warning.main"
                              >
                                套餐未包含此节点
                              </Typography>
                            )}
                            {r.last_error && (
                              <Typography
                                variant="caption"
                                color="error"
                                display="block"
                                sx={{ maxWidth: 260, overflowWrap: "anywhere" }}
                              >
                                {r.last_error}
                              </Typography>
                            )}
                          </TableCell>
                          <TableCell>
                            <Switch
                              size="small"
                              checked={r.enabled && !r.deleting}
                              disabled={
                                r.deleting ||
                                toggle.isPending ||
                                (!r.enabled && r.plan_restricted)
                              }
                              slotProps={{
                                input: {
                                  "aria-label": `${r.enabled ? "停用" : "启用"} ${r.name}`,
                                },
                              }}
                              onChange={(_, enabled) =>
                                toggle.mutate({
                                  path: `/rules/${r.id}`,
                                  method: "PUT",
                                  data: { ...r, enabled },
                                })
                              }
                            />
                          </TableCell>
                          <TableCell>
                            <Stack direction="row" className="service-actions">
                              <Tooltip title="复制入口">
                                <IconButton
                                  size="small"
                                  aria-label={`复制 ${r.name} 入口`}
                                  onClick={async () => {
                                    const value = publicEntry(r, edge);
                                    try {
                                      await navigator.clipboard.writeText(
                                        value,
                                      );
                                      setNotice("入口已复制");
                                    } catch {
                                      setNotice("复制失败");
                                    }
                                  }}
                                >
                                  <ContentCopyIcon fontSize="small" />
                                </IconButton>
                              </Tooltip>
                              <Tooltip title="编辑">
                                <span>
                                  <IconButton
                                    size="small"
                                    aria-label={`编辑 ${r.name}`}
                                    disabled={r.deleting}
                                    onClick={() => setForm(r)}
                                  >
                                    <EditOutlinedIcon fontSize="small" />
                                  </IconButton>
                                </span>
                              </Tooltip>
                              <Tooltip title="删除">
                                <span>
                                  <IconButton
                                    size="small"
                                    color="error"
                                    aria-label={`删除 ${r.name}`}
                                    disabled={r.deleting}
                                    onClick={() => {
                                      remove.reset();
                                      setDeleting(r);
                                    }}
                                  >
                                    <DeleteOutlineIcon fontSize="small" />
                                  </IconButton>
                                </span>
                              </Tooltip>
                            </Stack>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                </TableBody>
              </TableFrame>
            </Box>
            <TablePagination
              component="div"
              count={rows.length}
              page={activePage}
              rowsPerPage={pageSize}
              rowsPerPageOptions={[25, 50, 100]}
              onRowsPerPageChange={(e) =>
                updateParams({ size: e.target.value })
              }
              labelRowsPerPage="每页"
              getItemAriaLabel={(type) =>
                ({
                  first: "第一页",
                  last: "最后一页",
                  next: "下一页",
                  previous: "上一页",
                })[type]
              }
              onPageChange={(_, p) =>
                setParams((old) => {
                  const next = new URLSearchParams(old);
                  next.set("page", String(p));
                  return next;
                })
              }
              labelDisplayedRows={({ from, to, count }) =>
                `${from}–${to} / ${count}`
              }
            />
          </>
        )}
      </Load>
      {form && (
        <RuleForm
          initial={form === "new" ? undefined : form}
          sites={sites}
          onClose={() => {
            setForm(undefined);
            if (params.has("create")) updateParams({});
          }}
        />
      )}
      <Snackbar
        open={!!notice}
        autoHideDuration={2500}
        message={notice}
        onClose={() => setNotice("")}
      />
      {deleting && (
        <Confirm
          title={`删除 ${deleting.name}`}
          onClose={() => setDeleting(undefined)}
          onConfirm={() =>
            remove.mutate({ path: `/rules/${deleting.id}`, method: "DELETE" })
          }
          error={remove.error}
          busy={remove.isPending}
          label="提交删除"
        >
          <Typography>
            删除将中断现有连接。公网端口和域名在出口节点停止转发或授权到期后释放。
          </Typography>
        </Confirm>
      )}
    </>
  );
}

export function RulePage() {
  const { id } = useParams();
  const q = useQuery<Rule>({
    queryKey: ["rules", "detail", id],
    queryFn: ({ signal }) => request(`/rules/${id}`, { signal }),
  });
  const devices = useResource<Device>("/devices", "devices"),
    edges = useResource<Edge>("/edges", "edges"),
    templates = useResource<ACLTemplate>("/acl-templates", "acl");
  const [edit, setEdit] = useState(false);
  const r = q.data,
    d = devices.data?.items.find((x) => x.id === r?.device_id),
    e = edges.data?.items.find((x) => x.id === r?.edge_id);
  const site = r ? isSite(r.protocol) : false;
  return (
    <>
      <PageTitle
        title={r?.name || "规则详情"}
        action={
          <Stack direction="row">
            <Button component={Link} to={site ? "/sites" : "/rules"}>
              返回列表
            </Button>
            <Button
              variant="contained"
              disabled={!r || r.deleting}
              onClick={() => setEdit(true)}
            >
              编辑配置
            </Button>
          </Stack>
        }
      />
      <Load loading={q.isPending} error={q.error}>
        {r && (
          <Stack spacing={3}>
            <Paper variant="outlined" sx={{ p: 3 }}>
              <Typography className="mono" sx={{ mb: 3 }}>
                {publicEntry(r, e)} → {e?.name || r.edge_id} →{" "}
                {d?.name || r.device_id} → {r.target}
              </Typography>
              <Box className="detail-grid">
                <DetailField label="配置应用">
                  <Status value={ruleState(r)} />
                </DetailField>
                <DetailField label="期望 / 出口节点已应用版本">
                  v{r.version} / v{r.applied_version}
                </DetailField>
                <DetailField label="客户端 应用修订">
                  {d?.applied_revision || "未上报"}
                </DetailField>
                <DetailField label="客户端 控制会话">
                  <Status
                    value={
                      d?.revoked
                        ? "revoked"
                        : observedOnline(d?.last_seen)
                          ? "online"
                          : "offline"
                    }
                  />
                </DetailField>
                <DetailField label="目标服务健康">未检查</DetailField>
                <DetailField label="客户端传输观测">
                  <Button
                    component={Link}
                    to={`/devices/${r.device_id}`}
                    sx={{ p: 0, justifyContent: "flex-start" }}
                  >
                    查看客户端传输
                  </Button>
                </DetailField>
                <DetailField label="配置传输偏好">{r.transport}</DetailField>
                <DetailField label="来源模式">{r.source_mode}</DetailField>
                <DetailField label="回源 Host / TLS 名称">
                  {r.host || "保留目标 Host"} /{" "}
                  {r.server_name || "使用回源主机名"}
                </DetailField>
                <DetailField label="超时">{r.timeout_seconds} 秒</DetailField>
              </Box>
            </Paper>
            {r.last_error && <Alert severity="error">{r.last_error}</Alert>}
            {r.source_mode === "native" && (
              <Alert
                severity={
                  nativeSourceCapability(r.protocol, d?.capabilities)
                    ? "info"
                    : "error"
                }
              >
                {nativeSourceCapability(r.protocol, d?.capabilities)
                  ? "原生保源：保留来源 IP 和端口，需配置目标网络回程与策略路由。"
                  : d?.runtime?.platform === "windows"
                    ? "Windows 不支持源 IP/端口透传，请使用普通转发。"
                    : "客户端未上报原生保源能力，规则停止转发。"}
              </Alert>
            )}
            {site ? (
              <Paper variant="outlined" sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  HTTP(S) 配置
                </Typography>
                <Typography>
                  公网证书：
                  {r.certificate_id || "无（HTTP 入口）"}
                </Typography>
                <Typography sx={{ mt: 1 }}>
                  错误响应：连接离线 503，回源失败 502，回源超时 504。
                </Typography>
                <Typography sx={{ mt: 1 }}>
                  来源信息：客户端设置可信来源头
                </Typography>
              </Paper>
            ) : (
              <Paper variant="outlined" sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  TCP/UDP 访问策略
                </Typography>
                <Typography>
                  规则模板：
                  {templates.data?.items.find((t) => t.id === r.acl_template_id)
                    ?.name ||
                    r.acl_template_id ||
                    (r.acl ? "独立策略" : "未选择模板")}
                </Typography>
                {templates.data?.items
                  .filter((t) => t.mandatory)
                  .map((t) => (
                    <Typography key={t.id}>
                      强制父策略：{t.name} · v
                      {t.published?.version || t.policy.version}
                    </Typography>
                  ))}
                <Typography color="text.secondary" sx={{ mt: 1 }}>
                  强制父策略与规则策略取交集。
                </Typography>
                <ACLSimulation
                  target={{ rule_id: r.id }}
                  title={r.name}
                  protocol={r.protocol}
                />
                <ACLObservations ruleId={r.id} title={r.name} />
              </Paper>
            )}
          </Stack>
        )}
      </Load>
      {r && edit && (
        <RuleForm initial={r} sites={site} onClose={() => setEdit(false)} />
      )}
    </>
  );
}
