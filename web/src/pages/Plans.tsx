import { useState } from "react";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  List,
  ListItem,
  ListItemText,
  MenuItem,
  Stack,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { request } from "../api";
import { fmtBytes, fmtLimit, fmtPeriod, fmtRate } from "../format";
import {
  Confirm,
  Empty,
  Load,
  MutationError,
  PageTitle,
  TableFrame,
  invalidate,
  useDraftGuard,
  useResource,
  useWriter,
} from "../ui";
import type { Edge, Plan, List as ResourceList } from "../types";

function PlanForm({
  initial,
  onClose,
}: {
  initial?: Plan;
  onClose: () => void;
}) {
  const edges = useResource<Edge>("/edges", "edges");
  const [form, setForm] = useState({
    name: initial?.name || "",
    bandwidth: initial
      ? initial.bandwidth_bps < 0
        ? -1
        : initial.bandwidth_bps / 1000000
      : 10,
    max_ports: initial?.max_ports ?? 5,
    max_sites: initial?.max_sites ?? 2,
    all_edges: initial?.all_edges ?? false,
    edge_ids: initial?.edge_ids || [],
    default: initial?.default ?? false,
    burst_enabled: initial?.burst_enabled ?? false,
    burst_bandwidth: initial?.burst_bps ? initial.burst_bps / 1000000 : 20,
    burst_seconds: initial?.burst_seconds || 10,
    traffic_metered: initial?.traffic_metered ?? false,
    traffic_gib: initial?.traffic_metered
      ? initial.traffic_bytes / 1024 ** 3
      : 100,
    period_days: initial?.traffic_metered ? initial.period_seconds / 86400 : 30,
    overage_action: initial?.overage_action || "reject",
    overage_bandwidth: initial?.overage_bps ? initial.overage_bps / 1000000 : 1,
  });
  const [dirty, setDirty] = useState(false);
  const [validation, setValidation] = useState("");
  const [version, setVersion] = useState(initial?.version || 0);
  const canClose = useDraftGuard(dirty);
  const m = useWriter(() => {
    invalidate("plans", "users", "quotas", "account", "overview", "edges");
    onClose();
  });
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
    const bandwidth =
      form.bandwidth < 0
        ? form.bandwidth
        : Math.round(form.bandwidth * 1000000);
    if (
      !form.name.trim() ||
      !Number.isSafeInteger(bandwidth) ||
      bandwidth < -1 ||
      bandwidth > 2 ** 50 ||
      [form.max_ports, form.max_sites].some(
        (n) => !Number.isInteger(n) || n < -1 || n > 1000000,
      )
    ) {
      setValidation(
        "名称必填；带宽和数量须为有效数值，-1 表示不限，0 表示不可用",
      );
      return;
    }
    const burst = Math.round(form.burst_bandwidth * 1000000),
      traffic = Math.round(form.traffic_gib * 1024 ** 3),
      period = Math.round(form.period_days * 86400),
      overage = Math.round(form.overage_bandwidth * 1000000);
    if (
      form.burst_enabled &&
      (bandwidth <= 0 ||
        !Number.isSafeInteger(burst) ||
        burst <= bandwidth ||
        burst > 2 ** 50 ||
        !Number.isInteger(form.burst_seconds) ||
        form.burst_seconds < 1 ||
        form.burst_seconds > 3600)
    ) {
      setValidation("突发带宽须大于基础带宽，突发时长须为 1–3600 秒");
      return;
    }
    if (
      form.traffic_metered &&
      (!Number.isSafeInteger(traffic) ||
        traffic < 0 ||
        traffic > 2 ** 60 ||
        !Number.isSafeInteger(period) ||
        period < 0 ||
        period > 366 * 86400 ||
        (period > 0 && period < 60))
    ) {
      setValidation("流量额度须为非负数；周期为 0 或 1 分钟至 366 天");
      return;
    }
    if (
      form.traffic_metered &&
      form.overage_action === "throttle" &&
      (!Number.isSafeInteger(overage) ||
        overage <= 0 ||
        overage > 2 ** 50 ||
        bandwidth === 0 ||
        (bandwidth > 0 && overage > bandwidth))
    ) {
      setValidation("超额速率须大于 0，且不超过基础带宽");
      return;
    }
    m.mutate({
      path: initial ? `/plans/${initial.id}` : "/plans",
      method: initial ? "PUT" : "POST",
      data: {
        name: form.name,
        bandwidth_bps: bandwidth,
        burst_enabled: form.burst_enabled,
        burst_bps: form.burst_enabled ? burst : 0,
        burst_seconds: form.burst_enabled ? form.burst_seconds : 0,
        traffic_metered: form.traffic_metered,
        traffic_bytes: form.traffic_metered ? traffic : 0,
        period_seconds: form.traffic_metered ? period : 0,
        overage_action: form.overage_action,
        overage_bps:
          form.traffic_metered && form.overage_action === "throttle"
            ? overage
            : 0,
        max_ports: form.max_ports,
        max_sites: form.max_sites,
        all_edges: form.all_edges,
        edge_ids: form.all_edges ? [] : form.edge_ids,
        default: form.default,
        version,
      },
    });
  };
  return (
    <Dialog open fullWidth maxWidth="sm" onClose={close}>
      <DialogTitle>{initial ? "编辑套餐" : "创建套餐"}</DialogTitle>
      <DialogContent>
        <Stack spacing={1.5} sx={{ pt: 1 }}>
          <TextField
            label="套餐名称"
            value={form.name}
            onChange={(e) => set("name", e.target.value)}
            autoFocus
            required
          />
          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: { xs: "1fr", sm: "repeat(3,minmax(0,1fr))" },
              gap: 1.5,
            }}
          >
            <TextField
              label="基础带宽（Mbps）"
              type="number"
              value={form.bandwidth}
              onChange={(e) => set("bandwidth", Number(e.target.value))}
              slotProps={{ htmlInput: { min: -1, step: 0.1 } }}
            />
            <TextField
              label="端口总数"
              type="number"
              value={form.max_ports}
              onChange={(e) => set("max_ports", Number(e.target.value))}
              slotProps={{ htmlInput: { min: -1, max: 1000000 } }}
            />
            <TextField
              label="网站数"
              type="number"
              value={form.max_sites}
              onChange={(e) => set("max_sites", Number(e.target.value))}
              slotProps={{ htmlInput: { min: -1, max: 1000000 } }}
            />
          </Box>
          <Typography variant="caption" color="text.secondary">
            -1 不限，0 不可用。端口和带宽在所有出口节点间合计。
          </Typography>
          <FormControlLabel
            label="允许突发"
            control={
              <Checkbox
                checked={form.burst_enabled}
                onChange={(e) => set("burst_enabled", e.target.checked)}
              />
            }
          />
          {form.burst_enabled && (
            <Box className="form-grid">
              <TextField
                label="突发带宽（Mbps）"
                type="number"
                value={form.burst_bandwidth}
                onChange={(e) => set("burst_bandwidth", Number(e.target.value))}
                slotProps={{ htmlInput: { min: 0, step: 0.1 } }}
              />
              <TextField
                label="突发时长（秒）"
                type="number"
                value={form.burst_seconds}
                onChange={(e) => set("burst_seconds", Number(e.target.value))}
                slotProps={{ htmlInput: { min: 1, max: 3600 } }}
              />
            </Box>
          )}
          <FormControlLabel
            label="按流量计费"
            control={
              <Checkbox
                checked={form.traffic_metered}
                onChange={(e) => set("traffic_metered", e.target.checked)}
              />
            }
          />
          {form.traffic_metered && (
            <Box className="form-grid">
              <TextField
                label="流量额度（GiB）"
                type="number"
                value={form.traffic_gib}
                onChange={(e) => set("traffic_gib", Number(e.target.value))}
                slotProps={{ htmlInput: { min: 0, step: 0.1 } }}
              />
              <TextField
                label="流量周期（天）"
                type="number"
                value={form.period_days}
                onChange={(e) => set("period_days", Number(e.target.value))}
                helperText="0 不重置"
                slotProps={{ htmlInput: { min: 0, max: 366 } }}
              />
              <TextField
                label="超额策略"
                select
                value={form.overage_action}
                onChange={(e) =>
                  set("overage_action", e.target.value as "reject" | "throttle")
                }
              >
                <MenuItem value="reject">拒绝连接</MenuItem>
                <MenuItem value="throttle">限速</MenuItem>
              </TextField>
              {form.overage_action === "throttle" && (
                <TextField
                  label="超额速率（Mbps）"
                  type="number"
                  value={form.overage_bandwidth}
                  onChange={(e) =>
                    set("overage_bandwidth", Number(e.target.value))
                  }
                  slotProps={{ htmlInput: { min: 0, step: 0.1 } }}
                />
              )}
            </Box>
          )}
          <Box>
            <Stack
              direction="row"
              alignItems="center"
              justifyContent="space-between"
            >
              <Typography fontWeight={600}>可用出口节点</Typography>
              <FormControlLabel
                label="全部节点"
                control={
                  <Checkbox
                    checked={form.all_edges}
                    onChange={(e) => set("all_edges", e.target.checked)}
                  />
                }
              />
            </Stack>
            <Load loading={edges.isLoading} error={edges.error}>
              {!edges.data?.items.length ? (
                <Typography variant="body2" color="text.secondary">
                  暂无出口节点
                </Typography>
              ) : (
                <List
                  dense
                  disablePadding
                  sx={{
                    border: 1,
                    borderColor: "divider",
                    borderRadius: 1,
                    maxHeight: 220,
                    overflowY: "auto",
                  }}
                >
                  {edges.data.items.map((edge) => (
                    <ListItem key={edge.id} disablePadding>
                      <FormControlLabel
                        sx={{ m: 0, px: 0.5, width: "100%" }}
                        control={
                          <Checkbox
                            disabled={form.all_edges}
                            checked={
                              form.all_edges || form.edge_ids.includes(edge.id)
                            }
                            onChange={(e) =>
                              set(
                                "edge_ids",
                                e.target.checked
                                  ? [...form.edge_ids, edge.id]
                                  : form.edge_ids.filter(
                                      (id) => id !== edge.id,
                                    ),
                              )
                            }
                          />
                        }
                        label={
                          <ListItemText
                            primary={edge.name}
                            secondary={edge.public_host}
                          />
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              )}
            </Load>
          </Box>
          <FormControlLabel
            label="新用户默认套餐"
            control={
              <Checkbox
                checked={form.default}
                onChange={(e) => set("default", e.target.checked)}
              />
            }
          />
          {validation && <Alert severity="error">{validation}</Alert>}
          <MutationError
            error={m.error}
            reload={
              initial
                ? async () => {
                    try {
                      const list = await request<ResourceList<Plan>>("/plans");
                      const latest = list.items.find(
                        (p) => p.id === initial.id,
                      );
                      if (!latest) {
                        setValidation("套餐已删除");
                        return;
                      }
                      setVersion(latest.version);
                      m.reset();
                    } catch (e) {
                      setValidation(
                        e instanceof Error ? e.message : "读取失败",
                      );
                    }
                  }
                : undefined
            }
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={close} disabled={m.isPending}>
          取消
        </Button>
        <Button
          variant="contained"
          onClick={submit}
          disabled={m.isPending || !form.name.trim() || edges.isError}
        >
          {m.isPending ? "保存中…" : "保存"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export default function PlansPage() {
  const plans = useResource<Plan>("/plans", "plans"),
    edges = useResource<Edge>("/edges", "edges");
  const [form, setForm] = useState<Plan | "new">(),
    [deleting, setDeleting] = useState<Plan>();
  const [search, setSearch] = useState("");
  const remove = useWriter(() => {
    setDeleting(undefined);
    invalidate("plans");
  });
  const rows =
    plans.data?.items.filter((p) =>
      p.name.toLowerCase().includes(search.toLowerCase()),
    ) || [];
  return (
    <>
      <PageTitle
        title="套餐管理"
        action={
          <Button variant="contained" onClick={() => setForm("new")}>
            创建套餐
          </Button>
        }
      />
      <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 1.5 }}>
        <TextField
          label="搜索套餐"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <Typography variant="body2" color="text.secondary">
          {rows.length} 个套餐
        </Typography>
      </Stack>
      <Load loading={plans.isLoading} error={plans.error}>
        {!rows.length ? (
          <Empty title="暂无套餐" />
        ) : (
          <TableFrame>
            <TableHead>
              <TableRow>
                <TableCell>套餐</TableCell>
                <TableCell>可用出口节点</TableCell>
                <TableCell>带宽</TableCell>
                <TableCell>流量</TableCell>
                <TableCell>端口总数</TableCell>
                <TableCell>网站数</TableCell>
                <TableCell>已分配空间</TableCell>
                <TableCell>操作</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.map((p) => (
                <TableRow key={p.id} hover>
                  <TableCell>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Typography fontWeight={600} variant="body2">
                        {p.name}
                      </Typography>
                      {p.default && (
                        <Chip size="small" color="primary" label="默认" />
                      )}
                    </Stack>
                  </TableCell>
                  <TableCell sx={{ maxWidth: 300 }}>
                    {p.all_edges
                      ? "全部出口节点"
                      : p.edge_ids.length
                        ? p.edge_ids
                            .map(
                              (id) =>
                                edges.data?.items.find((e) => e.id === id)
                                  ?.name || id,
                            )
                            .join("、")
                        : "无"}
                  </TableCell>
                  <TableCell>
                    {fmtRate(p.bandwidth_bps)}
                    <Typography
                      variant="caption"
                      display="block"
                      color="text.secondary"
                    >
                      {p.burst_enabled
                        ? `突发 ${fmtRate(p.burst_bps)} · ${p.burst_seconds} 秒`
                        : "不允许突发"}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    {p.traffic_metered
                      ? `${fmtBytes(p.traffic_bytes)} · ${fmtPeriod(p.period_seconds)}`
                      : "不按流量计费"}
                    {p.traffic_metered && (
                      <Typography
                        variant="caption"
                        display="block"
                        color="text.secondary"
                      >
                        {p.overage_action === "throttle"
                          ? `超额限速 ${fmtRate(p.overage_bps)}`
                          : "超额拒绝连接"}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>{fmtLimit(p.max_ports)}</TableCell>
                  <TableCell>{fmtLimit(p.max_sites)}</TableCell>
                  <TableCell>{p.members}</TableCell>
                  <TableCell>
                    <Stack direction="row">
                      <Button onClick={() => setForm(p)}>编辑</Button>
                      <Button
                        color="error"
                        disabled={p.default || p.members > 0}
                        onClick={() => {
                          remove.reset();
                          setDeleting(p);
                        }}
                      >
                        删除
                      </Button>
                    </Stack>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </TableFrame>
        )}
      </Load>
      {form && (
        <PlanForm
          initial={form === "new" ? undefined : form}
          onClose={() => setForm(undefined)}
        />
      )}
      {deleting && (
        <Confirm
          title={`删除套餐 ${deleting.name}`}
          onClose={() => setDeleting(undefined)}
          onConfirm={() =>
            remove.mutate({ path: `/plans/${deleting.id}`, method: "DELETE" })
          }
          busy={remove.isPending}
          error={remove.error}
        >
          删除后无法恢复。
        </Confirm>
      )}
    </>
  );
}
