import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Chip,
  LinearProgress,
  Paper,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { request } from "../api";
import { fmtBytes, fmtDate, fmtPeriod, fmtRate } from "../format";
import {
  DetailField,
  Load,
  MutationError,
  PageTitle,
  invalidate,
  useResource,
  useSessionContext,
  useWriter,
} from "../ui";
import type { Account, Edge } from "../types";

export function useAccount() {
  const { user } = useSessionContext();
  return useQuery<Account>({
    queryKey: ["account", user.id, user.tenant_id],
    queryFn: ({ signal }) => request("/account", { signal }),
  });
}

export function PlanUsage({
  account,
  compact = false,
}: {
  account: Account;
  compact?: boolean;
}) {
  const q = account.quota;
  const metered = q.period_bytes >= 0,
    exhausted = metered && q.used_bytes >= q.period_bytes,
    currentRate = exhausted
      ? q.overage_action === "throttle"
        ? q.overage_bps
        : 0
      : q.base_bps;
  return (
    <Paper variant="outlined" sx={{ p: 2 }}>
      <Stack
        direction="row"
        alignItems="center"
        justifyContent="space-between"
        useFlexGap
        flexWrap="wrap"
        gap={0.5}
        sx={{ mb: 1.5 }}
      >
        <Stack
          direction="row"
          useFlexGap
          flexWrap="wrap"
          gap={1}
          alignItems="center"
          sx={{ minWidth: 0, maxWidth: "100%" }}
        >
          <Typography
            fontWeight={600}
            sx={{ overflowWrap: "anywhere", minWidth: 0 }}
          >
            {account.plan?.name || "未分配套餐"}
          </Typography>
          <Chip
            size="small"
            color={exhausted ? "warning" : "default"}
            label={fmtRate(currentRate)}
          />
        </Stack>
        {compact && (
          <Button component={Link} to="/account">
            套餐详情
          </Button>
        )}
      </Stack>
      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: "repeat(2,minmax(0,1fr))",
          gap: 2,
        }}
      >
        {[
          ["端口", q.resources?.ports, q.max_ports],
          ["网站", q.resources?.sites, q.max_sites],
        ].map(([label, used, limit]) => {
          const max = Number(limit),
            count = typeof used === "number" ? used : 0;
          return (
            <Box key={String(label)}>
              <Stack direction="row" justifyContent="space-between">
                <Typography variant="body2">{label}</Typography>
                <Typography variant="body2">
                  {used ?? "—"} / {max < 0 ? "不限" : max}
                </Typography>
              </Stack>
              <LinearProgress
                color={max >= 0 && count >= max ? "warning" : "primary"}
                variant="determinate"
                value={
                  max > 0
                    ? Math.min(100, (count / max) * 100)
                    : count > 0
                      ? 100
                      : 0
                }
                sx={{ mt: 0.75, height: 4, borderRadius: 1 }}
              />
            </Box>
          );
        })}
      </Box>
      <Stack spacing={0.75} sx={{ mt: 1.5 }}>
        <Typography variant="body2" color="text.secondary">
          {q.peak_bps > q.base_bps && q.base_bps > 0
            ? `突发 ${fmtRate(q.peak_bps)}${account.plan?.burst_seconds ? ` · ${account.plan.burst_seconds} 秒` : ""}`
            : "不允许突发"}
        </Typography>
        {metered ? (
          <>
            <Stack
              direction="row"
              justifyContent="space-between"
              useFlexGap
              flexWrap="wrap"
              gap={0.5}
            >
              <Typography variant="body2">
                周期流量 · {fmtPeriod(q.period_seconds)}
              </Typography>
              <Typography variant="body2">
                {fmtBytes(q.used_bytes)} / {fmtBytes(q.period_bytes)}
              </Typography>
            </Stack>
            <LinearProgress
              variant="determinate"
              color={exhausted ? "warning" : "primary"}
              value={
                q.period_bytes > 0
                  ? Math.min(100, (q.used_bytes / q.period_bytes) * 100)
                  : 100
              }
              sx={{ height: 4, borderRadius: 1 }}
            />
            <Typography
              variant="body2"
              color={exhausted ? "warning.main" : "text.secondary"}
            >
              {exhausted ? "已达流量上限 · " : "超额"}
              {q.overage_action === "throttle"
                ? `限速 ${fmtRate(q.overage_bps)}`
                : "拒绝连接"}
            </Typography>
            {q.period_ends_at && !q.period_ends_at.startsWith("0001-") && (
              <Typography variant="caption" color="text.secondary">
                下次重置 {fmtDate(q.period_ends_at)}
              </Typography>
            )}
          </>
        ) : (
          <Typography variant="body2" color="text.secondary">
            不按流量计费
          </Typography>
        )}
      </Stack>
    </Paper>
  );
}

function PasswordForm() {
  const { user } = useSessionContext();
  const [current, setCurrent] = useState(""),
    [password, setPassword] = useState(""),
    [confirm, setConfirm] = useState("");
  const [notice, setNotice] = useState(""),
    [validation, setValidation] = useState("");
  const m = useWriter(() => {
    setCurrent("");
    setPassword("");
    setConfirm("");
    setNotice("密码已更新，其他登录会话已退出。");
    m.reset();
    invalidate("account");
  });
  const submit = () => {
    setNotice("");
    const length = new TextEncoder().encode(password).length;
    if (length < 10 || length > 72) {
      setValidation("密码长度须为 10–72 字节");
      return;
    }
    if (password !== confirm) {
      setValidation("两次输入的密码不一致");
      return;
    }
    setValidation("");
    m.mutate({
      path: "/account/password",
      method: "PUT",
      data: { current_password: current, password },
    });
  };
  return (
    <Paper variant="outlined" sx={{ p: 2 }}>
      <Typography fontWeight={600} sx={{ mb: 1.5 }}>
        修改密码
      </Typography>
      <Box
        component="form"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <input
          type="text"
          name="username"
          autoComplete="username"
          value={user.username}
          readOnly
          tabIndex={-1}
          aria-hidden="true"
          style={{ display: "none" }}
        />
        <Stack spacing={1.5} sx={{ maxWidth: 440 }}>
          <TextField
            label="当前密码"
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            required
          />
          <TextField
            label="新密码"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            helperText="10–72 字节"
            required
          />
          <TextField
            label="确认新密码"
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
          />
          {validation && <Alert severity="error">{validation}</Alert>}
          {notice && <Alert severity="success">{notice}</Alert>}
          <MutationError error={m.error} />
          <Box>
            <Button
              type="submit"
              variant="contained"
              disabled={m.isPending || !current || !password || !confirm}
            >
              {m.isPending ? "保存中…" : "更新密码"}
            </Button>
          </Box>
        </Stack>
      </Box>
    </Paper>
  );
}

export default function AccountPage() {
  const q = useAccount(),
    edges = useResource<Edge>("/edges", "edges");
  const available =
    edges.data?.items.filter(
      (e) =>
        q.data?.quota.allowed_edge_ids === null ||
        q.data?.quota.allowed_edge_ids.includes(e.id),
    ) || [];
  return (
    <>
      <PageTitle title="我的账户" />
      <Load loading={q.isPending} error={q.error}>
        {q.data && (
          <Stack spacing={2}>
            <Paper variant="outlined" sx={{ p: 2 }}>
              <Box className="detail-grid">
                <DetailField label="用户名">{q.data.user.username}</DetailField>
                <DetailField label="角色">
                  {q.data.user.role === "admin" ? "平台管理员" : "普通用户"}
                </DetailField>
                <DetailField label="注册时间">
                  {fmtDate(q.data.user.created_at)}
                </DetailField>
                <DetailField label="空间 ID">
                  <span className="mono">{q.data.user.tenant_id}</span>
                </DetailField>
              </Box>
            </Paper>
            <PlanUsage account={q.data} />
            <Paper variant="outlined" sx={{ p: 2 }}>
              <Typography fontWeight={600} sx={{ mb: 1 }}>
                可用出口节点 · {available.length}
              </Typography>
              <Load loading={edges.isLoading} error={edges.error}>
                <Stack direction="row" useFlexGap flexWrap="wrap" gap={1}>
                  {available.length ? (
                    available.map((e) => (
                      <Chip
                        key={e.id}
                        sx={{ maxWidth: "100%" }}
                        variant="outlined"
                        label={`${e.name} · ${e.public_host}`}
                      />
                    ))
                  ) : (
                    <Typography variant="body2" color="text.secondary">
                      无可用出口节点
                    </Typography>
                  )}
                </Stack>
              </Load>
            </Paper>
            <PasswordForm />
          </Stack>
        )}
      </Load>
    </>
  );
}
