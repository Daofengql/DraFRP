import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Stack,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import { request } from "../api";
import { fmtDate } from "../format";
import { Load, TableFrame } from "../ui";

interface Application {
  rule_id: string;
  rule_name: string;
  rule_version: number;
  edge_id: string;
  edge_name: string;
  boot_id: string;
  state: string;
  stale: boolean;
  observed_at?: string;
  ack_boot_id?: string;
  ack?: {
    rule_version: number;
    effective_digest: string;
    state: string;
    error?: string;
    applied_at: string;
    expires_at: string;
    active_flows: number;
    sampled_at: string;
    policies: Array<{
      kind: string;
      template_id?: string;
      version: number;
      digest: string;
    }>;
  };
}
interface Observations {
  protocol: string;
  has_more: boolean;
  next_cursor: string;
  application: Application;
  collection_loss: Record<string, number>;
  retention_days: number;
  items: Array<{
    key: string;
    rule_version: number;
    effective_digest: string;
    kind: string;
    policy: {
      kind: string;
      template_id?: string;
      version: number;
      digest: string;
    };
    entry_id?: string;
    entry_hash?: string;
    used_default: boolean;
    reason: string;
    allowed: number;
    denied: number;
    started_at: string;
    observed_at: string;
    boot_id: string;
    current: boolean;
  }>;
}
interface Applications {
  template_name: string;
  published: { version: number } | null;
  truncated: boolean;
  rule_limit: number;
  observed_at: string;
  items: Array<{
    edge_id: string;
    edge_name: string;
    boot_id: string;
    counts: Record<string, number>;
    rules: Application[];
  }>;
}
const states: Record<string, string> = {
  applied: "已应用",
  pending: "待确认",
  error: "应用失败",
  inactive: "已停用",
  expired: "应用授权已到期",
};
const kinds: Record<string, string> = {
  mandatory_template: "强制父策略",
  rule_template: "规则模板",
  rule_inline: "规则独立策略",
};
const reasons: Record<string, string> = {
  all_policies_allow: "所有适用策略允许",
  no_acl: "无适用策略",
  policy_denied: "策略拒绝",
  capability_missing: "地域能力缺失",
  geoip_unavailable: "地域库不可用",
};
function ApplicationEvidence({ value }: { value: Application }) {
  return (
    <Stack spacing={1}>
      <Alert
        severity={
          value.state === "applied" && !value.stale ? "success" : "warning"
        }
      >
        {states[value.state] || value.state}
        {value.stale ? " · 反馈已过期" : ""}
      </Alert>
      <Typography variant="body2" sx={{ overflowWrap: "anywhere" }}>
        期望规则 v{value.rule_version} · 边缘 {value.edge_name} · 启动标识{" "}
        {value.boot_id || "尚未启动"}
      </Typography>
      {value.ack ? (
        <>
          <Typography variant="body2" sx={{ overflowWrap: "anywhere" }}>
            应用反馈：规则 v{value.ack.rule_version} · 启动 {value.ack_boot_id}{" "}
            · 应用时间 {fmtDate(value.ack.applied_at)} · 授权到期{" "}
            {fmtDate(value.ack.expires_at)}
          </Typography>
          <Typography variant="body2">
            活跃流 {value.ack.active_flows}，采样于{" "}
            {fmtDate(value.ack.sampled_at)}；反馈时间{" "}
            {fmtDate(value.observed_at)}
          </Typography>
          {value.ack.error && <Alert severity="error">{value.ack.error}</Alert>}
        </>
      ) : (
        <Typography variant="body2">暂无边缘应用反馈</Typography>
      )}
    </Stack>
  );
}
function ObservationDialog({
  ruleId,
  title,
  onClose,
}: {
  ruleId: string;
  title: string;
  onClose: () => void;
}) {
  const [cursor, setCursor] = useState("");
  const q = useQuery({
    queryKey: ["acl-observations", ruleId, cursor],
    queryFn: ({ signal }) =>
      request<Observations>(
        `/acl/observations?rule_id=${encodeURIComponent(ruleId)}${cursor ? `&cursor=${cursor}` : ""}`,
        { signal },
      ),
    refetchInterval: 15_000,
  });
  return (
    <Dialog open fullWidth maxWidth="lg" onClose={onClose}>
      <DialogTitle>ACL 访问统计 · {title}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Typography variant="body2" color="text.secondary">
            TCP 按连接、UDP 按报文统计；规则合计与各策略层分别计数。
          </Typography>
          <Load loading={q.isLoading} error={q.error}>
            {q.data && (
              <>
                <ApplicationEvidence value={q.data.application} />
                <Typography variant="body2" color="text.secondary">
                  保留 {q.data.retention_days}{" "}
                  天，按边缘启动、规则版本和策略分组。
                </Typography>
                {Object.entries(q.data.collection_loss).some(
                  ([, n]) => n > 0,
                ) && (
                  <Alert severity="warning">
                    采集容量已满，部分统计缺失。边缘丢弃{" "}
                    {q.data.collection_loss.edge_dropped || 0} 次写入，云控丢弃{" "}
                    {q.data.collection_loss.cloud_dropped || 0} 条记录。
                  </Alert>
                )}
                {!q.data.items.length ? (
                  <Alert severity="info">暂无访问统计</Alert>
                ) : (
                  <TableFrame>
                    <TableHead>
                      <TableRow>
                        <TableCell>配置版本</TableCell>
                        <TableCell>命中层 / 条目</TableCell>
                        <TableCell>允许</TableCell>
                        <TableCell>拒绝</TableCell>
                        <TableCell>观测区间</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {q.data.items.map((item) => (
                        <TableRow key={item.key}>
                          <TableCell
                            sx={{ maxWidth: 240, overflowWrap: "anywhere" }}
                          >
                            {item.current ? "当前配置" : "历史配置"} · 规则 v
                            {item.rule_version}
                            <Typography variant="caption" display="block">
                              启动 {item.boot_id}
                            </Typography>
                            <Typography variant="caption" display="block">
                              摘要 {item.effective_digest.slice(0, 16)}
                            </Typography>
                          </TableCell>
                          <TableCell
                            sx={{ maxWidth: 280, overflowWrap: "anywhere" }}
                          >
                            {item.kind === "rule_total"
                              ? "规则合计"
                              : `${kinds[item.policy.kind] || item.policy.kind} v${item.policy.version}`}
                            <Typography variant="body2">
                              {item.used_default
                                ? "默认动作"
                                : item.entry_id ||
                                  reasons[item.reason] ||
                                  item.reason}
                            </Typography>
                            {item.policy.template_id && (
                              <Typography variant="caption">
                                模板 {item.policy.template_id}
                              </Typography>
                            )}
                          </TableCell>
                          <TableCell>{item.allowed.toLocaleString()}</TableCell>
                          <TableCell>{item.denied.toLocaleString()}</TableCell>
                          <TableCell>
                            {fmtDate(item.started_at)}
                            <br />至 {fmtDate(item.observed_at)}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </TableFrame>
                )}
                <Stack direction="row" spacing={1}>
                  {cursor && (
                    <Button onClick={() => setCursor("")}>返回第一页</Button>
                  )}
                  {q.data.has_more && (
                    <Button onClick={() => setCursor(q.data!.next_cursor)}>
                      下一页
                    </Button>
                  )}
                </Stack>
              </>
            )}
          </Load>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => void q.refetch()} disabled={q.isFetching}>
          刷新反馈
        </Button>
        <Button onClick={onClose}>关闭</Button>
      </DialogActions>
    </Dialog>
  );
}
export default function ACLObservations({
  ruleId,
  title,
}: {
  ruleId: string;
  title: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button onClick={() => setOpen(true)}>访问统计与应用状态</Button>
      {open && (
        <ObservationDialog
          ruleId={ruleId}
          title={title}
          onClose={() => setOpen(false)}
        />
      )}
    </>
  );
}
function ApplicationsDialog({
  templateId,
  onClose,
}: {
  templateId: string;
  onClose: () => void;
}) {
  const q = useQuery({
    queryKey: ["acl-applications", templateId],
    queryFn: ({ signal }) =>
      request<Applications>(
        `/acl/applications?template_id=${encodeURIComponent(templateId)}`,
        { signal },
      ),
    refetchInterval: 15_000,
  });
  return (
    <Dialog open fullWidth maxWidth="lg" onClose={onClose}>
      <DialogTitle>模板应用状态</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Load loading={q.isLoading} error={q.error}>
            {q.data && (
              <>
                <Typography>
                  {q.data.template_name} ·{" "}
                  {q.data.published
                    ? `已发布 v${q.data.published.version}`
                    : "尚未发布"}{" "}
                  · 查询于 {fmtDate(q.data.observed_at)}
                </Typography>
                {q.data.truncated && (
                  <Alert severity="warning">
                    规则超过 {q.data.rule_limit} 条，当前显示前{" "}
                    {q.data.rule_limit} 条。
                  </Alert>
                )}
                {!q.data.items.length && (
                  <Alert severity="info">暂无引用规则</Alert>
                )}
                {q.data.items.map((edge) => (
                  <Box
                    key={edge.edge_id}
                    sx={{
                      border: 1,
                      borderColor: "divider",
                      borderRadius: 1,
                      p: 2,
                    }}
                  >
                    <Typography variant="h6">{edge.edge_name}</Typography>
                    <Typography sx={{ mb: 2 }}>
                      {Object.entries(edge.counts)
                        .map(
                          ([state, count]) =>
                            `${states[state] || state} ${count}`,
                        )
                        .join(" · ")}
                    </Typography>
                    <Stack spacing={3}>
                      {edge.rules.map((rule) => (
                        <Box key={rule.rule_id}>
                          <Typography fontWeight={700} sx={{ mb: 1 }}>
                            {rule.rule_name}
                          </Typography>
                          <ApplicationEvidence value={rule} />
                        </Box>
                      ))}
                    </Stack>
                  </Box>
                ))}
              </>
            )}
          </Load>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => void q.refetch()} disabled={q.isFetching}>
          刷新反馈
        </Button>
        <Button onClick={onClose}>关闭</Button>
      </DialogActions>
    </Dialog>
  );
}
export function ACLApplications({ templateId }: { templateId: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button onClick={() => setOpen(true)}>应用状态</Button>
      {open && (
        <ApplicationsDialog
          templateId={templateId}
          onClose={() => setOpen(false)}
        />
      )}
    </>
  );
}
