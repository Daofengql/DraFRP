import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  Paper,
  Stack,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import { request } from "../api";
import { fmtBytes, fmtDate, fmtLimit, fmtRate } from "../format";
import {
  DetailField,
  Empty,
  Load,
  PageTitle,
  Status,
  TableFrame,
  useResource,
  useSessionContext,
} from "../ui";
import type { Audit, Overview, Quota, Rule, System, Usage } from "../types";
import ResourceQuotaUsage from "./ResourceQuotaUsage";

export function SystemPanel() {
  const q = useQuery<System>({
    queryKey: ["system"],
    queryFn: ({ signal }) => request("/system", { signal }),
  });
  return (
    <Load loading={q.isPending} error={q.error}>
      {q.data && (
        <Paper variant="outlined" sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            系统状态
          </Typography>
          <Box className="detail-grid">
            <DetailField label="MySQL">
              <Status value={q.data.mysql} />
            </DetailField>
            <DetailField label="临时状态后端">
              {q.data.cache?.backend || "未知"}
            </DetailField>
            <DetailField label="缓存命中 / 淘汰">
              {q.data.cache?.hits ?? "未上报"} /{" "}
              {q.data.cache?.evictions ?? "未上报"}
            </DetailField>
            <DetailField label="构建版本">
              {q.data.build_id || "未知"}
            </DetailField>
            <DetailField label="启动时间">
              {fmtDate(q.data.started_at)}
            </DetailField>
          </Box>
        </Paper>
      )}
    </Load>
  );
}

export function OverviewPage({ platform = false }: { platform?: boolean }) {
  const { user } = useSessionContext();
  const q = useQuery<Overview>({
    queryKey: ["overview", user.id, user.tenant_id, platform],
    queryFn: ({ signal }) =>
      request(platform ? "/overview?scope=platform" : "/overview", { signal }),
  });
  const rules = useResource<Rule>("/rules", "rules");
  const issues =
    rules.data?.items.filter(
      (r) => r.enabled && !r.deleting && (r.last_error || r.status !== "ready"),
    ) || [];
  return (
    <>
      <PageTitle
        title={platform ? "平台概览" : "概览"}
        detail={
          platform
            ? "节点登记与平台资源运行概况"
            : "当前空间的设备、规则及已上报业务用量"
        }
        action={<Button onClick={() => q.refetch()}>刷新快照</Button>}
      />
      <Load loading={q.isPending} error={q.error}>
        {q.data && (
          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit,minmax(165px,1fr))",
              gap: 2,
              mb: 3,
            }}
          >
            {[
              [
                "控制会话在线",
                `${q.data.online_devices} / ${q.data.devices}`,
                "近期在线 / 设备总数",
              ],
              [
                "规则应用",
                `${q.data.ready_rules} / ${q.data.rules}`,
                "承载已应用 / 总数",
              ],
              ["边缘", q.data.edges, "已登记节点"],
              [
                "上传",
                fmtBytes(q.data.usage_upload_bytes),
                "公网访问者 → 目标",
              ],
              [
                "下载",
                fmtBytes(q.data.usage_download_bytes),
                "目标 → 公网访问者",
              ],
            ].map(([a, b, c]) => (
              <Paper key={String(a)} variant="outlined" sx={{ p: 2.5 }}>
                <Typography color="text.secondary">{a}</Typography>
                <Typography variant="h5" fontWeight={700} sx={{ my: 1 }}>
                  {b}
                </Typography>
                <Typography variant="caption">{c}</Typography>
              </Paper>
            ))}
          </Box>
        )}
      </Load>
      <Alert severity="info" sx={{ mb: 3 }}>
        设备控制会话、规则应用与目标健康分别判断。目标未检查时不显示为健康；暂无统计时不补画流量曲线。
      </Alert>
      <Typography variant="h6" sx={{ mb: 1 }}>
        当前空间需处理的规则
      </Typography>
      <Load loading={rules.isLoading} error={rules.error}>
        {!issues.length ? (
          <Empty title="暂无待处理规则" detail="目标连通性尚未进行独立探测。" />
        ) : (
          <TableFrame>
            <TableHead>
              <TableRow>
                <TableCell>名称</TableCell>
                <TableCell>状态</TableCell>
                <TableCell>原因</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {issues.map((r) => (
                <TableRow key={r.id}>
                  <TableCell>
                    <Button
                      component={Link}
                      to={`/${["http", "https"].includes(r.protocol) ? "sites" : "rules"}/${r.id}`}
                    >
                      {r.name}
                    </Button>
                  </TableCell>
                  <TableCell>
                    <Status value={r.status} />
                  </TableCell>
                  <TableCell>{r.last_error || "等待边缘应用报告"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </TableFrame>
        )}
      </Load>
      {platform && (
        <Box sx={{ mt: 3 }}>
          <SystemPanel />
        </Box>
      )}
    </>
  );
}

export function UsagePage() {
  const q = useResource<Usage>("/usage", "usage"),
    quotas = useResource<Quota>("/quotas", "quotas");
  const { user } = useSessionContext();
  const quota = quotas.data?.items.find((x) => x.tenant_id === user.tenant_id);
  return (
    <>
      <PageTitle
        title="账号共享用量"
        detail="同空间设备、规则和边缘共享账号预算；业务计量不等于网卡物理流量"
        action={
          <Button
            onClick={() => {
              void q.refetch();
              void quotas.refetch();
            }}
          >
            刷新统计
          </Button>
        }
      />
      <Load loading={quotas.isLoading} error={quotas.error}>
        {quota && (
          <>
            <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
              <Box className="detail-grid">
                <DetailField label="基准 / 峰值速率">
                  {fmtRate(quota.base_bps)} / {fmtRate(quota.peak_bps)}
                </DetailField>
                <DetailField label="突发信用预算">
                  {fmtBytes(quota.burst_bytes)}
                </DetailField>
                <DetailField label="并发 / 每秒新流">
                  {fmtLimit(quota.max_connections)} /{" "}
                  {fmtLimit(quota.new_flows_per_second)}
                </DetailField>
                <DetailField label="周期计量 / 周期上限">
                  {fmtBytes(quota.used_bytes)} /{" "}
                  {quota.period_bytes === 0
                    ? "禁止 (0 B)"
                    : fmtBytes(quota.period_bytes)}
                </DetailField>
                <DetailField label="已预留给边缘">
                  {fmtBytes(quota.reserved_bytes)}
                </DetailField>
                <DetailField label="流量周期">
                  {quota.period_seconds
                    ? `${quota.period_seconds.toLocaleString("zh-CN")} 秒`
                    : "不限期"}{" "}
                  · {quota.period_id || "未记录"}
                </DetailField>
                <DetailField label="周期开始 / 到期">
                  {fmtDate(quota.period_started_at)} /{" "}
                  {quota.period_seconds
                    ? fmtDate(quota.period_ends_at)
                    : "不限期"}
                </DetailField>
                <DetailField label="窗口平均速率 / 当前剩余信用">
                  未上报
                </DetailField>
              </Box>
            </Paper>
            <ResourceQuotaUsage quota={quota} />
          </>
        )}
      </Load>
      <Alert severity="info" sx={{ mb: 2 }}>
        每行是边缘授权的一次累计观测，不将同一授权的多个批次相加。显示服务端观测时间；没有窗口采样时不估算瞬时速率或绘制秒级曲线。
      </Alert>
      <Load loading={q.isLoading} error={q.error}>
        {!q.data?.items.length ? (
          <Empty title="暂无用量统计" detail="等待边缘上报首个业务计量批次。" />
        ) : (
          <TableFrame>
            <TableHead>
              <TableRow>
                <TableCell>边缘 / 授权</TableCell>
                <TableCell>上传：访问者 → 目标</TableCell>
                <TableCell>下载：目标 → 访问者</TableCell>
                <TableCell>批次 / 状态</TableCell>
                <TableCell>观测截至</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {q.data.items.map((u) => (
                <TableRow key={`${u.grant_id}/${u.sequence}`}>
                  <TableCell>
                    <Typography className="mono">{u.edge_id}</Typography>
                    <Typography variant="caption" className="mono">
                      {u.grant_id}
                    </Typography>
                  </TableCell>
                  <TableCell>{fmtBytes(u.upload_bytes)}</TableCell>
                  <TableCell>{fmtBytes(u.download_bytes)}</TableCell>
                  <TableCell>
                    {u.sequence} ·{" "}
                    <Status value={u.closed ? "closed" : "active"} />
                  </TableCell>
                  <TableCell>{fmtDate(u.observed_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </TableFrame>
        )}
      </Load>
    </>
  );
}

export function AuditPage() {
  const q = useResource<Audit>("/audit", "audit");
  return (
    <>
      <PageTitle
        title="审计与系统"
        detail="配置与授权操作记录，以及当前数据库和临时存储状态"
      />
      <SystemPanel />
      <Typography variant="h6" sx={{ mt: 3, mb: 1 }}>
        操作审计
      </Typography>
      <Load loading={q.isLoading} error={q.error}>
        {!q.data?.items.length ? (
          <Empty title="暂无审计记录" />
        ) : (
          <TableFrame>
            <TableHead>
              <TableRow>
                <TableCell>时间</TableCell>
                <TableCell>操作者 / 空间</TableCell>
                <TableCell>动作</TableCell>
                <TableCell>资源</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {q.data.items.map((x) => (
                <TableRow key={x.id}>
                  <TableCell>{fmtDate(x.created_at)}</TableCell>
                  <TableCell>
                    <Typography className="mono">{x.actor}</Typography>
                    <Typography className="mono">{x.tenant_id}</Typography>
                  </TableCell>
                  <TableCell>{x.action}</TableCell>
                  <TableCell className="mono">{x.resource_id}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </TableFrame>
        )}
      </Load>
    </>
  );
}
