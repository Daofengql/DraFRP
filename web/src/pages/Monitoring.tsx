import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
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
import { fmtBytes, fmtDate } from "../format";
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
import type { Audit, Overview, Rule, System } from "../types";
import { PlanUsage, useAccount } from "./Account";

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
  const account = useAccount(!platform);
  const q = useQuery<Overview>({
    queryKey: ["overview", user.id, user.tenant_id, platform],
    queryFn: ({ signal }) =>
      request(platform ? "/overview?scope=platform" : "/overview", { signal }),
  });
  const rules = useResource<Rule>("/rules", "rules", !platform);
  const items = rules.data?.items || [],
    sites = items.filter(
      (r) => ["http", "https"].includes(r.protocol) && !r.deleting,
    );
  const issues = items.filter(
    (r) =>
      r.enabled &&
      !r.deleting &&
      (r.plan_restricted || r.last_error || r.status !== "ready"),
  );
  return (
    <>
      <PageTitle
        title={platform ? "平台概览" : "仪表盘"}
        action={
          <Stack direction="row" spacing={1}>
            <Button
              onClick={() => {
                void q.refetch();
                if (!platform) {
                  void rules.refetch();
                  void account.refetch();
                }
              }}
            >
              刷新
            </Button>
            {!platform && (
              <>
                <Button component={Link} to="/sites?create=1">
                  添加网站
                </Button>
                <Button
                  variant="contained"
                  component={Link}
                  to="/rules?create=1"
                >
                  添加隧道
                </Button>
              </>
            )}
          </Stack>
        }
      />
      <Load loading={q.isPending} error={q.error}>
        {q.data && (
          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit,minmax(145px,1fr))",
              gap: 1.5,
              mb: 2,
            }}
          >
            {[
              ["在线客户端", `${q.data.online_devices} / ${q.data.devices}`],
              ["已应用服务", `${q.data.ready_rules} / ${q.data.rules}`],
              ["出口节点", q.data.edges],
              ["累计上传", fmtBytes(q.data.usage_upload_bytes)],
              ["累计下载", fmtBytes(q.data.usage_download_bytes)],
            ].map(([label, value]) => (
              <Paper key={label} variant="outlined" sx={{ p: 1.5 }}>
                <Typography variant="body2" color="text.secondary">
                  {label}
                </Typography>
                <Typography variant="h5" fontWeight={600} sx={{ mt: 0.5 }}>
                  {value}
                </Typography>
              </Paper>
            ))}
          </Box>
        )}
      </Load>
      {!platform && (
        <Box sx={{ mb: 2 }}>
          <Load loading={account.isPending} error={account.error}>
            {account.data && <PlanUsage account={account.data} compact />}
          </Load>
        </Box>
      )}
      {!platform && (
        <>
          <Stack
            direction="row"
            alignItems="center"
            justifyContent="space-between"
            sx={{ mb: 1 }}
          >
            <Typography fontWeight={600}>
              待处理服务 · {issues.length}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              隧道{" "}
              {
                items.filter(
                  (r) => !["http", "https"].includes(r.protocol) && !r.deleting,
                ).length
              }{" "}
              · 网站 {sites.length}
            </Typography>
          </Stack>
          <Load loading={rules.isLoading} error={rules.error}>
            {!issues.length ? (
              <Empty title="暂无待处理服务" />
            ) : (
              <TableFrame>
                <TableHead>
                  <TableRow>
                    <TableCell>服务</TableCell>
                    <TableCell>协议</TableCell>
                    <TableCell>状态</TableCell>
                    <TableCell>原因</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {issues.slice(0, 8).map((r) => (
                    <TableRow key={r.id}>
                      <TableCell>
                        <Button
                          component={Link}
                          to={`/${["http", "https"].includes(r.protocol) ? "sites" : "rules"}/${r.id}`}
                        >
                          {r.name}
                        </Button>
                      </TableCell>
                      <TableCell>{r.protocol.toUpperCase()}</TableCell>
                      <TableCell>
                        <Status
                          value={
                            r.plan_restricted ? "plan_restricted" : r.status
                          }
                        />
                      </TableCell>
                      <TableCell>
                        {r.plan_restricted
                          ? "套餐未包含当前出口节点"
                          : r.last_error || "等待出口节点应用"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </TableFrame>
            )}
          </Load>
        </>
      )}
      {!platform && items.length > 0 && (
        <>
          <Typography fontWeight={600} sx={{ mt: 2, mb: 1 }}>
            最近服务
          </Typography>
          <TableFrame>
            <TableHead>
              <TableRow>
                <TableCell>服务</TableCell>
                <TableCell>目标</TableCell>
                <TableCell>状态</TableCell>
                <TableCell>操作</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {items.slice(0, 5).map((r) => (
                <TableRow key={r.id}>
                  <TableCell>
                    {r.name}{" "}
                    <Typography
                      component="span"
                      variant="caption"
                      color="text.secondary"
                    >
                      {r.protocol.toUpperCase()}
                    </Typography>
                  </TableCell>
                  <TableCell className="mono">{r.target}</TableCell>
                  <TableCell>
                    <Status
                      value={
                        r.deleting
                          ? "deleting"
                          : r.plan_restricted
                            ? "plan_restricted"
                            : !r.enabled
                              ? "disabled"
                              : r.status
                      }
                    />
                  </TableCell>
                  <TableCell>
                    <Button
                      component={Link}
                      to={`/${["http", "https"].includes(r.protocol) ? "sites" : "rules"}/${r.id}`}
                    >
                      详情
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </TableFrame>
        </>
      )}
      {platform && (
        <Box sx={{ mt: 2 }}>
          <SystemPanel />
        </Box>
      )}
    </>
  );
}

export function AuditPage() {
  const q = useResource<Audit>("/audit", "audit");
  return (
    <>
      <PageTitle title="审计与系统" detail="操作记录与系统状态" />
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
