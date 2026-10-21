import { Alert, Paper, Typography } from "@mui/material";
import { fmtDate, fmtLimit } from "../format";
import { DetailField } from "../ui";
import type { Quota } from "../types";

const fields = [
  ["devices", "max_devices", "设备"],
  ["rules", "max_rules", "规则与站点"],
  ["ports", "max_ports", "公网 TCP/UDP 端口"],
  ["domains", "max_domains", "域名"],
] as const;

export default function ResourceQuotaUsage({ quota }: { quota: Quota }) {
  const reached = fields.some(([used, limit]) => {
    const value = quota[limit];
    return (
      quota.resources &&
      value !== undefined &&
      value >= 0 &&
      quota.resources[used] >= value
    );
  });
  return (
    <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
      <Typography variant="h6" gutterBottom>
        配置资源
      </Typography>
      <div className="detail-grid">
        {fields.map(([used, limit, label]) => (
          <DetailField key={used} label={`${label}占用 / 上限`}>
            {quota.resources?.[used] ?? "未统计"} /{" "}
            {quota[limit] === undefined ? "未上报" : fmtLimit(quota[limit]!)}
          </DetailField>
        ))}
      </div>
      {reached && (
        <Alert severity="warning" sx={{ mt: 2 }}>
          部分资源已达配额上限。
        </Alert>
      )}
      <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
        统计时间：{fmtDate(quota.resources?.observed_at)}
      </Typography>
    </Paper>
  );
}
