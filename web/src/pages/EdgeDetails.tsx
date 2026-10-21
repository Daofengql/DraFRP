import {
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Paper,
  Stack,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import { fmtBytes, fmtDate, fmtRate, observedOnline } from "../format";
import { DetailField, Empty, Status, TableFrame } from "../ui";
import type { Edge } from "../types";

export default function EdgeDetails({
  edge,
  onClose,
}: {
  edge: Edge;
  onClose: () => void;
}) {
  const runtime = edge.runtime;
  const fresh = !!runtime && observedOnline(runtime.reported_at);
  const authorized =
    !!runtime && Date.parse(runtime.snapshot_expires_at) > Date.now();
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle>{edge.name} · 运行观测</DialogTitle>
      <DialogContent>
        <Stack spacing={3}>
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Box className="detail-grid">
              <DetailField label="节点 ID">
                <Typography className="mono">{edge.id}</Typography>
              </DetailField>
              <DetailField label="云控最后心跳">
                {fmtDate(edge.last_seen)}
              </DetailField>
              <DetailField label="配置应用修订">
                {edge.applied_revision || "未确认"}
              </DetailField>
              <DetailField label="节点容量配置">
                {fmtRate(edge.capacity_bps)}
              </DetailField>
            </Box>
          </Paper>
          {!runtime ? (
            <Empty title="暂无出口节点运行数据" />
          ) : (
            <>
              {(!fresh || !authorized) && (
                <Alert severity="warning">
                  {!fresh && "运行数据已过期。"}
                  {!authorized && "配置授权已到期。"}
                  显示最近一次记录。
                </Alert>
              )}
              <Typography variant="body2" color="text.secondary">
                统计范围：全部空间
              </Typography>
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Box className="detail-grid">
                  <DetailField label="采样时间">
                    {fmtDate(runtime.reported_at)}
                  </DetailField>
                  <DetailField label="配置授权到期">
                    {fmtDate(runtime.snapshot_expires_at)}
                  </DetailField>
                  <DetailField label="活动承载总数">
                    {runtime.active_carriers}
                  </DetailField>
                  <DetailField label="QUIC / TLS 活动承载">
                    {runtime.quic_carriers} / {runtime.tls_carriers}
                  </DetailField>
                  <DetailField label="活动业务流">
                    {runtime.active_flows}
                  </DetailField>
                  <DetailField label="UDP 会话映射">
                    {runtime.udp_mappings}
                  </DetailField>
                  <DetailField label="容量计量">
                    {runtime.capacity_enforcement === "wire"
                      ? "接口发送速率"
                      : runtime.capacity_enforcement === "wire_failed"
                        ? "接口限速失败"
                        : runtime.capacity_enforcement === "payload"
                          ? "业务载荷"
                          : "未上报"}
                  </DetailField>
                  <DetailField label="GeoIP 数据库状态">
                    {runtime.geoip_state === "ready"
                      ? "已加载"
                      : runtime.geoip_state === "error"
                        ? "加载失败"
                        : runtime.geoip_state === "unconfigured"
                          ? "未配置"
                          : "未上报"}
                  </DetailField>
                  <DetailField label="GeoIP 数据库版本">
                    {runtime.geoip_version || "未上报"}
                  </DetailField>
                </Box>
              </Paper>
              {runtime.capacity_error && (
                <Alert severity="error">
                  节点容量执行错误：{runtime.capacity_error}
                </Alert>
              )}
              {runtime.physical_interface && (
                <Paper variant="outlined" sx={{ p: 2 }}>
                  <Typography variant="h6" gutterBottom>
                    物理接口观测
                  </Typography>
                  <Box className="detail-grid">
                    <DetailField label="接口">
                      {runtime.physical_interface}
                    </DetailField>
                    <DetailField label="线速配置">
                      {fmtRate(runtime.wire_rate_bps)}
                    </DetailField>
                    <DetailField label="接口累计 RX">
                      {fmtBytes(runtime.physical_rx_bytes)}
                    </DetailField>
                    <DetailField label="接口累计 TX">
                      {fmtBytes(runtime.physical_tx_bytes)}
                    </DetailField>
                    <DetailField label="计数采样时间">
                      {fmtDate(runtime.physical_observed_at)}
                    </DetailField>
                  </Box>
                  <Typography
                    color="text.secondary"
                    variant="body2"
                    sx={{ mt: 2 }}
                  >
                    接口生命周期累计流量，含协议开销及重传。限速方向：发送。
                  </Typography>
                </Paper>
              )}
              {runtime.geoip_error && (
                <Alert severity="error">
                  GeoIP 加载失败：{runtime.geoip_error}
                  。地区匹配规则停止转发。
                </Alert>
              )}
              <Typography variant="h6">客户端 承载端点</Typography>
              {!runtime.endpoints?.length ? (
                <Empty title="暂无端点数据" />
              ) : (
                <TableFrame>
                  <TableHead>
                    <TableRow>
                      <TableCell>传输</TableCell>
                      <TableCell>配置入口</TableCell>
                      <TableCell>采样时监听状态</TableCell>
                      <TableCell>监听错误</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {runtime.endpoints.map((ep) => (
                      <TableRow key={`${ep.transport}/${ep.address}`}>
                        <TableCell>{ep.transport.toUpperCase()}</TableCell>
                        <TableCell className="mono">{ep.address}</TableCell>
                        <TableCell>
                          <Status
                            value={ep.listening ? "listening" : "not_listening"}
                          />
                          {!fresh && (
                            <Typography variant="caption" display="block">
                              观测已过期
                            </Typography>
                          )}
                        </TableCell>
                        <TableCell>{ep.error || "无上报错误"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </TableFrame>
              )}
            </>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>关闭</Button>
      </DialogActions>
    </Dialog>
  );
}
