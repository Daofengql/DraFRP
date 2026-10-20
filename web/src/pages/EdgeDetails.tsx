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
            <Empty
              title="尚无边缘运行观测"
              detail="端点配置不代表已经监听；等待边缘上报实际监听、承载和活动流数量。"
            />
          ) : (
            <>
              <Alert severity={fresh && authorized ? "info" : "warning"}>
                {fresh
                  ? "以下为边缘最近一次采样。"
                  : "这份运行观测已过期，仅供排查上一次状态。"}{" "}
                {authorized
                  ? "采样对应的配置快照尚在有效期内。"
                  : "采样对应的配置快照已过期，不能据此判定业务可用。"}{" "}
                节点总量包含所有空间；不会替代目标健康检测。
              </Alert>
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
                  <DetailField label="节点容量执行口径">
                    {runtime.capacity_enforcement === "wire"
                      ? "传输线速（wire）"
                      : runtime.capacity_enforcement === "wire_failed"
                        ? "线速限制失效（wire_failed）"
                        : runtime.capacity_enforcement === "payload"
                          ? "业务载荷（payload）"
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
                  。请由边缘管理员检查接口、权限与整形器配置。
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
                    接口累计计数包含控制流量、封装与重传；按接口生命周期累积，不等于账号业务用量或瞬时速率。wire
                    整形限制接口发出方向；接收方向只展示观测。
                  </Typography>
                </Paper>
              )}
              {runtime.geoip_error && (
                <Alert severity="error">
                  GeoIP 加载失败：{runtime.geoip_error}
                  。带地区条件的规则会拒绝承载。
                </Alert>
              )}
              {runtime.capacity_enforcement === "payload" && (
                <Alert severity="info">
                  节点容量当前按业务载荷执行。TLS / QUIC
                  协议、加密与网络报文开销不计入此数值，不能当作物理接口线速上限。
                </Alert>
              )}
              <Typography variant="h6">Agent 承载端点的实际监听</Typography>
              {!runtime.endpoints?.length ? (
                <Empty
                  title="采样时没有端点"
                  detail="这可能是边缘尚未取得首个有效配置快照。"
                />
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
