import {
  Alert,
  Paper,
  Stack,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import { fmtDate, observedOnline } from "../format";
import { DetailField, TableFrame } from "../ui";
import { carrierQualitySummary, milliseconds } from "../carrierQuality";
import type { CarrierQualityRuntime, Device } from "../types";

const errors: Record<string, string> = {
  authorization_rejected: "客户端授权被拒绝",
  tls_identity_failed: "出口节点证书校验失败",
  path_timeout: "连接超时",
  connection_failed: "连接失败",
  race_not_selected: "本次选用其他路径",
  carrier_closed: "承载已断开",
};
function QualityObservation({ quality }: { quality?: CarrierQualityRuntime }) {
  const summary = carrierQualitySummary(quality);
  if (!quality || !summary)
    return (
      <Typography variant="body2" color="text.secondary">
        暂无 RTT 数据
      </Typography>
    );
  const native = quality.quic;
  return (
    <Stack
      spacing={0.5}
      sx={{ minWidth: { xs: 0, md: 260 }, overflowWrap: "anywhere" }}
    >
      <Typography variant="body2">控制流往返 {summary.latest}</Typography>
      <Typography variant="caption">{summary.range}</Typography>
      <Typography variant="caption">{summary.outcomes}</Typography>
      <Typography variant="caption">
        窗口 {fmtDate(quality.window_started_at)} 至{" "}
        {fmtDate(quality.observed_at)}
      </Typography>
      <Typography variant="caption">
        最近成功 {fmtDate(quality.last_success_at)} · 间隔{" "}
        {quality.interval_ms / 1000} 秒 · 超时 {quality.timeout_ms / 1000} 秒 ·
        窗口 {quality.window_limit} 次
      </Typography>
      {native?.source === "quic_go_rfc9002" && (
        <>
          <Typography variant="caption">
            QUIC ACK RTT：最近 {milliseconds(native.latest_rtt_ms)} / 平滑{" "}
            {milliseconds(native.smoothed_rtt_ms)} / 最小{" "}
            {milliseconds(native.min_rtt_ms)}
          </Typography>
          <Typography variant="caption">
            QUIC 包统计：发送 {native.packets_sent} 包，接收{" "}
            {native.packets_received} 包，当前判丢 {native.packets_lost} 包 /{" "}
            {native.bytes_lost} 字节。
          </Typography>
          <Typography variant="caption">
            连接期（含握手）{fmtDate(native.started_at)} 至{" "}
            {fmtDate(native.observed_at)}。
          </Typography>
        </>
      )}
    </Stack>
  );
}

export default function DeviceTransport({ device }: { device: Device }) {
  const runtime = device.runtime;
  if (!runtime) return <Alert severity="info">暂无传输数据</Alert>;
  const current =
    !device.revoked &&
    runtime.session_id === device.session_id &&
    runtime.generation === device.generation &&
    observedOnline(runtime.reported_at) &&
    observedOnline(runtime.received_at) &&
    Date.parse(runtime.snapshot_expires_at) > Date.now();
  return (
    <Stack spacing={2}>
      <Typography variant="h6">客户端 传输观测</Typography>
      {!current && (
        <Alert severity="warning">传输数据已失效，显示最近一次记录。</Alert>
      )}
      {runtime.truncated && (
        <Alert severity="info">数据已截断，当前显示部分端点和承载。</Alert>
      )}
      <Paper variant="outlined" sx={{ p: 3 }}>
        <div className="detail-grid">
          <DetailField label="客户端 采样时间">
            {fmtDate(runtime.reported_at)}
          </DetailField>
          <DetailField label="云控接收时间">
            {fmtDate(runtime.received_at)}
          </DetailField>
          <DetailField label="本地传输偏好">
            {runtime.preferred_transport}
          </DetailField>
          <DetailField label="采样时活动流">{runtime.active_flows}</DetailField>
          <DetailField label="采样时承载数量">
            {runtime.active_carriers} · QUIC {runtime.quic_carriers} / TLS{" "}
            {runtime.tls_carriers}
          </DetailField>
          <DetailField label="配置授权到期">
            {fmtDate(runtime.snapshot_expires_at)}
          </DetailField>
        </div>
      </Paper>
      <Typography variant="subtitle1">采样时已建立的承载</Typography>
      {!runtime.carriers?.length ? (
        <Typography color="text.secondary">
          采样时没有已建立的出口节点承载。
        </Typography>
      ) : (
        <TableFrame>
          <TableHead>
            <TableRow>
              <TableCell>出口节点 / 端点</TableCell>
              <TableCell>传输</TableCell>
              <TableCell>活动流</TableCell>
              <TableCell>握手耗时</TableCell>
              <TableCell sx={{ display: { xs: "none", md: "table-cell" } }}>
                持续往返 / 探测窗口
              </TableCell>
              <TableCell>建立时间</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {runtime.carriers.map((carrier, i) => (
              <TableRow
                key={`${carrier.edge_id}/${carrier.transport}/${carrier.address}/${i}`}
              >
                <TableCell>
                  <Typography className="mono" variant="body2">
                    {carrier.edge_id}
                  </Typography>
                  {carrier.address}
                  {carrier.remote_address && (
                    <Typography variant="caption" display="block">
                      实际连接：
                      {carrier.remote_address.includes("[")
                        ? "IPv6"
                        : "IPv4"} · {carrier.remote_address}
                    </Typography>
                  )}
                </TableCell>
                <TableCell>{carrier.transport.toUpperCase()}</TableCell>
                <TableCell>{carrier.active_flows}</TableCell>
                <TableCell>{milliseconds(carrier.handshake_ms)}</TableCell>
                <TableCell sx={{ display: { xs: "none", md: "table-cell" } }}>
                  <QualityObservation quality={carrier.quality} />
                </TableCell>
                <TableCell>{fmtDate(carrier.established_at)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </TableFrame>
      )}
      {!!runtime.carriers?.length && (
        <Stack spacing={1} sx={{ display: { xs: "flex", md: "none" } }}>
          {runtime.carriers.map((carrier, i) => (
            <Paper
              key={`${carrier.edge_id}/${carrier.transport}/${carrier.address}/${i}`}
              variant="outlined"
              sx={{ p: 2, overflowWrap: "anywhere" }}
            >
              <Typography variant="subtitle2" gutterBottom>
                {carrier.transport.toUpperCase()} ·{" "}
                {carrier.remote_address || carrier.address}
              </Typography>
              <QualityObservation quality={carrier.quality} />
            </Paper>
          ))}
        </Stack>
      )}
      <Typography variant="subtitle1">端点最近连接尝试</Typography>
      {!runtime.endpoints?.length ? (
        <Typography color="text.secondary">尚无端点尝试记录。</Typography>
      ) : (
        <TableFrame>
          <TableHead>
            <TableRow>
              <TableCell>出口节点 / 端点</TableCell>
              <TableCell>状态 / 连续失败</TableCell>
              <TableCell>最近尝试 / 成功</TableCell>
              <TableCell>成功握手耗时</TableCell>
              <TableCell>可重试时间</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {runtime.endpoints.map((endpoint) => (
              <TableRow
                key={`${endpoint.edge_id}/${endpoint.transport}/${endpoint.address}/${endpoint.server_name}/${endpoint.remote_address || ""}`}
              >
                <TableCell>
                  <Typography className="mono" variant="body2">
                    {endpoint.edge_id}
                  </Typography>
                  {endpoint.transport.toUpperCase()} · {endpoint.address}
                  {endpoint.remote_address && (
                    <Typography variant="caption" display="block">
                      候选地址：{endpoint.remote_address}
                    </Typography>
                  )}
                </TableCell>
                <TableCell>
                  {endpoint.probing
                    ? "连接探测中"
                    : endpoint.error_code
                      ? errors[endpoint.error_code] || endpoint.error_code
                      : "最近连接成功"}
                  <Typography variant="caption" display="block">
                    连续失败 {endpoint.recent_failures}
                  </Typography>
                </TableCell>
                <TableCell>
                  {fmtDate(endpoint.last_attempt)}
                  <Typography variant="caption" display="block">
                    成功：{fmtDate(endpoint.last_success)}
                  </Typography>
                </TableCell>
                <TableCell>
                  {fmtDate(endpoint.last_success) === "未上报"
                    ? "未观测"
                    : milliseconds(endpoint.handshake_ms)}
                </TableCell>
                <TableCell>{fmtDate(endpoint.retry_at)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </TableFrame>
      )}
      <Typography variant="body2" color="text.secondary">
        RTT：承载控制流往返时间，包含排队与处理耗时。
      </Typography>
    </Stack>
  );
}
