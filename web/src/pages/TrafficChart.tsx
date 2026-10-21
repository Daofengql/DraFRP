import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Paper,
  Stack,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
  useTheme,
} from "@mui/material";
import { fmtBytes, fmtDate } from "../format";
import { trafficLine, trafficRate, trafficStats } from "../traffic";
import type { TrafficHistory } from "../types";

export default function TrafficChart({
  history,
  live,
  label,
}: {
  history: TrafficHistory;
  live: boolean;
  label: string;
}) {
  const [metric, setMetric] = useState<"bandwidth" | "bytes">("bandwidth");
  const [selected, setSelected] = useState(history.points.at(-1)?.start || "");
  const [pinned, setPinned] = useState(false);
  useEffect(() => {
    if (!pinned) return;
    const release = (e: KeyboardEvent) => {
      if (e.key === "Escape") setPinned(false);
    };
    window.addEventListener("keydown", release);
    return () => window.removeEventListener("keydown", release);
  }, [pinned]);
  const theme = useTheme();
  const color = theme.palette.primary.main;
  const { points } = history;
  const stats = trafficStats(history);
  const format =
    metric === "bytes" ? (n: number) => fmtBytes(Math.round(n)) : trafficRate;
  const value = (p: (typeof points)[number]) =>
    metric === "bytes"
      ? p.upload_bytes + p.download_bytes
      : p.upload_bps + p.download_bps;
  const max = Math.max(1, ...points.map(value));
  const width = 900,
    height = 260,
    left = 96,
    right = 18,
    top = 18,
    bottom = 38;
  const plotWidth = width - left - right,
    plotHeight = height - top - bottom;
  const x = (i: number) => left + ((i + 0.5) / points.length) * plotWidth;
  const y = (n: number) => top + plotHeight - (n / max) * plotHeight;
  const xy = (n: number, i: number) => `${x(i)},${y(n)}`;
  const index = Math.max(
    0,
    points.findIndex((p) => p.start === selected),
  );
  const current = points[index];
  const selectPoint = (i: number) => setSelected(points[i]?.start || "");
  const pointIndex = (clientX: number, rect: DOMRect) =>
    Math.max(
      0,
      Math.min(
        points.length - 1,
        Math.floor(
          ((((clientX - rect.left) / rect.width) * width - left) / plotWidth) *
            points.length,
        ),
      ),
    );
  const start = Date.parse(history.start),
    end = Date.parse(history.end);
  const timeLabel = (i: number) =>
    new Date(start + (i / 4) * (end - start)).toLocaleString("zh-CN", {
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
      <Stack
        direction={{ xs: "column", sm: "row" }}
        justifyContent="space-between"
        spacing={1.5}
      >
        <Box>
          <Typography fontWeight={600}>
            {metric === "bytes" ? "流量趋势" : "平均带宽趋势"}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            每{" "}
            {history.interval_seconds >= 86400
              ? `${history.interval_seconds / 86400} 天`
              : history.interval_seconds >= 3600
                ? `${history.interval_seconds / 3600} 小时`
                : `${history.interval_seconds / 60} 分钟`}
            一个统计点{live ? " · 每分钟刷新" : ""}
          </Typography>
        </Box>
        <Stack
          direction="row"
          alignItems="center"
          spacing={1}
          useFlexGap
          flexWrap="wrap"
        >
          <Button onClick={() => setPinned(!pinned)} aria-pressed={pinned}>
            {pinned ? "取消固定" : "固定详情"}
          </Button>
          <ToggleButtonGroup
            size="small"
            exclusive
            value={metric}
            onChange={(_, v) => v && setMetric(v)}
            aria-label="图表指标"
          >
            <ToggleButton value="bandwidth">带宽</ToggleButton>
            <ToggleButton value="bytes">流量</ToggleButton>
          </ToggleButtonGroup>
        </Stack>
      </Stack>
      <Typography variant="body2" sx={{ color, mt: 1 }}>
        ● {label} · 上传与下载合计
      </Typography>
      {!stats.samples ? (
        <Alert severity="info" sx={{ mt: 2 }}>
          此时间范围暂无上报数据
        </Alert>
      ) : null}
      <Box sx={{ overflowX: "auto", mt: 1 }}>
        <Box sx={{ minWidth: 560, position: "relative" }}>
          <svg
            viewBox={`0 0 ${width} ${height}`}
            style={{ display: "block", width: "100%", cursor: "crosshair" }}
            role="img"
            tabIndex={0}
            aria-label={`${label}${metric === "bytes" ? "流量" : "平均带宽"}折线图，悬停吸附，点击或方向键固定详情，Esc 取消固定`}
            onPointerMove={(e) => {
              if (!pinned)
                selectPoint(
                  pointIndex(
                    e.clientX,
                    e.currentTarget.getBoundingClientRect(),
                  ),
                );
            }}
            onClick={(e) => {
              const next = pointIndex(
                e.clientX,
                e.currentTarget.getBoundingClientRect(),
              );
              selectPoint(next);
              setPinned(!(pinned && next === index));
            }}
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                setPinned(false);
                return;
              }
              if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key))
                return;
              e.preventDefault();
              setPinned(true);
              selectPoint(
                e.key === "Home"
                  ? 0
                  : e.key === "End"
                    ? points.length - 1
                    : Math.max(
                        0,
                        Math.min(
                          points.length - 1,
                          index + (e.key === "ArrowLeft" ? -1 : 1),
                        ),
                      ),
              );
            }}
          >
            <title>
              {metric === "bytes"
                ? "各时间段上传和下载流量"
                : "各时间段上传和下载平均带宽"}
            </title>
            {[0, 1, 2, 3, 4].map((tick) => (
              <g key={tick}>
                <line
                  x1={left}
                  x2={width - right}
                  y1={y((max * tick) / 4)}
                  y2={y((max * tick) / 4)}
                  stroke="currentColor"
                  opacity=".12"
                  strokeDasharray={tick ? "4 4" : undefined}
                />
                <text
                  x={left - 10}
                  y={y((max * tick) / 4) + 4}
                  textAnchor="end"
                  fontSize="11"
                  fill="currentColor"
                >
                  {format((max * tick) / 4)}
                </text>
                <text
                  x={left + (tick / 4) * plotWidth}
                  y={height - 12}
                  textAnchor={
                    tick === 0 ? "start" : tick === 4 ? "end" : "middle"
                  }
                  fontSize="11"
                  fill="currentColor"
                >
                  {timeLabel(tick)}
                </text>
              </g>
            ))}
            <path
              d={trafficLine(points, value, xy)}
              fill="none"
              stroke={color}
              strokeWidth="2.5"
              strokeLinejoin="round"
            />
            {points.map((p, i) =>
              p.samples ? (
                <g key={p.start}>
                  <circle
                    cx={x(i)}
                    cy={y(value(p))}
                    r={points.length > 400 ? 1.5 : 2}
                    fill={color}
                  />
                </g>
              ) : null,
            )}
            {current && (
              <>
                <line
                  x1={x(index)}
                  x2={x(index)}
                  y1={top}
                  y2={top + plotHeight}
                  stroke="currentColor"
                  opacity=".35"
                  strokeDasharray="3 3"
                />
                {!!current.samples && (
                  <circle
                    cx={x(index)}
                    cy={y(value(current))}
                    r="5"
                    fill={color}
                    stroke={theme.palette.background.paper}
                    strokeWidth="2"
                  />
                )}
              </>
            )}
          </svg>
          {current && (
            <Paper
              role="tooltip"
              variant="outlined"
              sx={{
                position: "absolute",
                pointerEvents: "none",
                top: 8,
                left: `clamp(8px, calc(${(x(index) / width) * 100}% - 110px), calc(100% - 236px))`,
                width: 220,
                p: 1.25,
                boxShadow: 2,
              }}
            >
              <Typography variant="caption" color="text.secondary">
                {fmtDate(current.start)}
              </Typography>
              <Typography variant="body2" fontWeight={600}>
                {label} ·{" "}
                {current.samples ? format(value(current)) : "未收到报告"}
              </Typography>
              {!!current.samples && (
                <Typography variant="caption" component="div">
                  上传{" "}
                  {format(
                    metric === "bytes"
                      ? current.upload_bytes
                      : current.upload_bps,
                  )}{" "}
                  · 下载{" "}
                  {format(
                    metric === "bytes"
                      ? current.download_bytes
                      : current.download_bps,
                  )}
                </Typography>
              )}
              <Typography variant="caption" color="text.secondary">
                {pinned
                  ? "已固定 · 点击同一点或按 Esc 取消"
                  : "点击或触摸可固定详情"}
              </Typography>
            </Paper>
          )}
        </Box>
      </Box>
      <Box
        sx={{
          p: 1.25,
          bgcolor: "action.hover",
          borderRadius: 1,
          minHeight: 48,
        }}
        aria-live="polite"
      >
        <Typography variant="caption" color="text.secondary">
          {current
            ? `${fmtDate(current.start)} ～ ${fmtDate(current.end)}`
            : "暂无数据"}
        </Typography>
        <Typography variant="body2">
          {current?.samples
            ? `上传 ${format(metric === "bytes" ? current.upload_bytes : current.upload_bps)} · 下载 ${format(metric === "bytes" ? current.download_bytes : current.download_bps)} · 流量合计 ${fmtBytes(current.upload_bytes + current.download_bytes)}`
            : "此时间段未收到报告"}
        </Typography>
      </Box>
      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit,minmax(135px,1fr))",
          gap: 2,
          my: 2,
        }}
      >
        {[
          ["范围上传", fmtBytes(history.upload_bytes)],
          ["范围下载", fmtBytes(history.download_bytes)],
          [
            "记录平均带宽",
            stats.samples ? trafficRate(stats.average) : "未观测",
          ],
          [
            "最高区间平均带宽",
            stats.samples ? trafficRate(stats.peak) : "未观测",
          ],
        ].map(([label, value]) => (
          <Box key={label}>
            <Typography variant="body2" color="text.secondary">
              {label}
            </Typography>
            <Typography variant="h6">{value}</Typography>
          </Box>
        ))}
      </Box>
      {history.receipt_bytes > 0 && (
        <Alert severity="info" sx={{ mb: 1 }}>
          {fmtBytes(history.receipt_bytes)}{" "}
          流量按云控收到报告的时间汇总；对应节点未提供原始分钟记录。
        </Alert>
      )}
      <Typography variant="caption" color="text.secondary">
        记录起点 {fmtDate(history.available_from)}。带宽按流量 × 8 ÷
        区间秒数计算，当前区间按已过时间计算。未上报区间留空；真实零流量显示为
        0。悬停吸附数据点，点击或触摸固定；方向键可逐点查看，Esc 取消固定。
      </Typography>
    </Paper>
  );
}
