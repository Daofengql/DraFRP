import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  FormControl,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Stack,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { request } from "../api";
import { fmtBytes, fmtDate } from "../format";
import {
  localDateTime,
  trafficIntervals,
  trafficRangeError,
  trafficWindow,
  type TrafficInterval,
  type TrafficRange,
} from "../traffic";
import { Empty, Load, PageTitle, TableFrame, useSessionContext } from "../ui";
import type { List, TrafficHistory } from "../types";
import TrafficChart from "./TrafficChart";

type NodeUsage = {
  edge_id: string;
  edge_name: string;
  upload_bytes: number;
  download_bytes: number;
  observed_at: string;
};

export default function UsagePage({
  platform = false,
}: {
  platform?: boolean;
}) {
  const { user } = useSessionContext();
  const scope = platform ? "platform" : "tenant";
  const [range, setRange] = useState<TrafficRange>("24h");
  const [interval, setInterval] = useState<TrafficInterval>("auto");
  const [edgeID, setEdgeID] = useState("");
  const [custom, setCustom] = useState(() => ({
    start: localDateTime(Date.now() - 3_600_000),
    end: localDateTime(Date.now()),
  }));
  const [draft, setDraft] = useState(custom);
  const [formError, setFormError] = useState("");
  const window = trafficWindow(range, custom);
  const rangeError = trafficRangeError(window.start, window.end, interval);
  const summary = useQuery<List<NodeUsage>>({
    queryKey: ["usage", user.id, user.tenant_id, "summary", scope],
    queryFn: ({ signal }) =>
      request(`/usage-summary?scope=${scope}`, { signal }),
    refetchInterval: 60_000,
  });
  const history = useQuery<TrafficHistory>({
    queryKey: [
      "usage-history",
      user.id,
      user.tenant_id,
      scope,
      range,
      interval,
      edgeID,
      custom,
    ],
    queryFn: ({ signal }) => {
      const times = trafficWindow(range, custom);
      const params = new URLSearchParams({
        scope,
        interval,
        start: new Date(times.start).toISOString(),
        end: new Date(times.end).toISOString(),
      });
      if (edgeID) params.set("edge_id", edgeID);
      return request(`/usage-history?${params}`, { signal });
    },
    enabled: !rangeError,
    refetchInterval: range === "custom" ? false : 60_000,
  });
  const nodes = summary.data?.items || [];
  const rows = edgeID ? nodes.filter((n) => n.edge_id === edgeID) : nodes;
  const up = rows.reduce((n, r) => n + r.upload_bytes, 0);
  const down = rows.reduce((n, r) => n + r.download_bytes, 0);
  return (
    <>
      <PageTitle
        title={platform ? "全平台流量统计" : "流量统计"}
        detail={`${platform ? "全部空间" : "我的空间"} · 流量与平均带宽 · 最小粒度 1 分钟 · 最近 30 天`}
        action={
          <Button
            disabled={history.isFetching || summary.isFetching || !!rangeError}
            onClick={() => {
              void history.refetch();
              void summary.refetch();
            }}
          >
            刷新
          </Button>
        }
      />
      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Box
          sx={{
            display: "flex",
            gap: 1.5,
            flexWrap: "wrap",
            alignItems: "center",
          }}
        >
          <FormControl
            size="small"
            sx={{ minWidth: 140, flexGrow: { xs: 1, sm: 0 } }}
          >
            <InputLabel id="traffic-range-label">时间范围</InputLabel>
            <Select
              labelId="traffic-range-label"
              label="时间范围"
              value={range}
              onChange={(e) => {
                const next = e.target.value as TrafficRange;
                const times = trafficWindow(next, custom);
                if (trafficRangeError(times.start, times.end, interval))
                  setInterval("auto");
                setFormError("");
                setRange(next);
              }}
            >
              <MenuItem value="1h">近 1 小时</MenuItem>
              <MenuItem value="6h">近 6 小时</MenuItem>
              <MenuItem value="24h">近 24 小时</MenuItem>
              <MenuItem value="7d">近 7 天</MenuItem>
              <MenuItem value="30d">近 30 天</MenuItem>
              <MenuItem value="custom">自定义时间</MenuItem>
            </Select>
          </FormControl>
          <FormControl
            size="small"
            sx={{ minWidth: 130, flexGrow: { xs: 1, sm: 0 } }}
          >
            <InputLabel id="traffic-interval-label">统计粒度</InputLabel>
            <Select
              labelId="traffic-interval-label"
              label="统计粒度"
              value={interval}
              onChange={(e) => setInterval(e.target.value as TrafficInterval)}
            >
              {trafficIntervals.map(([value, label, step]) => (
                <MenuItem
                  key={value}
                  value={value}
                  disabled={
                    !!step &&
                    Math.ceil((window.end - window.start) / step) > 1440
                  }
                >
                  {label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl
            size="small"
            sx={{ minWidth: 180, maxWidth: "100%", flexGrow: { xs: 1, sm: 0 } }}
          >
            <InputLabel id="traffic-edge-label" shrink>
              出口节点
            </InputLabel>
            <Select
              displayEmpty
              labelId="traffic-edge-label"
              label="出口节点"
              value={edgeID}
              onChange={(e) => setEdgeID(e.target.value)}
            >
              <MenuItem value="">全部出口节点</MenuItem>
              {nodes.map((r) => (
                <MenuItem key={r.edge_id} value={r.edge_id}>
                  {r.edge_name || "已移除节点"}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Box>
        {range === "custom" && (
          <Stack
            component="form"
            direction={{ xs: "column", sm: "row" }}
            spacing={1.5}
            sx={{ mt: 2 }}
            onSubmit={(e) => {
              e.preventDefault();
              const times = trafficWindow("custom", draft);
              const error = trafficRangeError(times.start, times.end, interval);
              setFormError(error);
              if (!error) setCustom({ ...draft });
            }}
          >
            <TextField
              size="small"
              type="datetime-local"
              label="开始时间"
              value={draft.start}
              onChange={(e) => setDraft({ ...draft, start: e.target.value })}
              slotProps={{ inputLabel: { shrink: true } }}
            />
            <TextField
              size="small"
              type="datetime-local"
              label="结束时间"
              value={draft.end}
              onChange={(e) => setDraft({ ...draft, end: e.target.value })}
              slotProps={{ inputLabel: { shrink: true } }}
            />
            <Button type="submit" variant="outlined">
              查询
            </Button>
          </Stack>
        )}
        {(formError || rangeError) && (
          <Alert severity="warning" sx={{ mt: 1.5 }}>
            {formError || rangeError}
          </Alert>
        )}
      </Paper>
      {!rangeError && (
        <Load loading={history.isPending} error={history.error}>
          {history.data && (
            <TrafficChart
              history={history.data}
              live={range !== "custom"}
              label={
                edgeID
                  ? nodes.find((n) => n.edge_id === edgeID)?.edge_name ||
                    "所选节点"
                  : "全部节点汇总"
              }
              key={`${scope}/${range}/${interval}/${edgeID}/${custom.start}/${custom.end}`}
            />
          )}
        </Load>
      )}
      <Typography fontWeight={600} sx={{ mb: 1 }}>
        累计用量 · {scope === "platform" ? "全平台" : "我的空间"}
      </Typography>
      <Load loading={summary.isPending} error={summary.error}>
        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(145px,1fr))",
            gap: 1.5,
            mb: 2,
          }}
        >
          {[
            ["累计上传", up],
            ["累计下载", down],
            ["累计总流量", up + down],
          ].map(([label, value]) => (
            <Paper key={label} variant="outlined" sx={{ p: 1.5 }}>
              <Typography variant="body2" color="text.secondary">
                {label}
              </Typography>
              <Typography variant="h5" fontWeight={600} sx={{ mt: 0.5 }}>
                {fmtBytes(Number(value))}
              </Typography>
            </Paper>
          ))}
        </Box>
        {!rows.length ? (
          <Empty title="暂无累计用量" />
        ) : (
          <TableFrame>
            <TableHead>
              <TableRow>
                <TableCell>出口节点</TableCell>
                <TableCell>上传</TableCell>
                <TableCell>下载</TableCell>
                <TableCell>总流量</TableCell>
                <TableCell>最近上报</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.map((r) => (
                <TableRow key={r.edge_id}>
                  <TableCell>{r.edge_name || "已移除节点"}</TableCell>
                  <TableCell>{fmtBytes(r.upload_bytes)}</TableCell>
                  <TableCell>{fmtBytes(r.download_bytes)}</TableCell>
                  <TableCell>
                    {fmtBytes(r.upload_bytes + r.download_bytes)}
                  </TableCell>
                  <TableCell>{fmtDate(r.observed_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </TableFrame>
        )}
      </Load>
    </>
  );
}
