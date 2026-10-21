import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Button,
  Chip,
  MenuItem,
  Stack,
  TableBody,
  TableCell,
  TableHead,
  TablePagination,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { request } from "../api";
import { fmtDate } from "../format";
import {
  Empty,
  Load,
  PageTitle,
  TableFrame,
  useResource,
  useSessionContext,
} from "../ui";
import type { Edge } from "../types";

interface PortPage {
  edge_id: string;
  port_min: number;
  port_max: number;
  total: number;
  observed_at: string;
  items: Array<{
    protocol: string;
    port: number;
    in_business_pool: boolean;
    status: "available" | "reserved" | "occupied" | "releasing";
    reservations?: string[];
    release_at?: string;
    rule?: {
      id: string;
      name?: string;
      tenant_id?: string;
      current_claim: boolean;
    };
  }>;
}
const statusLabels = {
  available: "可申请",
  reserved: "系统保留",
  occupied: "已占用",
  releasing: "释放中",
};
const reservationLabels: Record<string, string> = {
  carrier_tls: "TLS 承载",
  carrier_quic: "QUIC 承载",
  http: "共享 HTTP",
  https: "共享 HTTPS",
};

export default function PortsPage() {
  const session = useSessionContext();
  const [params, setParams] = useSearchParams();
  const [protocol, setProtocol] = useState("");
  const [page, setPage] = useState(0);
  const [size, setSize] = useState(50);
  const edges = useResource<Edge>("/edges", "edges");
  const items = edges.data?.items || [];
  const selected = params.get("edge_id") || "";
  const edgeID = items.some((e) => e.id === selected)
    ? selected
    : items[0]?.id || "";
  useEffect(() => {
    setPage(0);
  }, [edgeID]);
  const ports = useQuery({
    queryKey: ["port-resources", session.user.id, edgeID, protocol, page, size],
    queryFn: ({ signal }) => {
      const query = new URLSearchParams({
        edge_id: edgeID,
        offset: String(page * size),
        limit: String(size),
      });
      if (protocol) query.set("protocol", protocol);
      return request<PortPage>(`/port-resources?${query}`, { signal });
    },
    enabled: !!edgeID,
    staleTime: 0,
  });
  useEffect(() => {
    if (!ports.data) return;
    const maxPage = Math.max(0, Math.ceil(ports.data.total / size) - 1);
    setPage((current) => Math.min(current, maxPage));
  }, [ports.data?.total, size]);
  return (
    <>
      <PageTitle
        title="公网端口"
        detail="各边缘节点的端口分配状态"
        action={
          <Button
            onClick={() => ports.refetch()}
            disabled={!edgeID || ports.isFetching}
          >
            刷新端口状态
          </Button>
        }
      />
      <Load loading={edges.isPending} error={edges.error}>
        {!items.length ? (
          <Empty title="暂无边缘节点" />
        ) : (
          <Stack spacing={2}>
            <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
              <TextField
                select
                label="边缘节点"
                value={edgeID}
                onChange={(e) => {
                  setParams({ edge_id: e.target.value });
                  setPage(0);
                }}
                sx={{ minWidth: 240 }}
              >
                {items.map((edge) => (
                  <MenuItem key={edge.id} value={edge.id}>
                    {edge.name} · {edge.public_host}
                  </MenuItem>
                ))}
              </TextField>
              <TextField
                select
                label="端口协议"
                value={protocol}
                onChange={(e) => {
                  setProtocol(e.target.value);
                  setPage(0);
                }}
                sx={{ minWidth: 160 }}
              >
                <MenuItem value="">TCP 与 UDP</MenuItem>
                <MenuItem value="tcp">TCP</MenuItem>
                <MenuItem value="udp">UDP</MenuItem>
              </TextField>
            </Stack>
            <Load loading={ports.isPending} error={ports.error}>
              {ports.data && (
                <>
                  <Typography variant="body2" color="text.secondary">
                    业务池 {ports.data.port_min}–{ports.data.port_max} ·
                    查询时间 {fmtDate(ports.data.observed_at)}
                  </Typography>
                  <TableFrame>
                    <TableHead>
                      <TableRow>
                        <TableCell>协议 / 端口</TableCell>
                        <TableCell>状态</TableCell>
                        <TableCell>用途 / 所属隧道</TableCell>
                        <TableCell>预计释放时间</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {ports.data.items.map((port) => (
                        <TableRow key={`${port.protocol}/${port.port}`}>
                          <TableCell className="mono">
                            {port.protocol.toUpperCase()} / {port.port}
                          </TableCell>
                          <TableCell>
                            <Chip
                              size="small"
                              variant="outlined"
                              color={
                                port.status === "available"
                                  ? "success"
                                  : "default"
                              }
                              label={statusLabels[port.status] || port.status}
                            />
                          </TableCell>
                          <TableCell>
                            {port.reservations?.length ? (
                              port.reservations
                                .map((kind) => reservationLabels[kind] || kind)
                                .join("、")
                            ) : port.rule ? (
                              <>
                                {port.rule.tenant_id ===
                                  session.user.tenant_id &&
                                port.rule.current_claim ? (
                                  <Button
                                    component={Link}
                                    to={`/rules/${port.rule.id}`}
                                    size="small"
                                  >
                                    {port.rule.name || port.rule.id}
                                  </Button>
                                ) : (
                                  <Typography variant="body2">
                                    {port.rule.name || port.rule.id}
                                  </Typography>
                                )}
                                {!port.rule.current_claim && (
                                  <Typography
                                    variant="caption"
                                    color="text.secondary"
                                  >
                                    旧版本仍占用此端口
                                  </Typography>
                                )}
                              </>
                            ) : port.status === "available" ? (
                              "业务端口"
                            ) : (
                              "其他空间占用"
                            )}
                          </TableCell>
                          <TableCell>
                            {port.release_at ? fmtDate(port.release_at) : "—"}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </TableFrame>
                  <TablePagination
                    component="div"
                    count={ports.data.total}
                    page={page}
                    rowsPerPage={size}
                    rowsPerPageOptions={[25, 50, 100]}
                    labelRowsPerPage="每页"
                    labelDisplayedRows={({ from, to, count }) =>
                      `${from}–${to} / ${count}`
                    }
                    onPageChange={(_, next) => setPage(next)}
                    onRowsPerPageChange={(e) => {
                      setSize(Number(e.target.value));
                      setPage(0);
                    }}
                  />
                </>
              )}
            </Load>
          </Stack>
        )}
      </Load>
    </>
  );
}
