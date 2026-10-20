import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
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
  TextField,
  Typography,
} from "@mui/material";
import { request } from "../api";
import {
  fmtDate,
  nativeSourceCapability,
  observedOnline,
  ruleState,
} from "../format";
import {
  Confirm,
  DetailField,
  Empty,
  Load,
  MutationError,
  PageTitle,
  Status,
  TableFrame,
  invalidate,
  useResource,
  useSessionContext,
  useWriter,
} from "../ui";
import type { Binding, Device, Rule } from "../types";
import DeviceTransport from "./DeviceTransport";

export function BindPage() {
  const { code = "" } = useParams();
  const { user } = useSessionContext();
  const [name, setName] = useState("");
  const [deviceID, setDeviceID] = useState("");
  const q = useQuery<Binding>({
    queryKey: ["binding", code, user.id],
    queryFn: ({ signal }) =>
      request(`/bind/${encodeURIComponent(code)}`, { signal }),
    retry: false,
  });
  useEffect(() => {
    if (q.data) setName(q.data.name);
  }, [q.data?.user_code]);
  const m = useWriter<{ device_id: string }>((data) => {
    setDeviceID(data.device_id);
    invalidate("devices");
  });
  const expired = q.data && Date.parse(q.data.expires_at) <= Date.now();
  return (
    <>
      <Typography variant="h4" color="primary" fontWeight={800} sx={{ mb: 3 }}>
        DraFRP
      </Typography>
      <Paper variant="outlined" sx={{ p: 3 }}>
        <PageTitle title="确认设备绑定" detail={`已登录为 ${user.username}`} />
        {deviceID ? (
          <Stack spacing={2}>
            <Alert severity="success">
              设备已绑定，等待 Agent 使用自身身份同步。
            </Alert>
            <Button
              component={Link}
              to={`/devices/${deviceID}`}
              variant="contained"
            >
              查看设备
            </Button>
          </Stack>
        ) : (
          <Load loading={q.isPending} error={q.error}>
            <Stack spacing={2}>
              {q.data && (
                <>
                  <DetailField label="用户码">
                    <Typography className="mono">{q.data.user_code}</Typography>
                  </DetailField>
                  <DetailField label="目标空间">
                    <Typography className="mono">{user.tenant_id}</Typography>
                  </DetailField>
                  <DetailField label="公钥指纹">
                    <Typography className="mono">
                      {q.data.public_key_fingerprint}
                    </Typography>
                  </DetailField>
                  <DetailField label="有效期">
                    {fmtDate(q.data.expires_at)}
                  </DetailField>
                  <Status
                    value={
                      expired
                        ? "expired"
                        : q.data.status === "pending"
                          ? "waiting_confirmation"
                          : q.data.status
                    }
                  />
                  <Alert severity="info">
                    请核对 Agent
                    显示的设备名称、公钥指纹和用户码。仅绑定你正在操作的设备。
                  </Alert>
                  <TextField
                    label="设备名称"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    inputProps={{ maxLength: 255 }}
                  />
                  <MutationError error={m.error} />
                  <Button
                    variant="contained"
                    disabled={
                      m.isPending || expired || q.data.status !== "pending"
                    }
                    onClick={() =>
                      m.mutate({
                        path: "/bind/confirm",
                        method: "POST",
                        data: { user_code: code, name },
                      })
                    }
                  >
                    {m.isPending ? "确认中…" : "确认绑定到当前空间"}
                  </Button>
                </>
              )}
              <Button component={Link} to="/devices">
                返回设备
              </Button>
            </Stack>
          </Load>
        )}
      </Paper>
    </>
  );
}

export function DevicesPage() {
  const q = useResource<Device>("/devices", "devices", true, 10_000);
  const rules = useResource<Rule>("/rules", "rules");
  const [params, setParams] = useSearchParams();
  const search = params.get("q") || "",
    filter = params.get("status") || "";
  const [bind, setBind] = useState(false),
    [code, setCode] = useState("");
  const [revoking, setRevoking] = useState<Device>(),
    [editing, setEditing] = useState<Device>(),
    [name, setName] = useState("");
  const revoke = useWriter(() => {
    setRevoking(undefined);
    invalidate("devices", "rules", "overview");
  });
  const rename = useWriter(() => {
    setEditing(undefined);
    invalidate("devices");
  });
  const rows =
    q.data?.items.filter(
      (d) =>
        `${d.name} ${d.id}`.toLowerCase().includes(search.toLowerCase()) &&
        (!filter ||
          (d.revoked
            ? "revoked"
            : observedOnline(d.last_seen)
              ? "online"
              : "offline") === filter),
    ) || [];
  return (
    <>
      <PageTitle
        title="设备"
        detail="每台 Agent 拥有独立身份、能力和会话"
        action={
          <Button variant="contained" onClick={() => setBind(true)}>
            确认绑定
          </Button>
        }
      />
      <Stack direction={{ xs: "column", sm: "row" }} spacing={2} sx={{ mb: 2 }}>
        <TextField
          size="small"
          label="搜索名称或 ID"
          value={search}
          onChange={(e) =>
            setParams({ q: e.target.value, status: filter }, { replace: true })
          }
        />
        <TextField
          select
          size="small"
          label="状态"
          value={filter}
          onChange={(e) =>
            setParams({ q: search, status: e.target.value }, { replace: true })
          }
          SelectProps={{ native: true }}
          sx={{ minWidth: 160 }}
        >
          <option value="">全部</option>
          <option value="online">近期在线</option>
          <option value="offline">离线</option>
          <option value="revoked">已撤销</option>
        </TextField>
      </Stack>
      <Load loading={q.isLoading} error={q.error}>
        {!rows.length ? (
          <Empty
            title={q.data?.items.length ? "没有匹配设备" : "还没有绑定设备"}
            detail="在 Agent 本机运行绑定命令，打开其授权链接或填写用户码。"
          />
        ) : (
          <TableFrame>
            <TableHead>
              <TableRow>
                <TableCell>名称 / ID</TableCell>
                <TableCell>控制会话</TableCell>
                <TableCell>能力</TableCell>
                <TableCell>关联规则</TableCell>
                <TableCell>最后心跳</TableCell>
                <TableCell>操作</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.map((d) => (
                <TableRow key={d.id}>
                  <TableCell>
                    <Button
                      component={Link}
                      to={`/devices/${d.id}`}
                      sx={{ p: 0, justifyContent: "flex-start" }}
                    >
                      {d.name}
                    </Button>
                    <Typography className="mono">{d.id}</Typography>
                  </TableCell>
                  <TableCell>
                    <Status
                      value={
                        d.revoked
                          ? "revoked"
                          : observedOnline(d.last_seen)
                            ? "online"
                            : "offline"
                      }
                    />
                  </TableCell>
                  <TableCell>
                    {d.capabilities?.join("、") || "未上报"}
                  </TableCell>
                  <TableCell>
                    {rules.data
                      ? rules.data.items.filter((r) => r.device_id === d.id)
                          .length
                      : "未读取"}
                  </TableCell>
                  <TableCell>{fmtDate(d.last_seen)}</TableCell>
                  <TableCell>
                    <Stack direction="row">
                      <Button
                        onClick={() => {
                          rename.reset();
                          setEditing(d);
                          setName(d.name);
                        }}
                      >
                        重命名
                      </Button>
                      <Button
                        color="error"
                        disabled={d.revoked}
                        onClick={() => {
                          revoke.reset();
                          setRevoking(d);
                        }}
                      >
                        撤销
                      </Button>
                    </Stack>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </TableFrame>
        )}
      </Load>
      {revoking && (
        <Confirm
          title={`撤销设备 ${revoking.name}`}
          onClose={() => setRevoking(undefined)}
          busy={revoke.isPending}
          error={revoke.error}
          label="撤销设备"
          onConfirm={() =>
            revoke.mutate({ path: `/devices/${revoking.id}`, method: "DELETE" })
          }
        >
          <Typography>
            该设备的{" "}
            {rules.data?.items.filter((r) => r.device_id === revoking.id)
              .length ?? "未知数量"}{" "}
            条关联规则将停用，现有连接可能中断。恢复使用需要在 Agent
            上重新绑定。
          </Typography>
        </Confirm>
      )}
      <Dialog
        open={!!editing}
        onClose={() => !rename.isPending && setEditing(undefined)}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>重命名设备</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="设备名称"
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
              required
            />
            <MutationError error={rename.error} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditing(undefined)}>取消</Button>
          <Button
            variant="contained"
            disabled={!name.trim() || rename.isPending}
            onClick={() =>
              rename.mutate({
                path: `/devices/${editing!.id}`,
                method: "PATCH",
                data: { name },
              })
            }
          >
            保存
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={bind}
        onClose={() => setBind(false)}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>填写 Agent 用户码</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Typography>
              浏览器仅确认设备归属，不接收设备私钥或长期凭据。
            </Typography>
            <TextField
              label="用户码"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              autoFocus
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setBind(false)}>取消</Button>
          <Button
            component={Link}
            to={`/bind/${encodeURIComponent(code.trim().toUpperCase())}`}
            disabled={!code.trim()}
            variant="contained"
          >
            核对设备
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}

export function DevicePage() {
  const { id } = useParams();
  const devices = useResource<Device>("/devices", "devices", true, 10_000),
    rules = useResource<Rule>("/rules", "rules");
  const d = devices.data?.items.find((x) => x.id === id),
    rows = rules.data?.items.filter((r) => r.device_id === id) || [];
  return (
    <>
      <PageTitle
        title={d?.name || "设备详情"}
        action={
          <Button component={Link} to="/devices">
            返回设备
          </Button>
        }
      />
      <Load loading={devices.isLoading} error={devices.error}>
        {!d ? (
          <Empty title="设备不存在或无权访问" />
        ) : (
          <Stack spacing={3}>
            <Paper variant="outlined" sx={{ p: 3 }}>
              <Box className="detail-grid">
                <DetailField label="设备 ID">
                  <Typography className="mono">{d.id}</Typography>
                </DetailField>
                <DetailField label="控制会话">
                  <Status
                    value={
                      d.revoked
                        ? "revoked"
                        : observedOnline(d.last_seen)
                          ? "online"
                          : "offline"
                    }
                  />
                </DetailField>
                <DetailField label="最后心跳">
                  {fmtDate(d.last_seen)}
                </DetailField>
                <DetailField label="应用修订">
                  {d.applied_revision || "尚未确认"}
                </DetailField>
                <DetailField label="会话代次">{d.generation}</DetailField>
                <DetailField label="上报能力">
                  {d.capabilities?.join("、") || "尚未上报"}
                </DetailField>
              </Box>
            </Paper>
            <DeviceTransport device={d} />
            <Alert severity="info">
              Linux IPv4 透明 socket：TCP{" "}
              {nativeSourceCapability("tcp", d.capabilities)
                ? "已上报 IP+端口能力"
                : "未上报能力"}
              ；UDP{" "}
              {nativeSourceCapability("udp", d.capabilities)
                ? "已上报 IP+端口能力"
                : "未上报能力"}
              。使用前需要本机 transparent 网络模式、权限及目标网络回程配置；TUN
              与 IPv6 保源尚未实现。
            </Alert>
            <Typography variant="h6">该设备的规则</Typography>
            <Load loading={rules.isLoading} error={rules.error}>
              {!rows.length ? (
                <Empty title="暂无关联规则" />
              ) : (
                <TableFrame>
                  <TableHead>
                    <TableRow>
                      <TableCell>名称</TableCell>
                      <TableCell>协议 / 目标</TableCell>
                      <TableCell>状态</TableCell>
                      <TableCell>应用版本</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {rows.map((r) => (
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
                          {r.protocol.toUpperCase()} · {r.target}
                        </TableCell>
                        <TableCell>
                          <Status value={ruleState(r)} />
                        </TableCell>
                        <TableCell>
                          {r.applied_version} / {r.version}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </TableFrame>
              )}
            </Load>
          </Stack>
        )}
      </Load>
    </>
  );
}
