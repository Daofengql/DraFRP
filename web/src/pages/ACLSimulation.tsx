import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  MenuItem,
  Stack,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { request } from "../api";
import { fmtDate } from "../format";
import { MutationError, TableFrame } from "../ui";
import type { ACLPolicy } from "../types";

type Target =
  | { rule_id: string }
  | { template_id: string; template_revision: "draft" | "published" }
  | { policy: ACLPolicy };
interface Simulation {
  scope: string;
  observed_at: string;
  evaluated_at: string;
  allowed: boolean;
  reason: string;
  chain: Array<{
    kind: string;
    name?: string;
    template_id?: string;
    revision?: string;
    policy_version: number;
    requires_geo: boolean;
    decision: {
      allowed: boolean;
      reason: string;
      matched_entry_id?: string;
      used_default: boolean;
    };
  }>;
}
const kinds: Record<string, string> = {
  mandatory_template: "强制父策略",
  rule_template: "规则模板",
  rule_inline: "规则独立策略",
  template: "模板",
  draft: "草稿",
};
const reasons: Record<string, string> = {
  all_policies_allow: "所有适用策略均允许",
  no_acl: "没有适用的来源 ACL",
  policy_denied: "适用策略拒绝",
  capability_missing: "缺少策略要求的地域查询能力",
  geoip_unavailable: "地域数据库不可用",
};

function SimulationDialog({
  target,
  title,
  protocol,
  onClose,
}: {
  target: Target;
  title: string;
  protocol?: string;
  onClose: () => void;
}) {
  const [form, setForm] = useState({
    source_ip: "",
    source_port: "",
    protocol: protocol || "tcp",
    at: "",
    geo_state: "unavailable",
    country: "",
    region: "",
    geo_version: "",
  });
  const [validation, setValidation] = useState("");
  const simulation = useMutation({
    mutationFn: (body: object) =>
      request<Simulation>("/acl/simulate", {
        method: "POST",
        body: JSON.stringify(body),
      }),
  });
  const set = (key: keyof typeof form, value: string) => {
    setForm((previous) => ({ ...previous, [key]: value }));
    setValidation("");
    simulation.reset();
  };
  const submit = () => {
    const port = Number(form.source_port);
    if (
      !form.source_ip.trim() ||
      !Number.isInteger(port) ||
      port < 1 ||
      port > 65535
    ) {
      setValidation("请输入来源 IP 和 1–65535 的访客来源端口。");
      return;
    }
    if (form.at && !Number.isFinite(Date.parse(form.at))) {
      setValidation("模拟时间需使用有效 RFC3339 时间。");
      return;
    }
    simulation.mutate({
      ...target,
      source_ip: form.source_ip.trim(),
      source_port: port,
      protocol: form.protocol,
      ...(form.at.trim() ? { at: form.at.trim() } : {}),
      geo: {
        state: form.geo_state,
        ...(form.geo_state === "known"
          ? {
              country: form.country.trim(),
              ...(form.region.trim() ? { region: form.region.trim() } : {}),
            }
          : {}),
        ...(form.geo_version.trim()
          ? { version: form.geo_version.trim() }
          : {}),
      },
    });
  };
  return (
    <Dialog
      open
      onClose={() => !simulation.isPending && onClose()}
      fullWidth
      maxWidth="md"
    >
      <DialogTitle>来源 ACL 模拟 · {title}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Typography variant="body2" color="text.secondary">
            按指定来源和地域条件计算策略匹配结果。
          </Typography>
          <div className="form-grid">
            <TextField
              label="访客来源 IP"
              value={form.source_ip}
              onChange={(e) => set("source_ip", e.target.value)}
              required
              disabled={simulation.isPending}
            />
            <TextField
              label="访客来源端口"
              type="number"
              value={form.source_port}
              onChange={(e) => set("source_port", e.target.value)}
              required
              disabled={simulation.isPending}
            />
            <TextField
              select
              label="访问协议"
              value={form.protocol}
              onChange={(e) => set("protocol", e.target.value)}
              disabled={simulation.isPending || !!protocol}
            >
              <MenuItem value="tcp">TCP</MenuItem>
              <MenuItem value="udp">UDP</MenuItem>
            </TextField>
            <TextField
              label="模拟时间（可选）"
              helperText="RFC3339 格式；留空使用当前时间"
              value={form.at}
              onChange={(e) => set("at", e.target.value)}
              disabled={simulation.isPending}
            />
          </div>
          <TextField
            select
            label="模拟地域状态"
            value={form.geo_state}
            onChange={(e) => set("geo_state", e.target.value)}
            disabled={simulation.isPending}
          >
            <MenuItem value="unavailable">地址库不可用</MenuItem>
            <MenuItem value="unknown">地域未知</MenuItem>
            <MenuItem value="known">指定国家 / 地区</MenuItem>
          </TextField>
          {form.geo_state === "known" && (
            <div className="form-grid">
              <TextField
                label="来源国家代码"
                value={form.country}
                onChange={(e) => set("country", e.target.value)}
                helperText="两位大写字母"
                disabled={simulation.isPending}
              />
              <TextField
                label="来源地区代码（可选）"
                value={form.region}
                onChange={(e) => set("region", e.target.value)}
                disabled={simulation.isPending}
              />
            </div>
          )}
          {form.geo_state !== "unavailable" && (
            <TextField
              label="地址库版本（可选）"
              value={form.geo_version}
              onChange={(e) => set("geo_version", e.target.value)}
              disabled={simulation.isPending}
            />
          )}
          {validation && <Alert severity="error">{validation}</Alert>}
          <MutationError error={simulation.error} />
          {simulation.data && (
            <>
              <Alert severity={simulation.data.allowed ? "success" : "warning"}>
                {simulation.data.allowed ? "ACL 允许" : "ACL 拒绝"} ·{" "}
                {reasons[simulation.data.reason] || simulation.data.reason}
              </Alert>
              <Typography variant="body2" color="text.secondary">
                云控配置读取时间 {fmtDate(simulation.data.observed_at)} ·
                模拟时间 {fmtDate(simulation.data.evaluated_at)}
              </Typography>
              {!!simulation.data.chain.length && (
                <TableFrame>
                  <TableHead>
                    <TableRow>
                      <TableCell>适用策略</TableCell>
                      <TableCell>版本</TableCell>
                      <TableCell>判断</TableCell>
                      <TableCell>命中依据</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {simulation.data.chain.map((layer, i) => (
                      <TableRow key={`${layer.kind}/${layer.template_id || i}`}>
                        <TableCell>
                          {layer.name || kinds[layer.kind] || layer.kind}
                        </TableCell>
                        <TableCell>
                          v{layer.policy_version} ·{" "}
                          {layer.revision === "draft"
                            ? "草稿"
                            : layer.revision === "published"
                              ? "已发布"
                              : "当前输入"}
                        </TableCell>
                        <TableCell>
                          {layer.decision.allowed ? "允许" : "拒绝"}
                        </TableCell>
                        <TableCell>
                          {layer.decision.used_default
                            ? "默认动作"
                            : layer.decision.matched_entry_id ||
                              reasons[layer.decision.reason] ||
                              layer.decision.reason}
                        </TableCell>
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
        <Button onClick={onClose} disabled={simulation.isPending}>
          关闭
        </Button>
        <Button
          variant="contained"
          onClick={submit}
          disabled={simulation.isPending}
        >
          {simulation.isPending ? "模拟中…" : "运行模拟"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export default function ACLSimulation({
  target,
  title,
  protocol,
  label = "访问模拟",
}: {
  target: Target;
  title: string;
  protocol?: string;
  label?: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button onClick={() => setOpen(true)}>{label}</Button>
      {open && (
        <SimulationDialog
          target={target}
          title={title}
          protocol={protocol}
          onClose={() => setOpen(false)}
        />
      )}
    </>
  );
}
