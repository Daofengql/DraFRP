import { useState } from "react";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  MenuItem,
  Paper,
  Stack,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import {
  Confirm,
  Empty,
  Load,
  MutationError,
  PageTitle,
  TableFrame,
  invalidate,
  useDraftGuard,
  useResource,
  useWriter,
} from "../ui";
import type { ACLEntry, ACLTemplate, Rule } from "../types";
import { aclDraftEntries, aclDraftError } from "../aclDraft";
import ACLSimulation from "./ACLSimulation";
import { ACLApplications } from "./ACLObservations";

function TemplateForm({
  initial,
  latest,
  reload,
  onClose,
}: {
  initial?: ACLTemplate;
  latest?: ACLTemplate;
  reload: () => void;
  onClose: () => void;
}) {
  const [name, setName] = useState(initial?.name || ""),
    [action, setAction] = useState(initial?.policy.default_action || "deny");
  const [entries, setEntries] = useState<ACLEntry[]>(
      initial?.policy.entries || [],
    ),
    [version, setVersion] = useState(initial?.version || 0);
  const [dirty, setDirty] = useState(false),
    [compare, setCompare] = useState(false),
    [validation, setValidation] = useState("");
  const canClose = useDraftGuard(dirty);
  const m = useWriter(() => {
    invalidate("acl", "rules");
    onClose();
  });
  const update = (i: number, patch: Partial<ACLEntry>) => {
    setDirty(true);
    setEntries((items) =>
      items.map((entry, n) => (n === i ? { ...entry, ...patch } : entry)),
    );
  };
  const close = () => {
    if (!m.isPending && canClose()) onClose();
  };
  const submit = () => {
    if (!name.trim()) return;
    const error = aclDraftError(entries);
    if (error) {
      setValidation(error);
      return;
    }
    setValidation("");
    const policy = {
      default_action: action,
      entries: initial ? aclDraftEntries(entries) : [],
      version: initial?.policy.version || 0,
    };
    m.mutate({
      path: initial ? `/acl-templates/${initial.id}` : "/acl-templates",
      method: initial ? "PUT" : "POST",
      data: {
        name,
        policy,
        ...(initial
          ? { version, default: initial.default, mandatory: initial.mandatory }
          : {}),
      },
    });
  };
  return (
    <Dialog open onClose={close} fullWidth maxWidth="md">
      <DialogTitle>{initial ? "编辑 ACL 草稿" : "创建空 ACL 草稿"}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <TextField
            label="模板名称"
            value={name}
            onChange={(e) => {
              setDirty(true);
              setName(e.target.value);
            }}
            required
            autoFocus
          />
          <TextField
            select
            label="未匹配时的默认动作"
            value={action}
            onChange={(e) => {
              setDirty(true);
              setAction(e.target.value);
            }}
            helperText="动作由管理员选择；不会自动加入 CIDR、地区或预制条目"
          >
            <MenuItem value="deny">拒绝 deny</MenuItem>
            <MenuItem value="allow">允许 allow</MenuItem>
          </TextField>
          {initial ? (
            <>
              <Typography variant="h6">草稿条目</Typography>
              <Typography variant="body2" color="text.secondary">
                按 priority 从小到大匹配，命中首条执行动作；协议留空匹配
                TCP/UDP，端口留空不额外限制。列表字段以逗号、空格或换行分隔；国家与地区完全由管理员填写。
              </Typography>
              {!entries.length && (
                <Empty
                  title="草稿中没有匹配条目"
                  detail="发布后所有流量使用上方的默认动作。"
                />
              )}
              {entries.map((entry, i) => (
                <Paper variant="outlined" key={entry.id} sx={{ p: 2 }}>
                  <Stack spacing={2}>
                    <Box className="form-grid">
                      <TextField
                        label="优先级"
                        type="number"
                        value={entry.priority}
                        onChange={(e) =>
                          update(i, { priority: Number(e.target.value) })
                        }
                      />
                      <TextField
                        select
                        label="动作"
                        value={entry.action}
                        onChange={(e) => update(i, { action: e.target.value })}
                      >
                        <MenuItem value="allow">允许 allow</MenuItem>
                        <MenuItem value="deny">拒绝 deny</MenuItem>
                      </TextField>
                      <TextField
                        select
                        label="协议"
                        value={entry.protocol || ""}
                        onChange={(e) =>
                          update(i, { protocol: e.target.value || undefined })
                        }
                      >
                        <MenuItem value="">TCP / UDP</MenuItem>
                        <MenuItem value="tcp">TCP</MenuItem>
                        <MenuItem value="udp">UDP</MenuItem>
                      </TextField>
                      <TextField
                        label="来源端口（可选）"
                        defaultValue={entry.ports?.join(", ") || ""}
                        onBlur={(e) =>
                          update(i, {
                            ports: e.target.value.trim()
                              ? e.target.value.split(/[\s,]+/).map(Number)
                              : undefined,
                          })
                        }
                      />
                    </Box>
                    <TextField
                      label="来源 CIDR（可选；留空匹配所有来源）"
                      multiline
                      minRows={2}
                      defaultValue={(entry.cidrs || []).join("\n")}
                      onBlur={(e) =>
                        update(i, {
                          cidrs: e.target.value.split(/[\s,]+/).filter(Boolean),
                        })
                      }
                    />
                    <Box className="form-grid">
                      <TextField
                        label="国家代码（可选）"
                        multiline
                        minRows={2}
                        defaultValue={(entry.countries || []).join("\n")}
                        helperText="两位大写字母；不预填任何国家集合"
                        onBlur={(e) =>
                          update(i, {
                            countries: e.target.value
                              .split(/[\s,]+/)
                              .filter(Boolean),
                          })
                        }
                      />
                      <TextField
                        label="地区代码（可选）"
                        multiline
                        minRows={2}
                        defaultValue={(entry.regions || []).join("\n")}
                        helperText="COUNTRY-REGION；大写字母、数字与连字符，总长 4–16"
                        onBlur={(e) =>
                          update(i, {
                            regions: e.target.value
                              .split(/[\s,]+/)
                              .filter(Boolean),
                          })
                        }
                      />
                    </Box>
                    <TextField
                      select
                      label="GeoIP 未知来源动作"
                      value={entry.geo_unknown_action || ""}
                      required={
                        !!(entry.countries?.length || entry.regions?.length)
                      }
                      onChange={(e) =>
                        update(i, {
                          geo_unknown_action: (e.target.value ||
                            undefined) as ACLEntry["geo_unknown_action"],
                        })
                      }
                      helperText="有国家或地区条件时必须显式选择；无地区条件时此字段不会发送"
                    >
                      <MenuItem value="">请选择</MenuItem>
                      <MenuItem value="deny">立即拒绝 deny</MenuItem>
                      <MenuItem value="no_match">
                        跳过本条，继续匹配 no_match
                      </MenuItem>
                    </TextField>
                    {!!(entry.countries?.length || entry.regions?.length) && (
                      <Alert severity="warning">
                        地区条件依赖边缘管理员提供有效 GeoIP
                        数据库。数据库缺失或无效时规则拒绝承载；未知来源动作只用于有效数据库中未识别的来源。国家与地区同时填写时，需同时匹配。
                      </Alert>
                    )}
                    <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
                      <TextField
                        label="生效时间 RFC3339（可选）"
                        value={entry.not_before || ""}
                        onChange={(e) =>
                          update(i, { not_before: e.target.value || undefined })
                        }
                        fullWidth
                      />
                      <TextField
                        label="失效时间 RFC3339（可选）"
                        value={entry.expires_at || ""}
                        onChange={(e) =>
                          update(i, { expires_at: e.target.value || undefined })
                        }
                        fullWidth
                      />
                    </Stack>
                    <Button
                      color="error"
                      onClick={() => {
                        setDirty(true);
                        setEntries((items) => items.filter((_, n) => n !== i));
                      }}
                    >
                      删除条目
                    </Button>
                  </Stack>
                </Paper>
              ))}
              <Button
                variant="outlined"
                onClick={() => {
                  setDirty(true);
                  setEntries((items) => [
                    ...items,
                    {
                      id: crypto.randomUUID(),
                      priority: items.length
                        ? Math.max(...items.map((e) => e.priority)) + 10
                        : 10,
                      action: "deny",
                      cidrs: [],
                    },
                  ]);
                }}
              >
                添加空条目
              </Button>
              <Alert severity="info">
                保存草稿不会改变线上已发布策略。默认模板与强制父策略需在“绑定设置”单独修改。
              </Alert>
              <ACLSimulation
                target={{
                  policy: {
                    default_action: action,
                    entries: aclDraftEntries(entries),
                    version: initial.policy.version,
                  },
                }}
                title={`${name} · 当前输入`}
                label="模拟当前草稿（不保存）"
              />
            </>
          ) : (
            <Alert severity="info">
              首次只创建空草稿。创建后可添加条目并发布；发布前不能绑定为默认或强制策略。
            </Alert>
          )}
          {validation && <Alert severity="error">{validation}</Alert>}
          <MutationError
            error={m.error}
            reload={() => {
              reload();
              setCompare(true);
            }}
          />
          {compare && latest && (
            <Paper variant="outlined" sx={{ p: 2 }}>
              <Typography>最新草稿 v{latest.version}</Typography>
              <Box
                component="pre"
                sx={{ overflow: "auto", maxHeight: 220, fontSize: 12 }}
              >
                {JSON.stringify(latest.policy, null, 2)}
              </Box>
              <Button
                onClick={() => {
                  setVersion(latest.version);
                  setCompare(false);
                  m.reset();
                }}
              >
                已比较，保留输入并使用最新版本
              </Button>
            </Paper>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button disabled={m.isPending} onClick={close}>
          取消
        </Button>
        <Button
          variant="contained"
          disabled={!name.trim() || m.isPending}
          onClick={submit}
        >
          {m.isPending ? "保存中…" : initial ? "保存草稿" : "创建空草稿"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function BindingSettings({
  template,
  onClose,
}: {
  template: ACLTemplate;
  onClose: () => void;
}) {
  const [def, setDef] = useState(template.default),
    [mandatory, setMandatory] = useState(template.mandatory);
  const m = useWriter(() => {
    invalidate("acl", "rules");
    onClose();
  });
  return (
    <Dialog
      open
      onClose={() => !m.isPending && onClose()}
      fullWidth
      maxWidth="sm"
    >
      <DialogTitle>{template.name} · 绑定设置</DialogTitle>
      <DialogContent>
        <Stack spacing={2}>
          <Typography>
            设置针对已发布 v{template.published?.version || "—"}
            ，不会发布草稿中的改动。
          </Typography>
          <FormControlLabel
            control={
              <Checkbox
                checked={def}
                onChange={(e) => setDef(e.target.checked)}
              />
            }
            label="作为新建 TCP/UDP 规则的默认模板"
          />
          <FormControlLabel
            control={
              <Checkbox
                checked={mandatory}
                onChange={(e) => setMandatory(e.target.checked)}
              />
            }
            label="作为所有 TCP/UDP 规则的强制父策略"
          />
          <Alert severity="warning">
            默认选择只影响后续新建规则。强制策略会叠加到全部 TCP/UDP
            规则，与规则自身策略取交集；收紧设置可能关闭现有连接。
          </Alert>
          <MutationError error={m.error} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={m.isPending}>
          取消
        </Button>
        <Button
          variant="contained"
          disabled={m.isPending}
          onClick={() =>
            m.mutate({
              path: `/acl-templates/${template.id}`,
              method: "PUT",
              data: { ...template, default: def, mandatory },
            })
          }
        >
          保存绑定设置
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export default function ACLPage() {
  const q = useResource<ACLTemplate>("/acl-templates", "acl"),
    rules = useResource<Rule>("/rules", "rules");
  const [editing, setEditing] = useState<ACLTemplate | "new">(),
    [publishing, setPublishing] = useState<ACLTemplate>(),
    [deleting, setDeleting] = useState<ACLTemplate>(),
    [settings, setSettings] = useState<ACLTemplate>(),
    [view, setView] = useState<ACLTemplate>();
  const publish = useWriter(() => {
      setPublishing(undefined);
      invalidate("acl", "rules");
    }),
    del = useWriter(() => {
      setDeleting(undefined);
      invalidate("acl");
    });
  return (
    <>
      <PageTitle
        title="TCP/UDP ACL 模板"
        detail="从空草稿开始，管理员独立维护、发布和绑定策略"
        action={
          <Button variant="contained" onClick={() => setEditing("new")}>
            创建空模板
          </Button>
        }
      />
      <Alert severity="info" sx={{ mb: 2 }}>
        HTTP(S) 站点不使用这些模板。系统不预置 CIDR、地区集合或其他策略内容。
      </Alert>
      <Load loading={q.isLoading} error={q.error}>
        {!q.data?.items.length ? (
          <Empty
            title="暂无 ACL 模板"
            detail="创建空模板后自行添加匹配字段与动作；保存草稿与发布是两个独立操作。"
          />
        ) : (
          <TableFrame>
            <TableHead>
              <TableRow>
                <TableCell>名称</TableCell>
                <TableCell>草稿</TableCell>
                <TableCell>已发布策略</TableCell>
                <TableCell>绑定</TableCell>
                <TableCell>操作</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {q.data.items.map((t) => (
                <TableRow key={t.id}>
                  <TableCell>
                    {t.name}
                    <Typography className="mono">{t.id}</Typography>
                  </TableCell>
                  <TableCell>
                    资源 v{t.version}
                    <Typography variant="caption" display="block">
                      {t.policy.entries.length} 条 · 默认{" "}
                      {t.policy.default_action}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    {t.published ? (
                      <Button onClick={() => setView(t)}>
                        v{t.published.version} · {t.published.entries.length} 条
                      </Button>
                    ) : (
                      "未发布"
                    )}
                  </TableCell>
                  <TableCell>
                    {t.default ? "新建规则默认" : "非默认"}
                    <br />
                    {t.mandatory ? "强制父策略" : "非强制"}
                  </TableCell>
                  <TableCell>
                    <Stack direction="row" flexWrap="wrap">
                      <ACLApplications templateId={t.id} />
                      <Button onClick={() => setEditing(t)}>编辑草稿</Button>
                      <ACLSimulation
                        target={{
                          template_id: t.id,
                          template_revision: "draft",
                        }}
                        title={`${t.name} · 草稿`}
                        label="模拟草稿"
                      />
                      {t.published && (
                        <ACLSimulation
                          target={{
                            template_id: t.id,
                            template_revision: "published",
                          }}
                          title={`${t.name} · 已发布`}
                          label="模拟已发布"
                        />
                      )}
                      <Button
                        onClick={() => {
                          publish.reset();
                          setPublishing(t);
                        }}
                      >
                        发布
                      </Button>
                      <Button
                        disabled={!t.published}
                        onClick={() => setSettings(t)}
                      >
                        绑定设置
                      </Button>
                      <Button
                        color="error"
                        onClick={() => {
                          del.reset();
                          setDeleting(t);
                        }}
                      >
                        删除
                      </Button>
                    </Stack>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </TableFrame>
        )}
      </Load>
      {editing && (
        <TemplateForm
          initial={editing === "new" ? undefined : editing}
          latest={
            editing === "new"
              ? undefined
              : q.data?.items.find((t) => t.id === editing.id)
          }
          reload={() => void q.refetch()}
          onClose={() => setEditing(undefined)}
        />
      )}
      {settings && (
        <BindingSettings
          template={settings}
          onClose={() => setSettings(undefined)}
        />
      )}
      {publishing && (
        <Confirm
          title={`发布 ${publishing.name} 的当前草稿`}
          onClose={() => setPublishing(undefined)}
          onConfirm={() =>
            publish.mutate({
              path: `/acl-templates/${publishing.id}/publish`,
              method: "POST",
              data: { version: publishing.version },
            })
          }
          error={publish.error}
          busy={publish.isPending}
          label="发布当前草稿"
        >
          <Typography>
            草稿有 {publishing.policy.entries.length} 条匹配，默认动作为{" "}
            {publishing.policy.default_action}。当前空间直接引用{" "}
            {rules.data?.items.filter(
              (r) => r.acl_template_id === publishing.id,
            ).length ?? "未知数量"}{" "}
            条规则；其他空间引用也会受影响。
          </Typography>
          {publishing.mandatory && (
            <Alert severity="warning">
              这是强制父策略，发布影响所有空间的 TCP/UDP 规则。
            </Alert>
          )}
          {!publishing.policy.entries.length && (
            <Alert severity="warning">
              空策略发布后，对所有流量执行默认{" "}
              {publishing.policy.default_action}。
              {publishing.policy.default_action === "deny"
                ? "这将拒绝所有匹配范围内流量。"
                : "这将允许所有匹配范围内流量，但仍受其他强制策略约束。"}
            </Alert>
          )}
          <Typography>
            收紧策略可能中断现有连接。发布后等待边缘实际应用，不把提交成功当作生效完成。
          </Typography>
        </Confirm>
      )}
      {deleting && (
        <Confirm
          title={`删除模板 ${deleting.name}`}
          onClose={() => setDeleting(undefined)}
          onConfirm={() =>
            del.mutate({
              path: `/acl-templates/${deleting.id}`,
              method: "DELETE",
            })
          }
          error={del.error}
          busy={del.isPending}
        >
          <Typography>
            请先解除所有规则引用、默认选择与强制标志。服务端会检查其他空间的引用后再删除。
          </Typography>
        </Confirm>
      )}
      <Dialog
        open={!!view}
        onClose={() => setView(undefined)}
        fullWidth
        maxWidth="md"
      >
        <DialogTitle>
          {view?.name} · 已发布 v{view?.published?.version}
        </DialogTitle>
        <DialogContent>
          <Box
            component="pre"
            sx={{
              whiteSpace: "pre-wrap",
              overflowWrap: "anywhere",
              fontSize: 13,
            }}
          >
            {JSON.stringify(view?.published, null, 2)}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setView(undefined)}>关闭</Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
