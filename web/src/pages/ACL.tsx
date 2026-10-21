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
      <DialogTitle>{initial ? "编辑 ACL 草稿" : "创建 ACL 模板"}</DialogTitle>
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
            label="默认动作"
            value={action}
            onChange={(e) => {
              setDirty(true);
              setAction(e.target.value);
            }}
            helperText="未命中条目时执行"
          >
            <MenuItem value="deny">拒绝</MenuItem>
            <MenuItem value="allow">允许</MenuItem>
          </TextField>
          {initial && (
            <>
              <Typography variant="h6">匹配条目</Typography>
              <Typography variant="body2" color="text.secondary">
                按优先级升序匹配，执行首条命中的动作。多值字段以逗号、空格或换行分隔。
              </Typography>
              {!entries.length && <Empty title="暂无匹配条目" />}
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
                        <MenuItem value="allow">允许</MenuItem>
                        <MenuItem value="deny">拒绝</MenuItem>
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
                      label="来源 CIDR（可选）"
                      helperText="留空匹配全部来源"
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
                        helperText="两位大写字母"
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
                        helperText="COUNTRY-REGION 格式，4–16 个字符"
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
                      label="地域未知时的动作"
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
                      helperText="设置国家或地区条件时必填"
                    >
                      <MenuItem value="">请选择</MenuItem>
                      <MenuItem value="deny">拒绝</MenuItem>
                      <MenuItem value="no_match">继续匹配</MenuItem>
                    </TextField>
                    {!!(entry.countries?.length || entry.regions?.length) && (
                      <Alert severity="warning">
                        地区匹配依赖 GeoIP
                        数据库，不可用时停止转发。国家与地区条件取交集。
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
                添加条目
              </Button>
              <ACLSimulation
                target={{
                  policy: {
                    default_action: action,
                    entries: aclDraftEntries(entries),
                    version: initial.policy.version,
                  },
                }}
                title={`${name} · 当前输入`}
                label="模拟草稿"
              />
            </>
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
                保留输入，使用最新版本
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
          {m.isPending ? "保存中…" : initial ? "保存草稿" : "创建模板"}
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
            绑定版本：v{template.published?.version || "—"}
          </Typography>
          <FormControlLabel
            control={
              <Checkbox
                checked={def}
                onChange={(e) => setDef(e.target.checked)}
              />
            }
            label="新建 TCP/UDP 规则的默认模板"
          />
          <FormControlLabel
            control={
              <Checkbox
                checked={mandatory}
                onChange={(e) => setMandatory(e.target.checked)}
              />
            }
            label="全部 TCP/UDP 规则的强制父策略"
          />
          <Alert severity="warning">
            强制父策略与规则策略取交集。收紧策略可能中断现有连接。
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
        detail="TCP/UDP 来源访问策略"
        action={
          <Button variant="contained" onClick={() => setEditing("new")}>
            创建模板
          </Button>
        }
      />
      <Load loading={q.isLoading} error={q.error}>
        {!q.data?.items.length ? (
          <Empty title="暂无 ACL 模板" />
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
                    v{t.version}
                    <Typography variant="caption" display="block">
                      {t.policy.entries.length} 条 · 默认{" "}
                      {t.policy.default_action === "allow" ? "允许" : "拒绝"}
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
          title={`发布模板 ${publishing.name}`}
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
          label="发布"
        >
          <Typography>
            {publishing.policy.entries.length} 条匹配，默认动作：
            {publishing.policy.default_action === "allow" ? "允许" : "拒绝"}
            。当前空间引用：
            {rules.data?.items.filter(
              (r) => r.acl_template_id === publishing.id,
            ).length ?? "未知数量"}{" "}
            条规则。发布影响所有空间的引用规则。
          </Typography>
          {publishing.mandatory && (
            <Alert severity="warning">
              强制父策略：发布影响全部 TCP/UDP 规则。
            </Alert>
          )}
          {!publishing.policy.entries.length && (
            <Alert severity="warning">
              {publishing.policy.default_action === "deny"
                ? "无匹配条目，默认拒绝全部流量。"
                : "无匹配条目，默认允许全部流量；强制父策略仍然生效。"}
            </Alert>
          )}
          <Typography>收紧策略可能中断现有连接。发布后由边缘应用。</Typography>
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
            删除条件：无规则引用，且未设为默认模板或强制父策略。
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
