import { useState } from "react";
import {
  Alert,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Stack,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { fmtDate } from "../format";
import {
  Confirm,
  Empty,
  Load,
  MutationError,
  PageTitle,
  Status,
  TableFrame,
  invalidate,
  useDraftGuard,
  useResource,
  useWriter,
} from "../ui";
import type { Certificate, Rule } from "../types";
import Domains from "./Domains";

function Upload({ onClose }: { onClose: () => void }) {
  const [form, setForm] = useState({ name: "", cert_pem: "", key_pem: "" });
  const canClose = useDraftGuard(
    !!form.name || !!form.cert_pem || !!form.key_pem,
  );
  const clear = () => {
    setForm({ name: "", cert_pem: "", key_pem: "" });
    m.reset();
    onClose();
  };
  const m = useWriter<Certificate>(() => {
    invalidate("certificates");
    clear();
  });
  const close = () => {
    if (!m.isPending && canClose()) clear();
  };
  return (
    <Dialog open onClose={close} fullWidth maxWidth="md">
      <DialogTitle>上传公网证书</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Alert severity="info">
            域名与有效期从证书解析。私钥只在本次上传中提交，查询、详情和后续编辑均不回显。
          </Alert>
          <TextField
            label="证书名称"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            required
            autoFocus
          />
          <TextField
            label="证书链 PEM"
            value={form.cert_pem}
            onChange={(e) => setForm({ ...form, cert_pem: e.target.value })}
            multiline
            minRows={5}
            required
            autoComplete="off"
          />
          <TextField
            label="私钥 PEM（仅提交）"
            value={form.key_pem}
            onChange={(e) => setForm({ ...form, key_pem: e.target.value })}
            multiline
            minRows={5}
            required
            autoComplete="off"
            spellCheck={false}
          />
          <MutationError error={m.error} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button disabled={m.isPending} onClick={close}>
          取消
        </Button>
        <Button
          variant="contained"
          disabled={
            m.isPending ||
            !form.name.trim() ||
            !form.cert_pem.trim() ||
            !form.key_pem.trim()
          }
          onClick={() =>
            m.mutate({ path: "/certificates", method: "POST", data: form })
          }
        >
          {m.isPending ? "上传中…" : "上传证书"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export default function CertificatesPage() {
  const q = useResource<Certificate>("/certificates", "certificates"),
    rules = useResource<Rule>("/rules", "rules");
  const [upload, setUpload] = useState(false),
    [deleting, setDeleting] = useState<Certificate>();
  const del = useWriter(() => {
    setDeleting(undefined);
    invalidate("certificates");
  });
  return (
    <>
      <PageTitle
        title="域名与证书"
        detail="公网 TLS 证书元信息与站点引用；私钥不回显"
        action={
          <Button variant="contained" onClick={() => setUpload(true)}>
            上传证书
          </Button>
        }
      />
      <Domains />
      <Typography variant="h6" sx={{ mt: 4, mb: 2 }}>
        公网证书
      </Typography>
      <Load loading={q.isLoading} error={q.error}>
        {!q.data?.items.length ? (
          <Empty
            title="暂无公网证书"
            detail="HTTP 入口无需公网证书；HTTPS 入口需上传匹配的 PEM 证书链和私钥。"
          />
        ) : (
          <TableFrame>
            <TableHead>
              <TableRow>
                <TableCell>名称</TableCell>
                <TableCell>证书域名</TableCell>
                <TableCell>有效期</TableCell>
                <TableCell>站点引用</TableCell>
                <TableCell>操作</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {q.data.items.map((c) => (
                <TableRow key={c.id}>
                  <TableCell>
                    {c.name}
                    <Typography className="mono">{c.id}</Typography>
                  </TableCell>
                  <TableCell>
                    {c.domains.join("、") || "未包含 DNS 域名"}
                  </TableCell>
                  <TableCell>
                    {fmtDate(c.expires_at)}
                    <br />
                    <Status
                      value={
                        Date.parse(c.expires_at) <= Date.now()
                          ? "expired"
                          : "active"
                      }
                    />
                  </TableCell>
                  <TableCell>
                    {rules.data
                      ? rules.data.items.filter(
                          (r) => r.certificate_id === c.id,
                        ).length
                      : "未读取"}
                    <Typography variant="caption" display="block">
                      部署以站点应用反馈为准
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Button
                      color="error"
                      onClick={() => {
                        del.reset();
                        setDeleting(c);
                      }}
                    >
                      删除
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </TableFrame>
        )}
      </Load>
      {upload && <Upload onClose={() => setUpload(false)} />}
      {deleting && (
        <Confirm
          title={`删除证书 ${deleting.name}`}
          onClose={() => setDeleting(undefined)}
          busy={del.isPending}
          error={del.error}
          onConfirm={() =>
            del.mutate({
              path: `/certificates/${deleting.id}`,
              method: "DELETE",
            })
          }
        >
          <Typography>
            被站点引用的证书不能删除。请先切换关联站点证书，并等待规则应用与释放完成。
          </Typography>
        </Confirm>
      )}
    </>
  );
}
