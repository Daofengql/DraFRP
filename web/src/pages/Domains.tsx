import { useState } from "react";
import {
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
import { fmtDate } from "../format";
import {
  Confirm,
  Empty,
  Load,
  MutationError,
  Status,
  TableFrame,
  invalidate,
  useResource,
  useWriter,
} from "../ui";
import type { Domain } from "../types";

export default function Domains() {
  const q = useResource<Domain>("/domains", "domains");
  const [creating, setCreating] = useState(false),
    [domain, setDomain] = useState(""),
    [deleting, setDeleting] = useState<Domain>(),
    [challenge, setChallenge] = useState<Domain>();
  const create = useWriter<Domain>((d) => {
    setCreating(false);
    setDomain("");
    setChallenge(d);
    invalidate("domains");
  });
  const verify = useWriter<Domain>((d) => {
    setChallenge(d);
    invalidate("domains");
  });
  const del = useWriter(() => {
    setDeleting(undefined);
    invalidate("domains");
  });
  return (
    <>
      <Stack
        direction={{ xs: "column", sm: "row" }}
        justifyContent="space-between"
        spacing={1}
        sx={{ mb: 2 }}
      >
        <Typography variant="h6">域名归属验证</Typography>
        <Button
          variant="outlined"
          onClick={() => {
            create.reset();
            setCreating(true);
          }}
        >
          添加域名
        </Button>
      </Stack>
      <Load loading={q.isLoading} error={q.error}>
        {!q.data?.items.length ? (
          <Empty title="暂无域名" />
        ) : (
          <TableFrame>
            <TableHead>
              <TableRow>
                <TableCell>域名</TableCell>
                <TableCell>归属状态</TableCell>
                <TableCell>验证时间</TableCell>
                <TableCell>操作</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {q.data.items.map((d) => (
                <TableRow key={d.id}>
                  <TableCell>{d.domain}</TableCell>
                  <TableCell>
                    <Status
                      value={
                        d.status === "pending"
                          ? "waiting_verification"
                          : d.status
                      }
                    />
                  </TableCell>
                  <TableCell>{fmtDate(d.verified_at)}</TableCell>
                  <TableCell>
                    <Button
                      onClick={() => {
                        verify.reset();
                        setChallenge(d);
                      }}
                    >
                      TXT 记录 / 验证
                    </Button>
                    <Button
                      color="error"
                      onClick={() => {
                        del.reset();
                        setDeleting(d);
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
      <Dialog
        open={creating}
        onClose={() => !create.isPending && setCreating(false)}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>添加域名</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="完整域名"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              required
              autoFocus
              helperText="不含协议、端口或路径"
            />
            <MutationError error={create.error} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button
            disabled={create.isPending}
            onClick={() => setCreating(false)}
          >
            取消
          </Button>
          <Button
            variant="contained"
            disabled={!domain.trim() || create.isPending}
            onClick={() =>
              create.mutate({
                path: "/domains",
                method: "POST",
                data: { domain: domain.trim() },
              })
            }
          >
            生成验证记录
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={!!challenge}
        onClose={() => !verify.isPending && setChallenge(undefined)}
        fullWidth
        maxWidth="md"
      >
        <DialogTitle>{challenge?.domain} · DNS TXT 验证</DialogTitle>
        <DialogContent>
          <Stack spacing={2}>
            {challenge && (
              <>
                <Status value={challenge.status} />
                <Typography>验证记录：DNS TXT</Typography>
                <Paper variant="outlined" sx={{ p: 2 }}>
                  <Typography variant="caption">记录名称</Typography>
                  <Typography className="mono" sx={{ userSelect: "all" }}>
                    {challenge.txt_name}
                  </Typography>
                  <Typography variant="caption">TXT 值</Typography>
                  <Typography className="mono" sx={{ userSelect: "all" }}>
                    {challenge.txt_value}
                  </Typography>
                </Paper>
                <MutationError error={verify.error} />
              </>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button
            disabled={verify.isPending}
            onClick={() => setChallenge(undefined)}
          >
            关闭
          </Button>
          <Button
            variant="contained"
            disabled={verify.isPending || !challenge}
            onClick={() =>
              verify.mutate({
                path: `/domains/${challenge!.id}/verify`,
                method: "POST",
                data: {},
              })
            }
          >
            {verify.isPending ? "检查 DNS 中…" : "验证 TXT 记录"}
          </Button>
        </DialogActions>
      </Dialog>
      {deleting && (
        <Confirm
          title={`删除域名 ${deleting.domain}`}
          onClose={() => setDeleting(undefined)}
          onConfirm={() =>
            del.mutate({ path: `/domains/${deleting.id}`, method: "DELETE" })
          }
          busy={del.isPending}
          error={del.error}
        >
          <Typography>无站点引用时可删除。重新添加后需验证归属。</Typography>
        </Confirm>
      )}
    </>
  );
}
