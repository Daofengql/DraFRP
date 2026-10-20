import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Paper,
  Stack,
  Table,
  TableContainer,
  Typography,
} from "@mui/material";
import {
  APIError,
  createIdempotentWriter,
  errorMessage,
  queryClient,
  request,
} from "./api";
import type { List, Session } from "./types";

export const SessionContext = createContext<Session | null>(null);
export function useSessionContext() {
  return useContext(SessionContext)!;
}
export function useResource<T>(
  path: string,
  key: string,
  enabled = true,
  refetchInterval: number | false = false,
) {
  const session = useSessionContext();
  return useQuery<List<T>>({
    queryKey: [key, session.user.id, session.user.tenant_id, path],
    queryFn: ({ signal }) => request<List<T>>(path, { signal }),
    enabled,
    refetchInterval,
  });
}
export function useWriter<T>(onSuccess: (data: T) => void) {
  const [write] = useState(() => createIdempotentWriter());
  return useMutation({
    mutationFn: ({
      path,
      method,
      data,
    }: {
      path: string;
      method: string;
      data?: unknown;
    }) => write<T>(path, method, data),
    onSuccess,
  });
}
export function invalidate(...keys: string[]) {
  for (const key of keys)
    void queryClient.invalidateQueries({ queryKey: [key] });
}
export function useDraftGuard(dirty: boolean) {
  useEffect(() => {
    if (!dirty) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [dirty]);
  return () => !dirty || window.confirm("放弃尚未提交的输入？");
}

const labels: Record<string, string> = {
  ready: "承载已应用",
  online: "近期在线",
  offline: "离线 / 观测过期",
  pending: "已保存，等待应用",
  deleting: "正在释放",
  disabled: "已停用",
  revoked: "已撤销",
  error: "应用失败",
  capability_missing: "能力不足",
  healthy: "正常",
  unhealthy: "异常",
  unknown: "未检查",
  active: "有效",
  closed: "已关闭",
  applied: "已应用",
  approved: "已确认",
  verified: "归属已验证",
  listening: "采样时已监听",
  not_listening: "未监听",
  waiting_confirmation: "等待确认",
  waiting_verification: "等待 DNS 验证",
  expired: "已过期",
  cancelled: "已取消",
  used: "已使用",
};
export function Status({ value }: { value?: string }) {
  const text = value || "unknown";
  const good = [
    "online",
    "healthy",
    "active",
    "applied",
    "approved",
    "verified",
  ].includes(text);
  const bad = [
    "error",
    "capability_missing",
    "unhealthy",
    "revoked",
    "expired",
  ].includes(text);
  return (
    <Chip
      size="small"
      label={labels[text] || text}
      color={good ? "success" : bad ? "error" : "default"}
      variant={good ? "filled" : "outlined"}
    />
  );
}
export function Empty({
  title,
  detail,
  action,
}: {
  title: string;
  detail?: string;
  action?: ReactNode;
}) {
  return (
    <Paper
      variant="outlined"
      sx={{ p: 4, textAlign: "center", borderStyle: "dashed" }}
    >
      <Typography variant="h6">{title}</Typography>
      {detail && (
        <Typography color="text.secondary" sx={{ mt: 1 }}>
          {detail}
        </Typography>
      )}
      {action && <Box sx={{ mt: 2 }}>{action}</Box>}
    </Paper>
  );
}
export function PageTitle({
  title,
  detail,
  action,
}: {
  title: string;
  detail?: string;
  action?: ReactNode;
}) {
  return (
    <Stack
      direction={{ xs: "column", sm: "row" }}
      justifyContent="space-between"
      alignItems={{ sm: "center" }}
      spacing={2}
      sx={{ mb: 3 }}
    >
      <Box>
        <Typography variant="h4" component="h1" fontWeight={700}>
          {title}
        </Typography>
        {detail && (
          <Typography color="text.secondary" sx={{ mt: 0.5 }}>
            {detail}
          </Typography>
        )}
      </Box>
      {action}
    </Stack>
  );
}
export function TableFrame({ children }: { children: ReactNode }) {
  return (
    <TableContainer component={Paper} variant="outlined">
      <Table size="small" className="resource-table">
        {children}
      </Table>
    </TableContainer>
  );
}
export function Load({
  loading,
  error,
  children,
}: {
  loading: boolean;
  error: unknown;
  children: ReactNode;
}) {
  if (loading)
    return (
      <Box
        role="status"
        aria-label="加载中"
        sx={{ py: 8, textAlign: "center" }}
      >
        <CircularProgress />
      </Box>
    );
  if (error)
    return (
      <Alert severity="error" sx={{ mb: 2 }}>
        {errorMessage(error)}
      </Alert>
    );
  return <>{children}</>;
}
export function MutationError({
  error,
  reload,
}: {
  error: unknown;
  reload?: () => void;
}) {
  if (!error) return null;
  return (
    <Alert
      severity="error"
      action={
        error instanceof APIError &&
        error.code === "version_conflict" &&
        reload ? (
          <Button color="inherit" onClick={reload}>
            读取最新配置
          </Button>
        ) : undefined
      }
    >
      {errorMessage(error)}
    </Alert>
  );
}
export function Confirm({
  title,
  children,
  onClose,
  onConfirm,
  busy,
  error,
  label = "确认",
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  onConfirm: () => void;
  busy?: boolean;
  error?: unknown;
  label?: string;
}) {
  return (
    <Dialog open onClose={() => !busy && onClose()} fullWidth maxWidth="sm">
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <Stack spacing={2}>
          {children}
          <MutationError error={error} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={busy}>
          取消
        </Button>
        <Button
          onClick={onConfirm}
          disabled={busy}
          variant="contained"
          color="error"
        >
          {busy ? "提交中…" : label}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
export function DetailField({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <Box>
      <Typography variant="caption" color="text.secondary">
        {label}
      </Typography>
      <Box sx={{ overflowWrap: "anywhere" }}>{children}</Box>
    </Box>
  );
}

// Exactly one stream per authenticated session. Named invalidations are advisory;
// reopening always fetches a snapshot to recover events lost while offline.
export function useSessionEvents(identity: string) {
  const [state, setState] = useState<
    "connecting" | "connected" | "disconnected"
  >("connecting");
  useEffect(() => {
    let disposed = false,
      timer: ReturnType<typeof setTimeout> | undefined,
      delay = 15_000;
    const es = new EventSource("/api/v1/events");
    const refresh = () => {
      if (!disposed) void queryClient.invalidateQueries();
    };
    const poll = () => {
      if (disposed) return;
      if (document.visibilityState === "visible") refresh();
      delay = Math.min(delay * 2, 60_000);
      timer = setTimeout(poll, delay);
    };
    es.onopen = () => {
      setState("connected");
      delay = 15_000;
      clearTimeout(timer);
      timer = undefined;
      refresh();
    };
    es.onerror = () => {
      setState("disconnected");
      if (!timer) timer = setTimeout(poll, delay);
    };
    es.addEventListener("invalidate", refresh);
    es.onmessage = refresh;
    const visibility = () => {
      if (document.visibilityState === "visible") refresh();
    };
    document.addEventListener("visibilitychange", visibility);
    return () => {
      disposed = true;
      es.close();
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", visibility);
    };
  }, [identity]);
  return state;
}
