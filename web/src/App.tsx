import {
  lazy,
  Suspense,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { Link, Route, Routes, useLocation } from "react-router-dom";
import { useQuery, useMutation } from "@tanstack/react-query";
import {
  Alert,
  AppBar,
  Box,
  Button,
  Chip,
  CircularProgress,
  Collapse,
  Container,
  CssBaseline,
  Drawer,
  IconButton,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  MenuItem,
  Paper,
  Stack,
  TextField,
  Toolbar,
  Typography,
  useMediaQuery,
  ThemeProvider,
  createTheme,
} from "@mui/material";
import MenuIcon from "@mui/icons-material/Menu";
import LogoutIcon from "@mui/icons-material/Logout";
import DashboardOutlinedIcon from "@mui/icons-material/DashboardOutlined";
import HubOutlinedIcon from "@mui/icons-material/HubOutlined";
import DnsOutlinedIcon from "@mui/icons-material/DnsOutlined";
import DataUsageOutlinedIcon from "@mui/icons-material/DataUsageOutlined";
import AdminPanelSettingsOutlinedIcon from "@mui/icons-material/AdminPanelSettingsOutlined";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import { APIError, errorMessage, queryClient, request, setCSRF } from "./api";
import { SessionContext, useSessionEvents } from "./ui";
import type { Session } from "./types";
import AuthPage from "./pages/Auth";

const DevicesPage = lazy(() =>
  import("./pages/Devices").then((m) => ({ default: m.DevicesPage })),
);
const DevicePage = lazy(() =>
  import("./pages/Devices").then((m) => ({ default: m.DevicePage })),
);
const BindPage = lazy(() =>
  import("./pages/Devices").then((m) => ({ default: m.BindPage })),
);
const RulesPage = lazy(() =>
  import("./pages/Rules").then((m) => ({ default: m.RulesPage })),
);
const RulePage = lazy(() =>
  import("./pages/Rules").then((m) => ({ default: m.RulePage })),
);
const CertificatesPage = lazy(() => import("./pages/Certificates"));
const PortsPage = lazy(() => import("./pages/Ports"));
const OverviewPage = lazy(() =>
  import("./pages/Monitoring").then((m) => ({ default: m.OverviewPage })),
);
const UsagePage = lazy(() =>
  import("./pages/Monitoring").then((m) => ({ default: m.UsagePage })),
);
const AuditPage = lazy(() =>
  import("./pages/Monitoring").then((m) => ({ default: m.AuditPage })),
);
const UsersPage = lazy(() =>
  import("./pages/Admin").then((m) => ({ default: m.UsersPage })),
);
const EdgesPage = lazy(() =>
  import("./pages/Admin").then((m) => ({ default: m.EdgesPage })),
);
const QuotasPage = lazy(() =>
  import("./pages/Admin").then((m) => ({ default: m.QuotasPage })),
);
const ACLPage = lazy(() => import("./pages/ACL"));

declare const __BUILD_ID__: string;
type NavLink = { path: string; label: string };
type NavItem = {
  id: string;
  label: string;
  icon: ReactNode;
  adminOnly?: boolean;
} & (
  | { path: string; children?: never }
  | { path?: never; children: NavLink[] }
);
const nav: NavItem[] = [
  { id: "overview", path: "/", label: "概览", icon: <DashboardOutlinedIcon /> },
  {
    id: "connections",
    label: "连接管理",
    icon: <HubOutlinedIcon />,
    children: [
      { path: "/devices", label: "设备" },
      { path: "/rules", label: "TCP / UDP 隧道" },
      { path: "/sites", label: "HTTP(S) 站点" },
    ],
  },
  {
    id: "resources",
    label: "网络资源",
    icon: <DnsOutlinedIcon />,
    children: [
      { path: "/ports", label: "公网端口" },
      { path: "/certificates", label: "域名与证书" },
    ],
  },
  {
    id: "usage",
    path: "/usage",
    label: "用量",
    icon: <DataUsageOutlinedIcon />,
  },
  {
    id: "platform",
    label: "平台管理",
    icon: <AdminPanelSettingsOutlinedIcon />,
    adminOnly: true,
    children: [
      { path: "/admin/overview", label: "平台概览" },
      { path: "/admin/users", label: "用户与空间" },
      { path: "/admin/edges", label: "边缘与端口池" },
      { path: "/admin/quotas", label: "账号配额" },
      { path: "/admin/acl", label: "TCP/UDP ACL 模板" },
      { path: "/admin/audit", label: "审计与系统" },
    ],
  },
];
function matchesNav(pathname: string, path: string) {
  return pathname === path || (path !== "/" && pathname.startsWith(`${path}/`));
}
const loading = (
  <Box role="status" aria-label="加载中" sx={{ p: 8, textAlign: "center" }}>
    <CircularProgress />
  </Box>
);

function Shell({
  session,
  themeMode,
  onTheme,
  children,
}: {
  session: Session;
  themeMode: string;
  onTheme: (mode: string) => void;
  children: ReactNode;
}) {
  const loc = useLocation(),
    small = useMediaQuery("(max-width:900px)");
  const [open, setOpen] = useState(false);
  const admin = ["admin", "platform_admin"].includes(session.user.role);
  const items = nav.filter((item) => !item.adminOnly || admin);
  const currentItem = items.find((item) =>
    item.children
      ? item.children.some(({ path }) => matchesNav(loc.pathname, path))
      : matchesNav(loc.pathname, item.path),
  );
  const currentGroup = currentItem?.children ? currentItem.id : null;
  const currentPage = currentItem?.children
    ? currentItem.children.find(({ path }) => matchesNav(loc.pathname, path))
        ?.label
    : currentItem?.label;
  const current = currentPage
    ? [currentGroup && currentItem?.label, currentPage]
        .filter(Boolean)
        .join(" / ")
    : "页面不存在";
  const [expandedGroup, setExpandedGroup] = useState(currentGroup);
  useEffect(() => {
    setExpandedGroup(currentGroup);
  }, [loc.pathname, currentGroup]);
  const logout = useMutation({
    mutationFn: () => request<void>("/auth/logout", { method: "POST" }),
    onSuccess: () => {
      setCSRF("");
      queryClient.removeQueries({ predicate: (q) => q.queryKey[0] !== "me" });
      queryClient.setQueryData(["me"], null);
    },
  });
  const navLink = (item: NavLink, icon?: ReactNode) => {
    const active = matchesNav(loc.pathname, item.path);
    return (
      <ListItem key={item.path} disablePadding>
        <ListItemButton
          component={Link}
          to={item.path}
          onClick={() => setOpen(false)}
          selected={active}
          aria-current={active ? "page" : undefined}
          sx={{
            pl: icon ? 2 : 6.5,
            borderRadius: 1,
            color: active ? "primary.main" : "text.secondary",
            "& .MuiListItemText-primary": {
              fontSize: 14,
              fontWeight: active ? 700 : 400,
            },
          }}
        >
          {icon && (
            <ListItemIcon sx={{ minWidth: 36, color: "inherit" }}>
              {icon}
            </ListItemIcon>
          )}
          <ListItemText primary={item.label} />
        </ListItemButton>
      </ListItem>
    );
  };
  const drawer = (
    <Box sx={{ width: 244, py: 1 }} component="nav" aria-label="控制台导航">
      <Typography
        sx={{ px: 3, py: 2 }}
        variant="h6"
        fontWeight={800}
        color="primary"
      >
        DraFRP
      </Typography>
      <List disablePadding sx={{ px: 1 }}>
        {items.map((item) => {
          if (!item.children) return navLink(item, item.icon);
          const expanded = expandedGroup === item.id;
          const active = currentGroup === item.id;
          return (
            <Box component="li" key={item.id} sx={{ listStyle: "none" }}>
              <ListItemButton
                onClick={() => setExpandedGroup(expanded ? null : item.id)}
                aria-expanded={expanded}
                aria-controls={`nav-${item.id}`}
                sx={{
                  borderRadius: 1,
                  color: active ? "primary.main" : "text.secondary",
                }}
              >
                <ListItemIcon sx={{ minWidth: 36, color: "inherit" }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={item.label}
                  primaryTypographyProps={{
                    fontSize: 14,
                    fontWeight: active ? 700 : 500,
                  }}
                />
                {expanded ? (
                  <ExpandLessIcon fontSize="small" />
                ) : (
                  <ExpandMoreIcon fontSize="small" />
                )}
              </ListItemButton>
              <Collapse in={expanded} timeout="auto" unmountOnExit>
                <List
                  id={`nav-${item.id}`}
                  aria-label={item.label}
                  disablePadding
                >
                  {item.children.map((child) => navLink(child))}
                </List>
              </Collapse>
            </Box>
          );
        })}
      </List>
    </Box>
  );
  return (
    <Box sx={{ minHeight: "100vh" }}>
      <AppBar
        position="fixed"
        color="inherit"
        elevation={0}
        sx={{
          borderBottom: 1,
          borderColor: "divider",
          zIndex: (t) => (small ? t.zIndex.appBar : t.zIndex.drawer + 1),
        }}
      >
        <Toolbar>
          {small && (
            <IconButton
              onClick={() => setOpen(!open)}
              edge="start"
              aria-label="打开导航"
            >
              <MenuIcon />
            </IconButton>
          )}
          <Typography
            sx={{ flex: 1, minWidth: 0, mr: 1 }}
            noWrap
            title={`控制台 / ${current}`}
            color="text.secondary"
          >
            控制台 / {current}
          </Typography>
          <TextField
            select
            size="small"
            label="主题"
            value={themeMode}
            onChange={(e) => onTheme(e.target.value)}
            sx={{ width: 100, mr: 1 }}
          >
            <MenuItem value="system">跟随系统</MenuItem>
            <MenuItem value="light">浅色</MenuItem>
            <MenuItem value="dark">深色</MenuItem>
          </TextField>
          <Typography sx={{ mx: 1, display: { xs: "none", sm: "block" } }}>
            {session.user.username}
          </Typography>
          <IconButton
            onClick={() => logout.mutate()}
            disabled={logout.isPending}
            aria-label="退出登录"
          >
            <LogoutIcon />
          </IconButton>
        </Toolbar>
      </AppBar>
      <Drawer
        variant={small ? "temporary" : "permanent"}
        open={!small || open}
        onClose={() => setOpen(false)}
        ModalProps={{ keepMounted: true }}
        sx={{
          "& .MuiDrawer-paper": {
            top: small ? 0 : 64,
            height: small ? "100%" : "calc(100% - 64px)",
          },
        }}
      >
        {drawer}
      </Drawer>
      <Box
        component="main"
        sx={{ ml: small ? 0 : "244px", pt: 10, px: { xs: 2, md: 4 }, pb: 6 }}
      >
        <Container maxWidth="xl">
          <Stack
            direction="row"
            spacing={1}
            alignItems="center"
            sx={{ mb: 2, overflowWrap: "anywhere" }}
          >
            <Chip size="small" label="当前空间" />
            <Typography variant="body2" className="mono">
              {session.user.tenant_id}
            </Typography>
          </Stack>
          {logout.error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {errorMessage(logout.error)}
            </Alert>
          )}
          {children}
        </Container>
      </Box>
    </Box>
  );
}

function Authenticated({
  session,
  themeMode,
  onTheme,
}: {
  session: Session;
  themeMode: string;
  onTheme: (mode: string) => void;
}) {
  const events = useSessionEvents(
    `${session.user.id}/${session.user.tenant_id}`,
  );
  const location = useLocation();
  const admin = ["admin", "platform_admin"].includes(session.user.role);
  const buildMismatch =
    __BUILD_ID__ !== "development" &&
    session.build_id &&
    session.build_id !== __BUILD_ID__;
  const notices = (
    <>
      {events === "disconnected" && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          状态事件连接已中断。当前显示最后快照，页面可见时将以 15–60
          秒间隔重新读取。
        </Alert>
      )}
      {buildMismatch && (
        <Alert
          severity="warning"
          sx={{ mb: 2 }}
          action={
            <Button color="inherit" onClick={() => window.location.reload()}>
              刷新版本
            </Button>
          }
        >
          服务已升级。请先处理未提交的表单，再刷新页面。页面 {__BUILD_ID__} /
          服务 {session.build_id}
        </Alert>
      )}
    </>
  );
  const content = (
    <Suspense fallback={loading}>
      <Routes>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/devices" element={<DevicesPage />} />
        <Route path="/devices/:id" element={<DevicePage />} />
        <Route path="/rules" element={<RulesPage />} />
        <Route path="/rules/:id" element={<RulePage />} />
        <Route path="/ports" element={<PortsPage />} />
        <Route path="/sites" element={<RulesPage sites />} />
        <Route path="/sites/:id" element={<RulePage />} />
        <Route path="/certificates" element={<CertificatesPage />} />
        <Route path="/usage" element={<UsagePage />} />
        {admin && (
          <>
            <Route path="/admin/overview" element={<OverviewPage platform />} />
            <Route path="/admin/users" element={<UsersPage />} />
            <Route path="/admin/edges" element={<EdgesPage />} />
            <Route path="/admin/quotas" element={<QuotasPage />} />
            <Route path="/admin/acl" element={<ACLPage />} />
            <Route path="/admin/audit" element={<AuditPage />} />
          </>
        )}
        <Route
          path="*"
          element={
            <Paper variant="outlined" sx={{ p: 4 }}>
              <Typography variant="h4" gutterBottom>
                404 · 页面不存在
              </Typography>
              <Button component={Link} to="/">
                返回概览
              </Button>
            </Paper>
          }
        />
      </Routes>
    </Suspense>
  );
  return (
    <SessionContext.Provider value={session}>
      {location.pathname.startsWith("/bind/") ? (
        <Container maxWidth="sm" sx={{ py: 6 }}>
          {notices}
          <Suspense fallback={loading}>
            <Routes>
              <Route path="/bind/:code" element={<BindPage />} />
            </Routes>
          </Suspense>
        </Container>
      ) : (
        <Shell session={session} themeMode={themeMode} onTheme={onTheme}>
          {notices}
          {content}
        </Shell>
      )}
    </SessionContext.Provider>
  );
}

export default function App() {
  const systemDark = useMediaQuery("(prefers-color-scheme: dark)");
  const [mode, setMode] = useState(
    () => localStorage.getItem("drafrp-theme") || "system",
  );
  const theme = useMemo(
    () =>
      createTheme({
        palette: {
          mode:
            mode === "dark" || (mode === "system" && systemDark)
              ? "dark"
              : "light",
          primary: { main: "#258781" },
        },
        shape: { borderRadius: 8 },
        typography: { fontFamily: '"Segoe UI", "Microsoft YaHei", sans-serif' },
        components: {
          MuiButton: { defaultProps: { disableElevation: true } },
          MuiPaper: { styleOverrides: { root: { backgroundImage: "none" } } },
        },
      }),
    [mode, systemDark],
  );
  const session = useQuery<Session | null>({
    queryKey: ["me"],
    queryFn: ({ signal }) => request<Session>("/me", { signal }),
    retry: false,
    staleTime: 60_000,
  });
  useEffect(() => {
    setCSRF(session.data?.csrf_token || "");
  }, [session.data]);
  useEffect(() => {
    const expired = () => {
      setCSRF("");
      void queryClient.cancelQueries();
      queryClient.removeQueries({ predicate: (q) => q.queryKey[0] !== "me" });
      queryClient.setQueryData(["me"], null);
    };
    window.addEventListener("drafrp-session-expired", expired);
    return () => window.removeEventListener("drafrp-session-expired", expired);
  }, []);
  const content = session.isPending ? (
    loading
  ) : session.error &&
    !(session.error instanceof APIError && session.error.status === 401) ? (
    <Container maxWidth="sm" sx={{ py: 8 }}>
      <Alert severity="error">
        无法读取登录状态：{errorMessage(session.error)}
      </Alert>
      <Button sx={{ mt: 2 }} onClick={() => session.refetch()}>
        重新连接
      </Button>
    </Container>
  ) : !session.data ? (
    <AuthPage />
  ) : (
    <Authenticated
      session={session.data}
      themeMode={mode}
      onTheme={(m) => {
        setMode(m);
        localStorage.setItem("drafrp-theme", m);
      }}
    />
  );
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      {content}
    </ThemeProvider>
  );
}
