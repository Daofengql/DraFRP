# DraFRP 管理控制台

React 19、TypeScript 严格模式、MUI、TanStack Query、React Router、React Hook Form / Zod。路由固定为 `/console/`，API 为同源 `/api/v1/`，登录接口为 `/auth/`。页面使用本地系统字体与随包图标，不依赖外部 CDN。

## 本地开发

使用 Node.js 22.12 或更新版本（当前验证环境为 Node.js 24）。在 `web/` 执行：

```powershell
npm ci
$env:DRAFRP_DEV_PROXY = 'http://127.0.0.1:8080'
npm run dev
```

打开 Vite 输出的 `/console/` 地址。`/api` 与 `/auth` 代理到已启动的真实云控。登录使用 HttpOnly Cookie，写操作携带 `/me` 返回的 CSRF 值；浏览器持久化存储仅保存主题偏好。

```powershell
npm test
npm run format:check
npm run build
```

测试覆盖 bit/s 与 byte 的单位、配额 `-1` / `0` / 缺失统计、过期心跳、准确 native 能力、地区 ACL 的显式未知来源动作、幂等重试和版本冲突错误。`npm test` 使用 Node 自带测试器与 TypeScript 类型转换，不启动真实后端。

## 发布与嵌入

登录页根据真实 `/auth/options` 显示注册与图形验证码；支持刷新、过期提示、确认密码与服务端错误，注册成功后要求重新登录。从 `/console/bind/:code` 进入时，切换注册和登录均保留设备授权地址。2026-10-21 已使用正式嵌入前端和真实 MySQL 验证注册、错误验证码自动换图、新验证码登录、普通用户权限、指纹确认、设备绑定与云控重启恢复；390×844 注册页无横向溢出，记录见 `docs/validation/2026-10-21/auth-browser.json`。

“公网端口”页面通过实时分页 API 查看业务池、承载/站点系统保留及占用/释放状态。其他空间只显示通用占用信息；可申请状态不预留端口，最终创建仍由后端事务裁决。

设备列表与详情每 10 秒刷新签名传输观测，展示实际承载、活动流、端点失败分类、重试和握手耗时。会话到期后隐藏旧观测；握手时间不作为持续 RTT。ACL 支持未保存草稿、已保存草稿、已发布模板和规则有效链模拟，不产生配置写入。真实 MySQL 与正式三进程的浏览器验证见 `docs/validation/2026-10-21/console-features.json`，包含 183 项端口分页、草稿/发布差异及实际 QUIC 活动流。

从仓库根使用 `scripts/build.ps1` 或 `scripts/build.sh`。发布脚本统一设置 `DRAFRP_BUILD_ID`，构建 `web/dist`，复制到 `internal/webui/dist`，再以 Go `release` 标签构建云控。不要手工维护生成的 `dist`。普通 Go 开发构建提供开发提示页，不要求已有前端产物。

`Vite base`、`BrowserRouter basename`、Go 静态挂载始终对应 `/console/`；反向代理应保留此前缀。深层页面刷新返回 SPA，未知页面由 React 显示 404。缺失静态文件、API、认证路径及非 GET/HEAD 方法不会回退到 SPA。入口禁止缓存，哈希资源为 immutable，普通元数据要求重验证；Go 测试验证 HEAD、ETag 条件请求及服务路由隔离。

## 浏览器检查与证据边界

2026-10-20 使用独立 Playwright CLI 会话，对 `tests/console-fixture.mjs` 的隔离契约环境完成：登录后保留设备授权路由、指纹核对与绑定、设备详情、TCP 修改 v3 冲突保留输入并显式比较 v4 后保存、UDP 自动端口创建、HTTPS 域名与证书选择及 `forwarded_headers` 请求、空 deny ACL 草稿发布、含随机令牌和真实 endpoint 字段的边缘登记。另检查了 1440px 桌面与 390px 窄屏用量页，无页面水平溢出。

后续回归覆盖地区条件的未知来源动作必选与手工字段保留、TCP/UDP native 精确能力的启用和禁用、只有 `/me` 返回 401 时的旧会话清理，以及节点实际监听/错误、GeoIP 加载错误、wire 接口累计计数与单位展示。节点详情截图保存在本地忽略的 `output/playwright/edge-wire-runtime.png`；这些运行数据也是隔离 fixture 输入。

这证明页面交互与请求形状，不证明真实 MySQL 持久化、DNS、公网证书部署或业务隧道连通；真实全栈验证由仓库 Go 集成测试与三服务验收完成。fixture 只能在本机临时检查 UI，不能部署为云控：

```powershell
node tests/console-fixture.mjs
```

仅当隔离环境运行时打开 `http://127.0.0.1:5173/console/bind/TESTCODE`；示例用户名与密码是测试输入，不是项目预置账号。检查结束后停止进程。截图与 Playwright 临时输出位于忽略的 `.playwright-cli/` 或 `output/playwright/`。

控制台只展示服务端已有观测。配置保存与监听应用不等于目标健康；没有逐设备 RTT、窗口速率或目标探测时明确显示未上报。native 入口仅在设备上报对应 `native_tcp_ipv4_ip_port` / `native_udp_ipv4_ip_port` 时可选，语义为 Linux IPv4 透明 socket 严格保留 IP 与端口；TUN 和 IPv6 保源不作为已实现能力展示。

管理员可在边缘列表打开运行观测，查看边缘实际采样的监听状态与错误、QUIC/TLS 承载数、活动业务流、UDP 映射及快照授权期限，以及 GeoIP 数据库状态、版本和加载错误。陈旧观测明确标注，节点统计包含全部空间；容量执行口径按后端实际报告区分 payload、wire 与 wire_failed，未知字段不会当作已实现。可选 Linux wire 整形为接口发出方向，物理 RX/TX 是包含控制、封装和重传的接口累计计数，与账号业务计量分别展示。

ACL 国家与地区字段使用自由文本，不包含预制列表。国家为两位大写代码，地区使用 `COUNTRY-REGION` 格式；使用任一条件时必须显式选择 `deny` 或 `no_match` 作为未知来源动作。地区策略依赖边缘管理员提供有效 GeoIP 数据库；数据库缺失或无效时拒绝承载，与有效数据库内地址未命中的处理分开。保存草稿保留所有手工输入，发布仍为独立操作。
