export function fmtBytes(n?: number) {
  if (n === undefined || !Number.isFinite(n)) return "暂无统计";
  if (n < 0) return "不限";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const i =
    n === 0
      ? 0
      : Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
  return `${(n / 1024 ** i).toLocaleString("zh-CN", { maximumFractionDigits: i ? 1 : 0 })} ${units[i]}`;
}
export function fmtRate(n?: number) {
  if (n === undefined || !Number.isFinite(n)) return "未观测";
  if (n < 0) return "不限";
  if (n === 0) return "禁止 (0 bit/s)";
  const units = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s"];
  const i = Math.min(
    Math.floor(Math.log(n) / Math.log(1000)),
    units.length - 1,
  );
  return `${(n / 1000 ** i).toLocaleString("zh-CN", { maximumFractionDigits: 2 })} ${units[i]}`;
}
export function fmtLimit(n: number, unit = "") {
  return n < 0
    ? "不限"
    : n === 0
      ? "禁止 (0)"
      : `${n.toLocaleString("zh-CN")}${unit}`;
}
export function fmtPeriod(seconds = 0) {
  if (!seconds) return "不重置";
  if (seconds % 86400 === 0) return `每 ${seconds / 86400} 天`;
  if (seconds % 3600 === 0) return `每 ${seconds / 3600} 小时`;
  if (seconds % 60 === 0) return `每 ${seconds / 60} 分钟`;
  return `每 ${seconds} 秒`;
}
export function fmtDate(value?: string) {
  if (!value || value.startsWith("0001-")) return "未上报";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? "未知时间" : d.toLocaleString("zh-CN");
}
export function observedOnline(lastSeen?: string, now = Date.now()) {
  const at = lastSeen ? Date.parse(lastSeen) : NaN;
  return (
    Number.isFinite(at) && at > 0 && now - at >= -60_000 && now - at < 120_000
  );
}
export function ruleState(rule: {
  deleting: boolean;
  enabled: boolean;
  status: string;
  plan_restricted?: boolean;
}) {
  return rule.deleting
    ? "deleting"
    : rule.plan_restricted
      ? "plan_restricted"
      : !rule.enabled
        ? "disabled"
        : rule.status || "unknown";
}
export function nativeSourceCapability(
  protocol: string,
  capabilities: string[] = [],
) {
  return (
    ["tcp", "udp"].includes(protocol) &&
    capabilities.includes(`native_${protocol}_ipv4_ip_port`)
  );
}
