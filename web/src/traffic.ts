import type { TrafficHistory, TrafficPoint } from "./types.ts";

export type TrafficInterval = "auto" | "1m" | "5m" | "1h" | "1d";
export type TrafficRange = "1h" | "6h" | "24h" | "7d" | "30d" | "custom";
export const trafficIntervals: [TrafficInterval, string, number][] = [
  ["auto", "自动", 0],
  ["1m", "1 分钟", 60_000],
  ["5m", "5 分钟", 300_000],
  ["1h", "1 小时", 3_600_000],
  ["1d", "1 天", 86_400_000],
];

export function localDateTime(at: number) {
  const d = new Date(at);
  return new Date(at - d.getTimezoneOffset() * 60_000)
    .toISOString()
    .slice(0, 16);
}

export function trafficWindow(
  range: TrafficRange,
  custom: { start: string; end: string },
  now = Date.now(),
) {
  const end = Math.ceil(now / 60_000) * 60_000;
  if (range === "custom") {
    return { start: Date.parse(custom.start), end: Date.parse(custom.end) };
  }
  const hours = { "1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720 };
  return { start: end - hours[range] * 3_600_000, end };
}

export function trafficRangeError(
  start: number,
  end: number,
  interval: TrafficInterval,
  now = Date.now(),
) {
  const latest = Math.ceil(now / 60_000) * 60_000;
  if (
    !Number.isFinite(start) ||
    !Number.isFinite(end) ||
    end <= start ||
    start < latest - 30 * 86_400_000 ||
    end > latest
  ) {
    return "请选择最近 30 天内的有效起止时间";
  }
  const step = trafficIntervals.find(([key]) => key === interval)![2];
  if (step && Math.ceil((end - start) / step) > 1440) {
    return "数据点超过 1440 个，请缩短时间范围或选择更大的统计粒度";
  }
  return "";
}

export function trafficRate(value: number) {
  if (!value) return "0 bit/s";
  const units = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"];
  const unit = Math.max(0, Math.min(4, Math.floor(Math.log10(value) / 3)));
  return `${(value / 1000 ** unit).toLocaleString("zh-CN", { maximumFractionDigits: 2 })} ${units[unit]}`;
}

export function trafficLine(
  points: TrafficPoint[],
  value: (p: TrafficPoint) => number,
  xy: (n: number, i: number) => string,
) {
  let connected = false;
  return points
    .map((p, i) => {
      if (!p.samples) {
        connected = false;
        return "";
      }
      const part = `${connected ? "L" : "M"}${xy(value(p), i)}`;
      connected = true;
      return part;
    })
    .join(" ");
}

export function trafficStats(history: TrafficHistory) {
  const seconds = Math.max(
    1,
    (Math.min(Date.parse(history.end), Date.parse(history.observed_at)) -
      Date.parse(history.start)) /
      1000,
  );
  return {
    average: ((history.upload_bytes + history.download_bytes) * 8) / seconds,
    peak: Math.max(
      0,
      ...history.points.map((p) => p.upload_bps + p.download_bps),
    ),
    samples: history.points.filter((p) => p.samples > 0).length,
  };
}
