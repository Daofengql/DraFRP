import type { CarrierQualityRuntime } from "./types";

export const milliseconds = (value: number) =>
  Number.isFinite(value) && value >= 0 ? `${value.toFixed(2)} ms` : "未观测";

export function carrierQualitySummary(quality?: CarrierQualityRuntime) {
  if (!quality || quality.source !== "carrier_probe_v1" || quality.samples < 1)
    return undefined;
  return {
    latest:
      quality.successes > 0 ? milliseconds(quality.latest_rtt_ms) : "未观测",
    range:
      quality.successes > 0
        ? `均值 ${milliseconds(quality.mean_rtt_ms)} · 最小 ${milliseconds(quality.min_rtt_ms)} · 最大 ${milliseconds(quality.max_rtt_ms)}`
        : "窗口内没有成功的往返探测",
    outcomes: `${quality.samples} 次：成功 ${quality.successes} / 超时 ${quality.timeouts} (${((quality.timeouts / quality.samples) * 100).toFixed(1)}%) / 其他失败 ${quality.errors}`,
  };
}
