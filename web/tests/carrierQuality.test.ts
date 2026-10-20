import assert from "node:assert/strict";
import { test } from "node:test";
import { carrierQualitySummary, milliseconds } from "../src/carrierQuality.ts";
import type { CarrierQualityRuntime } from "../src/types.ts";

const quality: CarrierQualityRuntime = {
  source: "carrier_probe_v1",
  window_started_at: "2026-10-21T12:00:00Z",
  observed_at: "2026-10-21T12:00:12Z",
  last_success_at: "2026-10-21T12:00:10Z",
  interval_ms: 5000,
  timeout_ms: 2000,
  window_limit: 64,
  samples: 3,
  successes: 1,
  timeouts: 1,
  errors: 1,
  latest_rtt_ms: 17.2,
  mean_rtt_ms: 17.2,
  min_rtt_ms: 17.2,
  max_rtt_ms: 17.2,
};

test("legacy and empty windows never substitute a handshake or zero RTT", () => {
  assert.equal(carrierQualitySummary(), undefined);
  assert.equal(carrierQualitySummary({ ...quality, samples: 0 }), undefined);
  const failed = carrierQualitySummary({
    ...quality,
    successes: 0,
    timeouts: 2,
    latest_rtt_ms: 0,
  });
  assert.equal(failed?.latest, "未观测");
  assert.equal(failed?.range, "窗口内没有成功的往返探测");
  assert.equal(milliseconds(Number.NaN), "未观测");
});

test("the displayed timeout fraction uses all completed probe outcomes", () => {
  const summary = carrierQualitySummary(quality);
  assert.equal(summary?.latest, "17.20 ms");
  assert.equal(summary?.outcomes, "3 次：成功 1 / 超时 1 (33.3%) / 其他失败 1");
  assert.ok(summary?.range.includes("最大 17.20 ms"));
});

test("completed zero-tick probes stay distinct from a missing observation", () => {
  assert.equal(
    carrierQualitySummary({
      ...quality,
      latest_rtt_ms: 0,
      min_rtt_ms: 0,
      mean_rtt_ms: 0,
      max_rtt_ms: 0,
    })?.latest,
    "0.00 ms",
  );
});
