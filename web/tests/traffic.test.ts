import assert from "node:assert/strict";
import { test } from "node:test";
import {
  trafficLine,
  trafficRangeError,
  trafficRate,
  trafficStats,
  trafficWindow,
} from "../src/traffic.ts";
import type { TrafficHistory, TrafficPoint } from "../src/types.ts";

test("minute ranges stay aligned inside retention, including the full 30 days", () => {
  const at = Date.parse("2026-10-20T12:34:56Z");
  const full = trafficWindow("30d", { start: "", end: "" }, at);
  assert.equal(full.end, Date.parse("2026-10-20T12:35:00Z"));
  assert.equal(trafficRangeError(full.start, full.end, "auto", at), "");
  assert.match(trafficRangeError(full.start, full.end, "1m", at), /1440/);
  assert.equal(
    trafficRangeError(full.end - 86_400_000, full.end, "1m", at),
    "",
  );
  assert.match(trafficRangeError(NaN, full.end, "auto", at), /起止/);
  assert.match(trafficRangeError(full.end, full.start, "auto", at), /起止/);
});

test("traffic zero is an observation and missing reports break the plotted line", () => {
  const points = [
    { samples: 1, upload_bps: 0 },
    { samples: 1, upload_bps: 8 },
    { samples: 0, upload_bps: 0 },
    { samples: 1, upload_bps: 16 },
  ] as TrafficPoint[];
  const line = trafficLine(
    points,
    (p) => p.upload_bps,
    (n, i) => `${i},${n}`,
  );
  assert.equal(line, "M0,0 L1,8  M3,16");
  assert.equal(trafficRate(0), "0 bit/s");
  assert.equal(trafficRate(8_000_000), "8 Mbit/s");
  assert.equal(trafficRate(0.5), "0.5 bit/s");
});

test("history averages use bit/s and the peak is the largest interval average", () => {
  const history = {
    start: "2026-10-20T12:00:00Z",
    end: "2026-10-20T12:02:00Z",
    observed_at: "2026-10-20T12:02:00Z",
    upload_bytes: 60,
    download_bytes: 120,
    points: [
      { samples: 1, upload_bps: 8, download_bps: 16 },
      { samples: 0, upload_bps: 0, download_bps: 0 },
    ],
  } as TrafficHistory;
  assert.deepEqual(trafficStats(history), {
    average: 12,
    peak: 24,
    samples: 1,
  });
});
