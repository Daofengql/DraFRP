import assert from "node:assert/strict";
import { test } from "node:test";
import {
  fmtBytes,
  fmtDate,
  fmtLimit,
  fmtRate,
  nativeSourceCapability,
  observedOnline,
  ruleState,
} from "../src/format.ts";

test("quota rates are bits, sentinel zero and unlimited remain distinct from missing telemetry", () => {
  assert.equal(fmtRate(8_000_000), "8 Mbit/s");
  assert.equal(fmtRate(-1), "不限");
  assert.equal(fmtRate(0), "禁止 (0 bit/s)");
  assert.equal(fmtRate(undefined), "未观测");
  assert.equal(fmtBytes(1024), "1 KiB");
  assert.equal(fmtBytes(undefined), "暂无统计");
  assert.equal(fmtBytes(-1), "不限");
  assert.equal(fmtLimit(0), "禁止 (0)");
});

test("native selection requires the exact protocol and IPv4 IP+port capability", () => {
  assert.equal(nativeSourceCapability("tcp", ["tun", "native"]), false);
  assert.equal(
    nativeSourceCapability("tcp", ["native_udp_ipv4_ip_port"]),
    false,
  );
  assert.equal(
    nativeSourceCapability("tcp", ["native_tcp_ipv4_ip_port"]),
    true,
  );
  assert.equal(
    nativeSourceCapability("udp", ["native_udp_ipv4_ip_port"]),
    true,
  );
  assert.equal(
    nativeSourceCapability("http", ["native_tcp_ipv4_ip_port"]),
    false,
  );
});

test("zero Go times, stale heartbeats and future clocks never imply online", () => {
  const now = Date.parse("2026-10-20T00:00:00Z");
  assert.equal(fmtDate("0001-01-01T00:00:00Z"), "未上报");
  assert.equal(observedOnline("0001-01-01T00:00:00Z", now), false);
  assert.equal(observedOnline("2026-10-19T23:55:00Z", now), false);
  assert.equal(observedOnline("2026-10-20T00:10:00Z", now), false);
  assert.equal(observedOnline("2026-10-19T23:59:50Z", now), true);
  assert.equal(
    ruleState({ deleting: true, enabled: false, status: "ready" }),
    "deleting",
  );
  assert.equal(
    ruleState({ deleting: false, enabled: false, status: "ready" }),
    "disabled",
  );
});
