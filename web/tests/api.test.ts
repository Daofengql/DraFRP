import assert from "node:assert/strict";
import { test } from "node:test";
import {
  APIError,
  createIdempotentWriter,
  errorMessage,
  request,
  setCSRF,
} from "../src/api.ts";

test("ambiguous create retries retain their key and version; changed drafts get a new operation key", async () => {
  const calls: Array<{ path: string; headers: Headers; body: string }> = [];
  const original = globalThis.fetch;
  let fail = true;
  globalThis.fetch = (async (
    input: string | URL | Request,
    init?: RequestInit,
  ) => {
    calls.push({
      path: String(input),
      headers: new Headers(init?.headers),
      body: String(init?.body),
    });
    assert.equal(init?.credentials, "same-origin");
    assert.equal(init?.cache, "no-store");
    if (fail) {
      fail = false;
      throw new TypeError("connection reset after server committed");
    }
    return new Response(JSON.stringify({ id: "rule", version: 8 }), {
      status: 200,
    });
  }) as typeof fetch;
  try {
    setCSRF("session-csrf");
    const write = createIdempotentWriter();
    const draft = { name: "retained input", protocol: "udp", version: 7 };
    await assert.rejects(write("/rules/rule", "PUT", draft));
    await write("/rules/rule", "PUT", draft);
    assert.equal(
      calls[0].headers.get("Idempotency-Key"),
      calls[1].headers.get("Idempotency-Key"),
    );
    assert.ok(calls[0].headers.get("Idempotency-Key"));
    assert.equal(calls[1].headers.get("X-CSRF-Token"), "session-csrf");
    assert.equal(JSON.parse(calls[1].body).version, 7);
    await write("/rules/rule", "PUT", { ...draft, name: "changed" });
    assert.notEqual(
      calls[1].headers.get("Idempotency-Key"),
      calls[2].headers.get("Idempotency-Key"),
    );
    await request("/rules");
    assert.equal(calls[3].headers.has("Idempotency-Key"), false);
  } finally {
    globalThis.fetch = original;
    setCSRF("");
  }
});

test("resource and version conflicts remain distinguishable and preserve draft guidance", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(
      JSON.stringify({
        error: { code: "version_conflict", message: "changed" },
      }),
      { status: 409 },
    )) as typeof fetch;
  try {
    await assert.rejects(
      request("/rules/rule"),
      (e) =>
        e instanceof APIError &&
        e.code === "version_conflict" &&
        errorMessage(e).includes("输入已保留"),
    );
    assert.ok(
      errorMessage(
        new APIError(409, "domain_unverified", "TXT missing"),
      ).includes("资源冲突"),
    );
  } finally {
    globalThis.fetch = original;
  }
});

test("expired session inspection clears authenticated state even without another active resource", async () => {
  const originalFetch = globalThis.fetch;
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const events: string[] = [];
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: { dispatchEvent: (event: Event) => events.push(event.type) },
  });
  globalThis.fetch = (async () =>
    new Response(
      JSON.stringify({ error: { code: "unauthorized", message: "expired" } }),
      { status: 401 },
    )) as typeof fetch;
  try {
    await assert.rejects(
      request("/me"),
      (e) => e instanceof APIError && e.status === 401,
    );
    assert.deepEqual(events, ["drafrp-session-expired"]);
    await assert.rejects(request("/auth/login", { method: "POST" }));
    assert.equal(events.length, 1);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalWindow)
      Object.defineProperty(globalThis, "window", originalWindow);
    else Reflect.deleteProperty(globalThis, "window");
  }
});
