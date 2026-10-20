import { QueryClient } from "@tanstack/react-query";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 20_000,
      retry: (count, error) =>
        !(error instanceof APIError && error.status < 500) && count < 1,
      refetchOnWindowFocus: true,
    },
    mutations: { retry: false },
  },
});
let csrf = "";
export function setCSRF(value: string) {
  csrf = value;
}
export class APIError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

export async function request<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body) headers.set("Content-Type", "application/json");
  if (init.method && !["GET", "HEAD"].includes(init.method.toUpperCase()))
    headers.set("X-CSRF-Token", csrf);
  const response = await fetch(
    path.startsWith("/auth/") ? path : `/api/v1${path}`,
    { ...init, headers, credentials: "same-origin", cache: "no-store" },
  );
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    if (response.status === 401 && !path.startsWith("/auth/"))
      window.dispatchEvent(new Event("drafrp-session-expired"));
    throw new APIError(
      response.status,
      body?.error?.code || "request_failed",
      body?.error?.message || `请求失败 (${response.status})`,
    );
  }
  if (response.status === 204) return undefined as T;
  return response.json();
}

export function mutate<T>(
  path: string,
  method: string,
  data?: unknown,
  key?: string,
) {
  return request<T>(path, {
    method,
    body: data === undefined ? undefined : JSON.stringify(data),
    headers: key ? { "Idempotency-Key": key } : undefined,
  });
}

// Keep a key for the exact operation across manual retries after an ambiguous network failure.
export function createIdempotentWriter() {
  let fingerprint = "",
    key = "";
  return <T>(path: string, method: string, data?: unknown) => {
    const next = JSON.stringify([path, method, data]);
    if (next !== fingerprint) {
      fingerprint = next;
      key = crypto.randomUUID();
    }
    return mutate<T>(path, method, data, key);
  };
}

export function errorMessage(error: unknown) {
  if (error instanceof APIError && error.code === "resource_quota_exceeded")
    return `${error.message}。当前输入已保留。`;
  if (error instanceof APIError && error.code === "version_conflict")
    return `配置已被其他操作修改。当前输入已保留，请读取最新配置比较后再保存。${error.message}`;
  if (error instanceof APIError && error.status === 409)
    return `资源冲突：${error.message}。当前输入已保留。`;
  return error instanceof Error ? error.message : "操作失败，请重试";
}
