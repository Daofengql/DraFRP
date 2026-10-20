import { QueryClient } from '@tanstack/react-query';
export const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 20_000, retry: 1, refetchOnWindowFocus: true }, mutations: { retry: false } } });
let csrf = '';
export function setCSRF(value: string) { csrf = value; }
export class APIError extends Error { constructor(public status: number, public code: string, message: string) { super(message); } }
export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  if (init.body) headers.set('Content-Type', 'application/json');
  if (init.method && !['GET', 'HEAD'].includes(init.method)) { headers.set('X-CSRF-Token', csrf); headers.set('Idempotency-Key', crypto.randomUUID()); }
  const response = await fetch(path.startsWith('/auth/') ? path : `/api/v1${path}`, { ...init, headers, credentials: 'same-origin', cache: 'no-store' });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    if (response.status === 401 && path !== '/me' && !path.startsWith('/auth/')) window.dispatchEvent(new Event('drafrp-session-expired'));
    throw new APIError(response.status, body?.error?.code || 'request_failed', body?.error?.message || `请求失败 (${response.status})`);
  }
  if (response.status === 204) return undefined as T;
  return response.json();
}
export function mutate<T>(path: string, method: string, data?: unknown) { return request<T>(path, { method, body: data === undefined ? undefined : JSON.stringify(data) }); }
export function errorMessage(error: unknown) {
  if (error instanceof APIError && error.status === 409) return `版本或资源冲突：${error.message}。输入已保留，请关闭后重新载入最新配置进行比较。`;
  return error instanceof Error ? error.message : '操作失败，请重试';
}
