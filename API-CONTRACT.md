# DraFRP implementation contract

The seven design documents remain authoritative. Shared Go wire types live in `internal/model`. JSON uses snake_case. There are three commands: `drafrp-cloud`, `drafrp-edge`, `drafrp-client`. Only cloud imports SQL, Redis and webui.

Browser API prefix `/api/v1`. JSON errors: `{error:{code,message}}`. Lists: `{items:[],total:N}`. Resource mutations return the persisted resource. Versioned edits send `version` equal to the existing version; server increments it. Creation may send `Idempotency-Key`. Browser writes require `X-CSRF-Token`, obtained from `GET /api/v1/me` or login. Cookie sessions are HttpOnly. No credential in localStorage.

* POST `/auth/login` `{username,password}` -> `{user,csrf_token}`; POST `/auth/logout`; GET `/api/v1/me` -> `{user,csrf_token,build_id}`.
* GET `/api/v1/overview` -> `{devices,online_devices,rules,ready_rules,edges,usage_upload_bytes,usage_download_bytes}` (real measurements only).
* GET/POST `/api/v1/devices`; PATCH/DELETE `/api/v1/devices/{id}` (revoke). Device creation is via binding, not an arbitrary credential issued by browser. POST `/api/v1/bind/confirm` `{user_code,name}`.
* GET/POST `/api/v1/rules`; GET/PUT/DELETE `/api/v1/rules/{id}`. HTTP(S) sites use the same resource, filtered client-side by protocol. Source modes: `socket`, `native`, `forwarded_headers`. Transport: `auto`, `quic_only`, `tls_only`.
* GET/POST `/api/v1/edges`; GET/PUT/DELETE `/api/v1/edges/{id}` (admin). Edge creation `{...edge,token}`; token is write-only.
* GET/POST `/api/v1/acl-templates`; PUT `/api/v1/acl-templates/{id}`; POST `/{id}/publish`; DELETE `/{id}` (admin). No seeded ACL contents.
* GET/POST `/api/v1/certificates`; DELETE `/api/v1/certificates/{id}`. Private keys never returned to browser.
* GET `/api/v1/quotas`; PUT `/api/v1/quotas/{tenant_id}` (admin). GET `/api/v1/usage`; GET `/api/v1/audit`; GET `/api/v1/system`; GET/POST `/api/v1/users` (admin).
* GET `/api/v1/events`: one session-authenticated SSE invalidation stream; reconnect refetches snapshots.

Runtime API (JSON model types):

* POST `/api/v1/runtime/edge/sync`: Bearer edge token, `EdgeSyncRequest` -> `EdgeSnapshot`. Edge boot ID changes on every start. Grants never refill existing balances.
* POST `/api/v1/runtime/client/bind`: `BindRequest` -> `BindResponse`; POST `/api/v1/runtime/client/bind/poll` `{id,poll_token}` -> `BindResponse`. Approved response contains device ID, never browser session. Device owns an Ed25519 private key before binding.
* POST `/api/v1/runtime/client/sync`: `ClientSyncRequest` -> `ClientSnapshot`. Ed25519 signature (base64 standard) over `model.SyncPayload`, maximum clock skew 60 seconds. Conflicting active session is rejected, no repeated eviction. Key encodings use standard base64. Snapshot expiry bounds data plane authority.

Cloud and edge HTTPS clients verify certificates via optional CA file; no default insecure TLS mode. Agent authenticates edge carriers with its private key and edge-issued nonce, comparing device/session/generation against cloud snapshot. Independent ALPN `drafrp/1`.
