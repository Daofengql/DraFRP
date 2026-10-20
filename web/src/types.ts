// Browser contract mirrors internal/model. Secrets are deliberately absent from read types.
export interface User { id: string; username: string; role: string; tenant_id: string; disabled: boolean }
export interface Session { user: User; csrf_token: string; build_id?: string }
export interface Device { id: string; tenant_id: string; name: string; revoked: boolean; generation: number; last_seen: string; capabilities: string[]; applied_revision: number }
export interface Endpoint { transport: string; address: string; server_name: string }
export interface Edge { id: string; name: string; endpoints: Endpoint[]; ca_cert: string; public_host: string; listen_host: string; http_port: number; https_port: number; port_min: number; port_max: number; max_carriers: number; capacity_bps: number; last_seen: string; applied_revision: number; boot_id?: string }
export interface ACLEntry { id: string; priority: number; action: string; cidrs: string[]; protocol?: string; ports?: number[] }
export interface ACLPolicy { default_action: string; entries: ACLEntry[]; version: number }
export interface ACLTemplate { id: string; name: string; policy: ACLPolicy; published?: ACLPolicy; version: number; default: boolean; mandatory: boolean }
export interface Rule { id: string; tenant_id: string; name: string; protocol: string; device_id: string; edge_id: string; public_port: number; domain?: string; target: string; host?: string; server_name?: string; certificate_id?: string; source_mode: string; transport: string; acl_template_id?: string; enabled: boolean; deleting: boolean; version: number; status: string; last_error?: string; applied_version: number; timeout_seconds: number }
export interface Certificate { id: string; tenant_id: string; name: string; domains: string[]; expires_at: string }
export interface Quota { tenant_id: string; base_bps: number; peak_bps: number; burst_bytes: number; max_connections: number; new_flows_per_second: number; period_bytes: number; used_bytes: number; reserved_bytes: number; version: number }
export interface Overview { devices: number; online_devices: number; rules: number; ready_rules: number; edges: number; usage_upload_bytes: number; usage_download_bytes: number }
export interface List<T> { items: T[]; total: number }
export type RecordData = Record<string, unknown>;
