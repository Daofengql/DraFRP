// Browser wire contract mirrors internal/model. Read types contain no long-lived secrets.
export interface User {
  id: string;
  username: string;
  role: string;
  tenant_id: string;
  disabled: boolean;
  created_at?: string;
  plan_id?: string;
  plan_name?: string;
}
export interface Session {
  user: User;
  csrf_token: string;
  build_id?: string;
}
export interface Plan {
  id: string;
  name: string;
  bandwidth_bps: number;
  burst_enabled: boolean;
  burst_bps: number;
  burst_seconds: number;
  traffic_metered: boolean;
  traffic_bytes: number;
  period_seconds: number;
  overage_action: "reject" | "throttle";
  overage_bps: number;
  max_ports: number;
  max_sites: number;
  all_edges: boolean;
  edge_ids: string[];
  default: boolean;
  version: number;
  members: number;
  legacy: boolean;
}
export interface Account {
  user: User;
  plan: Plan | null;
  quota: Quota;
}
export interface Device {
  id: string;
  tenant_id: string;
  name: string;
  revoked: boolean;
  generation: number;
  session_id?: string;
  last_seen: string;
  capabilities: string[];
  applied_revision: number;
  runtime?: DeviceRuntime;
}
export interface DeviceRuntime {
  reported_at: string;
  received_at: string;
  snapshot_expires_at: string;
  session_id: string;
  generation: number;
  preferred_transport: string;
  active_flows: number;
  active_carriers: number;
  quic_carriers: number;
  tls_carriers: number;
  truncated: boolean;
  carriers: Array<{
    edge_id: string;
    transport: string;
    address: string;
    server_name: string;
    active_flows: number;
    established_at: string;
    handshake_ms: number;
    quality?: CarrierQualityRuntime;
  }>;
  endpoints: Array<{
    edge_id: string;
    transport: string;
    address: string;
    server_name: string;
    recent_failures: number;
    retry_at?: string;
    last_attempt?: string;
    last_success?: string;
    handshake_ms: number;
    error_code?: string;
    probing: boolean;
  }>;
}
export interface CarrierQualityRuntime {
  source: "carrier_probe_v1";
  window_started_at: string;
  observed_at: string;
  last_success_at: string;
  interval_ms: number;
  timeout_ms: number;
  window_limit: number;
  samples: number;
  successes: number;
  timeouts: number;
  errors: number;
  latest_rtt_ms: number;
  mean_rtt_ms: number;
  min_rtt_ms: number;
  max_rtt_ms: number;
  quic?: {
    source: "quic_go_rfc9002";
    started_at: string;
    observed_at: string;
    latest_rtt_ms: number;
    smoothed_rtt_ms: number;
    min_rtt_ms: number;
    packets_sent: number;
    packets_received: number;
    bytes_sent: number;
    bytes_received: number;
    packets_lost: number;
    bytes_lost: number;
  };
}
export interface Endpoint {
  transport: string;
  address: string;
  server_name: string;
}
export interface Edge {
  id: string;
  name: string;
  endpoints: Endpoint[];
  ca_cert: string;
  public_host: string;
  listen_host: string;
  http_port: number;
  https_port: number;
  port_min: number;
  port_max: number;
  max_carriers: number;
  capacity_bps: number;
  last_seen: string;
  applied_revision: number;
  boot_id?: string;
  runtime?: EdgeRuntime;
}
export interface EdgeRuntime {
  reported_at: string;
  snapshot_expires_at: string;
  endpoints: Array<{
    transport: string;
    address: string;
    listening: boolean;
    error?: string;
  }>;
  active_flows: number;
  active_carriers: number;
  quic_carriers: number;
  tls_carriers: number;
  udp_mappings: number;
  capacity_enforcement: "payload" | "wire" | "wire_failed";
  physical_interface?: string;
  wire_rate_bps?: number;
  physical_tx_bytes?: number;
  physical_rx_bytes?: number;
  physical_observed_at?: string;
  capacity_error?: string;
  geoip_state?: "unconfigured" | "ready" | "error";
  geoip_version?: string;
  geoip_error?: string;
}
export interface ACLEntry {
  id: string;
  priority: number;
  action: string;
  cidrs?: string[];
  protocol?: string;
  ports?: number[];
  countries?: string[];
  regions?: string[];
  geo_unknown_action?: "deny" | "no_match";
  not_before?: string;
  expires_at?: string;
}
export interface ACLPolicy {
  default_action: string;
  entries: ACLEntry[];
  version: number;
}
export interface ACLTemplate {
  id: string;
  name: string;
  policy: ACLPolicy;
  published?: ACLPolicy;
  version: number;
  default: boolean;
  mandatory: boolean;
}
export interface Rule {
  plan_restricted?: boolean;
  id: string;
  tenant_id: string;
  name: string;
  protocol: string;
  device_id: string;
  edge_id: string;
  public_port: number;
  domain?: string;
  target: string;
  host?: string;
  server_name?: string;
  certificate_id?: string;
  source_mode: string;
  transport: string;
  acl_template_id?: string;
  acl?: ACLPolicy;
  enabled: boolean;
  deleting: boolean;
  version: number;
  status: string;
  last_error?: string;
  applied_version: number;
  timeout_seconds: number;
}
export interface Domain {
  id: string;
  domain: string;
  status: string;
  txt_name: string;
  txt_value: string;
  verified_at?: string;
  created_at: string;
}
export interface Certificate {
  id: string;
  tenant_id: string;
  name: string;
  domains: string[];
  expires_at: string;
}
export interface Quota {
  plan_id: string;
  allowed_edge_ids: string[] | null;
  max_sites: number;
  tenant_id: string;
  base_bps: number;
  peak_bps: number;
  burst_bytes: number;
  max_connections: number;
  new_flows_per_second: number;
  max_devices?: number;
  max_rules?: number;
  max_ports?: number;
  max_domains?: number;
  resources?: {
    sites: number;
    devices: number;
    rules: number;
    ports: number;
    domains: number;
    observed_at: string;
  };
  period_bytes: number;
  overage_action: "reject" | "throttle";
  overage_bps: number;
  used_bytes: number;
  reserved_bytes: number;
  version: number;
  period_id?: string;
  period_seconds?: number;
  period_started_at?: string;
  period_ends_at?: string;
}
export interface Overview {
  devices: number;
  online_devices: number;
  rules: number;
  ready_rules: number;
  edges: number;
  usage_upload_bytes: number;
  usage_download_bytes: number;
}
export interface Binding {
  user_code: string;
  name: string;
  public_key_fingerprint: string;
  status: string;
  expires_at: string;
}
export interface Usage {
  grant_id: string;
  tenant_id: string;
  edge_id: string;
  boot_id: string;
  upload_bytes: number;
  download_bytes: number;
  sequence: number;
  closed: boolean;
  observed_at: string;
}
export interface Audit {
  id: string;
  actor: string;
  action: string;
  resource_id: string;
  tenant_id: string;
  created_at: string;
}
export interface System {
  mysql: string;
  cache?: {
    backend?: string;
    hits?: number;
    evictions?: number;
    [key: string]: unknown;
  };
  build_id: string;
  started_at: string;
}
export interface List<T> {
  items: T[];
  total: number;
}

export interface TrafficPoint {
  start: string;
  end: string;
  upload_bytes: number;
  download_bytes: number;
  upload_bps: number;
  download_bps: number;
  samples: number;
  receipt_bytes: number;
}

export interface TrafficHistory {
  scope: "tenant" | "platform";
  edge_id?: string;
  start: string;
  end: string;
  interval_seconds: number;
  available_from: string;
  observed_at: string;
  upload_bytes: number;
  download_bytes: number;
  receipt_bytes: number;
  points: TrafficPoint[];
}
