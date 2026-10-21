// Package model defines the versioned cloud, edge and agent contracts.
package model

import (
	"encoding/json"
	"time"
)

const APIVersion = "v1"
const ProtocolVersion = 1

type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	TenantID  string    `json:"tenant_id"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	PlanID    string    `json:"plan_id,omitempty"`
	PlanName  string    `json:"plan_name,omitempty"`
}
type Device struct {
	ID              string         `json:"id"`
	TenantID        string         `json:"tenant_id"`
	Name            string         `json:"name"`
	PublicKey       string         `json:"public_key"`
	Revoked         bool           `json:"revoked"`
	Generation      uint64         `json:"generation"`
	SessionID       string         `json:"session_id,omitempty"`
	LastSeen        time.Time      `json:"last_seen"`
	Capabilities    []string       `json:"capabilities"`
	AppliedRevision uint64         `json:"applied_revision"`
	Runtime         *DeviceRuntime `json:"runtime,omitempty"`
}

// DeviceRuntime is sampled by the Agent and signed with its process session.
// SessionID, Generation and ReceivedAt are assigned by the accepting cloud;
// these observations never grant forwarding authority. Carrier quality names
// its own measurement source and interval independently of handshake timing.
type DeviceRuntime struct {
	ReportedAt         time.Time               `json:"reported_at"`
	ReceivedAt         time.Time               `json:"received_at,omitempty"`
	SessionID          string                  `json:"session_id,omitempty"`
	Generation         uint64                  `json:"generation,omitempty"`
	SnapshotExpiresAt  time.Time               `json:"snapshot_expires_at"`
	PreferredTransport string                  `json:"preferred_transport"`
	ActiveFlows        int                     `json:"active_flows"`
	ActiveCarriers     int                     `json:"active_carriers"`
	QUICCarriers       int                     `json:"quic_carriers"`
	TLSCarriers        int                     `json:"tls_carriers"`
	Carriers           []DeviceCarrierRuntime  `json:"carriers"`
	Endpoints          []DeviceEndpointRuntime `json:"endpoints"`
	Truncated          bool                    `json:"truncated"`
}

type DeviceCarrierRuntime struct {
	EdgeID        string                 `json:"edge_id"`
	Transport     string                 `json:"transport"`
	Address       string                 `json:"address"`
	ServerName    string                 `json:"server_name"`
	ActiveFlows   int                    `json:"active_flows"`
	EstablishedAt time.Time              `json:"established_at"`
	HandshakeMS   float64                `json:"handshake_ms"`
	Quality       *CarrierQualityRuntime `json:"quality,omitempty"`
}

type DeviceEndpointRuntime struct {
	EdgeID         string    `json:"edge_id"`
	Transport      string    `json:"transport"`
	Address        string    `json:"address"`
	ServerName     string    `json:"server_name"`
	RecentFailures uint      `json:"recent_failures"`
	RetryAt        time.Time `json:"retry_at,omitempty"`
	LastAttempt    time.Time `json:"last_attempt,omitempty"`
	LastSuccess    time.Time `json:"last_success,omitempty"`
	HandshakeMS    float64   `json:"handshake_ms"`
	ErrorCode      string    `json:"error_code,omitempty"`
	Probing        bool      `json:"probing"`
}

const MaxDeviceRuntimeEntries = 128

type Endpoint struct {
	Transport  string `json:"transport"`
	Address    string `json:"address"`
	ServerName string `json:"server_name"`
}

// EndpointRuntime is an edge observation, not a promise inferred from config.
type EndpointRuntime struct {
	Transport string `json:"transport"`
	Address   string `json:"address"`
	Listening bool   `json:"listening"`
	Error     string `json:"error,omitempty"`
}

type EdgeRuntime struct {
	ReportedAt          time.Time         `json:"reported_at"`
	SnapshotExpiresAt   time.Time         `json:"snapshot_expires_at"`
	Endpoints           []EndpointRuntime `json:"endpoints"`
	ActiveFlows         int               `json:"active_flows"`
	ActiveCarriers      int               `json:"active_carriers"`
	QUICCarriers        int               `json:"quic_carriers"`
	TLSCarriers         int               `json:"tls_carriers"`
	UDPMappings         int               `json:"udp_mappings"`
	CapacityEnforcement string            `json:"capacity_enforcement"`
	PhysicalInterface   string            `json:"physical_interface,omitempty"`
	WireRateBPS         int64             `json:"wire_rate_bps,omitempty"`
	PhysicalTXBytes     uint64            `json:"physical_tx_bytes"`
	PhysicalRXBytes     uint64            `json:"physical_rx_bytes"`
	PhysicalObservedAt  time.Time         `json:"physical_observed_at,omitempty"`
	CapacityError       string            `json:"capacity_error,omitempty"`
	GeoIPState          string            `json:"geoip_state"`
	GeoIPVersion        string            `json:"geoip_version,omitempty"`
	GeoIPError          string            `json:"geoip_error,omitempty"`
}
type Edge struct {
	ID              string       `json:"id"`
	Name            string       `json:"name"`
	Endpoints       []Endpoint   `json:"endpoints"`
	CACert          string       `json:"ca_cert"`
	PublicHost      string       `json:"public_host"`
	ListenHost      string       `json:"listen_host"`
	HTTPPort        int          `json:"http_port"`
	HTTPSPort       int          `json:"https_port"`
	PortMin         int          `json:"port_min"`
	PortMax         int          `json:"port_max"`
	MaxCarriers     int          `json:"max_carriers"`
	CapacityBPS     int64        `json:"capacity_bps"`
	BootID          string       `json:"boot_id,omitempty"`
	LastSeen        time.Time    `json:"last_seen"`
	AppliedRevision uint64       `json:"applied_revision"`
	Runtime         *EdgeRuntime `json:"runtime,omitempty"`
}
type Rule struct {
	PlanRestricted bool       `json:"plan_restricted,omitempty"`
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	Name           string     `json:"name"`
	Protocol       string     `json:"protocol"`
	DeviceID       string     `json:"device_id"`
	EdgeID         string     `json:"edge_id"`
	PublicPort     int        `json:"public_port"`
	Domain         string     `json:"domain,omitempty"`
	Target         string     `json:"target"`
	Host           string     `json:"host,omitempty"`
	ServerName     string     `json:"server_name,omitempty"`
	CertificateID  string     `json:"certificate_id,omitempty"`
	SourceMode     string     `json:"source_mode"`
	Transport      string     `json:"transport"`
	ACLTemplateID  string     `json:"acl_template_id,omitempty"`
	ACL            *ACLPolicy `json:"acl,omitempty"`
	Enabled        bool       `json:"enabled"`
	Deleting       bool       `json:"deleting"`
	Version        uint64     `json:"version"`
	Status         string     `json:"status"`
	LastError      string     `json:"last_error,omitempty"`
	AppliedVersion uint64     `json:"applied_version"`
	TimeoutSeconds int        `json:"timeout_seconds"`
}
type ACLEntry struct {
	ID               string     `json:"id"`
	Priority         int        `json:"priority"`
	Action           string     `json:"action"`
	CIDRs            []string   `json:"cidrs"`
	Protocol         string     `json:"protocol,omitempty"`
	Ports            []int      `json:"ports,omitempty"`
	NotBefore        *time.Time `json:"not_before,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	Countries        []string   `json:"countries,omitempty"`
	Regions          []string   `json:"regions,omitempty"`
	GeoUnknownAction string     `json:"geo_unknown_action,omitempty"`
}
type ACLPolicy struct {
	TemplateID    string     `json:"template_id,omitempty"`
	DefaultAction string     `json:"default_action"`
	Entries       []ACLEntry `json:"entries"`
	Version       uint64     `json:"version"`
}
type ACLTemplate struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Policy    ACLPolicy  `json:"policy"`
	Published *ACLPolicy `json:"published,omitempty"`
	Version   uint64     `json:"version"`
	Default   bool       `json:"default"`
	Mandatory bool       `json:"mandatory"`
}
type Certificate struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	Domains   []string  `json:"domains"`
	CertPEM   string    `json:"cert_pem,omitempty"`
	KeyPEM    string    `json:"key_pem,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Quota struct {
	PlanID            string         `json:"plan_id"`
	AllowedEdgeIDs    []string       `json:"allowed_edge_ids"`
	MaxSites          int            `json:"max_sites"`
	TenantID          string         `json:"tenant_id"`
	BaseBPS           int64          `json:"base_bps"`
	PeakBPS           int64          `json:"peak_bps"`
	BurstBytes        int64          `json:"burst_bytes"`
	MaxConnections    int            `json:"max_connections"`
	NewFlowsPerSecond int            `json:"new_flows_per_second"`
	MaxDevices        int            `json:"max_devices"`
	MaxRules          int            `json:"max_rules"`
	MaxPorts          int            `json:"max_ports"`
	MaxDomains        int            `json:"max_domains"`
	Resources         *ResourceUsage `json:"resources,omitempty"`
	PeriodBytes       int64          `json:"period_bytes"`
	OverageAction     string         `json:"overage_action"`
	OverageBPS        int64          `json:"overage_bps"`
	UsedBytes         int64          `json:"used_bytes"`
	ReservedBytes     int64          `json:"reserved_bytes"`
	Version           uint64         `json:"version"`
	PeriodID          string         `json:"period_id"`
	PeriodSeconds     int64          `json:"period_seconds"`
	PeriodStartedAt   time.Time      `json:"period_started_at"`
	PeriodEndsAt      time.Time      `json:"period_ends_at"`
}
type Grant struct {
	WaitForCredit     bool      `json:"wait_for_credit,omitempty"`
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	EdgeID            string    `json:"edge_id"`
	BootID            string    `json:"boot_id"`
	ExpiresAt         time.Time `json:"expires_at"`
	Bytes             int64     `json:"bytes"`
	BaseBPS           int64     `json:"base_bps"`
	PeakBPS           int64     `json:"peak_bps"`
	BurstBytes        int64     `json:"burst_bytes"`
	MaxConnections    int       `json:"max_connections"`
	NewFlowsPerSecond int       `json:"new_flows_per_second"`
	PolicyVersion     uint64    `json:"policy_version"`
	PeriodID          string    `json:"period_id"`
}
type Usage struct {
	Minutes       []TrafficMinute `json:"minutes,omitempty"`
	GrantID       string          `json:"grant_id"`
	Sequence      uint64          `json:"sequence"`
	UploadBytes   int64           `json:"upload_bytes"`
	DownloadBytes int64           `json:"download_bytes"`
	Closed        bool            `json:"closed"`
	ObservedAt    time.Time       `json:"observed_at"`
}
type RuleStatus struct {
	ID      string `json:"id"`
	Version uint64 `json:"version"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
}
type DeviceGrant struct {
	DeviceID     string    `json:"device_id"`
	TenantID     string    `json:"tenant_id"`
	PublicKey    string    `json:"public_key"`
	SessionID    string    `json:"session_id"`
	Generation   uint64    `json:"generation"`
	ExpiresAt    time.Time `json:"expires_at"`
	Capabilities []string  `json:"capabilities,omitempty"`
}
type EdgeSyncRequest struct {
	ACL             *ACLReport   `json:"acl,omitempty"`
	EdgeID          string       `json:"edge_id"`
	BootID          string       `json:"boot_id"`
	AppliedRevision uint64       `json:"applied_revision"`
	Statuses        []RuleStatus `json:"statuses"`
	Usage           []Usage      `json:"usage"`
	Runtime         *EdgeRuntime `json:"runtime,omitempty"`
}
type EdgeSnapshot struct {
	Revision      uint64        `json:"revision"`
	ExpiresAt     time.Time     `json:"expires_at"`
	Edge          Edge          `json:"edge"`
	Devices       []DeviceGrant `json:"devices"`
	Rules         []Rule        `json:"rules"`
	Grants        []Grant       `json:"grants"`
	Certificates  []Certificate `json:"certificates"`
	MandatoryACLs []ACLPolicy   `json:"mandatory_acls"`
}
type ClientSyncRequest struct {
	DeviceID        string         `json:"device_id"`
	SessionID       string         `json:"session_id"`
	Timestamp       int64          `json:"timestamp"`
	Signature       string         `json:"signature"`
	Capabilities    []string       `json:"capabilities"`
	AppliedRevision uint64         `json:"applied_revision"`
	Nonce           string         `json:"nonce"`
	Runtime         *DeviceRuntime `json:"runtime,omitempty"`
}

// ClientSyncPayload signs every field that can affect authorization or status.
func ClientSyncPayload(r ClientSyncRequest) []byte {
	r.Signature = ""
	b, _ := json.Marshal(r)
	return append([]byte("drafrp-client-sync-v2\n"), b...)
}

type ClientSnapshot struct {
	Revision  uint64      `json:"revision"`
	ExpiresAt time.Time   `json:"expires_at"`
	Device    DeviceGrant `json:"device"`
	Edges     []Edge      `json:"edges"`
	Rules     []Rule      `json:"rules"`
}

// SyncPayload binds a signed request to its operation and process session.
func SyncPayload(deviceID, sessionID string, timestamp int64) []byte {
	return []byte("drafrp-client-sync-v1\n" + deviceID + "\n" + sessionID + "\n" + time.Unix(timestamp, 0).UTC().Format(time.RFC3339))
}

type BindRequest struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}
type BindResponse struct {
	ID              string    `json:"id"`
	UserCode        string    `json:"user_code"`
	PollToken       string    `json:"poll_token"`
	VerificationURI string    `json:"verification_uri"`
	ExpiresAt       time.Time `json:"expires_at"`
	DeviceID        string    `json:"device_id,omitempty"`
	Status          string    `json:"status"`
}
