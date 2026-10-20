// Package model defines the versioned cloud, edge and agent contracts.
package model

import "time"

const APIVersion = "v1"
const ProtocolVersion = 1

type User struct {
	ID string `json:"id"`
	Username string `json:"username"`
	Role string `json:"role"`
	TenantID string `json:"tenant_id"`
	Disabled bool `json:"disabled"`
}
type Device struct {
	ID string `json:"id"`
	TenantID string `json:"tenant_id"`
	Name string `json:"name"`
	PublicKey string `json:"public_key"`
	Revoked bool `json:"revoked"`
	Generation uint64 `json:"generation"`
	SessionID string `json:"session_id,omitempty"`
	LastSeen time.Time `json:"last_seen"`
	Capabilities []string `json:"capabilities"`
	AppliedRevision uint64 `json:"applied_revision"`
}
type Endpoint struct {
	Transport string `json:"transport"`
	Address string `json:"address"`
	ServerName string `json:"server_name"`
}
type Edge struct {
	ID string `json:"id"`
	Name string `json:"name"`
	Endpoints []Endpoint `json:"endpoints"`
	CACert string `json:"ca_cert"`
	PublicHost string `json:"public_host"`
	ListenHost string `json:"listen_host"`
	HTTPPort int `json:"http_port"`
	HTTPSPort int `json:"https_port"`
	PortMin int `json:"port_min"`
	PortMax int `json:"port_max"`
	MaxCarriers int `json:"max_carriers"`
	CapacityBPS int64 `json:"capacity_bps"`
	BootID string `json:"boot_id,omitempty"`
	LastSeen time.Time `json:"last_seen"`
	AppliedRevision uint64 `json:"applied_revision"`
}
type Rule struct {
	ID string `json:"id"`
	TenantID string `json:"tenant_id"`
	Name string `json:"name"`
	Protocol string `json:"protocol"`
	DeviceID string `json:"device_id"`
	EdgeID string `json:"edge_id"`
	PublicPort int `json:"public_port"`
	Domain string `json:"domain,omitempty"`
	Target string `json:"target"`
	Host string `json:"host,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	CertificateID string `json:"certificate_id,omitempty"`
	SourceMode string `json:"source_mode"`
	Transport string `json:"transport"`
	ACLTemplateID string `json:"acl_template_id,omitempty"`
	ACL *ACLPolicy `json:"acl,omitempty"`
	Enabled bool `json:"enabled"`
	Deleting bool `json:"deleting"`
	Version uint64 `json:"version"`
	Status string `json:"status"`
	LastError string `json:"last_error,omitempty"`
	AppliedVersion uint64 `json:"applied_version"`
	TimeoutSeconds int `json:"timeout_seconds"`
}
type ACLEntry struct {
	ID string `json:"id"`
	Priority int `json:"priority"`
	Action string `json:"action"`
	CIDRs []string `json:"cidrs"`
	Protocol string `json:"protocol,omitempty"`
	Ports []int `json:"ports,omitempty"`
}
type ACLPolicy struct {
	DefaultAction string `json:"default_action"`
	Entries []ACLEntry `json:"entries"`
	Version uint64 `json:"version"`
}
type ACLTemplate struct {
	ID string `json:"id"`
	Name string `json:"name"`
	Policy ACLPolicy `json:"policy"`
	Published *ACLPolicy `json:"published,omitempty"`
	Version uint64 `json:"version"`
	Default bool `json:"default"`
	Mandatory bool `json:"mandatory"`
}
type Certificate struct {
	ID string `json:"id"`
	TenantID string `json:"tenant_id"`
	Name string `json:"name"`
	Domains []string `json:"domains"`
	CertPEM string `json:"cert_pem,omitempty"`
	KeyPEM string `json:"key_pem,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Quota struct {
	TenantID string `json:"tenant_id"`
	BaseBPS int64 `json:"base_bps"`
	PeakBPS int64 `json:"peak_bps"`
	BurstBytes int64 `json:"burst_bytes"`
	MaxConnections int `json:"max_connections"`
	NewFlowsPerSecond int `json:"new_flows_per_second"`
	PeriodBytes int64 `json:"period_bytes"`
	UsedBytes int64 `json:"used_bytes"`
	ReservedBytes int64 `json:"reserved_bytes"`
	Version uint64 `json:"version"`
}
type Grant struct {
	ID string `json:"id"`
	TenantID string `json:"tenant_id"`
	EdgeID string `json:"edge_id"`
	BootID string `json:"boot_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Bytes int64 `json:"bytes"`
	BaseBPS int64 `json:"base_bps"`
	PeakBPS int64 `json:"peak_bps"`
	BurstBytes int64 `json:"burst_bytes"`
	MaxConnections int `json:"max_connections"`
	NewFlowsPerSecond int `json:"new_flows_per_second"`
}
type Usage struct {
	GrantID string `json:"grant_id"`
	Sequence uint64 `json:"sequence"`
	UploadBytes int64 `json:"upload_bytes"`
	DownloadBytes int64 `json:"download_bytes"`
	Closed bool `json:"closed"`
	ObservedAt time.Time `json:"observed_at"`
}
type RuleStatus struct {
	ID string `json:"id"`
	Version uint64 `json:"version"`
	Status string `json:"status"`
	Error string `json:"error,omitempty"`
}
type DeviceGrant struct {
	DeviceID string `json:"device_id"`
	TenantID string `json:"tenant_id"`
	PublicKey string `json:"public_key"`
	SessionID string `json:"session_id"`
	Generation uint64 `json:"generation"`
	ExpiresAt time.Time `json:"expires_at"`
}
type EdgeSyncRequest struct {
	EdgeID string `json:"edge_id"`
	BootID string `json:"boot_id"`
	AppliedRevision uint64 `json:"applied_revision"`
	Statuses []RuleStatus `json:"statuses"`
	Usage []Usage `json:"usage"`
}
type EdgeSnapshot struct {
	Revision uint64 `json:"revision"`
	ExpiresAt time.Time `json:"expires_at"`
	Edge Edge `json:"edge"`
	Devices []DeviceGrant `json:"devices"`
	Rules []Rule `json:"rules"`
	Grants []Grant `json:"grants"`
	Certificates []Certificate `json:"certificates"`
	MandatoryACLs []ACLPolicy `json:"mandatory_acls"`
}
type ClientSyncRequest struct {
	DeviceID string `json:"device_id"`
	SessionID string `json:"session_id"`
	Timestamp int64 `json:"timestamp"`
	Signature string `json:"signature"`
	Capabilities []string `json:"capabilities"`
	AppliedRevision uint64 `json:"applied_revision"`
}
type ClientSnapshot struct {
	Revision uint64 `json:"revision"`
	ExpiresAt time.Time `json:"expires_at"`
	Device DeviceGrant `json:"device"`
	Edges []Edge `json:"edges"`
	Rules []Rule `json:"rules"`
}
// SyncPayload binds a signed request to its operation and process session.
func SyncPayload(deviceID, sessionID string, timestamp int64) []byte {
	return []byte("drafrp-client-sync-v1\n" + deviceID + "\n" + sessionID + "\n" + time.Unix(timestamp,0).UTC().Format(time.RFC3339))
}
type BindRequest struct {
	Name string `json:"name"`
	PublicKey string `json:"public_key"`
}
type BindResponse struct {
	ID string `json:"id"`
	UserCode string `json:"user_code"`
	PollToken string `json:"poll_token"`
	VerificationURI string `json:"verification_uri"`
	ExpiresAt time.Time `json:"expires_at"`
	DeviceID string `json:"device_id,omitempty"`
	Status string `json:"status"`
}
