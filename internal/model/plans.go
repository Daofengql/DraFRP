package model

// Plan is an administrator-managed service package. Bandwidth uses bit/s and
// applies to the account across all exit nodes. Nil allowed edges on Quota
// means all nodes; an empty slice grants none.
type Plan struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	BandwidthBPS   int64    `json:"bandwidth_bps"`
	BurstEnabled   bool     `json:"burst_enabled"`
	BurstBPS       int64    `json:"burst_bps"`
	BurstSeconds   int64    `json:"burst_seconds"`
	TrafficMetered bool     `json:"traffic_metered"`
	TrafficBytes   int64    `json:"traffic_bytes"`
	PeriodSeconds  int64    `json:"period_seconds"`
	OverageAction  string   `json:"overage_action"`
	OverageBPS     int64    `json:"overage_bps"`
	MaxPorts       int      `json:"max_ports"`
	MaxSites       int      `json:"max_sites"`
	AllEdges       bool     `json:"all_edges"`
	EdgeIDs        []string `json:"edge_ids"`
	Default        bool     `json:"default"`
	Version        uint64   `json:"version"`
	Members        int      `json:"members"`
	Legacy         bool     `json:"legacy"`
}
