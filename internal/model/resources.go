package model

import "time"

// ResourceUsage counts committed configuration, including rules and public
// port reservations awaiting revocation acknowledgement. These counters do not
// replace data-plane account budgets or describe currently active traffic.
type ResourceUsage struct {
	Devices    int64     `json:"devices"`
	Rules      int64     `json:"rules"`
	Ports      int64     `json:"ports"`
	Domains    int64     `json:"domains"`
	Sites      int64     `json:"sites"`
	ObservedAt time.Time `json:"observed_at"`
}
