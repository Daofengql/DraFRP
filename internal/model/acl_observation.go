package model

import "time"

// ACLPolicyRef identifies the immutable policy actually compiled by an edge.
type ACLPolicyRef struct {
	Kind       string `json:"kind"`
	TemplateID string `json:"template_id,omitempty"`
	Version    uint64 `json:"version"`
	Digest     string `json:"digest"`
}

type ACLApplied struct {
	RuleID           string         `json:"rule_id"`
	RuleVersion      uint64         `json:"rule_version"`
	EffectiveDigest  string         `json:"effective_digest"`
	Policies         []ACLPolicyRef `json:"policies"`
	State            string         `json:"state"`
	Error            string         `json:"error,omitempty"`
	SnapshotRevision uint64         `json:"snapshot_revision"`
	AppliedAt        time.Time      `json:"applied_at"`
	ExpiresAt        time.Time      `json:"expires_at"`
	ActiveFlows      int            `json:"active_flows"`
	SampledAt        time.Time      `json:"sampled_at"`
}

// Counts are cumulative within one edge boot and immutable effective policy.
// No visitor IP, port, hostname, or other attacker-chosen label is retained.
type ACLHit struct {
	RuleID          string       `json:"rule_id"`
	RuleVersion     uint64       `json:"rule_version"`
	EffectiveDigest string       `json:"effective_digest"`
	Protocol        string       `json:"protocol"`
	Kind            string       `json:"kind"`
	Policy          ACLPolicyRef `json:"policy"`
	EntryID         string       `json:"entry_id,omitempty"`
	EntryHash       string       `json:"entry_hash,omitempty"`
	UsedDefault     bool         `json:"used_default"`
	Reason          string       `json:"reason"`
	Allowed         uint64       `json:"allowed"`
	Denied          uint64       `json:"denied"`
	StartedAt       time.Time    `json:"started_at"`
}

type ACLReport struct {
	Sequence   uint64       `json:"sequence"`
	StartedAt  time.Time    `json:"started_at"`
	ObservedAt time.Time    `json:"observed_at"`
	Dropped    uint64       `json:"dropped"`
	Rows       []ACLHit     `json:"rows"`
	ACKs       []ACLApplied `json:"acks"`
}
