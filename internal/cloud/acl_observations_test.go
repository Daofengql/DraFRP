package cloud

import (
	"drafrp/internal/acl"
	"drafrp/internal/model"
	"strings"
	"testing"
	"time"
)

func TestACLReportBoundsAndIdentity(t *testing.T) {
	makeReport := func() *model.ACLReport {
		clock := now()
		return &model.ACLReport{Sequence: 1, StartedAt: clock, ObservedAt: clock, Rows: []model.ACLHit{{RuleID: "r", RuleVersion: 1, EffectiveDigest: acl.EffectiveDigest("r", 1, nil), Protocol: "udp", Kind: "rule_total", Allowed: 1, StartedAt: clock}}}
	}
	if err := validateACLReport(makeReport()); err != nil {
		t.Fatal(err)
	}
	for name, modify := range map[string]func(*model.ACLReport){
		"row capacity": func(r *model.ACLReport) {
			row := r.Rows[0]
			r.Rows = make([]model.ACLHit, 257)
			for i := range r.Rows {
				r.Rows[i] = row
			}
		},
		"HTTP":                   func(r *model.ACLReport) { r.Rows[0].Protocol = "http" },
		"source label inflation": func(r *model.ACLReport) { r.Rows[0].Reason = strings.Repeat("x", 129) },
		"counter overflow":       func(r *model.ACLReport) { r.Rows[0].Denied = aclStoredCounterMaximum + 1 },
		"future clock":           func(r *model.ACLReport) { r.ObservedAt = now().Add(2 * time.Minute) },
		"missing digest":         func(r *model.ACLReport) { r.Rows[0].EffectiveDigest = "" },
		"fake policy": func(r *model.ACLReport) {
			r.Rows[0].Kind = "policy"
			r.Rows[0].Policy = model.ACLPolicyRef{Kind: "arbitrary", Digest: strings.Repeat("a", 64)}
		},
		"ACK missing sample": func(r *model.ACLReport) {
			r.ACKs = []model.ACLApplied{{RuleID: "r", RuleVersion: 1, State: "applied", AppliedAt: now(), ExpiresAt: now().Add(time.Minute)}}
		},
		"ACK forged digest": func(r *model.ACLReport) {
			r.ACKs = []model.ACLApplied{{RuleID: "r", RuleVersion: 1, State: "applied", AppliedAt: now(), SampledAt: r.ObservedAt, ExpiresAt: now().Add(time.Minute), EffectiveDigest: strings.Repeat("a", 64)}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			report := makeReport()
			modify(report)
			if validateACLReport(report) == nil {
				t.Fatal("invalid telemetry accepted")
			}
		})
	}
}
