package edge

import (
	"drafrp/internal/acl"
	"drafrp/internal/model"
	"encoding/json"
	"net/netip"
	"sort"
	"sync"
	"time"
	"unicode/utf8"
)

const aclCounterCapacity = 4096
const aclCounterMaximum = uint64(1 << 60)

type aclMetrics struct {
	mu                   sync.Mutex
	started              time.Time
	sequence, dropped    uint64
	rows                 map[model.ACLHit]model.ACLHit
	acks                 map[string]model.ACLApplied
	rowCursor, ackCursor int
}

func newACLMetrics() *aclMetrics {
	return &aclMetrics{started: time.Now().UTC(), rows: map[model.ACLHit]model.ACLHit{}, acks: map[string]model.ACLApplied{}}
}

func aclMetricLabel(hit model.ACLHit) model.ACLHit {
	hit.Allowed, hit.Denied, hit.StartedAt = 0, 0, time.Time{}
	return hit
}

func (m *aclMetrics) add(hit model.ACLHit, allowed bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := aclMetricLabel(hit)
	row, exists := m.rows[key]
	if !exists {
		if len(m.rows) >= aclCounterCapacity {
			if m.dropped < aclCounterMaximum {
				m.dropped++
			}
			return
		}
		row = hit
		row.StartedAt = time.Now().UTC()
	}
	if allowed && row.Allowed < aclCounterMaximum {
		row.Allowed++
	}
	if !allowed && row.Denied < aclCounterMaximum {
		row.Denied++
	}
	m.rows[key] = row
}

// Only ingress uses this method. Background rechecks and simulation use allow /
// ExplainAt and cannot increment these real-traffic counters.
func (r *Runtime) allowObservedACL(rr *ruleRuntime, source netip.AddrPort) bool {
	if rr.rule.Protocol != "tcp" && rr.rule.Protocol != "udp" {
		return rr.allow(source)
	}
	base := model.ACLHit{RuleID: rr.rule.ID, RuleVersion: rr.rule.Version, EffectiveDigest: rr.aclDigest, Protocol: rr.rule.Protocol, Kind: "rule_total", Reason: "all_policies_allow"}
	if len(rr.policies) == 0 {
		base.Reason = "no_acl"
	}
	for i, policy := range rr.policies {
		decision := policy.ExplainAt(source.Addr(), rr.rule.Protocol, int(source.Port()), time.Now())
		hit := base
		hit.Kind, hit.Reason, hit.UsedDefault = "policy", decision.Reason, decision.UsedDefault
		if i < len(rr.aclRefs) {
			hit.Policy = rr.aclRefs[i]
		}
		// Entry identity is exact in the digest even when its display label is
		// truncated; arbitrary administrator text cannot inflate report labels.
		if decision.MatchedEntryID != "" {
			hit.EntryHash = acl.Digest(decision.MatchedEntryID)
			hit.EntryID = boundedACLLabel(decision.MatchedEntryID)
		}
		hit.Reason = boundedACLLabel(hit.Reason)
		r.aclMetrics.add(hit, decision.Allowed)
		if !decision.Allowed {
			base.Reason = "policy_denied"
			r.aclMetrics.add(base, false)
			return false
		}
	}
	r.aclMetrics.add(base, true)
	return true
}

func boundedACLLabel(value string) string {
	if len(value) <= 128 {
		return value
	}
	value = value[:128]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func (r *Runtime) appliedACLLocked(snapshot model.EdgeSnapshot) {
	if r.aclMetrics == nil {
		r.aclMetrics = newACLMetrics()
	}
	m := r.aclMetrics
	m.mu.Lock()
	defer m.mu.Unlock()
	next := map[string]model.ACLApplied{}
	for _, rule := range snapshot.Rules {
		if rule.Protocol != "tcp" && rule.Protocol != "udp" {
			continue
		}
		ack := model.ACLApplied{RuleID: rule.ID, RuleVersion: rule.Version, State: "inactive", SnapshotRevision: snapshot.Revision, AppliedAt: time.Now().UTC(), ExpiresAt: snapshot.ExpiresAt, Policies: []model.ACLPolicyRef{}}
		if rr := r.rules[rule.ID]; rr != nil {
			ack.Policies, ack.EffectiveDigest = rr.aclRefs, rr.aclDigest
			ack.State = "applied"
			if rr.policyError != "" {
				ack.State, ack.Error = "error", boundedACLLabel(rr.policyError)
			}
		}
		next[rule.ID] = ack
	}
	m.acks = next
}

func (r *Runtime) failedACLApply(snapshot model.EdgeSnapshot, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.aclMetrics == nil {
		r.aclMetrics = newACLMetrics()
	}
	m := r.aclMetrics
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rule := range snapshot.Rules {
		if len(m.acks) >= aclCounterCapacity {
			if _, exists := m.acks[rule.ID]; !exists {
				continue
			}
		}
		if rule.Protocol != "tcp" && rule.Protocol != "udp" {
			continue
		}
		m.acks[rule.ID] = model.ACLApplied{RuleID: rule.ID, RuleVersion: rule.Version, State: "error", Error: boundedACLLabel(err.Error()), SnapshotRevision: snapshot.Revision, AppliedAt: time.Now().UTC(), ExpiresAt: snapshot.ExpiresAt, Policies: []model.ACLPolicyRef{}}
	}
}

// Caller holds r.mu. Reports are periodic, cumulative, size-bounded batches;
// the cursor prevents busy rules from starving older policy versions.
func (r *Runtime) aclReportLocked() *model.ACLReport {
	m := r.aclMetrics
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sequence++
	out := &model.ACLReport{Sequence: m.sequence, StartedAt: m.started, ObservedAt: time.Now().UTC(), Dropped: m.dropped, Rows: []model.ACLHit{}, ACKs: []model.ACLApplied{}}
	type counterKey struct {
		label  model.ACLHit
		digest string
	}
	keys := make([]counterKey, 0, len(m.rows))
	for key := range m.rows {
		keys = append(keys, counterKey{key, acl.HitKey(key)})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].digest < keys[j].digest })
	bytes := 0
	for n := 0; n < len(keys) && n < 256; n++ {
		row := m.rows[keys[(m.rowCursor+n)%len(keys)].label]
		encoded, _ := json.Marshal(row)
		if bytes+len(encoded) > 60<<10 {
			break
		}
		bytes += len(encoded)
		out.Rows = append(out.Rows, row)
	}
	if len(keys) > 0 {
		m.rowCursor = (m.rowCursor + len(out.Rows)) % len(keys)
	}
	ackKeys := make([]string, 0, len(m.acks))
	for key := range m.acks {
		ackKeys = append(ackKeys, key)
	}
	sort.Strings(ackKeys)
	active := map[string]int{}
	for _, flow := range r.flows {
		if !flow.finished && (flow.ctx == nil || flow.ctx.Err() == nil) {
			active[flow.rule.ID]++
		}
	}
	for n := 0; n < len(ackKeys) && n < 16; n++ {
		ack := m.acks[ackKeys[(m.ackCursor+n)%len(ackKeys)]]
		ack.ActiveFlows, ack.SampledAt = active[ack.RuleID], out.ObservedAt
		encoded, _ := json.Marshal(ack)
		if bytes+len(encoded) > 120<<10 {
			break
		}
		bytes += len(encoded)
		out.ACKs = append(out.ACKs, ack)
	}
	if len(ackKeys) > 0 {
		m.ackCursor = (m.ackCursor + len(out.ACKs)) % len(ackKeys)
	}
	return out
}

func (r *Runtime) acknowledgeACLLocked(report *model.ACLReport) {
	if report == nil || r.aclMetrics == nil {
		return
	}
	m := r.aclMetrics
	m.mu.Lock()
	defer m.mu.Unlock()
	live := map[string]bool{}
	for _, ack := range m.acks {
		live[ack.EffectiveDigest] = true
	}
	for _, sent := range report.Rows {
		key := aclMetricLabel(sent)
		row := m.rows[key]
		if !live[row.EffectiveDigest] && row.Allowed == sent.Allowed && row.Denied == sent.Denied {
			delete(m.rows, key)
		}
	}
}
