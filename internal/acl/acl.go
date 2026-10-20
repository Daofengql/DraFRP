// Package acl compiles only administrator-supplied TCP/UDP policies.
package acl

import (
	"drafrp/internal/geoip"
	"drafrp/internal/model"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"
)

type entry struct {
	model.ACLEntry
	prefixes []netip.Prefix
}
type Policy struct {
	defaultAction string
	entries       []entry
	lookup        func(netip.Addr) (string, string, bool)
	requiresGeo   bool
}

// Decision describes the same first-match result used by live forwarding.
// MatchedEntryID is separate from Reason so arbitrary entry IDs cannot be
// confused with synthetic reasons such as "default" or "geoip_unavailable".
type Decision struct {
	Allowed        bool   `json:"allowed"`
	Action         string `json:"action"`
	Reason         string `json:"reason"`
	MatchedEntryID string `json:"matched_entry_id,omitempty"`
	UsedDefault    bool   `json:"used_default"`
}

func decision(allowed bool, reason, entryID string, usedDefault bool) Decision {
	action := "deny"
	if allowed {
		action = "allow"
	}
	return Decision{Allowed: allowed, Action: action, Reason: reason, MatchedEntryID: entryID, UsedDefault: usedDefault}
}

func Compile(p model.ACLPolicy) (*Policy, error) {
	return CompileWithGeo(p, nil)
}
func CompileWithGeo(p model.ACLPolicy, lookup func(netip.Addr) (string, string, bool)) (*Policy, error) {
	if p.DefaultAction != "allow" && p.DefaultAction != "deny" {
		return nil, errors.New("ACL requires explicit default_action")
	}
	if len(p.Entries) > 1024 {
		return nil, errors.New("too many ACL entries")
	}
	out := &Policy{defaultAction: p.DefaultAction, lookup: lookup}
	priorities := map[int]bool{}
	ids := map[string]bool{}
	for _, e := range p.Entries {
		if e.ID == "" || ids[e.ID] {
			return nil, errors.New("ACL entry IDs must be nonempty and unique")
		}
		ids[e.ID] = true
		if e.Action != "allow" && e.Action != "deny" {
			return nil, errors.New("invalid ACL action")
		}
		if e.Protocol != "" && e.Protocol != "tcp" && e.Protocol != "udp" {
			return nil, errors.New("invalid ACL protocol")
		}
		if priorities[e.Priority] {
			return nil, errors.New("duplicate ACL priority")
		}
		priorities[e.Priority] = true
		if e.CIDRs != nil && len(e.CIDRs) == 0 || e.Ports != nil && len(e.Ports) == 0 {
			return nil, errors.New("ACL match sets must be nonempty when specified")
		}
		if e.NotBefore != nil && e.ExpiresAt != nil && !e.NotBefore.Before(*e.ExpiresAt) {
			return nil, errors.New("invalid ACL time interval")
		}
		if len(e.Countries) > 0 || len(e.Regions) > 0 {
			out.requiresGeo = true
			if e.GeoUnknownAction != "deny" && e.GeoUnknownAction != "no_match" {
				return nil, errors.New("regional ACL requires explicit geo_unknown_action deny or no_match")
			}
			if len(e.Countries) > 256 || len(e.Regions) > 1024 {
				return nil, errors.New("regional ACL match sets exceed limit")
			}
			for _, code := range e.Countries {
				if !geoip.CountryCode(code) {
					return nil, errors.New("invalid uppercase country code")
				}
			}
			for _, code := range e.Regions {
				if !geoip.RegionCode(code) {
					return nil, errors.New("invalid uppercase region code")
				}
			}
		} else if e.GeoUnknownAction != "" {
			return nil, errors.New("geo_unknown_action requires a regional condition")
		}
		ce := entry{ACLEntry: e}
		for _, s := range e.CIDRs {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("ACL CIDR: %w", err)
			}
			if p.Addr().Is4In6() {
				if p.Bits() < 96 {
					return nil, errors.New("ambiguous mapped IPv6 prefix")
				}
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			ce.prefixes = append(ce.prefixes, p.Masked())
		}
		for _, port := range e.Ports {
			if port < 1 || port > 65535 {
				return nil, errors.New("invalid ACL port")
			}
		}
		out.entries = append(out.entries, ce)
	}
	sort.Slice(out.entries, func(i, j int) bool { return out.entries[i].Priority < out.entries[j].Priority })
	return out, nil
}
func (p *Policy) RequiresGeo() bool { return p.requiresGeo }
func (p *Policy) Allow(ip netip.Addr, proto string, port int) (bool, string) {
	return p.AllowAt(ip, proto, port, time.Now())
}
func (p *Policy) AllowAt(ip netip.Addr, proto string, port int, now time.Time) (bool, string) {
	out := p.ExplainAt(ip, proto, port, now)
	return out.Allowed, out.Reason
}

// ExplainAt evaluates without changing counters or policy state. Callers that
// require geographic capability must still check RequiresGeo before forwarding,
// just as the edge validates the whole compiled rule before admitting traffic.
func (p *Policy) ExplainAt(ip netip.Addr, proto string, port int, now time.Time) Decision {
	if !ip.IsValid() || proto != "tcp" && proto != "udp" || port < 1 || port > 65535 {
		return decision(false, "invalid_source", "", false)
	}
	ip = ip.Unmap()
	for _, e := range p.entries {
		if e.Protocol != "" && e.Protocol != proto {
			continue
		}
		if e.NotBefore != nil && now.Before(*e.NotBefore) || e.ExpiresAt != nil && !now.Before(*e.ExpiresAt) {
			continue
		}
		if len(e.Ports) > 0 {
			found := false
			for _, v := range e.Ports {
				found = found || v == port
			}
			if !found {
				continue
			}
		}
		if len(e.prefixes) > 0 {
			found := false
			for _, v := range e.prefixes {
				found = found || v.Contains(ip)
			}
			if !found {
				continue
			}
		}
		if len(e.Countries) > 0 || len(e.Regions) > 0 {
			// Missing capability never opens a rule, even if unknown addresses
			// were explicitly configured to skip this geographic condition.
			if p.lookup == nil {
				return decision(false, "geoip_unavailable", e.ID, false)
			}
			country, region, known := p.lookup(ip)
			if !known {
				if e.GeoUnknownAction == "deny" {
					return decision(false, e.ID+":geo_unknown", e.ID, false)
				}
				continue
			}
			contains := func(values []string, value string) bool {
				if len(values) == 0 {
					return true
				}
				for _, v := range values {
					if v == value {
						return true
					}
				}
				return false
			}
			if !contains(e.Countries, country) || !contains(e.Regions, region) {
				continue
			}
		}
		return decision(e.Action == "allow", e.ID, e.ID, false)
	}
	return decision(p.defaultAction == "allow", "default", "", true)
}
