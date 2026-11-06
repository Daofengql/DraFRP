package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"drafrp/internal/model"
	"drafrp/internal/protocol"
)

type dialCandidate struct {
	ep             model.Endpoint
	key            endpointKey
	ipv6           bool
	handshake, rtt time.Duration
}

// Bound DNS results before making sockets. Addresses are observations of an
// authorized endpoint, never substitute authorities or target source metadata.
func (a *Agent) dialCandidates(ctx context.Context, edge model.Edge, d model.DeviceGrant, mode string) ([]dialCandidate, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	lookup := a.lookupIP
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNetIP
	}
	a.mu.Lock()
	a.pruneEndpointHealthLocked()
	for id, c := range a.carriers {
		if q := c.Quality(); q != nil && q.Successes > 0 && time.Since(q.LastSuccessAt) < 3*protocol.ProbeInterval {
			if h := a.pathHealth[carrierPathKey(a.carrierEdges[id], c)]; h != nil {
				h.RTT = max(time.Nanosecond, time.Duration(q.MeanRTTMS*float64(time.Millisecond)))
				h.RTTAt = q.LastSuccessAt
			}
		}
	}
	a.mu.Unlock()
	cache := map[string][]netip.Addr{}
	out := []dialCandidate{}
	var earliest time.Time
	var failures []error
	for _, ep := range edge.Endpoints {
		if len(out) >= 8 {
			break
		}
		if ep.Transport != "quic" && ep.Transport != "tls" || mode == "quic_only" && ep.Transport != "quic" || mode == "tls_only" && ep.Transport != "tls" {
			continue
		}
		host, port, err := net.SplitHostPort(ep.Address)
		p, pe := strconv.Atoi(port)
		if err != nil || pe != nil || p < 1 || p > 65535 {
			continue
		}
		ips, cached := cache[host]
		if !cached {
			if ip, err := netip.ParseAddr(host); err == nil {
				ips = []netip.Addr{ip}
			} else {
				ips, err = lookup(ctx, "ip", host)
				if err != nil {
					failures = append(failures, err)
				}
			}
			cache[host] = ips
		}
		perFamily := map[bool]int{}
		seen := map[netip.Addr]bool{}
		for _, ip := range ips {
			ip = ip.Unmap()
			if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" || seen[ip] || perFamily[ip.Is6()] >= 2 {
				continue
			}
			seen[ip] = true
			perFamily[ip.Is6()]++
			k := pathKey(edge, ep, d)
			k.RemoteAddress = netip.AddrPortFrom(ip, uint16(p)).String()
			if ok, retry := a.endpointEligible(k, time.Now()); !ok {
				if !retry.IsZero() && (earliest.IsZero() || retry.Before(earliest)) {
					earliest = retry
				}
				continue
			}
			c := dialCandidate{ep: ep, key: k, ipv6: ip.Is6()}
			a.mu.RLock()
			if h := a.pathHealth[k]; h != nil {
				c.handshake, c.rtt = h.Handshake, h.RTT
				if time.Since(h.RTTAt) > time.Minute {
					c.rtt = 0
				}
			}
			a.mu.RUnlock()
			out = append(out, c)
		}
	}
	// A stable score per candidate avoids pairwise threshold comparisons that
	// would violate sort's ordering contract. Prefer IPv6 absent measurements.
	sort.SliceStable(out, func(i, j int) bool {
		x, y := out[i], out[j]
		if x.ep.Transport != y.ep.Transport {
			return x.ep.Transport == "quic"
		}
		if (x.rtt > 0) != (y.rtt > 0) {
			return x.rtt > 0
		}
		if x.rtt/(10*time.Millisecond) != y.rtt/(10*time.Millisecond) {
			return x.rtt < y.rtt
		}
		if (x.handshake > 0) != (y.handshake > 0) {
			return x.handshake > 0
		}
		if x.handshake/(50*time.Millisecond) != y.handshake/(50*time.Millisecond) {
			return x.handshake < y.handshake
		}
		if x.ipv6 != y.ipv6 {
			return x.ipv6
		}
		return x.key.RemoteAddress < y.key.RemoteAddress
	})
	if len(out) > 8 {
		out = out[:8]
	}
	if len(out) == 0 && len(failures) > 0 {
		return nil, earliest, errors.Join(failures...)
	}
	return out, earliest, nil
}

// Maintain a second address family only within the approved carrier budget.
// The stable window and candidate cooldown bound background work. Published
// carriers and their established flows remain in place while a path recovers.
func (a *Agent) familyRecovery(ctx context.Context, edge model.Edge, mode string) bool {
	a.mu.RLock()
	d := a.snap.Device
	active := map[string]bool{}
	stable := false
	for _, c := range a.carriers {
		if c.EdgeID != edge.ID || mode == "quic_only" && c.Transport != "quic" || mode == "tls_only" && c.Transport != "tls" {
			continue
		}
		active[c.Transport+"/"+c.RemoteAddress] = true
		stable = stable || time.Since(c.EstablishedAt) >= endpointStableWindow
	}
	a.mu.RUnlock()
	if !stable {
		return false
	}
	candidates, _, _ := a.dialCandidates(ctx, edge, d, mode)
	for _, candidate := range candidates {
		if !active[candidate.ep.Transport+"/"+candidate.key.RemoteAddress] {
			return true
		}
	}
	return false
}
