package edge

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"drafrp/internal/model"
)

func (c Config) validateListeners() error {
	ip, err := netip.ParseAddr(c.ListenHost)
	if err != nil || !ip.Is4() || ip.IsMulticast() {
		return errors.New("listen_host must be an IPv4 address for TCP/UDP business listeners")
	}
	for _, hosts := range [][]string{c.CarrierListenHosts, c.HTTPListenHosts} {
		if len(hosts) == 0 || len(hosts) > 8 {
			return errors.New("carrier_listen_hosts and http_listen_hosts require 1..8 IP addresses")
		}
		seen := map[netip.Addr]bool{}
		for _, host := range hosts {
			ip, err := netip.ParseAddr(host)
			if err != nil || ip.Is4In6() || ip.Zone() != "" || ip.IsMulticast() || seen[ip] {
				return fmt.Errorf("invalid or duplicate listen address %q", host)
			}
			seen[ip] = true
		}
	}
	return nil
}

// Empty plans are used while an edge has no forwarding authorization. A
// published plan uses exactly one UDP and one TCP port, each shared by all
// devices and address families; no per-flow or range listener is created.
func validateCarrierPorts(eps []model.Endpoint) error {
	if len(eps) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, ep := range eps {
		host, port, err := net.SplitHostPort(ep.Address)
		p, pe := strconv.Atoi(port)
		if err != nil || pe != nil || host == "" || p < 1 || p > 65535 || ep.ServerName == "" || (ep.Transport != "quic" && ep.Transport != "tls") || seen[ep.Transport] {
			return errors.New("edge requires one QUIC/UDP endpoint and one TLS/TCP endpoint; publish dual-stack addresses through DNS")
		}
		seen[ep.Transport] = true
	}
	if !seen["quic"] || !seen["tls"] {
		return errors.New("edge requires both its QUIC/UDP and TLS/TCP dedicated ports")
	}
	return nil
}

type listenerBinding struct {
	key, address, network string
}

func bindings(key, network, port string, hosts []string) []listenerBinding {
	out := make([]listenerBinding, 0, len(hosts))
	for i, host := range hosts {
		k := key
		if i > 0 {
			k += "/" + host
		}
		n := network + "4"
		if ip, _ := netip.ParseAddr(host); ip.Is6() {
			n = network + "6"
		}
		out = append(out, listenerBinding{k, net.JoinHostPort(host, port), n})
	}
	return out
}

func (r *Runtime) carrierBindings(ep model.Endpoint) []listenerBinding {
	_, port, err := net.SplitHostPort(ep.Address)
	if err != nil {
		return nil
	}
	network := "tcp"
	if ep.Transport == "quic" {
		network = "udp"
	}
	return bindings("carrier/"+ep.Transport+"/"+ep.Address, network, port, r.cfg.CarrierListenHosts)
}

func (r *Runtime) siteBindings(kind string, port int) []listenerBinding {
	return bindings("site/"+kind+"/"+strconv.Itoa(port), "tcp", strconv.Itoa(port), r.cfg.HTTPListenHosts)
}

func (r *Runtime) siteListening(kind string, port int) (bool, string) {
	var errs []error
	listening := false
	for _, b := range r.siteBindings(kind, port) {
		listening = listening || r.listeners[b.key].closer != nil
		if e := r.listenerErrors[b.key]; e != "" {
			errs = append(errs, fmt.Errorf("%s: %s", b.address, e))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return listening, err.Error()
	}
	return listening, ""
}
