// Package geoip reads an administrator supplied, versioned prefix database.
// It never downloads or seeds geographic policy data.
package geoip

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
)

type Record struct {
	CIDR    string `json:"cidr"`
	Country string `json:"country"`
	Region  string `json:"region,omitempty"`
}
type File struct {
	Version string   `json:"version"`
	Records []Record `json:"records"`
}
type node struct {
	next  [2]*node
	value *Record
}
type Database struct {
	Version, SHA256 string
	v4, v6          node
	Records         int
}

func CountryCode(v string) bool {
	return len(v) == 2 && v[0] >= 'A' && v[0] <= 'Z' && v[1] >= 'A' && v[1] <= 'Z'
}
func RegionCode(v string) bool {
	if len(v) < 4 || len(v) > 16 || !CountryCode(v[:2]) || v[2] != '-' {
		return false
	}
	for _, c := range v[3:] {
		if c != '-' && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
func Load(path string) (*Database, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (64<<20)+1))
	if e != nil {
		return nil, e
	}
	if len(b) > 64<<20 {
		return nil, errors.New("GeoIP database exceeds 64 MiB")
	}
	return Parse(b)
}
func Parse(b []byte) (*Database, error) {
	if len(b) > 64<<20 {
		return nil, errors.New("GeoIP database exceeds 64 MiB")
	}
	var data File
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if e := dec.Decode(&data); e != nil {
		return nil, e
	}
	if dec.Decode(new(any)) != io.EOF {
		return nil, errors.New("GeoIP requires one JSON object")
	}
	if strings.TrimSpace(data.Version) == "" || len(data.Version) > 128 || len(data.Records) > 250_000 {
		return nil, errors.New("invalid GeoIP version or record count")
	}
	hash := sha256.Sum256(b)
	db := &Database{Version: data.Version, SHA256: hex.EncodeToString(hash[:]), Records: len(data.Records)}
	seen := map[netip.Prefix]bool{}
	nodes := 0
	for _, record := range data.Records {
		p, e := netip.ParsePrefix(record.CIDR)
		if e != nil {
			return nil, e
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return nil, errors.New("ambiguous mapped GeoIP prefix")
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		p = p.Masked()
		if seen[p] {
			return nil, fmt.Errorf("duplicate GeoIP prefix %s", p)
		}
		seen[p] = true
		if !CountryCode(record.Country) || record.Region != "" && (!RegionCode(record.Region) || !strings.HasPrefix(record.Region, record.Country+"-")) {
			return nil, errors.New("GeoIP requires uppercase country and matching region codes")
		}
		record.CIDR = p.String()
		n := &db.v6
		if p.Addr().Is4() {
			n = &db.v4
		}
		ip := p.Addr().AsSlice()
		for bit := 0; bit < p.Bits(); bit++ {
			index := (ip[bit/8] >> uint(7-bit%8)) & 1
			if n.next[index] == nil {
				nodes++
				if nodes > 2_000_000 {
					return nil, errors.New("GeoIP prefix tree exceeds two million nodes")
				}
				n.next[index] = &node{}
			}
			n = n.next[index]
		}
		copy := record
		n.value = &copy
	}
	return db, nil
}

// Lookup uses longest-prefix matching. Private/loopback/link-local/multicast
// addresses have no applicable public geography, even if listed in a file.
func (db *Database) Lookup(ip netip.Addr) (country, region string, known bool) {
	ip = ip.Unmap()
	if db == nil || !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return "", "", false
	}
	n := &db.v6
	if ip.Is4() {
		n = &db.v4
	}
	value := n.value
	data := ip.AsSlice()
	for bit, bits := 0, ip.BitLen(); bit < bits; bit++ {
		n = n.next[(data[bit/8]>>uint(7-bit%8))&1]
		if n == nil {
			break
		}
		if n.value != nil {
			value = n.value
		}
	}
	if value == nil {
		return "", "", false
	}
	return value.Country, value.Region, true
}
