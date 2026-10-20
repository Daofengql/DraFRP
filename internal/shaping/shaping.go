// Package shaping owns an optional Linux egress qdisc on an explicitly
// dedicated interface. It never replaces or deletes an unknown qdisc.
package shaping

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type Config struct {
	Interface          string        `json:"interface"`
	DedicatedInterface bool          `json:"dedicated_interface"`
	StateDir           string        `json:"state_dir"`
	RateBPS            int64         `json:"rate_bps"`
	BurstBytes         int64         `json:"burst_bytes"`
	Latency            time.Duration `json:"latency"`
}

type Status struct {
	Interface  string    `json:"interface"`
	Enforced   bool      `json:"enforced"`
	RateBPS    int64     `json:"rate_bps"`
	BurstBytes int64     `json:"burst_bytes"`
	TXBytes    uint64    `json:"tx_bytes"`
	RXBytes    uint64    `json:"rx_bytes"`
	ObservedAt time.Time `json:"observed_at"`
	Error      string    `json:"error,omitempty"`
}

// The outer strict config reader normalizes top-level durations. Keep the
// optional nested shaping object equally strict and accept readable durations.
func (c *Config) UnmarshalJSON(b []byte) error {
	var value struct {
		Interface          string          `json:"interface"`
		DedicatedInterface bool            `json:"dedicated_interface"`
		StateDir           string          `json:"state_dir"`
		RateBPS            int64           `json:"rate_bps"`
		BurstBytes         int64           `json:"burst_bytes"`
		Latency            json.RawMessage `json:"latency"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&value); err != nil {
		return err
	}
	var latency time.Duration
	if len(value.Latency) > 0 {
		if value.Latency[0] == '"' {
			var text string
			if err := json.Unmarshal(value.Latency, &text); err != nil {
				return err
			}
			var err error
			latency, err = time.ParseDuration(text)
			if err != nil {
				return fmt.Errorf("wire_shaping.latency: %w", err)
			}
		} else {
			if string(value.Latency) == "null" {
				return errors.New("wire_shaping.latency must be a duration")
			}
			if err := json.Unmarshal(value.Latency, &latency); err != nil {
				return err
			}
		}
		if latency < 0 {
			return errors.New("wire_shaping.latency must not be negative")
		}
	}
	*c = Config{Interface: value.Interface, DedicatedInterface: value.DedicatedInterface, StateDir: value.StateDir, RateBPS: value.RateBPS, BurstBytes: value.BurstBytes, Latency: latency}
	return nil
}

func (c *Config) defaults() error {
	if !c.DedicatedInterface || c.Interface == "" || c.Interface == "lo" || c.StateDir == "" {
		return errors.New("wire shaping requires an explicitly dedicated non-loopback interface and private state_dir")
	}
	if c.RateBPS < 8 || c.RateBPS > 100_000_000_000 || c.RateBPS%8 != 0 {
		return errors.New("wire rate_bps must be a positive multiple of 8, at most 100 Gbit/s")
	}
	if c.BurstBytes == 0 {
		c.BurstBytes = 64 << 10
	}
	if c.Latency == 0 {
		c.Latency = 50 * time.Millisecond
	}
	if c.BurstBytes < 1500 || c.BurstBytes > 16<<20 || c.Latency < time.Millisecond || c.Latency > time.Second || c.RateBPS/8*int64(c.Latency/time.Millisecond)/1000+c.BurstBytes > 64<<20 {
		return errors.New("wire burst/latency exceeds bounded egress queue limits")
	}
	return nil
}
