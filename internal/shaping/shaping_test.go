package shaping

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNestedReadableDurationIsStrict(t *testing.T) {
	var c Config
	if err := json.Unmarshal([]byte(`{"interface":"eth0","dedicated_interface":true,"state_dir":"/private","rate_bps":8000000,"latency":"100ms"}`), &c); err != nil || c.Latency != 100*time.Millisecond {
		t.Fatalf("duration: %+v %v", c, err)
	}
	for _, s := range []string{`{"latency":"-1s"}`, `{"latency":null}`, `{"latency":-1}`, `{"unknown":true}`} {
		if json.Unmarshal([]byte(s), &c) == nil {
			t.Fatalf("invalid nested config accepted: %s", s)
		}
	}
}

func TestDedicatedInterfaceAndBoundedQueue(t *testing.T) {
	base := Config{Interface: "eth0", DedicatedInterface: true, StateDir: t.TempDir(), RateBPS: 8_000_000}
	if err := base.defaults(); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*Config){
		func(c *Config) { c.DedicatedInterface = false },
		func(c *Config) { c.Interface = "lo" },
		func(c *Config) { c.RateBPS = 0 },
		func(c *Config) { c.RateBPS = 7 },
		func(c *Config) { c.BurstBytes = 1 },
		func(c *Config) { c.Latency = 2 * time.Second },
		func(c *Config) { c.RateBPS = 100_000_000_000; c.Latency = time.Second },
	} {
		c := base
		alter(&c)
		if c.defaults() == nil {
			t.Fatalf("invalid config accepted: %+v", c)
		}
	}
}
