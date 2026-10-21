package cloud

import (
	"net/url"
	"testing"
	"time"
)

func TestParseTrafficRangeUsesMinuteMinimumAndBoundedPoints(t *testing.T) {
	at := time.Date(2026, 10, 21, 12, 34, 56, 0, time.UTC)
	r, err := parseTrafficRange(url.Values{"interval": {"1m"}, "start": {"2026-10-21T12:00:00Z"}, "end": {"2026-10-21T12:30:00Z"}}, at)
	if err != nil || r.interval != time.Minute || r.start.Minute() != 0 || r.end.Minute() != 30 {
		t.Fatalf("unexpected one-minute range: %+v %v", r, err)
	}
	if _, err = parseTrafficRange(url.Values{"interval": {"1m"}, "start": {"2026-10-01T00:00:00Z"}, "end": {"2026-10-21T12:00:00Z"}}, at); err == nil {
		t.Fatal("range larger than one day was accepted at one-minute granularity")
	}
	r, err = parseTrafficRange(url.Values{"interval": {"auto"}, "start": {"2026-10-01T00:00:00Z"}, "end": {"2026-10-21T12:00:00Z"}}, at)
	if err != nil || r.interval != 24*time.Hour {
		t.Fatalf("automatic long-range aggregation failed: %+v %v", r, err)
	}
	for name, query := range map[string]url.Values{
		"sub-minute interval": {"interval": {"30s"}},
		"only start":          {"start": {"2026-10-21T12:00:00Z"}},
		"future":              {"start": {"2026-10-21T12:00:00Z"}, "end": {"2026-10-21T12:36:00Z"}},
		"expired":             {"start": {"2026-09-01T12:00:00Z"}, "end": {"2026-09-02T12:00:00Z"}},
		"reverse":             {"start": {"2026-10-21T12:30:00Z"}, "end": {"2026-10-21T12:00:00Z"}},
		"repeated":            {"interval": {"1m", "1h"}},
		"tenant override":     {"tenant_id": {"someone-else"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseTrafficRange(query, at); err == nil {
				t.Fatal("invalid range was accepted")
			}
		})
	}
}
