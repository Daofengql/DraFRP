package cloud

import (
	"math"
	"testing"
	"time"

	"drafrp/internal/model"
)

func qualityReport(at time.Time) *model.DeviceRuntime {
	r := runtimeReport(at, "edge")
	r.Carriers[0].EstablishedAt = at.Add(-time.Minute)
	r.Carriers[0].Quality = &model.CarrierQualityRuntime{Source: "carrier_probe_v1", WindowStartedAt: at.Add(-12 * time.Second), ObservedAt: at, LastSuccessAt: at.Add(-5 * time.Second), IntervalMS: 5000, TimeoutMS: 2000, WindowLimit: 64, Samples: 3, Successes: 1, Timeouts: 1, Errors: 1, LatestRTTMS: 20, MeanRTTMS: 20, MinRTTMS: 20, MaxRTTMS: 20}
	return r
}

func TestCarrierQualityValidation(t *testing.T) {
	at := time.Now().UTC()
	if !validDeviceRuntime(qualityReport(at), at) {
		t.Fatal("valid signed quality report rejected")
	}
	zero := qualityReport(at)
	zero.Carriers[0].Quality.LatestRTTMS = 0
	zero.Carriers[0].Quality.MinRTTMS = 0
	zero.Carriers[0].Quality.MeanRTTMS = 0
	zero.Carriers[0].Quality.MaxRTTMS = 0
	if !validDeviceRuntime(zero, at) {
		t.Fatal("successful zero-tick measurement rejected as absent")
	}
	for _, tc := range []struct {
		name string
		edit func(*model.CarrierQualityRuntime)
	}{
		{"unknown_source", func(q *model.CarrierQualityRuntime) { q.Source = "ping" }},
		{"no_window_start", func(q *model.CarrierQualityRuntime) { q.WindowStartedAt = time.Time{} }},
		{"old_window", func(q *model.CarrierQualityRuntime) { q.WindowStartedAt = at.Add(-321 * time.Second) }},
		{"future_observation", func(q *model.CarrierQualityRuntime) { q.ObservedAt = at.Add(2 * time.Second) }},
		{"stale_observation", func(q *model.CarrierQualityRuntime) { q.ObservedAt = at.Add(-time.Minute - time.Second) }},
		{"unbounded_samples", func(q *model.CarrierQualityRuntime) { q.Samples = 65; q.Successes = 63 }},
		{"negative_samples", func(q *model.CarrierQualityRuntime) { q.Samples = -1 }},
		{"unbounded_window", func(q *model.CarrierQualityRuntime) { q.WindowLimit++ }},
		{"unbounded_frequency", func(q *model.CarrierQualityRuntime) { q.IntervalMS = 1 }},
		{"unbounded_timeout", func(q *model.CarrierQualityRuntime) { q.TimeoutMS = 60000 }},
		{"inconsistent_outcomes", func(q *model.CarrierQualityRuntime) { q.Errors++ }},
		{"negative_outcomes", func(q *model.CarrierQualityRuntime) { q.Errors = -1; q.Successes = 3 }},
		{"nan_rtt", func(q *model.CarrierQualityRuntime) { q.LatestRTTMS = math.NaN() }},
		{"infinite_rtt", func(q *model.CarrierQualityRuntime) { q.MeanRTTMS = math.Inf(1) }},
		{"negative_rtt", func(q *model.CarrierQualityRuntime) { q.MinRTTMS = -1 }},
		{"inconsistent_range", func(q *model.CarrierQualityRuntime) { q.MaxRTTMS = 19 }},
		{"missing_success_time", func(q *model.CarrierQualityRuntime) { q.LastSuccessAt = time.Time{} }},
		{"fake_zero_success_rtt", func(q *model.CarrierQualityRuntime) { q.Successes = 0; q.Errors++; q.LastSuccessAt = time.Time{} }},
		{"tls_claims_quic", func(q *model.CarrierQualityRuntime) { q.QUIC = &model.QUICQualityRuntime{Source: "quic_go_rfc9002"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := qualityReport(at)
			tc.edit(r.Carriers[0].Quality)
			if validDeviceRuntime(r, at) {
				t.Fatal("invalid quality accepted")
			}
		})
	}
	r := qualityReport(at)
	q := r.Carriers[0].Quality
	q.Successes, q.Errors, q.LatestRTTMS, q.MeanRTTMS, q.MinRTTMS, q.MaxRTTMS = 0, 2, 0, 0, 0, 0
	q.LastSuccessAt = time.Time{}
	if !validDeviceRuntime(r, at) {
		t.Fatal("honest timeout/error-only window rejected")
	}
	r = qualityReport(at)
	r.TLSCarriers, r.QUICCarriers, r.Carriers[0].Transport = 0, 1, "quic"
	q = r.Carriers[0].Quality
	q.QUIC = &model.QUICQualityRuntime{Source: "quic_go_rfc9002", StartedAt: r.Carriers[0].EstablishedAt.Add(-time.Duration(r.Carriers[0].HandshakeMS * float64(time.Millisecond))), ObservedAt: at, LatestRTTMS: 10, SmoothedRTTMS: 12, MinRTTMS: 8, PacketsSent: 10, PacketsReceived: 8, BytesSent: 1000, BytesReceived: 800, PacketsLost: 2, BytesLost: 200}
	if !validDeviceRuntime(r, at) {
		t.Fatal("native QUIC snapshot rejected")
	}
	q.QUIC.PacketsLost-- // Late packets can revise gauges downward.
	if !validDeviceRuntime(r, at) {
		t.Fatal("native loss gauge incorrectly required monotonic growth")
	}
	q.QUIC.PacketsLost = 11
	if validDeviceRuntime(r, at) {
		t.Fatal("impossible lost count accepted")
	}
}
