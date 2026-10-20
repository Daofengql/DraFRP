package cloud

import (
	"math"
	"time"

	"drafrp/internal/model"
)

func validCarrierQuality(c model.DeviceCarrierRuntime, reportedAt time.Time) bool {
	q := c.Quality
	if q == nil {
		return true
	} // Legacy signed reports remain valid.
	if q.Source != "carrier_probe_v1" || q.IntervalMS != 5000 || q.TimeoutMS != 2000 || q.WindowLimit != 64 ||
		q.Samples < 1 || q.Samples > q.WindowLimit || q.Successes < 0 || q.Timeouts < 0 || q.Errors < 0 ||
		q.Successes > q.Samples || q.Timeouts > q.Samples || q.Errors > q.Samples ||
		q.Successes+q.Timeouts+q.Errors != q.Samples || q.WindowStartedAt.IsZero() || q.ObservedAt.IsZero() ||
		q.WindowStartedAt.Before(c.EstablishedAt) || q.WindowStartedAt.After(q.ObservedAt) ||
		q.ObservedAt.After(reportedAt.Add(time.Second)) || reportedAt.Sub(q.ObservedAt) > time.Minute ||
		q.ObservedAt.Sub(q.WindowStartedAt) > 320*time.Second {
		return false
	}
	validRTT := func(ms float64) bool { return !math.IsNaN(ms) && !math.IsInf(ms, 0) && ms >= 0 && ms <= 60_000 }
	for _, ms := range []float64{q.LatestRTTMS, q.MeanRTTMS, q.MinRTTMS, q.MaxRTTMS} {
		if !validRTT(ms) {
			return false
		}
	}
	if q.Successes == 0 {
		if !q.LastSuccessAt.IsZero() || q.LatestRTTMS != 0 || q.MeanRTTMS != 0 || q.MinRTTMS != 0 || q.MaxRTTMS != 0 || q.QUIC != nil {
			return false
		}
	} else if q.LastSuccessAt.Before(q.WindowStartedAt) || q.LastSuccessAt.After(q.ObservedAt) ||
		q.MinRTTMS > q.LatestRTTMS || q.LatestRTTMS > q.MaxRTTMS || q.MinRTTMS > q.MeanRTTMS || q.MeanRTTMS > q.MaxRTTMS {
		return false
	}
	if native := q.QUIC; native != nil {
		connectionStart := c.EstablishedAt.Add(-time.Duration(c.HandshakeMS * float64(time.Millisecond)))
		if c.Transport != "quic" || native.Source != "quic_go_rfc9002" || native.StartedAt.Sub(connectionStart).Abs() > time.Millisecond ||
			!native.ObservedAt.Equal(q.ObservedAt) || native.PacketsReceived == 0 ||
			native.PacketsLost > native.PacketsSent || native.BytesLost > native.BytesSent ||
			!validRTT(native.LatestRTTMS) || !validRTT(native.SmoothedRTTMS) || !validRTT(native.MinRTTMS) {
			return false
		}
	}
	return true
}
