package edge

import (
	"net/netip"
	"time"

	"drafrp/internal/model"
	"drafrp/internal/protocol"
)

// Selection only assigns new flows. A carrier's existing streams never move.
func preferCarrier(candidate, current *protocol.Carrier) bool {
	if candidate.Transport != current.Transport {
		return candidate.Transport == "quic"
	}
	// Keep a small load bucket so measured quality can influence selection
	// without routing an unbounded number of streams onto the same carrier.
	if candidate.Active()/32 != current.Active()/32 {
		return candidate.Active()/32 < current.Active()/32
	}
	x, y := candidate.Quality(), current.Quality()
	if stableQuality(candidate, x) && stableQuality(current, y) {
		xFailures, yFailures := (x.Timeouts+x.Errors)*4/x.Samples, (y.Timeouts+y.Errors)*4/y.Samples
		if xFailures != yFailures {
			return xFailures < yFailures
		}
		if int(x.MeanRTTMS/10) != int(y.MeanRTTMS/10) {
			return int(x.MeanRTTMS/10) < int(y.MeanRTTMS/10)
		}
	}
	if candidate.Active() != current.Active() {
		return candidate.Active() < current.Active()
	}
	xAddr, _ := netip.ParseAddrPort(candidate.RemoteAddress)
	yAddr, _ := netip.ParseAddrPort(current.RemoteAddress)
	if xAddr.Addr().Is6() != yAddr.Addr().Is6() {
		return xAddr.Addr().Is6()
	}
	return candidate.EstablishedAt.Before(current.EstablishedAt)
}

func stableQuality(c *protocol.Carrier, q *model.CarrierQualityRuntime) bool {
	return q != nil && q.Samples >= 3 && q.Successes > 0 && time.Since(c.EstablishedAt) >= 30*time.Second && time.Since(q.LastSuccessAt) < 3*protocol.ProbeInterval
}
