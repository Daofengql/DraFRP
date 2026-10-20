package model

import "time"

// CarrierQualityRuntime measures control-stream request/echo round trips on an
// already authenticated carrier. Timeouts are not IP packet loss. Only completed
// attempts in the bounded window are included; local cancellation is excluded.
type CarrierQualityRuntime struct {
	Source          string              `json:"source"`
	WindowStartedAt time.Time           `json:"window_started_at"`
	ObservedAt      time.Time           `json:"observed_at"`
	LastSuccessAt   time.Time           `json:"last_success_at"`
	IntervalMS      int                 `json:"interval_ms"`
	TimeoutMS       int                 `json:"timeout_ms"`
	WindowLimit     int                 `json:"window_limit"`
	Samples         int                 `json:"samples"`
	Successes       int                 `json:"successes"`
	Timeouts        int                 `json:"timeouts"`
	Errors          int                 `json:"errors"`
	LatestRTTMS     float64             `json:"latest_rtt_ms"`
	MeanRTTMS       float64             `json:"mean_rtt_ms"`
	MinRTTMS        float64             `json:"min_rtt_ms"`
	MaxRTTMS        float64             `json:"max_rtt_ms"`
	QUIC            *QUICQualityRuntime `json:"quic,omitempty"`
}

// QUICQualityRuntime is the local quic-go RFC 9002 connection snapshot. Lost
// counters are current loss declarations and can decrease after a late packet;
// they are neither monotonic totals nor IP packet loss or retransmission rates.
type QUICQualityRuntime struct {
	Source          string    `json:"source"`
	StartedAt       time.Time `json:"started_at"`
	ObservedAt      time.Time `json:"observed_at"`
	LatestRTTMS     float64   `json:"latest_rtt_ms"`
	SmoothedRTTMS   float64   `json:"smoothed_rtt_ms"`
	MinRTTMS        float64   `json:"min_rtt_ms"`
	PacketsSent     uint64    `json:"packets_sent"`
	PacketsReceived uint64    `json:"packets_received"`
	BytesSent       uint64    `json:"bytes_sent"`
	BytesReceived   uint64    `json:"bytes_received"`
	PacketsLost     uint64    `json:"packets_lost"`
	BytesLost       uint64    `json:"bytes_lost"`
}
