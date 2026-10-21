package model

import "time"

// TrafficMinute is a grant's cumulative payload count for one UTC minute.
// Edges retain unacknowledged minutes and retry them with cumulative usage.
type TrafficMinute struct {
	Start         time.Time `json:"start"`
	UploadBytes   int64     `json:"upload_bytes"`
	DownloadBytes int64     `json:"download_bytes"`
}

const MaxTrafficMinutes = 64

type TrafficPoint struct {
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
	UploadBytes   int64     `json:"upload_bytes"`
	DownloadBytes int64     `json:"download_bytes"`
	UploadBPS     float64   `json:"upload_bps"`
	DownloadBPS   float64   `json:"download_bps"`
	Samples       int64     `json:"samples"`
	ReceiptBytes  int64     `json:"receipt_bytes"`
}

type TrafficHistory struct {
	Scope           string         `json:"scope"`
	EdgeID          string         `json:"edge_id,omitempty"`
	Start           time.Time      `json:"start"`
	End             time.Time      `json:"end"`
	IntervalSeconds int64          `json:"interval_seconds"`
	AvailableFrom   time.Time      `json:"available_from"`
	ObservedAt      time.Time      `json:"observed_at"`
	UploadBytes     int64          `json:"upload_bytes"`
	DownloadBytes   int64          `json:"download_bytes"`
	ReceiptBytes    int64          `json:"receipt_bytes"`
	Points          []TrafficPoint `json:"points"`
}
