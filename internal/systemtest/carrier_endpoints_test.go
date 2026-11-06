package systemtest

import "drafrp/internal/model"

func carrierEndpoints(port int) []model.Endpoint {
	return []model.Endpoint{{Transport: "quic", Address: address(port), ServerName: "edge.test"}, {Transport: "tls", Address: address(port), ServerName: "edge.test"}}
}
