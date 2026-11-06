package client

import (
	"context"
	"drafrp/internal/model"
	"drafrp/internal/protocol"
	"testing"
	"time"
)

func TestPacketPathCannotBeRequestedFromSocketClient(t *testing.T) {
	_, c, r := connected(t, "tls", model.Rule{Protocol: "tcp", SourceMode: "socket", Target: "127.0.0.1:1"})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	st, err := c.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer protocol.Abort(st)
	_ = st.SetDeadline(time.Now().Add(3 * time.Second))
	if err = protocol.WriteJSON(st, protocol.Flow{ID: 1, RuleID: r.ID, Version: r.Version, Generation: c.Device.Generation, Protocol: "tcp", Peer: "203.0.113.1:12345", DataPath: "tun_ipv4_v1", IPDestination: "198.19.0.1:40000"}); err != nil {
		t.Fatal(err)
	}
	var result protocol.Result
	if err = protocol.ReadJSON(st, &result); err != nil {
		t.Fatal(err)
	}
	if result.Code != "unauthorized_flow" {
		t.Fatalf("packet flow reached a socket target: %+v", result)
	}
}
