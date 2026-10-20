//go:build linux

package edge

import (
	"context"
	"drafrp/internal/model"
	"drafrp/internal/shaping"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestLinuxWireFailureClosesForwarding(t *testing.T) {
	iface := os.Getenv("DRAFRP_TEST_SHAPING_INTERFACE")
	if iface == "" {
		t.Skip("requires a disposable NET_ADMIN namespace and explicit interface")
	}
	r := New(Config{EdgeID: "wire-edge", ListenHost: "127.0.0.1", WireShaping: &shaping.Config{Interface: iface, DedicatedInterface: true, StateDir: t.TempDir(), RateBPS: 8_000_000, BurstBytes: 16000}})
	defer r.Close()
	if r.initErr != nil {
		t.Fatal(r.initErr)
	}
	snapshot := model.EdgeSnapshot{Revision: 1, ExpiresAt: time.Now().Add(time.Minute), Edge: model.Edge{ID: "wire-edge", BootID: r.cfg.BootID, CapacityBPS: -1, MaxCarriers: 8}}
	if err := r.apply(snapshot); err != nil {
		t.Fatal(err)
	}
	status := r.RuntimeStatus()
	if status.CapacityEnforcement != "wire" || status.PhysicalInterface != iface || status.WireRateBPS != 8_000_000 || status.PhysicalObservedAt.IsZero() {
		t.Fatalf("wire observation missing: %+v", status)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.listeners["wire-test"] = listenerState{closer: listener, kind: "test"}
	r.mu.Unlock()
	b, err := exec.Command("tc", "-j", "qdisc", "show", "dev", iface).Output()
	if err != nil {
		t.Fatal(err)
	}
	var all []struct {
		Handle string `json:"handle"`
		Root   bool   `json:"root"`
	}
	if err = json.Unmarshal(b, &all); err != nil {
		t.Fatal(err)
	}
	var handle string
	for _, q := range all {
		if q.Root {
			handle = q.Handle
		}
	}
	if handle == "" || handle == "0:" {
		t.Fatal("wire qdisc missing")
	}
	if b, err = exec.Command("tc", "qdisc", "del", "dev", iface, "root", "handle", handle).CombinedOutput(); err != nil {
		t.Fatalf("remove own qdisc: %v %s", err, b)
	}
	eventually(t, func() bool { return !r.Ready() })
	if r.Ready() {
		t.Fatal("wire limiter loss remained ready")
	}
	status = r.RuntimeStatus()
	if status.CapacityEnforcement != "wire_failed" || status.CapacityError == "" {
		t.Fatalf("limiter failure hidden: %+v", status)
	}
	eventually(t, func() bool {
		c, err := net.DialTimeout("tcp", listener.Addr().String(), 100*time.Millisecond)
		if err == nil {
			c.Close()
			return false
		}
		return true
	})
	if err = r.apply(snapshot); err == nil {
		t.Fatal("cloud sync reopened forwarding without wire enforcement")
	}
	var reported *model.EdgeRuntime
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var in model.EdgeSyncRequest
		if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
			t.Error(err)
			http.Error(w, "bad", 400)
			return
		}
		reported = in.Runtime
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snapshot)
	}))
	defer server.Close()
	r.cfg.CloudURL, r.cfg.Token = server.URL, "shaping-test-token"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = r.Sync(ctx); err == nil {
		t.Fatal("failed wire shaper applied a renewed cloud snapshot")
	}
	if reported == nil || reported.CapacityEnforcement != "wire_failed" || reported.CapacityError == "" {
		t.Fatalf("wire failure was not reported to the control plane: %+v", reported)
	}
}
