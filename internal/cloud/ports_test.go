package cloud

import (
	"drafrp/internal/model"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestPortResourceSlotsReservationsAndPaging(t *testing.T) {
	edge := model.Edge{ID: "ports", PortMin: 20000, PortMax: 20002, HTTPPort: 20000, HTTPSPort: 18443, Endpoints: []model.Endpoint{
		{Transport: "tls", Address: "edge.example:8443"},
		{Transport: "tls", Address: "edge.example:08443"}, // Numeric identity, not spelling.
		{Transport: "quic", Address: "[::1]:20001"},
	}}
	all, total := portResourceSlots(edge, "", 0, 100)
	if total != 8 || len(all) != 8 {
		t.Fatalf("unexpected pool and out-of-pool reservations: %d %+v", total, all)
	}
	want := []string{"tcp/8443/reserved", "tcp/18443/reserved", "tcp/20000/reserved", "udp/20000/available", "tcp/20001/available", "udp/20001/reserved", "tcp/20002/available", "udp/20002/available"}
	for i, x := range all {
		got := x.Protocol + "/" + strconv.Itoa(x.Port) + "/" + x.Status
		if got != want[i] || x.EdgeID != edge.ID || x.InBusinessPool != (x.Port >= edge.PortMin && x.Port <= edge.PortMax) {
			t.Fatalf("item %d: %+v want %s", i, x, want[i])
		}
	}
	if !reflect.DeepEqual(all[0].Reservations, []string{"carrier_tls"}) || !reflect.DeepEqual(all[5].Reservations, []string{"carrier_quic"}) {
		t.Fatal("carrier reservations not deduplicated by protocol/number", all)
	}
	var paged []portResource
	for offset := 0; offset < total; offset += 3 {
		items, gotTotal := portResourceSlots(edge, "", offset, 3)
		if gotTotal != total || len(items) > 3 {
			t.Fatal("inconsistent pagination", gotTotal, len(items))
		}
		paged = append(paged, items...)
	}
	if !reflect.DeepEqual(paged, all) {
		t.Fatal("pagination skipped or repeated port resources")
	}
	udp, count := portResourceSlots(edge, "udp", 0, 100)
	if count != 3 || len(udp) != 3 || udp[0].Status != "available" || udp[1].Status != "reserved" {
		t.Fatal("TCP reservations affected UDP availability", count, udp)
	}
	tcp, count := portResourceSlots(edge, "tcp", 0, 100)
	if count != 5 || len(tcp) != 5 {
		t.Fatal("TCP pool lost out-of-pool reservations", count, tcp)
	}
	empty, count := portResourceSlots(edge, "", total, 3)
	if count != total || empty == nil || len(empty) != 0 {
		t.Fatal("past-end page must be an empty array", count, empty)
	}
	edge.PortMin, edge.PortMax = 1024, 65535
	last, count := portResourceSlots(edge, "", 129023, 500)
	if count != 129024 || len(last) != 1 || last[0].Protocol != "udp" || last[0].Port != 65535 {
		t.Fatal("full-size pool pagination failed", count, last)
	}
}

func TestPortResourceQueryGuardsBeforeDatabase(t *testing.T) {
	s := &Server{}
	for _, query := range []string{
		"", "?edge_id=", "?edge_id=x&protocol=http", "?edge_id=x&protocol=TCP", "?edge_id=x&offset=-1", "?edge_id=x&offset=", "?edge_id=x&offset=999999999999999999999999", "?edge_id=x&limit=0", "?edge_id=x&limit=501", "?edge_id=x&limit=no", "?edge_id=x&unknown=1", "?edge_id=x&limit=1&limit=2", "?edge_id=" + strings.Repeat("x", 65),
	} {
		w := httptest.NewRecorder()
		s.portResources(w, httptest.NewRequest("GET", "/api/v1/port-resources"+query, nil))
		if w.Code != 400 {
			t.Errorf("query %q: got %d want 400", query, w.Code)
		}
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "HEAD"} {
		w := httptest.NewRecorder()
		s.portResources(w, httptest.NewRequest(method, "/api/v1/port-resources?edge_id=x", nil))
		if w.Code != 405 {
			t.Errorf("method %s: got %d want 405", method, w.Code)
		}
	}
}
