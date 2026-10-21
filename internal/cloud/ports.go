package cloud

import (
	"database/sql"
	"drafrp/internal/model"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Port availability is an observation, not a reservation. Rule mutations still
// arbitrate ownership in their existing SQL transaction.
type portResource struct {
	EdgeID         string             `json:"edge_id"`
	Protocol       string             `json:"protocol"`
	Port           int                `json:"port"`
	InBusinessPool bool               `json:"in_business_pool"`
	Status         string             `json:"status"`
	Reservations   []string           `json:"reservations,omitempty"`
	ReleaseAt      *time.Time         `json:"release_at,omitempty"`
	Rule           *portResourceOwner `json:"rule,omitempty"`
}

type portResourceOwner struct {
	ID           string `json:"id"`
	Name         string `json:"name,omitempty"`
	TenantID     string `json:"tenant_id,omitempty"`
	CurrentClaim bool   `json:"current_claim"`
}

type portResourcePage struct {
	EdgeID     string         `json:"edge_id"`
	PortMin    int            `json:"port_min"`
	PortMax    int            `json:"port_max"`
	Items      []portResource `json:"items"`
	Total      int            `json:"total"`
	Offset     int            `json:"offset"`
	Limit      int            `json:"limit"`
	ObservedAt time.Time      `json:"observed_at"`
}

func (s *Server) portResources(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "GET") {
		return
	}
	query := r.URL.Query()
	for key, values := range query {
		if len(values) != 1 || (key != "edge_id" && key != "protocol" && key != "offset" && key != "limit") {
			apiErr(w, 400, "invalid_query", "use edge_id, protocol, offset and limit once each")
			return
		}
	}
	edgeID, protocol := query.Get("edge_id"), query.Get("protocol")
	if edgeID == "" || len(edgeID) > 64 || (protocol != "" && protocol != "tcp" && protocol != "udp") {
		apiErr(w, 400, "invalid_query", "edge_id is required; protocol must be tcp or udp")
		return
	}
	offset, limit := 0, 100
	var err error
	if raw, supplied := query["offset"]; supplied {
		offset, err = strconv.Atoi(raw[0])
		if err != nil || offset < 0 {
			apiErr(w, 400, "invalid_query", "offset must be a non-negative integer")
			return
		}
	}
	if raw, supplied := query["limit"]; supplied {
		limit, err = strconv.Atoi(raw[0])
		if err != nil || limit < 1 || limit > 500 {
			apiErr(w, 400, "invalid_query", "limit must be within 1..500")
			return
		}
	}
	// Read listeners and claims from one authoritative snapshot. A stale cache
	// must never label a claimed or reserved port as available.
	tx, err := s.db.BeginTx(r.Context(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		apiErr(w, 503, "database_unavailable", "could not read port resources")
		return
	}
	defer tx.Rollback()
	if !isAdmin(r) {
		q, e := readQuota(r.Context(), tx, tenant(r), false)
		if e != nil {
			apiErr(w, 503, "database_unavailable", e.Error())
			return
		}
		if !edgeAllowed(q, edgeID) {
			apiErr(w, 403, "plan_node_denied", "套餐未包含该出口节点")
			return
		}
	}
	edge := model.Edge{ID: edgeID}
	var raw string
	err = tx.QueryRowContext(r.Context(), "SELECT endpoints,http_port,https_port,port_min,port_max FROM edges WHERE id=?", edgeID).Scan(&raw, &edge.HTTPPort, &edge.HTTPSPort, &edge.PortMin, &edge.PortMax)
	if errors.Is(err, sql.ErrNoRows) {
		apiErr(w, 404, "not_found", "edge not found")
		return
	}
	if err != nil || json.Unmarshal([]byte(raw), &edge.Endpoints) != nil || edge.PortMin < 1024 || edge.PortMax > 65535 || edge.PortMax < edge.PortMin {
		apiErr(w, 503, "database_unavailable", "could not read edge port configuration")
		return
	}
	page := portResourcePage{EdgeID: edgeID, PortMin: edge.PortMin, PortMax: edge.PortMax, Offset: offset, Limit: limit, ObservedAt: now()}
	page.Items, page.Total = portResourceSlots(edge, protocol, offset, limit)
	keys := make([]string, 0, len(page.Items))
	byKey := make(map[string]int, len(page.Items))
	args := []any{edgeID, page.ObservedAt}
	for i := range page.Items {
		x := &page.Items[i]
		if x.Status == "reserved" {
			continue
		}
		key := x.Protocol + "/" + strconv.Itoa(x.Port)
		keys = append(keys, "?")
		args = append(args, key)
		byKey[key] = i
	}
	if len(keys) > 0 {
		// LEFT JOIN deliberately preserves claims left by an older snapshot
		// after the current rule moved or was acknowledged on another edge.
		rows, err := tx.QueryContext(r.Context(), "SELECT c.resource_key,c.rule_id,c.release_at,r.id,r.name,r.tenant_id,r.edge_id,r.protocol,r.public_port FROM resource_claims c LEFT JOIN rules r ON r.id=c.rule_id WHERE c.edge_id=? AND (c.release_at IS NULL OR c.release_at>?) AND c.resource_key IN ("+strings.Join(keys, ",")+")", args...)
		if err != nil {
			apiErr(w, 503, "database_unavailable", "could not read port claims")
			return
		}
		p, _ := r.Context().Value(pkey{}).(*principal)
		for rows.Next() {
			var key, ruleID string
			var release sql.NullTime
			var currentID, name, tenantID, currentEdge, currentProtocol sql.NullString
			var currentPort sql.NullInt64
			if err = rows.Scan(&key, &ruleID, &release, &currentID, &name, &tenantID, &currentEdge, &currentProtocol, &currentPort); err != nil {
				break
			}
			x := &page.Items[byKey[key]]
			x.Status = "occupied"
			if release.Valid {
				x.Status = "releasing"
				x.ReleaseAt = &release.Time
			}
			// Only the owner or an administrator may see claim identity. In
			// particular, an orphan has no tenant that can authorize disclosure.
			if p != nil && (p.User.Role == "admin" || (tenantID.Valid && tenantID.String == p.User.TenantID)) {
				x.Rule = &portResourceOwner{ID: ruleID, Name: name.String, TenantID: tenantID.String, CurrentClaim: currentID.Valid && currentEdge.String == edgeID && currentProtocol.String == x.Protocol && currentPort.Int64 == int64(x.Port)}
			}
		}
		readErr := rows.Err()
		closeErr := rows.Close()
		if err != nil || readErr != nil || closeErr != nil {
			apiErr(w, 503, "database_unavailable", "could not read port claims")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		apiErr(w, 503, "database_unavailable", "could not finish reading port resources")
		return
	}
	writeJSON(w, 200, page)
}

// The full pool can contain over 129,000 protocol/port pairs; only materialize
// the requested page. Sort by numeric port, then TCP before UDP.
func portResourceSlots(edge model.Edge, protocol string, offset, limit int) ([]portResource, int) {
	reserved := make(map[string][]string)
	add := func(proto string, port int, kind string) {
		if port < 1 || port > 65535 || (protocol != "" && protocol != proto) {
			return
		}
		key := proto + "/" + strconv.Itoa(port)
		for _, existing := range reserved[key] {
			if existing == kind {
				return
			}
		}
		reserved[key] = append(reserved[key], kind)
	}
	for _, endpoint := range edge.Endpoints {
		_, rawPort, err := net.SplitHostPort(endpoint.Address)
		port, parseErr := strconv.Atoi(rawPort)
		if err != nil || parseErr != nil {
			continue
		}
		switch endpoint.Transport {
		case "tls":
			add("tcp", port, "carrier_tls")
		case "quic":
			add("udp", port, "carrier_quic")
		}
	}
	add("tcp", edge.HTTPPort, "http")
	add("tcp", edge.HTTPSPort, "https")
	protocols := []string{"tcp", "udp"}
	if protocol != "" {
		protocols = []string{protocol}
	}
	total := (edge.PortMax - edge.PortMin + 1) * len(protocols)
	for key := range reserved {
		_, rawPort, _ := strings.Cut(key, "/")
		port, _ := strconv.Atoi(rawPort)
		if port < edge.PortMin || port > edge.PortMax {
			total++
		}
	}
	items := make([]portResource, 0, min(limit, max(0, total-offset)))
	index := 0
	for port := 1; port <= 65535 && len(items) < limit; port++ {
		inPool := port >= edge.PortMin && port <= edge.PortMax
		for _, proto := range protocols {
			kinds := reserved[proto+"/"+strconv.Itoa(port)]
			if !inPool && len(kinds) == 0 {
				continue
			}
			if index >= offset && len(items) < limit {
				status := "available"
				if len(kinds) > 0 {
					status = "reserved"
				}
				items = append(items, portResource{EdgeID: edge.ID, Protocol: proto, Port: port, InBusinessPool: inPool, Status: status, Reservations: kinds})
			}
			index++
		}
	}
	return items, total
}
