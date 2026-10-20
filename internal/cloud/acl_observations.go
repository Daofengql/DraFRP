package cloud

import (
	"context"
	"database/sql"
	"drafrp/internal/acl"
	"drafrp/internal/model"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const aclStoredRowLimit = 8192 // Per edge, across boots and policy versions.
const aclStoredCounterMaximum = uint64(1 << 60)

var errACLReport = errors.New("invalid ACL report")

func migrateACLObservations(ctx context.Context, db *sql.DB) error {
	for _, query := range []string{
		`CREATE TABLE IF NOT EXISTS acl_observations(edge_id VARCHAR(64) NOT NULL,counter_key CHAR(64) NOT NULL,tenant_id VARCHAR(64) NOT NULL,rule_id VARCHAR(64) NOT NULL,boot_id VARCHAR(96) NOT NULL,payload JSON NOT NULL,allowed BIGINT UNSIGNED NOT NULL,denied BIGINT UNSIGNED NOT NULL,observed_at DATETIME(6) NOT NULL,received_at DATETIME(6) NOT NULL,PRIMARY KEY(edge_id,counter_key),INDEX(tenant_id,rule_id),INDEX(received_at),FOREIGN KEY(edge_id) REFERENCES edges(id) ON DELETE CASCADE) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS acl_edge_state(edge_id VARCHAR(64) PRIMARY KEY,boot_id VARCHAR(96) NOT NULL,sequence_no BIGINT UNSIGNED NOT NULL,observed_at DATETIME(6) NOT NULL,received_at DATETIME(6) NOT NULL,edge_dropped BIGINT UNSIGNED NOT NULL DEFAULT 0,cloud_dropped BIGINT UNSIGNED NOT NULL DEFAULT 0,FOREIGN KEY(edge_id) REFERENCES edges(id) ON DELETE CASCADE) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS acl_rule_acks(edge_id VARCHAR(64) NOT NULL,rule_id VARCHAR(64) NOT NULL,boot_id VARCHAR(96) NOT NULL,payload JSON NOT NULL,observed_at DATETIME(6) NOT NULL,received_at DATETIME(6) NOT NULL,PRIMARY KEY(edge_id,rule_id),FOREIGN KEY(edge_id) REFERENCES edges(id) ON DELETE CASCADE) ENGINE=InnoDB`,
	} {
		if _, err := db.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("ACL observation schema: %w", err)
		}
	}
	return nil
}

func aclDigestValid(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(value) == 64 && len(b) == 32
}

func aclRefValid(ref model.ACLPolicyRef) bool {
	if !aclDigestValid(ref.Digest) || len(ref.TemplateID) > 64 {
		return false
	}
	switch ref.Kind {
	case "mandatory_template", "rule_template":
		return ref.TemplateID != "" && ref.Version > 0
	case "rule_inline":
		return ref.TemplateID == ""
	}
	return false
}

func validateACLReport(report *model.ACLReport) error {
	if report == nil {
		return nil
	}
	b, err := json.Marshal(report)
	if err != nil || len(b) > 128<<10 || len(report.Rows) > 256 || len(report.ACKs) > 16 || report.Sequence == 0 || report.Dropped > aclStoredCounterMaximum {
		return errACLReport
	}
	validTime := func(t time.Time) bool { return !t.IsZero() && !t.After(now().Add(time.Minute)) }
	if !validTime(report.StartedAt) || !validTime(report.ObservedAt) || report.StartedAt.After(report.ObservedAt) {
		return errACLReport
	}
	for _, row := range report.Rows {
		if row.RuleID == "" || len(row.RuleID) > 64 || row.RuleVersion == 0 || !aclDigestValid(row.EffectiveDigest) || (row.Protocol != "tcp" && row.Protocol != "udp") || len(row.EntryID) > 128 || !utf8.ValidString(row.EntryID) || len(row.Reason) > 128 || row.Allowed > aclStoredCounterMaximum || row.Denied > aclStoredCounterMaximum || !validTime(row.StartedAt) || row.StartedAt.After(report.ObservedAt) {
			return errACLReport
		}
		switch row.Kind {
		case "policy":
			if !aclRefValid(row.Policy) || (row.EntryHash != "" && !aclDigestValid(row.EntryHash)) || (row.UsedDefault && row.EntryHash != "") {
				return errACLReport
			}
		case "rule_total":
			if row.Policy != (model.ACLPolicyRef{}) || row.EntryID != "" || row.EntryHash != "" || row.UsedDefault {
				return errACLReport
			}
		default:
			return errACLReport
		}
	}
	for _, ack := range report.ACKs {
		if ack.RuleID == "" || len(ack.RuleID) > 64 || ack.RuleVersion == 0 || len(ack.Error) > 128 || len(ack.Policies) > 65 || ack.ActiveFlows < 0 || !validTime(ack.AppliedAt) || !validTime(ack.SampledAt) || ack.SampledAt.After(report.ObservedAt) || ack.ExpiresAt.IsZero() {
			return errACLReport
		}
		if ack.State != "applied" && ack.State != "error" && ack.State != "inactive" {
			return errACLReport
		}
		for _, ref := range ack.Policies {
			if !aclRefValid(ref) {
				return errACLReport
			}
		}
		if ack.State == "applied" && ack.EffectiveDigest != acl.EffectiveDigest(ack.RuleID, ack.RuleVersion, ack.Policies) {
			return errACLReport
		}
	}
	return nil
}

// The edge row is locked by edgeSync. Boot fencing, telemetry and the rest of
// the synchronization commit together. A successful HTTP response is its ACK.
func (s *Server) recordACLReport(ctx context.Context, edgeID, boot string, report *model.ACLReport) error {
	if err := validateACLReport(report); err != nil || report == nil {
		return err
	}
	db := s.store(ctx)
	var previousBoot string
	var previousSequence, cloudDropped uint64
	err := db.QueryRowContext(ctx, "SELECT boot_id,sequence_no,cloud_dropped FROM acl_edge_state WHERE edge_id=?", edgeID).Scan(&previousBoot, &previousSequence, &cloudDropped)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if previousBoot == boot && report.Sequence <= previousSequence {
		return nil // Retries and out-of-order reports never double count.
	}
	if previousBoot != boot {
		cloudDropped = 0
		if _, err = db.ExecContext(ctx, "DELETE FROM acl_rule_acks WHERE edge_id=?", edgeID); err != nil {
			return err
		}
	}
	if _, err = db.ExecContext(ctx, "DELETE FROM acl_observations WHERE edge_id=? AND received_at<?", edgeID, now().Add(-7*24*time.Hour)); err != nil {
		return err
	}
	if _, err = db.ExecContext(ctx, "DELETE a FROM acl_rule_acks a LEFT JOIN rules r ON r.id=a.rule_id AND r.edge_id=a.edge_id WHERE a.edge_id=? AND r.id IS NULL", edgeID); err != nil {
		return err
	}
	// Resolve tenant authority from current database rows, never report labels.
	ids := map[string]bool{}
	for _, row := range report.Rows {
		ids[row.RuleID] = true
	}
	for _, ack := range report.ACKs {
		ids[ack.RuleID] = true
	}
	placeholders := []string{}
	args := []any{edgeID}
	for id := range ids {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}
	if len(placeholders) == 0 {
		placeholders = append(placeholders, "NULL")
	}
	rows, err := db.QueryContext(ctx, "SELECT id,tenant_id,protocol FROM rules WHERE edge_id=? AND protocol IN ('tcp','udp') AND id IN ("+strings.Join(placeholders, ",")+")", args...)
	if err != nil {
		return err
	}
	type owner struct{ tenant, protocol string }
	owners := map[string]owner{}
	for rows.Next() {
		var id string
		var item owner
		if err = rows.Scan(&id, &item.tenant, &item.protocol); err != nil {
			rows.Close()
			return err
		}
		owners[id] = item
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var stored int
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM acl_observations WHERE edge_id=?", edgeID).Scan(&stored); err != nil {
		return err
	}
	for _, hit := range report.Rows {
		authority, exists := owners[hit.RuleID]
		if !exists || authority.protocol != hit.Protocol {
			continue // Deleted, reassigned or foreign rules cannot create labels.
		}
		key := acl.Digest([]string{boot, acl.HitKey(hit)})
		var present int
		if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM acl_observations WHERE edge_id=? AND counter_key=?", edgeID, key).Scan(&present); err != nil {
			return err
		}
		if present == 0 {
			if stored >= aclStoredRowLimit {
				if cloudDropped < aclStoredCounterMaximum {
					cloudDropped++
				}
				continue
			}
			stored++
		}
		if _, err = db.ExecContext(ctx, `INSERT INTO acl_observations(edge_id,counter_key,tenant_id,rule_id,boot_id,payload,allowed,denied,observed_at,received_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE allowed=GREATEST(allowed,VALUES(allowed)),denied=GREATEST(denied,VALUES(denied)),observed_at=GREATEST(observed_at,VALUES(observed_at)),received_at=VALUES(received_at)`, edgeID, key, authority.tenant, hit.RuleID, boot, encodeJSON(hit), hit.Allowed, hit.Denied, report.ObservedAt, now()); err != nil {
			return err
		}
	}
	var storedACKs int
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM acl_rule_acks WHERE edge_id=?", edgeID).Scan(&storedACKs); err != nil {
		return err
	}
	for _, ack := range report.ACKs {
		if _, exists := owners[ack.RuleID]; !exists {
			continue
		}
		var present int
		if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM acl_rule_acks WHERE edge_id=? AND rule_id=?", edgeID, ack.RuleID).Scan(&present); err != nil {
			return err
		}
		if present == 0 {
			if storedACKs >= 4096 {
				if cloudDropped < aclStoredCounterMaximum {
					cloudDropped++
				}
				continue
			}
			storedACKs++
		}
		if _, err = db.ExecContext(ctx, `INSERT INTO acl_rule_acks(edge_id,rule_id,boot_id,payload,observed_at,received_at) VALUES(?,?,?,?,?,?) ON DUPLICATE KEY UPDATE boot_id=VALUES(boot_id),payload=VALUES(payload),observed_at=VALUES(observed_at),received_at=VALUES(received_at)`, edgeID, ack.RuleID, boot, encodeJSON(ack), report.ObservedAt, now()); err != nil {
			return err
		}
	}
	_, err = db.ExecContext(ctx, `INSERT INTO acl_edge_state(edge_id,boot_id,sequence_no,observed_at,received_at,edge_dropped,cloud_dropped) VALUES(?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE boot_id=VALUES(boot_id),sequence_no=VALUES(sequence_no),observed_at=VALUES(observed_at),received_at=VALUES(received_at),edge_dropped=VALUES(edge_dropped),cloud_dropped=VALUES(cloud_dropped)`, edgeID, boot, report.Sequence, report.ObservedAt, now(), report.Dropped, cloudDropped)
	return err
}

type aclApplication struct {
	RuleID      string            `json:"rule_id"`
	RuleName    string            `json:"rule_name"`
	RuleVersion uint64            `json:"rule_version"`
	EdgeID      string            `json:"edge_id"`
	EdgeName    string            `json:"edge_name"`
	BootID      string            `json:"boot_id"`
	State       string            `json:"state"`
	Stale       bool              `json:"stale"`
	ObservedAt  *time.Time        `json:"observed_at,omitempty"`
	ACKBootID   string            `json:"ack_boot_id,omitempty"`
	ACK         *model.ACLApplied `json:"ack,omitempty"`
}

func expectedACLRefs(rule model.Rule, mandatory []model.ACLPolicy) []model.ACLPolicyRef {
	refs := []model.ACLPolicyRef{}
	for _, policy := range mandatory {
		refs = append(refs, acl.Reference(policy, "mandatory_template"))
	}
	if rule.ACL != nil {
		kind := "rule_inline"
		if rule.ACLTemplateID != "" {
			kind = "rule_template"
		}
		refs = append(refs, acl.Reference(*rule.ACL, kind))
	}
	return refs
}

func loadACLApplication(ctx context.Context, db sqlStore, rule model.Rule, refs []model.ACLPolicyRef) (aclApplication, error) {
	out := aclApplication{RuleID: rule.ID, RuleName: rule.Name, RuleVersion: rule.Version, EdgeID: rule.EdgeID, State: "pending"}
	var currentBoot sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT name,boot_id FROM edges WHERE id=?", rule.EdgeID).Scan(&out.EdgeName, &currentBoot); err != nil {
		return out, err
	}
	out.BootID = currentBoot.String
	var raw string
	var observed time.Time
	err := db.QueryRowContext(ctx, "SELECT boot_id,payload,observed_at FROM acl_rule_acks WHERE edge_id=? AND rule_id=?", rule.EdgeID, rule.ID).Scan(&out.ACKBootID, &raw, &observed)
	if err == sql.ErrNoRows {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	var ack model.ACLApplied
	if err = json.Unmarshal([]byte(raw), &ack); err != nil {
		return out, err
	}
	out.ACK, out.ObservedAt = &ack, &observed
	out.Stale = now().Sub(observed) > time.Minute
	if out.ACKBootID != out.BootID || ack.RuleVersion != rule.Version {
		return out, nil
	}
	if ack.State == "error" {
		out.State = "error"
		return out, nil
	}
	if ack.State == "inactive" && (!rule.Enabled || rule.Deleting) {
		out.State = "inactive"
		return out, nil
	}
	if !rule.Enabled || rule.Deleting || ack.EffectiveDigest != acl.EffectiveDigest(rule.ID, rule.Version, refs) {
		return out, nil
	}
	if !now().Before(ack.ExpiresAt) {
		out.State = "expired"
		return out, nil
	}
	if ack.State == "applied" {
		out.State = "applied"
	}
	return out, nil
}

func (s *Server) aclObservations(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "GET") {
		return
	}
	ruleID := r.URL.Query().Get("rule_id")
	cursor := r.URL.Query().Get("cursor")
	limit := 100
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100 {
			apiErr(w, 400, "invalid_query", "limit must be 1..100")
			return
		}
		limit = parsed
	}
	if ruleID == "" || len(ruleID) > 64 || (cursor != "" && !aclDigestValid(cursor)) {
		apiErr(w, 400, "invalid_query", "valid rule_id and cursor are required")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		apiErr(w, 503, "database_unavailable", "could not read ACL observations")
		return
	}
	defer tx.Rollback()
	ctx := context.WithValue(r.Context(), mutationKey{}, &mutation{tx: tx})
	query := " WHERE id=?"
	args := []any{ruleID}
	if !isAdmin(r) {
		query += " AND tenant_id=?"
		args = append(args, tenant(r))
	}
	rules, err := s.queryRules(ctx, query, args...)
	if err != nil {
		apiErr(w, 503, "database_unavailable", "could not read rule")
		return
	}
	if len(rules) != 1 {
		apiErr(w, 404, "not_found", "rule not found")
		return
	}
	rule := rules[0]
	if rule.Protocol != "tcp" && rule.Protocol != "udp" {
		apiErr(w, 400, "invalid_protocol", "ACL observations apply to TCP/UDP only")
		return
	}
	mandatory, err := s.effectiveACLs(ctx, rules)
	if err != nil {
		apiErr(w, 503, "invalid_policy", err.Error())
		return
	}
	refs := expectedACLRefs(rules[0], mandatory)
	application, err := loadACLApplication(ctx, tx, rule, refs)
	if err != nil {
		apiErr(w, 503, "database_unavailable", "could not read actual ACL ACK")
		return
	}
	type observation struct {
		model.ACLHit
		Key        string    `json:"key"`
		BootID     string    `json:"boot_id"`
		Current    bool      `json:"current"`
		ObservedAt time.Time `json:"observed_at"`
		ReceivedAt time.Time `json:"received_at"`
	}
	rows, err := tx.QueryContext(ctx, `SELECT counter_key,boot_id,payload,allowed,denied,observed_at,received_at FROM acl_observations WHERE edge_id=? AND rule_id=? AND tenant_id=? AND counter_key>? AND received_at>=? ORDER BY counter_key LIMIT ?`, rule.EdgeID, rule.ID, rule.TenantID, cursor, now().Add(-7*24*time.Hour), limit+1)
	if err != nil {
		apiErr(w, 503, "database_unavailable", "could not read ACL counters")
		return
	}
	items := []observation{}
	for rows.Next() {
		var item observation
		var raw string
		var allowed, denied uint64
		if err = rows.Scan(&item.Key, &item.BootID, &raw, &allowed, &denied, &item.ObservedAt, &item.ReceivedAt); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(raw), &item.ACLHit); err != nil {
			break
		}
		item.Allowed, item.Denied = allowed, denied
		item.Current = item.BootID == application.BootID && item.RuleVersion == rule.Version && item.EffectiveDigest == acl.EffectiveDigest(rule.ID, rule.Version, refs)
		items = append(items, item)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		apiErr(w, 503, "database_unavailable", "could not decode ACL counters")
		return
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	next := ""
	if hasMore {
		next = items[len(items)-1].Key
	}
	// Global edge loss counts are administrator-only; tenant responses contain
	// only this tenant's rules and no other tenant's traffic totals.
	loss := map[string]uint64{}
	if isAdmin(r) {
		var boot string
		var edgeDrop, cloudDrop uint64
		e := tx.QueryRowContext(ctx, "SELECT boot_id,edge_dropped,cloud_dropped FROM acl_edge_state WHERE edge_id=?", rule.EdgeID).Scan(&boot, &edgeDrop, &cloudDrop)
		if e != nil && e != sql.ErrNoRows {
			apiErr(w, 503, "database_unavailable", "could not read collection limits")
			return
		}
		if boot == application.BootID {
			loss["edge_dropped"], loss["cloud_dropped"] = edgeDrop, cloudDrop
		}
	}
	if err = tx.Commit(); err != nil {
		apiErr(w, 503, "database_unavailable", "could not finish ACL observation snapshot")
		return
	}
	writeJSON(w, 200, map[string]any{"rule_id": rule.ID, "protocol": rule.Protocol, "items": items, "has_more": hasMore, "next_cursor": next, "application": application, "collection_loss": loss, "retention_days": 7, "observed_at": now()})
}

func (s *Server) aclApplications(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "GET") {
		return
	}
	id := r.URL.Query().Get("template_id")
	if id == "" || len(id) > 64 {
		apiErr(w, 400, "invalid_query", "template_id is required")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		apiErr(w, 503, "database_unavailable", "could not read template applications")
		return
	}
	defer tx.Rollback()
	ctx := context.WithValue(r.Context(), mutationKey{}, &mutation{tx: tx})
	var name string
	var raw sql.NullString
	var mandatoryFlag bool
	err = tx.QueryRowContext(ctx, "SELECT name,published,mandatory FROM acl_templates WHERE id=?", id).Scan(&name, &raw, &mandatoryFlag)
	if err == sql.ErrNoRows {
		apiErr(w, 404, "not_found", "template not found")
		return
	}
	if err != nil {
		apiErr(w, 503, "database_unavailable", "could not read template")
		return
	}
	var published *model.ACLPolicy
	if raw.Valid {
		var p model.ACLPolicy
		if err = json.Unmarshal([]byte(raw.String), &p); err != nil {
			apiErr(w, 503, "invalid_policy", "invalid published policy")
			return
		}
		published = &p
	}
	query := " WHERE protocol IN ('tcp','udp') AND acl_template_id=? ORDER BY edge_id,id LIMIT 4097"
	args := []any{id}
	if mandatoryFlag {
		query = " WHERE protocol IN ('tcp','udp') ORDER BY edge_id,id LIMIT 4097"
		args = nil
	}
	rules, err := s.queryRules(ctx, query, args...)
	if err != nil {
		apiErr(w, 503, "database_unavailable", "could not read affected rules")
		return
	}
	truncated := len(rules) > 4096
	if truncated {
		rules = rules[:4096]
	}
	mandatory, err := s.effectiveACLs(ctx, rules)
	if err != nil {
		apiErr(w, 503, "invalid_policy", err.Error())
		return
	}
	type edgeSummary struct {
		EdgeID   string           `json:"edge_id"`
		EdgeName string           `json:"edge_name"`
		BootID   string           `json:"boot_id"`
		Counts   map[string]int   `json:"counts"`
		Rules    []aclApplication `json:"rules"`
	}
	edges := []*edgeSummary{}
	byEdge := map[string]*edgeSummary{}
	for _, rule := range rules {
		application, e := loadACLApplication(ctx, tx, rule, expectedACLRefs(rule, mandatory))
		if e != nil {
			apiErr(w, 503, "database_unavailable", "could not read actual ACL application")
			return
		}
		edge := byEdge[rule.EdgeID]
		if edge == nil {
			edge = &edgeSummary{EdgeID: rule.EdgeID, EdgeName: application.EdgeName, BootID: application.BootID, Counts: map[string]int{}, Rules: []aclApplication{}}
			byEdge[rule.EdgeID] = edge
			edges = append(edges, edge)
		}
		edge.Counts[application.State]++
		edge.Rules = append(edge.Rules, application)
	}
	if err = tx.Commit(); err != nil {
		apiErr(w, 503, "database_unavailable", "could not finish application snapshot")
		return
	}
	writeJSON(w, 200, map[string]any{"template_id": id, "template_name": name, "published": published, "mandatory": mandatoryFlag, "items": edges, "truncated": truncated, "rule_limit": 4096, "observed_at": now()})
}
