package cloud

import (
	"context"
	"database/sql"
	"drafrp/internal/acl"
	"drafrp/internal/geoip"
	"drafrp/internal/model"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const simulationPolicyLimit = 128

type simulationGeo struct {
	State   string `json:"state"`
	Country string `json:"country,omitempty"`
	Region  string `json:"region,omitempty"`
	Version string `json:"version,omitempty"`
}

type simulationRequest struct {
	SourceIP         string           `json:"source_ip"`
	SourcePort       int              `json:"source_port"`
	Protocol         string           `json:"protocol"`
	At               *time.Time       `json:"at,omitempty"`
	Geo              *simulationGeo   `json:"geo,omitempty"`
	RuleID           string           `json:"rule_id,omitempty"`
	TemplateID       string           `json:"template_id,omitempty"`
	TemplateRevision string           `json:"template_revision,omitempty"`
	Policy           *model.ACLPolicy `json:"policy,omitempty"`
}

type simulationLayer struct {
	Kind          string       `json:"kind"`
	TemplateID    string       `json:"template_id,omitempty"`
	Name          string       `json:"name,omitempty"`
	Revision      string       `json:"revision,omitempty"`
	PolicyVersion uint64       `json:"policy_version"`
	RequiresGeo   bool         `json:"requires_geo"`
	Decision      acl.Decision `json:"decision"`
	policy        model.ACLPolicy
}

type simulationRule struct {
	ID         string `json:"id"`
	Version    uint64 `json:"version"`
	Protocol   string `json:"protocol"`
	EdgeID     string `json:"edge_id"`
	PublicPort int    `json:"public_port"`
	Enabled    bool   `json:"enabled"`
	Deleting   bool   `json:"deleting"`
}

type simulationResponse struct {
	Scope           string    `json:"scope"`
	ObservedAt      time.Time `json:"observed_at"`
	EvaluatedAt     time.Time `json:"evaluated_at"`
	ACLOnly         bool      `json:"acl_only"`
	DesiredSnapshot bool      `json:"desired_snapshot"`
	Source          struct {
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	} `json:"source"`
	Geo struct {
		simulationGeo
		Source string `json:"source"`
	} `json:"geo"`
	Rule    *simulationRule   `json:"rule,omitempty"`
	Allowed bool              `json:"allowed"`
	Action  string            `json:"action"`
	Reason  string            `json:"reason"`
	Chain   []simulationLayer `json:"chain"`
}

// aclSimulation is a read-only POST. It deliberately does not use auth/mutate:
// a diagnostic must not create audit/replay rows or change config revision.
// Session, CSRF and Origin checks match authenticated browser mutations.
func (s *Server) aclSimulation(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, "POST") {
		return
	}
	p, err := s.principal(r)
	if err != nil {
		if errors.Is(err, errSession) {
			apiErr(w, 401, "unauthorized", "login required")
		} else {
			apiErr(w, 503, "database_unavailable", "could not validate session")
		}
		return
	}
	if hashToken(r.Header.Get("X-CSRF-Token")) != p.CSRF {
		apiErr(w, 403, "csrf", "missing or invalid CSRF token")
		return
	}
	if !sameOrigin(r) {
		apiErr(w, 403, "origin", "cross-origin diagnostic rejected")
		return
	}
	if !s.allowRequest(r, "acl_simulation", 60) {
		w.Header().Set("Retry-After", "60")
		apiErr(w, 429, "rate_limited", "too many ACL simulations")
		return
	}
	var in simulationRequest
	if err = readJSON(w, r, &in); err != nil {
		apiErr(w, 400, "invalid_json", err.Error())
		return
	}
	ip, lookup, err := validateSimulation(in)
	if err != nil {
		apiErr(w, 400, "invalid_simulation", err.Error())
		return
	}
	if (in.Policy != nil || in.TemplateRevision == "draft") && p.User.Role != "admin" {
		apiErr(w, 403, "forbidden", "administrator role required to preview draft policies")
		return
	}
	observed := now()
	out := simulationResponse{ObservedAt: observed, EvaluatedAt: observed, ACLOnly: true, DesiredSnapshot: true, Chain: []simulationLayer{}}
	out.Source.IP, out.Source.Port, out.Source.Protocol = ip.String(), in.SourcePort, in.Protocol
	out.Geo.State, out.Geo.Source = "unavailable", "unavailable"
	if in.Geo != nil {
		out.Geo.simulationGeo, out.Geo.Source = *in.Geo, "manual"
	}
	if in.At != nil {
		out.EvaluatedAt = in.At.UTC()
	}
	if in.Policy != nil {
		out.Scope = "draft_preview"
		out.Chain = append(out.Chain, simulationLayer{Kind: "draft", Revision: "draft", PolicyVersion: in.Policy.Version, policy: *in.Policy})
	} else {
		tx, err := s.db.BeginTx(r.Context(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
		if err != nil {
			apiErr(w, 503, "database_unavailable", "could not read policy snapshot")
			return
		}
		defer tx.Rollback()
		if status, code, message := loadSimulation(r.Context(), tx, p, in, &out); status != 0 {
			apiErr(w, status, code, message)
			return
		}
		if err := tx.Commit(); err != nil {
			apiErr(w, 503, "database_unavailable", "could not finish reading policy snapshot")
			return
		}
	}
	if err := evaluateSimulation(&out, ip, lookup); err != nil {
		apiErr(w, 400, "invalid_acl", err.Error())
		return
	}
	writeJSON(w, 200, out)
}

func validateSimulation(in simulationRequest) (netip.Addr, func(netip.Addr) (string, string, bool), error) {
	ip, err := netip.ParseAddr(in.SourceIP)
	if err != nil || ip.Zone() != "" || in.SourcePort < 1 || in.SourcePort > 65535 || (in.Protocol != "tcp" && in.Protocol != "udp") {
		return netip.Addr{}, nil, errors.New("source_ip must be an IPv4/IPv6 address without zone; source_port is 1..65535; protocol is tcp or udp")
	}
	targets := 0
	for _, selected := range []bool{in.RuleID != "", in.TemplateID != "", in.Policy != nil} {
		if selected {
			targets++
		}
	}
	if targets != 1 || len(in.RuleID) > 64 || len(in.TemplateID) > 64 {
		return netip.Addr{}, nil, errors.New("select exactly one rule_id, template_id or policy")
	}
	if in.TemplateRevision != "" && (in.TemplateID == "" || (in.TemplateRevision != "draft" && in.TemplateRevision != "published")) {
		return netip.Addr{}, nil, errors.New("template_revision may be draft or published only with template_id")
	}
	if in.At != nil && in.At.IsZero() {
		return netip.Addr{}, nil, errors.New("at must be a nonzero RFC3339 timestamp")
	}
	if in.Geo == nil {
		return ip.Unmap(), nil, nil
	}
	g := *in.Geo
	if len(g.Version) > 128 || strings.ContainsAny(g.Version, "\x00\r\n") {
		return netip.Addr{}, nil, errors.New("manual geographic version must be at most 128 bytes without control separators")
	}
	switch g.State {
	case "unavailable", "unknown":
		if g.Country != "" || g.Region != "" {
			return netip.Addr{}, nil, errors.New("unknown or unavailable geographic context cannot contain country or region")
		}
	case "known":
		if !geoip.CountryCode(g.Country) || (g.Region != "" && (!geoip.RegionCode(g.Region) || !strings.HasPrefix(g.Region, g.Country+"-"))) {
			return netip.Addr{}, nil, errors.New("known geographic context requires uppercase country and matching region")
		}
	default:
		return netip.Addr{}, nil, errors.New("geo.state must be unavailable, unknown or known")
	}
	if g.State == "unavailable" {
		return ip.Unmap(), nil, nil
	}
	lookup := func(netip.Addr) (string, string, bool) { return g.Country, g.Region, g.State == "known" }
	return ip.Unmap(), lookup, nil
}

func loadSimulation(ctx context.Context, tx *sql.Tx, p *principal, in simulationRequest, out *simulationResponse) (int, string, string) {
	if in.TemplateID != "" {
		out.Scope = "template_preview"
		layer, status, code, message := simulationTemplate(ctx, tx, in.TemplateID, in.TemplateRevision == "draft")
		if status != 0 {
			return status, code, message
		}
		out.Chain = append(out.Chain, layer)
		return 0, "", ""
	}
	out.Scope = "rule_effective"
	var rule simulationRule
	var tenantID string
	var templateID, inline sql.NullString
	err := tx.QueryRowContext(ctx, "SELECT id,tenant_id,version,protocol,edge_id,public_port,enabled,deleting,acl_template_id,acl FROM rules WHERE id=?", in.RuleID).Scan(&rule.ID, &tenantID, &rule.Version, &rule.Protocol, &rule.EdgeID, &rule.PublicPort, &rule.Enabled, &rule.Deleting, &templateID, &inline)
	if errors.Is(err, sql.ErrNoRows) || err == nil && p.User.Role != "admin" && tenantID != p.User.TenantID {
		return 404, "not_found", "rule not found"
	}
	if err != nil {
		return 503, "database_unavailable", "could not read rule"
	}
	if rule.Protocol != in.Protocol || (rule.Protocol != "tcp" && rule.Protocol != "udp") {
		return 400, "protocol_mismatch", "simulation protocol must match a TCP/UDP rule"
	}
	out.Rule = &rule
	rows, err := tx.QueryContext(ctx, "SELECT id,name,published FROM acl_templates WHERE mandatory=1 ORDER BY id LIMIT ?", simulationPolicyLimit+1)
	if err != nil {
		return 503, "database_unavailable", "could not read mandatory policies"
	}
	for rows.Next() {
		var layer simulationLayer
		var raw sql.NullString
		if err = rows.Scan(&layer.TemplateID, &layer.Name, &raw); err != nil {
			break
		}
		if len(out.Chain) >= simulationPolicyLimit {
			_ = rows.Close()
			return 400, "simulation_capacity", "too many mandatory policies to simulate in one request"
		}
		if !raw.Valid || json.Unmarshal([]byte(raw.String), &layer.policy) != nil {
			_ = rows.Close()
			return 409, "policy_unavailable", "a mandatory template has no valid published policy"
		}
		layer.Kind, layer.Revision, layer.PolicyVersion = "mandatory_template", "published", layer.policy.Version
		out.Chain = append(out.Chain, layer)
	}
	readErr := rows.Err()
	closeErr := rows.Close()
	if err != nil || readErr != nil || closeErr != nil {
		return 503, "database_unavailable", "could not read mandatory policies"
	}
	if templateID.Valid && templateID.String != "" {
		layer, status, code, message := simulationTemplate(ctx, tx, templateID.String, false)
		if status != 0 {
			return status, code, message
		}
		layer.Kind = "rule_template"
		out.Chain = append(out.Chain, layer)
	} else if inline.Valid && inline.String != "" && inline.String != "null" {
		layer := simulationLayer{Kind: "rule_inline"}
		if json.Unmarshal([]byte(inline.String), &layer.policy) != nil {
			return 409, "policy_unavailable", "rule inline policy is invalid"
		}
		layer.PolicyVersion = layer.policy.Version
		out.Chain = append(out.Chain, layer)
	}
	return 0, "", ""
}

func simulationTemplate(ctx context.Context, tx *sql.Tx, id string, draft bool) (simulationLayer, int, string, string) {
	layer := simulationLayer{Kind: "template", TemplateID: id, Revision: "published"}
	var raw string
	var published sql.NullString
	err := tx.QueryRowContext(ctx, "SELECT name,policy,published,version FROM acl_templates WHERE id=?", id).Scan(&layer.Name, &raw, &published, &layer.PolicyVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return layer, 404, "not_found", "template not found"
	}
	if err != nil {
		return layer, 503, "database_unavailable", "could not read template"
	}
	if draft {
		layer.Revision = "draft"
	} else {
		if !published.Valid {
			return layer, 404, "not_found", "published template not found"
		}
		raw = published.String
	}
	if err := json.Unmarshal([]byte(raw), &layer.policy); err != nil {
		return layer, 409, "policy_unavailable", "template policy is invalid"
	}
	if !draft {
		layer.PolicyVersion = layer.policy.Version
	}
	return layer, 0, "", ""
}

func evaluateSimulation(out *simulationResponse, ip netip.Addr, lookup func(netip.Addr) (string, string, bool)) error {
	out.Allowed, out.Action, out.Reason = true, "allow", "all_policies_allow"
	if len(out.Chain) == 0 {
		out.Reason = "no_acl"
	}
	for i := range out.Chain {
		layer := &out.Chain[i]
		compiled, err := acl.CompileWithGeo(layer.policy, lookup)
		if err != nil {
			return err
		}
		layer.RequiresGeo = compiled.RequiresGeo()
		if layer.RequiresGeo && lookup == nil {
			// The live edge disables the entire regional rule when its database
			// is missing, including when an earlier non-geographic entry allows.
			layer.Decision = acl.Decision{Action: "deny", Reason: "geoip_unavailable"}
			out.Allowed, out.Action, out.Reason = false, "deny", "capability_missing"
			continue
		}
		layer.Decision = compiled.ExplainAt(ip, out.Source.Protocol, out.Source.Port, out.EvaluatedAt)
		if !layer.Decision.Allowed {
			out.Allowed, out.Action = false, "deny"
			if out.Reason != "capability_missing" {
				out.Reason = "policy_denied"
			}
		}
	}
	return nil
}
