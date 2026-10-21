package cloud

import (
	"context"
	"drafrp/internal/model"
	"errors"
	"fmt"
	"net/http"
)

type resourceDelta struct {
	kind  string
	count int64
}

type resourceQuotaError struct {
	kind  string
	used  int64
	limit int
}

type resourceCapacityUnavailable struct{ error }

var errUnattributedPorts = errors.New("历史端口保留记录仍在等待归属核对或到期释放，当前暂不能增加有数量上限的公网端口")

func (e *resourceQuotaError) Error() string {
	label := map[string]string{"devices": "客户端", "rules": "服务", "ports": "公网 TCP/UDP 端口", "domains": "域名", "sites": "网站"}[e.kind]
	return fmt.Sprintf("%s数量已达套餐上限（已用 %d，上限 %d）", label, e.used, e.limit)
}

func resourceCount(ctx context.Context, db sqlStore, tenantID, kind string) (int64, error) {
	var query string
	switch kind {
	case "devices":
		query = "SELECT COUNT(*) FROM devices WHERE tenant_id=? AND revoked=0"
	case "rules":
		query = "SELECT COUNT(*) FROM rules WHERE tenant_id=?"
	case "sites":
		query = "SELECT COUNT(*) FROM rules WHERE tenant_id=? AND protocol IN ('http','https')"
	case "domains":
		query = "SELECT COUNT(*) FROM domains WHERE tenant_id=?"
	case "ports":
		// The same number in TCP and UDP counts as two public resources. Old
		// reservations remain charged until their ACK or expiry reclamation.
		query = "SELECT COUNT(*) FROM resource_claims c WHERE c.tenant_id <=> NULLIF(?,'') AND (c.resource_key LIKE 'tcp/%' OR c.resource_key LIKE 'udp/%') AND (c.release_at IS NULL OR c.release_at>?)"
	default:
		return 0, errors.New("unknown configuration resource kind")
	}
	args := []any{tenantID}
	if kind == "ports" {
		args = append(args, now())
	}
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

func resourceUsage(ctx context.Context, db sqlStore, tenantID string) (*model.ResourceUsage, error) {
	u := &model.ResourceUsage{ObservedAt: now()}
	// One statement gives a consistent observation without five round trips.
	err := db.QueryRowContext(ctx, `SELECT
  (SELECT COUNT(*) FROM devices WHERE tenant_id=? AND revoked=0),
  (SELECT COUNT(*) FROM rules WHERE tenant_id=?),
  (SELECT COUNT(*) FROM resource_claims WHERE tenant_id=? AND (resource_key LIKE 'tcp/%' OR resource_key LIKE 'udp/%') AND (release_at IS NULL OR release_at>?)),
  (SELECT COUNT(*) FROM domains WHERE tenant_id=?),
  (SELECT COUNT(*) FROM rules WHERE tenant_id=? AND protocol IN ('http','https'))`, tenantID, tenantID, tenantID, u.ObservedAt, tenantID, tenantID).Scan(&u.Devices, &u.Rules, &u.Ports, &u.Domains, &u.Sites)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// Serialize admission on the same durable quota row used by policy updates.
// This check and the resource write MUST share the supplied transaction; neither
// cache state nor a browser's last displayed count grants a configuration slot.
func requireResourceCapacity(ctx context.Context, tx *businessTx, tenantID string, changes ...resourceDelta) error {
	q, err := readQuota(ctx, tx, tenantID, true)
	if err != nil {
		return &resourceCapacityUnavailable{err}
	}
	limits := map[string]int{"devices": q.MaxDevices, "rules": q.MaxRules, "ports": q.MaxPorts, "domains": q.MaxDomains, "sites": q.MaxSites}
	for _, change := range changes {
		limit, ok := limits[change.kind]
		if !ok || change.count < 0 {
			return errors.New("invalid configuration resource delta")
		}
		if change.count == 0 || limit == -1 {
			continue
		}
		if change.kind == "ports" {
			// A legacy orphan without any recoverable owner must not silently
			// become free quota. Release requires expiry or ownership recovery.
			unknown, err := resourceCount(ctx, tx, "", "ports")
			if err != nil {
				return &resourceCapacityUnavailable{err}
			}
			if unknown != 0 {
				return errUnattributedPorts
			}
		}
		used, err := resourceCount(ctx, tx, tenantID, change.kind)
		if err != nil {
			return &resourceCapacityUnavailable{err}
		}
		if used+change.count > int64(limit) {
			return &resourceQuotaError{change.kind, used, limit}
		}
	}
	return nil
}

func writeResourceQuotaError(w http.ResponseWriter, err error) bool {
	var unavailable *resourceCapacityUnavailable
	if errors.As(err, &unavailable) {
		apiErr(w, http.StatusServiceUnavailable, "database_unavailable", "could not check configuration resource quota")
		return true
	}
	if errors.Is(err, errUnattributedPorts) {
		apiErr(w, http.StatusConflict, "resource_quota_pending", err.Error())
		return true
	}
	var quota *resourceQuotaError
	if !errors.As(err, &quota) {
		return false
	}
	apiErr(w, http.StatusConflict, "resource_quota_exceeded", quota.Error())
	return true
}
