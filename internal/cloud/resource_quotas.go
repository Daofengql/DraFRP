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
	label := map[string]string{"devices": "设备", "rules": "规则与站点", "ports": "公网 TCP/UDP 端口", "domains": "域名"}[e.kind]
	return fmt.Sprintf("%s数量已达上限（已占用 %d，上限 %d），请释放资源或联系管理员调整配额", label, e.used, e.limit)
}

func resourceCount(ctx context.Context, db sqlStore, tenantID, kind string) (int64, error) {
	var query string
	switch kind {
	case "devices":
		query = "SELECT COUNT(*) FROM devices WHERE tenant_id=? AND revoked=0"
	case "rules":
		query = "SELECT COUNT(*) FROM rules WHERE tenant_id=?"
	case "domains":
		query = "SELECT COUNT(*) FROM domains WHERE tenant_id=?"
	case "ports":
		// The same number in TCP and UDP counts as two public resources. Old
		// reservations remain charged until their ACK or expiry reclamation.
		query = "SELECT COUNT(*) FROM resource_claims c WHERE c.tenant_id=? AND (c.resource_key LIKE 'tcp/%' OR c.resource_key LIKE 'udp/%') AND (c.release_at IS NULL OR c.release_at>?)"
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
	for _, item := range []struct {
		kind  string
		value *int64
	}{
		{"devices", &u.Devices}, {"rules", &u.Rules}, {"ports", &u.Ports}, {"domains", &u.Domains},
	} {
		var err error
		*item.value, err = resourceCount(ctx, db, tenantID, item.kind)
		if err != nil {
			return nil, err
		}
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
	limits := map[string]int{"devices": q.MaxDevices, "rules": q.MaxRules, "ports": q.MaxPorts, "domains": q.MaxDomains}
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
