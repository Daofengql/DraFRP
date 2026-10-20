package cloud

import (
	"context"
)

// Reclamation waits for every snapshot that could authorize the old resource.
// An offline edge cannot hold a deleting rule forever after that authority ends.
func (s *Server) reapResources(ctx context.Context) error {
	if _, e := s.store(ctx).ExecContext(ctx, "DELETE FROM resource_claims WHERE release_at IS NOT NULL AND release_at<=?", now()); e != nil {
		return e
	}
	_, e := s.store(ctx).ExecContext(ctx, "DELETE r FROM rules r LEFT JOIN resource_claims c ON c.rule_id=r.id WHERE r.deleting=1 AND c.rule_id IS NULL")
	return e
}
