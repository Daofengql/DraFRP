package acl

import (
	"crypto/sha256"
	"drafrp/internal/model"
	"encoding/hex"
	"encoding/json"
)

func Digest(value any) string {
	b, _ := json.Marshal(value)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func Reference(policy model.ACLPolicy, kind string) model.ACLPolicyRef {
	return model.ACLPolicyRef{Kind: kind, TemplateID: policy.TemplateID, Version: policy.Version, Digest: Digest(policy)}
}

func EffectiveDigest(ruleID string, version uint64, refs []model.ACLPolicyRef) string {
	if refs == nil {
		refs = []model.ACLPolicyRef{}
	}
	return Digest(struct {
		ID       string
		Version  uint64
		Policies []model.ACLPolicyRef
	}{ruleID, version, refs})
}

func HitKey(hit model.ACLHit) string {
	hit.Allowed, hit.Denied = 0, 0
	hit.StartedAt = model.ACLHit{}.StartedAt
	return Digest(hit)
}
