package cloud

import (
	"drafrp/internal/acl"
	"drafrp/internal/model"
)

func compileDraft(p model.ACLPolicy) (*acl.Policy, error) {
	if p.DefaultAction == "" {
		p.DefaultAction = "deny"
	}
	return acl.Compile(p)
}
