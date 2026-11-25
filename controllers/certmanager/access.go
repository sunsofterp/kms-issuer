package certmanager

import (
	"fmt"
	"strings"
)

// Access is what the operator allows, from the controller's flags: the namespaces a
// KMSIssuer may live in and the KMS keys one may name. Both lists are required, so
// a KMSIssuer created anywhere else, or naming any other key, signs nothing.
type Access struct {
	namespaces map[string]bool
	keyIDs     map[string]bool
}

// NewAccess builds an Access from lists of namespaces and key IDs or ARNs. Aliases
// are refused: they can be re-pointed at another key.
func NewAccess(namespaces, keyIDs []string) (*Access, error) {
	a := &Access{namespaces: map[string]bool{}, keyIDs: map[string]bool{}}
	for _, ns := range namespaces {
		if ns = strings.TrimSpace(ns); ns != "" {
			a.namespaces[ns] = true
		}
	}
	for _, id := range keyIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if isAlias(id) {
			return nil, fmt.Errorf("%q is an alias; allow keys by key ID or ARN", id)
		}
		a.keyIDs[id] = true
	}
	if len(a.namespaces) == 0 {
		return nil, fmt.Errorf("at least one allowed issuer namespace is required")
	}
	if len(a.keyIDs) == 0 {
		return nil, fmt.Errorf("at least one allowed KMS key is required")
	}
	return a, nil
}

// Check returns an error unless a KMSIssuer in namespace may use keyID.
func (a *Access) Check(namespace, keyID string) error {
	if !a.namespaces[namespace] {
		return fmt.Errorf("namespace %q is not an allowed issuer namespace", namespace)
	}
	if isAlias(keyID) {
		return fmt.Errorf("keyId %q is an alias; name the key by key ID or ARN", keyID)
	}
	if !a.keyIDs[keyID] {
		return fmt.Errorf("KMS key %q is not an allowed key", keyID)
	}
	return nil
}

func isAlias(id string) bool {
	return strings.HasPrefix(id, "alias/") || strings.Contains(id, ":alias/")
}
