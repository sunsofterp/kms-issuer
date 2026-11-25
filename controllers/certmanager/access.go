package certmanager

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	kmsiapi "github.com/sunsofterp/kms-issuer/v5/apis/certmanager/v1alpha1"
	"github.com/sunsofterp/kms-issuer/v5/pkg/kmsca"
)

// Access is what the operator allows, from the controller's flags. A KMSIssuer may
// only live in an allowed namespace, use an allowed key, chain to the pinned root,
// and stay within the ceilings: its permitted domains inside the operator's, its
// leaf lifetime no longer, and wildcards only if the operator allows them. Whoever
// can write KMSIssuers can narrow the policy, never widen it past these. Any issuer
// outside them signs nothing.
type Access struct {
	namespaces map[string]bool
	keyIDs     map[string]bool
	ceilings   Ceilings
	roots      []*x509.Certificate
}

// Ceilings are the operator's upper bounds on every KMSIssuer.
type Ceilings struct {
	// PermittedDNSDomains: every issuer domain, and every name constraint of its
	// intermediate, must equal one or be a subdomain.
	PermittedDNSDomains []string
	// AllowWildcards: whether any issuer may allow wildcard names.
	AllowWildcards bool
	// MaxCertificateDuration: the longest issued validity any issuer may allow.
	MaxCertificateDuration time.Duration
	// MaxIntermediateDuration: the longest an issuer's intermediate may be valid
	// (0: kmsca.MaxIntermediateDuration, which is also the most it may be).
	MaxIntermediateDuration time.Duration
}

// NewAccess builds an Access. Namespaces, key IDs, permitted domains and at least
// one root are all required. Aliases are refused as keys: they can be re-pointed at
// another key. Each root must be a valid root for this CA (self-signed, path length
// 1, name constrained) with every permitted domain inside the operator's. More than
// one root is pinned only while replacing one: intermediates may chain to either.
func NewAccess(namespaces, keyIDs []string, ceilings Ceilings, roots []*x509.Certificate, now time.Time) (*Access, error) {
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
	for _, d := range ceilings.PermittedDNSDomains {
		d = normalizeDomain(d)
		if d == "" || !strings.Contains(d, ".") {
			return nil, fmt.Errorf("permitted DNS domain %q must have at least two labels", d)
		}
		a.ceilings.PermittedDNSDomains = append(a.ceilings.PermittedDNSDomains, d)
	}
	if len(a.ceilings.PermittedDNSDomains) == 0 {
		return nil, fmt.Errorf("at least one permitted DNS domain is required")
	}
	if ceilings.MaxCertificateDuration < time.Hour || ceilings.MaxCertificateDuration%time.Second != 0 {
		return nil, fmt.Errorf("the maximum certificate duration must be whole seconds and at least 1h")
	}
	if ceilings.MaxIntermediateDuration > kmsca.MaxIntermediateDuration {
		return nil, fmt.Errorf("the maximum intermediate duration is at most %s", kmsca.MaxIntermediateDuration)
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("at least one root certificate is required")
	}
	for i, root := range roots {
		if err := kmsca.ValidateRoot(root, now); err != nil {
			return nil, fmt.Errorf("root certificate %d: %w", i+1, err)
		}
		for _, d := range root.PermittedDNSDomains {
			if !withinDomains(d, a.ceilings.PermittedDNSDomains) {
				return nil, fmt.Errorf("root certificate %d permits %q, outside the permitted DNS domains %v", i+1, d, a.ceilings.PermittedDNSDomains)
			}
		}
	}
	a.ceilings.AllowWildcards = ceilings.AllowWildcards
	a.ceilings.MaxCertificateDuration = ceilings.MaxCertificateDuration
	a.ceilings.MaxIntermediateDuration = ceilings.MaxIntermediateDuration
	a.roots = roots
	return a, nil
}

// Roots are the pinned root certificates.
func (a *Access) Roots() []*x509.Certificate {
	return a.roots
}

// MaxIntermediateDuration is the longest an intermediate may be valid.
func (a *Access) MaxIntermediateDuration() time.Duration {
	return a.ceilings.MaxIntermediateDuration
}

// AllowedDomains are the operator's permitted DNS domains.
func (a *Access) AllowedDomains() []string {
	return a.ceilings.PermittedDNSDomains
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

// CheckIssuer returns an error unless the issuer is allowed (namespace and key) and
// its policy stays within the ceilings.
func (a *Access) CheckIssuer(issuer *kmsiapi.KMSIssuer, s settings) error {
	if err := a.Check(issuer.Namespace, issuer.Spec.KeyID); err != nil {
		return err
	}
	if len(issuer.Spec.PermittedDNSDomains) == 0 {
		return fmt.Errorf("permittedDNSDomains is required")
	}
	for _, d := range issuer.Spec.PermittedDNSDomains {
		if !withinDomains(normalizeDomain(d), a.ceilings.PermittedDNSDomains) {
			return fmt.Errorf("permitted DNS domain %q is outside the operator's %v", d, a.ceilings.PermittedDNSDomains)
		}
	}
	if issuer.Spec.AllowWildcards && !a.ceilings.AllowWildcards {
		return fmt.Errorf("allowWildcards is set but the operator does not allow wildcards")
	}
	if s.maxCertificateDuration > a.ceilings.MaxCertificateDuration {
		return fmt.Errorf("maxCertificateDuration %s is longer than the operator's %s", s.maxCertificateDuration, a.ceilings.MaxCertificateDuration)
	}
	return nil
}

func isAlias(id string) bool {
	return strings.HasPrefix(id, "alias/") || strings.Contains(id, ":alias/")
}

func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
}

// withinDomains reports whether d equals one of domains or is a subdomain of one.
func withinDomains(d string, domains []string) bool {
	for _, c := range domains {
		if d == c || strings.HasSuffix(d, "."+c) {
			return true
		}
	}
	return false
}
