// Package domains is the one place DNS names are matched against permitted
// domains, so the controller, the policy and the CA tool can never disagree.
package domains

import "strings"

// Normalize lower-cases d and drops surrounding space and one trailing dot.
func Normalize(d string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
}

// Within reports whether name equals one of domains or is a subdomain of one,
// both normalized. An empty name or domain matches nothing.
func Within(name string, domains []string) bool {
	name = Normalize(name)
	if name == "" {
		return false
	}
	for _, d := range domains {
		d = Normalize(d)
		if d != "" && (name == d || strings.HasSuffix(name, "."+d)) {
			return true
		}
	}
	return false
}
