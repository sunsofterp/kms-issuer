package domains

import "testing"

func TestWithin(t *testing.T) {
	allowed := []string{"example.internal", "Other.Internal."}
	for name, want := range map[string]bool{
		"example.internal":       true,
		"sso.example.internal":   true,
		"SSO.Example.Internal.":  true,
		"a.other.internal":       true,
		"badexample.internal":    false,
		"example.internal.evil":  false,
		"internal":               false,
		"":                       false,
		".":                      false,
		"x.example.internal.com": false,
	} {
		if got := Within(name, allowed); got != want {
			t.Errorf("Within(%q) = %v, want %v", name, got, want)
		}
	}
	if Within("example.internal", []string{"", " "}) {
		t.Error("an empty domain matched")
	}
}
