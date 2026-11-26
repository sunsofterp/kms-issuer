package certmanager

// Names the tests share.
const (
	testNamespace  = "default"
	otherNamespace = "elsewhere"
	caNamespace    = "ca"
	testIssuer     = "issuer"
	testDomain     = "example.internal"
	testWildcard   = "*.example.internal"
	testHost       = "svc.example.internal"
	otherDomain    = "other.internal"
	fleetDomain    = "fleet.internal"
	fleetHost      = "sso.fleet.internal"
	tldCom         = "com"
	tldInternal    = "internal"
	rootAlias      = "alias/root"
	testKeyID      = "key-1"
	suiteOwner     = "suite"
	reasonApproved = "Approved"
	reasonDenied   = "Denied"
)
