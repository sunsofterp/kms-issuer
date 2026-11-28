//go:build kmsca_test_endpoint

package main

import "flag"

// Test builds only (go build -tags kmsca_test_endpoint), for the e2e tests against
// a local KMS.
func init() {
	registerTestEndpoint = func(fs *flag.FlagSet, c *common) {
		fs.StringVar(&c.endpoint, "aws-endpoint", "", "Test only: a local KMS endpoint, with static test credentials.")
	}
}
