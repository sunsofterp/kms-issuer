// Command kms-ca makes the two CA certificates of a kms-issuer CA, by hand, with
// administrator credentials. Both private keys stay in KMS: the tool only asks KMS
// to sign.
//
//	kms-ca root --key-id <root key ARN> --common-name <name> --domains <d1,d2> --out root.pem
//	kms-ca intermediate --root-key-id <root key ARN> --root-certificate root.pem \
//	    --key-id <issuing key ARN> --common-name <name> --domains <d1,d2> --out intermediate.pem
//	kms-ca show <file.pem>
//
// The root (path length 1, name-constrained, default 20 years) is what devices
// trust; give it to the controller as --root-certificate. The intermediate (path
// length 0, server auth only, name-constrained inside the root's, at most and by
// default 183 days) is for the issuer's KMS key; put it in the KMSIssuer's
// intermediateCertificate. Keys are named by key ID or ARN, never alias. Neither
// command overwrites an existing file, and the output file is created before KMS is
// asked to sign anything. What was made, with which keys and by which AWS identity,
// is printed for the record.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/sunsofterp/kms-issuer/v5/pkg/kmsca"
)

const usage = `usage:
  kms-ca root --key-id ID --common-name NAME --domains D[,D...] --out FILE [--duration 175200h]
  kms-ca intermediate --root-key-id ID --root-certificate FILE --key-id ID --common-name NAME --domains D[,D...] --out FILE [--duration 4392h]
  kms-ca show FILE
`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "kms-ca:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "root":
		return root(args[1:], out)
	case "intermediate":
		return intermediate(args[1:], out)
	case "show":
		if len(args) != 2 {
			return errors.New(usage)
		}
		cert, err := readCertificate(args[1])
		if err != nil {
			return err
		}
		describe(out, cert)
		return nil
	}
	return errors.New(usage)
}

// common are the flags both signing commands take.
type common struct {
	keyID, commonName, domains, outFile, region, endpoint string
	duration                                              time.Duration
}

func (c *common) register(fs *flag.FlagSet, defaultDuration time.Duration) {
	fs.StringVar(&c.keyID, "key-id", "", "Required. The KMS key the certificate is for (key ID or ARN, not an alias).")
	fs.StringVar(&c.commonName, "common-name", "", "Required. The certificate's common name.")
	fs.StringVar(&c.domains, "domains", "", "Required. Comma-separated DNS domains (two labels or more): the name constraints.")
	fs.StringVar(&c.outFile, "out", "", "Required. Where to write the PEM certificate (must not exist).")
	fs.DurationVar(&c.duration, "duration", defaultDuration, "Validity.")
	fs.StringVar(&c.region, "region", "", "AWS region (default: the AWS configuration's).")
	if registerTestEndpoint != nil {
		registerTestEndpoint(fs, c)
	}
}

// registerTestEndpoint adds --aws-endpoint, a local test KMS. Only builds with the
// kmsca_test_endpoint tag have it (testendpoint.go). Release binaries, the ones
// handed root-key credentials, have no such flag, ignore proxies and refuse
// endpoint overrides and custom CA bundles (loadConfig, refuseRedirects).
var registerTestEndpoint func(fs *flag.FlagSet, c *common)

func (c *common) check() error {
	if c.keyID == "" || c.commonName == "" || c.domains == "" || c.outFile == "" {
		return errors.New("--key-id, --common-name, --domains and --out are required\n" + usage)
	}
	if isAlias(c.keyID) {
		return fmt.Errorf("--key-id %q is an alias: name the key by key ID or ARN (an alias can be re-pointed)", c.keyID)
	}
	for _, d := range splitList(c.domains) {
		if err := kmsca.ValidConstraintDomain(d); err != nil {
			return fmt.Errorf("--domains: %w", err)
		}
	}
	return nil
}

func (c *common) input() *kmsca.CAInput {
	return &kmsca.CAInput{
		Subject:             pkix.Name{CommonName: c.commonName},
		PermittedDNSDomains: splitList(c.domains),
		Duration:            c.duration,
		Now:                 time.Now(),
	}
}

// newCA connects to KMS and names the AWS identity in use; tests replace it.
var newCA = func(ctx context.Context, c *common) (*kmsca.KMSCA, string, error) { return c.connect(ctx) }

func (c *common) connect(ctx context.Context) (*kmsca.KMSCA, string, error) {
	cfg, err := c.loadConfig(ctx)
	if err != nil {
		return nil, "", err
	}
	if c.endpoint != "" {
		return kmsca.NewKMSCA(&cfg), "(test endpoint " + c.endpoint + ")", nil
	}
	endpoint, err := resolvedKMSEndpoint(ctx, cfg)
	if err != nil {
		return nil, "", err
	}
	who, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, "", fmt.Errorf("checking the AWS identity: %w", err)
	}
	return kmsca.NewKMSCA(&cfg), aws.ToString(who.Arn) + " via " + endpoint, nil
}

// loadConfig loads the AWS configuration and, outside test builds, makes sure
// every call to an AWS service (KMS, STS, SSO...) goes straight to AWS's own
// endpoint: no proxy (ignored, by credential fetches too), no CA bundle or
// SSL_CERT_* variable and no service endpoint override (refused). Where
// credentials come from (a profile, credential_process, the instance or
// container metadata endpoint) is left to the configuration; the identity they
// give is printed. Nothing is called: the defaults mode is pinned to standard,
// whose "auto" would ask the instance metadata service while loading.
func (c *common) loadConfig(ctx context.Context) (aws.Config, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if c.region != "" {
		opts = append(opts, awsconfig.WithRegion(c.region))
	}
	if c.endpoint != "" {
		opts = append(opts,
			awsconfig.WithBaseEndpoint(c.endpoint),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "test")))
		if c.region == "" {
			opts = append(opts, awsconfig.WithRegion("eu-west-1"))
		}
	} else {
		// Every client the configuration builds uses this one: the service
		// clients and the SSO and instance metadata credential providers through
		// WithHTTPClient, the container credential provider, which builds its
		// own otherwise, through WithEndpointCredentialOptions. Proxy settings
		// are ignored, so a proxy can neither stand in for AWS nor read
		// credentials fetched over plain HTTP.
		client := proxyless()
		opts = append(opts,
			awsconfig.WithHTTPClient(client),
			awsconfig.WithEndpointCredentialOptions(func(o *endpointcreds.Options) { o.HTTPClient = client }),
			awsconfig.WithDefaultsMode(aws.DefaultsModeStandard))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, err
	}
	if cfg.Region == "" {
		return aws.Config{}, errors.New("no AWS region: set --region or AWS_REGION")
	}
	if c.endpoint != "" {
		return cfg, nil
	}
	if err := refuseRedirects(cfg, os.Environ()); err != nil {
		return aws.Config{}, err
	}
	return cfg, nil
}

// proxyless is the HTTP client every AWS call of a release build uses: the SDK's
// default, with proxy settings ignored.
func proxyless() *awshttp.BuildableClient {
	return awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) { tr.Proxy = nil })
}

// refuseRedirects returns an error if anything in the AWS configuration could send
// a call to an AWS service anywhere but AWS's own endpoint, or trust a certificate
// the system store doesn't: any AWS_ENDPOINT_URL* variable (for any service: SSO
// too, which carries the admin's token), an endpoint_url or services section in
// the profile, a custom CA bundle (AWS_CA_BUNDLE or ca_bundle), SSL_CERT_FILE or
// SSL_CERT_DIR, and, as the SDK resolves them, the KMS and STS clients'
// endpoints. The root key must only ever be used through AWS.
func refuseRedirects(cfg aws.Config, environ []string) error {
	const fix = "kms-ca only talks to AWS's own endpoints with the system's trusted CAs; run it from a clean environment"
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		upper := strings.ToUpper(name)
		if value != "" && (strings.HasPrefix(upper, "AWS_ENDPOINT_URL") || upper == "SSL_CERT_FILE" || upper == "SSL_CERT_DIR") {
			return fmt.Errorf("%s is set: %s", name, fix)
		}
	}
	for _, src := range cfg.ConfigSources {
		switch s := src.(type) {
		case awsconfig.EnvConfig:
			if s.CustomCABundle != "" {
				return fmt.Errorf("AWS_CA_BUNDLE is set: %s", fix)
			}
		case awsconfig.SharedConfig:
			switch {
			case s.CustomCABundle != "":
				return fmt.Errorf("profile %q sets ca_bundle: %s", s.Profile, fix)
			case s.BaseEndpoint != "":
				return fmt.Errorf("profile %q sets endpoint_url: %s", s.Profile, fix)
			case len(s.Services.ServiceValues) > 0:
				return fmt.Errorf("profile %q has a services section (endpoint overrides): %s", s.Profile, fix)
			}
		}
	}
	for service, ep := range map[string]*string{
		"KMS": kms.NewFromConfig(cfg).Options().BaseEndpoint,
		"STS": sts.NewFromConfig(cfg).Options().BaseEndpoint,
	} {
		if ep != nil {
			return fmt.Errorf("the AWS configuration overrides the %s endpoint (%s): %s", service, aws.ToString(ep), fix)
		}
	}
	return nil
}

// resolvedKMSEndpoint is the endpoint the KMS client resolves for this
// configuration, with its FIPS and dual-stack settings.
func resolvedKMSEndpoint(ctx context.Context, cfg aws.Config) (string, error) {
	o := kms.NewFromConfig(cfg).Options()
	ep, err := o.EndpointResolverV2.ResolveEndpoint(ctx, kms.EndpointParameters{
		Region:       aws.String(o.Region),
		UseFIPS:      aws.Bool(o.EndpointOptions.UseFIPSEndpoint == aws.FIPSEndpointStateEnabled),
		UseDualStack: aws.Bool(o.EndpointOptions.UseDualStackEndpoint == aws.DualStackEndpointStateEnabled),
	})
	if err != nil {
		return "", fmt.Errorf("resolving the KMS endpoint: %w", err)
	}
	return ep.URI.String(), nil
}

func root(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("root", flag.ContinueOnError)
	var c common
	c.register(fs, 20*365*24*time.Hour)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	f, err := create(c.outFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ca, identity, err := newCA(ctx, &c)
	if err != nil {
		return discard(f, err)
	}
	cert, err := ca.MakeRoot(ctx, c.keyID, c.input())
	if err != nil {
		return discard(f, err)
	}
	if err := finish(f, cert); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s\n  signed by:    %s (root key)\n  as:           %s\n", c.outFile, c.keyID, identity)
	describe(out, cert)
	return nil
}

func intermediate(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("intermediate", flag.ContinueOnError)
	var c common
	var rootKeyID, rootFile string
	c.register(fs, kmsca.MaxIntermediateDuration)
	fs.StringVar(&rootKeyID, "root-key-id", "", "Required. The root's KMS key (key ID or ARN, not an alias).")
	fs.StringVar(&rootFile, "root-certificate", "", "Required. The root certificate (PEM) made with `kms-ca root`.")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	if rootKeyID == "" || rootFile == "" {
		return errors.New("--root-key-id and --root-certificate are required\n" + usage)
	}
	if isAlias(rootKeyID) {
		return fmt.Errorf("--root-key-id %q is an alias: name the key by key ID or ARN", rootKeyID)
	}
	rootCert, err := readCertificate(rootFile)
	if err != nil {
		return err
	}
	f, err := create(c.outFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ca, identity, err := newCA(ctx, &c)
	if err != nil {
		return discard(f, err)
	}
	cert, err := ca.MakeIntermediate(ctx, rootKeyID, rootCert, c.keyID, c.input())
	if err != nil {
		return discard(f, err)
	}
	pub, err := ca.PublicKey(ctx, c.keyID)
	if err != nil {
		return discard(f, err)
	}
	// Check it exactly as the controller will before handing it over.
	if _, err := kmsca.ValidateIntermediate(cert, kmsca.ExpectedIntermediate{
		Roots: []*x509.Certificate{rootCert}, PublicKey: pub, AllowedDomains: rootCert.PermittedDNSDomains, Now: time.Now(),
	}); err != nil {
		return discard(f, fmt.Errorf("the new intermediate does not validate: %w", err))
	}
	if err := finish(f, cert); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s\n  for key:      %s (issuing key)\n  signed by:    %s (root key)\n  as:           %s\n",
		c.outFile, c.keyID, rootKeyID, identity)
	describe(out, cert)
	return nil
}

// create makes the output file, failing if it exists, before anything is signed.
func create(file string) (*os.File, error) {
	return os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
}

// discard removes an output file left empty by a failure.
func discard(f *os.File, err error) error {
	f.Close()
	os.Remove(f.Name())
	return err
}

func finish(f *os.File, cert *x509.Certificate) error {
	if _, err := f.Write(kmsca.EncodeCertificatePEM(cert)); err != nil {
		return discard(f, err)
	}
	return f.Close()
}

func readCertificate(file string) (*x509.Certificate, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	cert, err := kmsca.ParseCertificatePEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return cert, nil
}

func describe(out io.Writer, cert *x509.Certificate) {
	sum := sha256.Sum256(cert.Raw)
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	pathLen := "unlimited"
	if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
		pathLen = fmt.Sprint(cert.MaxPathLen)
	}
	var ekus []string
	for _, e := range cert.ExtKeyUsage {
		switch e {
		case x509.ExtKeyUsageServerAuth:
			ekus = append(ekus, "server auth")
		default:
			ekus = append(ekus, fmt.Sprint(e))
		}
	}
	var excludedIPs []string
	for _, r := range cert.ExcludedIPRanges {
		excludedIPs = append(excludedIPs, r.String())
	}
	fmt.Fprintf(out, "  subject:          %s\n", cert.Subject)
	fmt.Fprintf(out, "  issuer:           %s\n", cert.Issuer)
	fmt.Fprintf(out, "  serial:           %s\n", cert.SerialNumber.Text(16))
	fmt.Fprintf(out, "  valid:            %s to %s (%s)\n", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339), cert.NotAfter.Sub(cert.NotBefore))
	fmt.Fprintf(out, "  CA:               %t, path length %s\n", cert.IsCA, pathLen)
	fmt.Fprintf(out, "  key usage:        cert sign %t, CRL sign %t\n", cert.KeyUsage&x509.KeyUsageCertSign != 0, cert.KeyUsage&x509.KeyUsageCRLSign != 0)
	fmt.Fprintf(out, "  extended usage:   %s\n", orNone(ekus))
	fmt.Fprintf(out, "  DNS constraints:  %s (critical: %t)\n", orNone(cert.PermittedDNSDomains), cert.PermittedDNSDomainsCritical)
	fmt.Fprintf(out, "  URI constraints:  %s\n", orNone(cert.PermittedURIDomains))
	fmt.Fprintf(out, "  email constraints: %s\n", orNone(cert.PermittedEmailAddresses))
	fmt.Fprintf(out, "  excluded IPs:     %s\n", orNone(excludedIPs))
	fmt.Fprintf(out, "  public key sha256: %s\n", hex.EncodeToString(spki[:]))
	fmt.Fprintf(out, "  certificate sha256: %s\n", hex.EncodeToString(sum[:]))
}

func orNone(list []string) string {
	if len(list) == 0 {
		return "none"
	}
	return strings.Join(list, ", ")
}

func isAlias(id string) bool {
	return strings.HasPrefix(id, "alias/") || strings.Contains(id, ":alias/")
}

func splitList(s string) []string {
	var list []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			list = append(list, item)
		}
	}
	return list
}
