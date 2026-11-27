/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/utils/clock"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	kmsiapi "github.com/sunsofterp/kms-issuer/v5/apis/certmanager/v1alpha1"
	"github.com/sunsofterp/kms-issuer/v5/controllers/certmanager"
	"github.com/sunsofterp/kms-issuer/v5/pkg/kmsca"
	//+kubebuilder:scaffold:imports
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(cmapi.AddToScheme(scheme))
	utilruntime.Must(kmsiapi.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

// The metrics endpoint authenticates callers with TokenReview and authorizes them
// with SubjectAccessReview (get on the /metrics non-resource URL).
// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create

func main() {
	var (
		metricsAddr, probeAddr, localAWSEndpoint string
		allowedNamespaces, allowedKeyIDs         string
		permittedDomains, rootCertificateFile    string
		enableLeaderElection, secureMetrics      bool
		enableKMSKeyController, allowWildcards   bool
		maxCertificateDuration                   time.Duration
		maxIntermediateDuration                  time.Duration
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8443", "The address the metrics endpoint binds to. \"0\" disables it.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true, "Serve metrics over HTTPS, to authenticated and authorized callers only.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&allowedNamespaces, "allowed-issuer-namespaces", "",
		"Required. Comma-separated namespaces a KMSIssuer may live in; KMSIssuers anywhere else sign nothing.")
	flag.StringVar(&allowedKeyIDs, "allowed-key-ids", "",
		"Required. Comma-separated KMS key IDs or ARNs (not aliases) a KMSIssuer may sign with.")
	flag.StringVar(&permittedDomains, "permitted-dns-domains", "",
		"Required. Comma-separated DNS domains (two labels or more): every KMSIssuer's permittedDNSDomains must be inside them.")
	flag.BoolVar(&allowWildcards, "allow-wildcards", false,
		"Let KMSIssuers allow wildcard names (allowWildcards). Off by default.")
	flag.DurationVar(&maxCertificateDuration, "max-certificate-duration", 30*24*time.Hour,
		"The longest issued validity any KMSIssuer may allow (maxCertificateDuration). Less than half --max-intermediate-duration.")
	flag.DurationVar(&maxIntermediateDuration, "max-intermediate-duration", kmsca.MaxIntermediateDuration,
		"The longest an intermediate may be valid (above zero, at most the default).")
	flag.StringVar(&rootCertificateFile, "root-certificate", "",
		"Required. File holding the PEM root CA certificate(s) (made with `kms-ca root`) every KMSIssuer's intermediate must chain to. "+
			"More than one only while replacing a root.")
	flag.BoolVar(&enableKMSKeyController, "enable-kmskey-controller", false,
		"Run the KMSKey controller, which creates and deletes KMS keys. Off by default: create keys outside the cluster.")
	flag.StringVar(&localAWSEndpoint, "local-aws-endpoint", "", "Test only: a local KMS endpoint, with static test credentials.")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog := ctrl.Log.WithName("setup")

	namespaces := splitList(allowedNamespaces)
	access, err := loadAccess(setupLog, rootCertificateFile, namespaces, splitList(allowedKeyIDs), certmanager.Ceilings{
		PermittedDNSDomains:     splitList(permittedDomains),
		AllowWildcards:          allowWildcards,
		MaxCertificateDuration:  maxCertificateDuration,
		MaxIntermediateDuration: maxIntermediateDuration,
	})
	if err != nil {
		os.Exit(1)
	}
	certmanager.RecordRoots(access)
	logRoots(setupLog, access)
	// Watch and cache namespaced objects (KMSIssuers, CertificateRequests) in the
	// allowed namespaces only: nothing elsewhere is read, let alone written.
	defaultNamespaces := map[string]cache.Config{}
	for _, ns := range namespaces {
		defaultNamespaces[ns] = cache.Config{}
	}

	metricsOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
	}
	if secureMetrics {
		metricsOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsOptions,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "kms-issuer.cert-manager.skyscanner.net",
		Cache:                  cache.Options{DefaultNamespaces: defaultNamespaces},
		// No reconcile (and so no KMS call) can hang a controller's worker.
		Controller: config.Controller{ReconciliationTimeout: 2 * time.Minute},
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	cfg, err := loadAWSConfig(setupLog, localAWSEndpoint)
	if err != nil {
		os.Exit(1)
	}
	ca := kmsca.NewKMSCA(&cfg)

	if err = certmanager.NewKMSIssuerReconciler(mgr, ca, access).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KMSIssuer")
		os.Exit(1)
	}

	if err = (&certmanager.CertificateRequestReconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Log:       ctrl.Log.WithName("controllers").WithName("CertificateRequest"),
		Recorder:  mgr.GetEventRecorder("certificaterequests-controller"),
		KMSCA:     ca,
		Access:    access,
		Clock:     clock.RealClock{},
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "CertificateRequest")
		os.Exit(1)
	}

	if enableKMSKeyController {
		if err = (certmanager.NewKMSKeyReconciler(mgr, ca)).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "KMSKey")
			os.Exit(1)
		}
	} else {
		setupLog.Info("KMSKey controller disabled (--enable-kmskey-controller=false)")
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// loadAccess reads the pinned roots from rootFile and builds the operator's access
// rules, logging what is wrong (and returning an error) if anything is.
func loadAccess(log logr.Logger, rootFile string, namespaces, keyIDs []string, ceilings certmanager.Ceilings) (*certmanager.Access, error) {
	rootPEM, err := os.ReadFile(rootFile) //nolint:gosec // G304: --root-certificate is set in the pod spec by whoever deploys the controller; its contents must pass the root checks
	if err != nil {
		log.Error(err, "reading --root-certificate")
		return nil, err
	}
	roots, err := kmsca.ParseCertificatesPEM(rootPEM)
	if err != nil {
		log.Error(err, "parsing --root-certificate")
		return nil, err
	}
	access, err := certmanager.NewAccess(namespaces, keyIDs, ceilings, roots, time.Now())
	if err != nil {
		log.Error(err, "invalid access flags")
		return nil, err
	}
	return access, nil
}

// logRoots logs every pinned root, and loudly an expired one, which must be
// removed from the pin.
func logRoots(log logr.Logger, access *certmanager.Access) {
	for _, root := range access.Roots() {
		log.Info("pinned root", "subject", root.Subject.String(), "notBefore", root.NotBefore, "notAfter", root.NotAfter,
			"permittedDNSDomains", root.PermittedDNSDomains)
	}
	for _, s := range access.Skipped() {
		if s.Expired {
			log.Error(s.Reason, "PINNED ROOT EXPIRED: nothing can chain to it; remove it from --root-certificate",
				"index", s.Index, "subject", s.Root.Subject.String(), "notAfter", s.Root.NotAfter)
			continue
		}
		log.Info("pinned root not valid yet: intermediates may chain to it from its notBefore",
			"index", s.Index, "subject", s.Root.Subject.String(), "notBefore", s.Root.NotBefore)
	}
}

// loadAWSConfig is the default AWS configuration (environment, Pod Identity,
// IMDS...), unless a local test endpoint is given; it must name a region.
func loadAWSConfig(log logr.Logger, localEndpoint string) (aws.Config, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if localEndpoint != "" {
		log.Info("Using a local AWS endpoint with test credentials", "endpoint", localEndpoint)
		opts = append(opts,
			awsconfig.WithBaseEndpoint(localEndpoint),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "test")),
			awsconfig.WithRegion("eu-west-1"),
		)
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		log.Error(err, "Error loading default aws config")
		return aws.Config{}, err
	}
	if cfg.Region == "" {
		err = errors.New("no AWS region: set AWS_REGION")
		log.Error(err, "no AWS region")
		return aws.Config{}, err
	}
	log.Info("Using region", "region", cfg.Region)
	return cfg, nil
}

func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
