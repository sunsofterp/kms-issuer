/*
Copyright 2020 Skyscanner Limited.

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

package certmanager

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	kmsca "github.com/sunsofterp/kms-issuer/v5/pkg/kmsca"
	mocks "github.com/sunsofterp/kms-issuer/v5/pkg/kmsmock"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	certmanagerv1alpha1 "github.com/sunsofterp/kms-issuer/v5/apis/certmanager/v1alpha1"
	// +kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var (
	k8sClient client.Client
	testEnv   *envtest.Environment
	ctx       context.Context
	cancel    context.CancelFunc
	ca        kmsca.KMSCA
	// allowedKeyID is the only key the controllers under test may sign with, and
	// "default" the only namespace; otherKeyID exists in KMS but is not allowed.
	allowedKeyID string
	otherKeyID   string
	// testRoot is the pinned root (on its own key, rootKeyID); allowedIntermediate
	// and otherIntermediate are intermediates it signed for the two issuing keys.
	rootKeyID           string
	testRoot            *x509.Certificate
	allowedIntermediate string
	otherIntermediate   string
	// testCeilings are the operator ceilings under test: example.internal only,
	// no wildcards, 90-day certificates.
	testCeilings = Ceilings{
		PermittedDNSDomains:    []string{"example.internal"},
		MaxCertificateDuration: 90 * 24 * time.Hour,
	}
)

// intermediateFor returns the test intermediate for an issuing key.
func intermediateFor(keyID string) string {
	if keyID == otherKeyID {
		return otherIntermediate
	}
	return allowedIntermediate
}

// makeTwoTier makes the suite's root and its intermediates in the mock.
func makeTwoTier(ca *kmsca.KMSCA) {
	var err error
	rootKeyID, err = ca.CreateKey(context.TODO(), &kmsca.CreateKeyInput{AliasName: "alias/root", OwnerUID: "suite"})
	Expect(err).NotTo(HaveOccurred())
	now := time.Now()
	input := func(name string, d time.Duration) *kmsca.CAInput {
		return &kmsca.CAInput{Subject: pkix.Name{CommonName: name}, PermittedDNSDomains: []string{"example.internal"}, Duration: d, Now: now}
	}
	testRoot, err = ca.MakeRoot(context.TODO(), rootKeyID, input("Test Root", 20*365*24*time.Hour))
	Expect(err).NotTo(HaveOccurred())
	for keyID, out := range map[string]*string{allowedKeyID: &allowedIntermediate, otherKeyID: &otherIntermediate} {
		cert, err := ca.MakeIntermediate(context.TODO(), rootKeyID, testRoot, keyID, input("Test Issuing", 365*24*time.Hour))
		Expect(err).NotTo(HaveOccurred())
		*out = string(kmsca.EncodeCertificatePEM(cert))
	}
}

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))
	ctx, cancel = context.WithCancel(context.TODO())

	_, ok := os.LookupEnv("KMS_ISSUER_USE_EXISTING_CLUSTER")

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
		UseExistingCluster:    &ok,
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = certmanagerv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())
	err = cmapi.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
	})
	Expect(k8sManager).NotTo(BeNil())
	Expect(err).NotTo(HaveOccurred())

	ca.Client = mocks.New()
	allowedKeyID, err = ca.CreateKey(ctx, &kmsca.CreateKeyInput{AliasName: "alias/allowed", OwnerUID: "suite"})
	Expect(err).NotTo(HaveOccurred())
	otherKeyID, err = ca.CreateKey(ctx, &kmsca.CreateKeyInput{AliasName: "alias/other", OwnerUID: "suite"})
	Expect(err).NotTo(HaveOccurred())
	makeTwoTier(&ca)
	access, err := NewAccess([]string{"default"}, []string{allowedKeyID}, testCeilings, testRoot, time.Now())
	Expect(err).NotTo(HaveOccurred())

	err = (&CertificateRequestReconciler{
		Client:    k8sManager.GetClient(),
		APIReader: k8sManager.GetAPIReader(),
		Log:       logf.Log,
		Recorder:  k8sManager.GetEventRecorderFor("certificaterequests-controller"),
		KMSCA:     &ca,
		Access:    access,
		Clock:     clock.RealClock{},
	}).SetupWithManager(k8sManager)
	Expect(err).NotTo(HaveOccurred(), "failed to setup the CertificateRequestReconciler controller")

	err = NewKMSIssuerReconciler(k8sManager, &ca, access).SetupWithManager(k8sManager)
	Expect(err).NotTo(HaveOccurred(), "failed to setup the KMSIssuerReconciler controller")

	err = NewKMSKeyReconciler(k8sManager, &ca).SetupWithManager(k8sManager)
	Expect(err).NotTo(HaveOccurred(), "failed to setup the KMSKeyReconciler controller")

	go func() {
		defer GinkgoRecover()
		err = k8sManager.Start(ctx)
		Expect(err).ToNot(HaveOccurred(), "failed to run manager")
	}()
})

var _ = AfterSuite(func() {
	cancel()
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})
