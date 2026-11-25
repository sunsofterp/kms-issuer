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
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	kmsiapi "github.com/sunsofterp/kms-issuer/v5/apis/certmanager/v1alpha1"
	"github.com/sunsofterp/kms-issuer/v5/pkg/kmsca"
)

const (
	// defaultCertDuration is the default validity of the CA certificate.
	defaultCertDuration = time.Hour * 24 * 365 * 10
	// defaultRenewBefore is how long before expiry a new CA certificate is made.
	defaultRenewBefore = time.Hour * 24 * 365
	// minCertDuration is the shortest CA certificate validity accepted.
	minCertDuration = 24 * time.Hour
	// defaultMaxCertificateDuration is the default longest issued validity.
	defaultMaxCertificateDuration = time.Hour * 24 * 90
	// maxRequeue bounds how long the issuer goes unchecked.
	maxRequeue = 12 * time.Hour
)

// KMSIssuerReconciler reconciles a KMSIssuer object.
type KMSIssuerReconciler struct {
	client.Client
	Log      logr.Logger
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	KMSCA    *kmsca.KMSCA
	Access   *Access
	Clock    clock.Clock
}

// Annotation for generating RBAC role for writing Events
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// +kubebuilder:rbac:groups=cert-manager.skyscanner.net,resources=kmsissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.skyscanner.net,resources=kmsissuers/status,verbs=get;update;patch

// NewKMSIssuerReconciler Initialise a new KMSIssuerReconciler
func NewKMSIssuerReconciler(mgr manager.Manager, ca *kmsca.KMSCA, access *Access) *KMSIssuerReconciler {
	return &KMSIssuerReconciler{
		Client:   mgr.GetClient(),
		Log:      ctrl.Log.WithName("controllers").WithName("kmsissuer_controller"),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("kmsissuer_controller"),
		KMSCA:    ca,
		Access:   access,
		Clock:    clock.RealClock{},
	}
}

// settings is an issuer's spec with defaults applied.
type settings struct {
	duration               time.Duration
	renewBefore            time.Duration
	maxCertificateDuration time.Duration
}

func issuerSettings(issuer *kmsiapi.KMSIssuer) settings {
	s := settings{
		duration:               defaultCertDuration,
		renewBefore:            defaultRenewBefore,
		maxCertificateDuration: defaultMaxCertificateDuration,
	}
	if d := issuer.Spec.Duration; d != nil && d.Duration != 0 {
		s.duration = d.Duration
	}
	if d := issuer.Spec.RenewBefore; d != nil {
		s.renewBefore = d.Duration
	}
	if d := issuer.Spec.MaxCertificateDuration; d != nil && d.Duration != 0 {
		s.maxCertificateDuration = d.Duration
	}
	return s
}

func (s settings) validate() error {
	if s.duration < minCertDuration {
		return fmt.Errorf("duration %s is shorter than %s", s.duration, minCertDuration)
	}
	if s.renewBefore < 0 || s.renewBefore >= s.duration {
		return fmt.Errorf("renewBefore %s must be at least 0 and shorter than duration %s", s.renewBefore, s.duration)
	}
	if s.maxCertificateDuration < time.Hour {
		return fmt.Errorf("maxCertificateDuration %s is shorter than 1h", s.maxCertificateDuration)
	}
	return nil
}

// Reconcile KMSIssuer resources.
func (r *KMSIssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("kms-issuer", req.NamespacedName)

	issuer := &kmsiapi.KMSIssuer{}
	if err := r.Get(ctx, req.NamespacedName, issuer); err != nil {
		if client.IgnoreNotFound(err) != nil {
			log.Error(err, "failed to retrieve KMSIssuer resource")
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.Access.Check(issuer.Namespace, issuer.Spec.KeyID); err != nil {
		return ctrl.Result{}, r.manageFailure(ctx, issuer, err, "This KMSIssuer may not issue")
	}
	if len(issuer.Spec.PermittedDNSDomains) == 0 {
		return ctrl.Result{}, r.manageFailure(ctx, issuer, errors.New("no permittedDNSDomains"), "permittedDNSDomains is required")
	}
	s := issuerSettings(issuer)
	if err := s.validate(); err != nil {
		return ctrl.Result{}, r.manageFailure(ctx, issuer, err, "Invalid issuer settings")
	}

	pub, err := r.KMSCA.PublicKey(ctx, issuer.Spec.KeyID)
	if err != nil {
		return ctrl.Result{}, r.manageFailure(ctx, issuer, err, "Failed to read the KMS key's public key")
	}
	now := r.Clock.Now()
	actual, _ := ParseCertificate(issuer.Status.Certificate)
	if reason := needsNewCA(actual, issuer, s, pub, now); reason != "" {
		log.Info("making a new CA certificate", "reason", reason)
		cert, err := r.KMSCA.GenerateAndSignCertificateAuthorityCertificate(ctx, &kmsca.GenerateCertificateAuthorityCertificateInput{
			KeyID:               issuer.Spec.KeyID,
			Subject:             pkix.Name{CommonName: issuer.Spec.CommonName},
			Duration:            s.duration,
			PermittedDNSDomains: issuer.Spec.PermittedDNSDomains,
			Now:                 now,
		})
		if err != nil {
			return ctrl.Result{}, r.manageFailure(ctx, issuer, err, "Failed to generate the Certificate Authority Certificate")
		}
		log.Info("made a new CA certificate", "serial", cert.SerialNumber.Text(16), "notBefore", cert.NotBefore, "notAfter", cert.NotAfter)
		issuer.Status.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if err := r.patchIssuerStatus(ctx, issuer); err != nil {
			return ctrl.Result{}, r.manageFailure(ctx, issuer, err, "Failed to update the issuer with the issued Certificate")
		}
		actual = cert
	}

	requeue := actual.NotAfter.Add(-s.renewBefore).Sub(now)
	if requeue > maxRequeue {
		requeue = maxRequeue
	}
	if requeue < time.Minute {
		requeue = time.Minute
	}
	return ctrl.Result{RequeueAfter: requeue}, r.manageSuccess(ctx, issuer)
}

// needsNewCA returns why a new CA certificate is needed, or "" when the current one
// still matches the spec and the key. Nothing here depends on the time it is
// checked except renewal, so a valid certificate is never re-made in a loop.
func needsNewCA(actual *x509.Certificate, issuer *kmsiapi.KMSIssuer, s settings, pub crypto.PublicKey, now time.Time) string {
	switch {
	case actual == nil:
		return "no valid CA certificate yet"
	case !actual.IsCA || !actual.MaxPathLenZero || actual.MaxPathLen != 0:
		return "the certificate is not a path-length-0 CA"
	case !publicKeyEqual(actual.PublicKey, pub):
		return "the certificate is not for the KMS key"
	case actual.Subject.CommonName != issuer.Spec.CommonName:
		return "the common name changed"
	case !sameDomains(actual.PermittedDNSDomains, issuer.Spec.PermittedDNSDomains) || !actual.PermittedDNSDomainsCritical:
		return "the permitted DNS domains changed"
	case actual.NotAfter.Sub(actual.NotBefore) != s.duration:
		return "the duration changed"
	case !now.Before(actual.NotAfter.Add(-s.renewBefore)):
		return "renewal is due"
	}
	return ""
}

func publicKeyEqual(a, b crypto.PublicKey) bool {
	ea, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ea.Equal(b)
}

func sameDomains(a, b []string) bool {
	norm := func(list []string) []string {
		out := make([]string, 0, len(list))
		for _, d := range list {
			out = append(out, strings.ToLower(strings.TrimSuffix(d, ".")))
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	return slices.Equal(norm(a), norm(b))
}

// patchIssuerStatus updates the kmsiapi.KMSIssuer using a MergeFrom strategy
func (r *KMSIssuerReconciler) patchIssuerStatus(ctx context.Context, issuer *kmsiapi.KMSIssuer) error {
	var latest kmsiapi.KMSIssuer

	if err := r.Get(ctx, client.ObjectKeyFromObject(issuer), &latest); err != nil {
		return err
	}

	patch := client.MergeFrom(latest.DeepCopy())
	latest.Status = issuer.Status

	return r.Client.Status().Patch(ctx, &latest, patch)
}

// ParseCertificate parses one PEM certificate.
func ParseCertificate(cert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(cert)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to parse certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// SetupWithManager is pre-generated
func (r *KMSIssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kmsiapi.KMSIssuer{}).
		Complete(r)
}

// manageSuccess
func (r *KMSIssuerReconciler) manageSuccess(ctx context.Context, issuer *kmsiapi.KMSIssuer) error {
	reason := kmsiapi.KMSIssuerReasonIssued
	msg := ""
	if issuer.Status.IsReady() {
		return nil
	}
	r.Recorder.Event(issuer, core.EventTypeNormal, reason, msg)
	ready := kmsiapi.NewCondition(kmsiapi.ConditionReady, kmsiapi.ConditionTrue, reason, msg)
	issuer.Status.SetCondition(&ready)
	return r.patchIssuerStatus(ctx, issuer)
}

// manageFailure
func (r *KMSIssuerReconciler) manageFailure(ctx context.Context, issuer *kmsiapi.KMSIssuer, issue error, message string) error {
	log := r.Log.WithValues("name", issuer.Name, "namespace", issuer.Namespace)
	reason := kmsiapi.KMSIssuerReasonFailed
	message = fmt.Sprintf("%s: %v", message, issue)
	log.Error(issue, message)
	r.Recorder.Event(issuer, core.EventTypeWarning, reason, message)
	ready := kmsiapi.NewCondition(kmsiapi.ConditionReady, kmsiapi.ConditionFalse, reason, message)
	issuer.Status.SetCondition(&ready)
	return r.patchIssuerStatus(ctx, issuer)
}
