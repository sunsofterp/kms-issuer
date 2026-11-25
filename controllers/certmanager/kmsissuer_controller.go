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
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	// minReissueInterval is the least time between two CA certificates for one
	// issuer: whatever the cause, the controller never re-signs in a tight loop.
	minReissueInterval = 10 * time.Minute

	eventCAIssued = "CACertificateIssued"
	eventKMSError = "KMSError"
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

// validate refuses settings that could not produce a stable CA certificate:
// certificate times have one-second precision, and renewal must not be due the
// moment a certificate is made (its notBefore is backdated).
func (s settings) validate() error {
	for name, d := range map[string]time.Duration{
		"duration": s.duration, "renewBefore": s.renewBefore, "maxCertificateDuration": s.maxCertificateDuration,
	} {
		if d%time.Second != 0 {
			return fmt.Errorf("%s %s is not a whole number of seconds", name, d)
		}
	}
	if s.duration < minCertDuration {
		return fmt.Errorf("duration %s is shorter than %s", s.duration, minCertDuration)
	}
	if s.renewBefore < 0 || s.renewBefore > s.duration/2 {
		return fmt.Errorf("renewBefore %s must be between 0 and half of duration (%s)", s.renewBefore, s.duration/2)
	}
	if s.maxCertificateDuration < time.Hour {
		return fmt.Errorf("maxCertificateDuration %s is shorter than 1h", s.maxCertificateDuration)
	}
	return nil
}

// Reconcile KMSIssuer resources.
//
// Configuration problems (outside the operator's ceilings, invalid settings) mark
// the issuer not ready and wait for the spec to change. KMS errors are returned so
// the work queue retries with backoff; while the stored CA certificate is still
// valid, the issuer stays ready through them, so a KMS blip never stops issuance.
func (r *KMSIssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("kms-issuer", req.NamespacedName)

	issuer := &kmsiapi.KMSIssuer{}
	if err := r.Get(ctx, req.NamespacedName, issuer); err != nil {
		if apierrors.IsNotFound(err) {
			caNotAfter.DeleteLabelValues(req.Namespace, req.Name)
			return ctrl.Result{}, nil
		}
		log.Error(err, "failed to retrieve KMSIssuer resource")
		return ctrl.Result{}, err
	}

	s := issuerSettings(issuer)
	if err := s.validate(); err != nil {
		return ctrl.Result{}, r.setNotReady(ctx, issuer, "Invalid issuer settings", err)
	}
	if err := r.Access.CheckIssuer(issuer, s); err != nil {
		return ctrl.Result{}, r.setNotReady(ctx, issuer, "This KMSIssuer may not issue", err)
	}

	now := r.Clock.Now()
	actual, _ := kmsca.ParseCertificatePEM(issuer.Status.Certificate)

	pub, err := r.KMSCA.PublicKey(ctx, issuer.Spec.KeyID)
	if err != nil {
		return ctrl.Result{}, r.kmsError(ctx, issuer, actual, "Failed to read the KMS key's public key", err, now)
	}
	expected := kmsca.ExpectedCA{
		PublicKey: pub, CommonName: issuer.Spec.CommonName,
		PermittedDNSDomains: issuer.Spec.PermittedDNSDomains, Now: now,
	}

	if reason := needsNewCA(actual, s, expected); reason != "" {
		if actual != nil {
			if since := now.Sub(actual.NotBefore.Add(5 * time.Minute)); since < minReissueInterval {
				log.Info("a new CA certificate is needed, but the last one is too recent; waiting", "reason", reason)
				return ctrl.Result{RequeueAfter: minReissueInterval - since}, nil
			}
		}
		log.Info("making a new CA certificate", "reason", reason)
		cert, err := r.KMSCA.GenerateAndSignCertificateAuthorityCertificate(ctx, &kmsca.GenerateCertificateAuthorityCertificateInput{
			KeyID:               issuer.Spec.KeyID,
			Subject:             pkix.Name{CommonName: issuer.Spec.CommonName},
			Duration:            s.duration,
			PermittedDNSDomains: issuer.Spec.PermittedDNSDomains,
			Now:                 now,
		})
		if err != nil {
			return ctrl.Result{}, r.kmsError(ctx, issuer, actual, "Failed to make the CA certificate", err, now)
		}
		if len(issuer.Status.Certificate) > 0 {
			issuer.Status.PreviousCertificate = issuer.Status.Certificate
		}
		issuer.Status.Certificate = kmsca.EncodeCertificatePEM(cert)
		if err := r.patchIssuerStatus(ctx, issuer); err != nil {
			return ctrl.Result{}, err
		}
		message := fmt.Sprintf("New CA certificate %s, valid %s to %s (%s): devices that trust this CA need this copy before the old one expires",
			cert.SerialNumber.Text(16), cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339), reason)
		log.Info("made a new CA certificate", "serial", cert.SerialNumber.Text(16), "notBefore", cert.NotBefore, "notAfter", cert.NotAfter, "reason", reason)
		r.Recorder.Event(issuer, core.EventTypeNormal, eventCAIssued, message)
		caIssued.WithLabelValues(issuer.Namespace, issuer.Name).Inc()
		actual = cert
	}
	caNotAfter.WithLabelValues(issuer.Namespace, issuer.Name).Set(float64(actual.NotAfter.Unix()))

	requeue := actual.NotAfter.Add(-s.renewBefore).Sub(now)
	if requeue > maxRequeue {
		requeue = maxRequeue
	}
	if requeue < time.Minute {
		requeue = time.Minute
	}
	return ctrl.Result{RequeueAfter: requeue}, r.setReady(ctx, issuer)
}

// needsNewCA returns why a new CA certificate is needed, or "" when the stored one
// is exactly what this controller would make now and renewal isn't due.
func needsNewCA(actual *x509.Certificate, s settings, expected kmsca.ExpectedCA) string {
	if actual == nil {
		return "no valid CA certificate stored"
	}
	if err := kmsca.ValidateCA(actual, expected); err != nil {
		return fmt.Sprintf("the stored CA certificate is not acceptable: %v", err)
	}
	if actual.NotAfter.Sub(actual.NotBefore) != s.duration {
		return "the duration changed"
	}
	if !expected.Now.Before(actual.NotAfter.Add(-s.renewBefore)) {
		return "renewal is due"
	}
	return ""
}

// kmsError handles a KMS failure: the error goes back to the work queue (retry with
// backoff). The issuer stays ready if its stored CA certificate is still usable;
// otherwise it is marked not ready.
func (r *KMSIssuerReconciler) kmsError(ctx context.Context, issuer *kmsiapi.KMSIssuer, actual *x509.Certificate, message string, err error, now time.Time) error {
	r.Recorder.Event(issuer, core.EventTypeWarning, eventKMSError, fmt.Sprintf("%s: %v", message, err))
	if issuer.Status.IsReady() && actual != nil && actual.IsCA && now.Before(actual.NotAfter) {
		r.Log.Error(err, message+"; keeping the current CA certificate", "kms-issuer", client.ObjectKeyFromObject(issuer))
		return err
	}
	return errors.Join(err, r.setNotReady(ctx, issuer, message, err))
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

// ParseCertificate parses exactly one PEM certificate.
func ParseCertificate(cert []byte) (*x509.Certificate, error) {
	return kmsca.ParseCertificatePEM(cert)
}

// SetupWithManager is pre-generated
func (r *KMSIssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kmsiapi.KMSIssuer{}).
		Complete(r)
}

func (r *KMSIssuerReconciler) setReady(ctx context.Context, issuer *kmsiapi.KMSIssuer) error {
	if issuer.Status.IsReady() {
		return nil
	}
	r.Recorder.Event(issuer, core.EventTypeNormal, kmsiapi.KMSIssuerReasonIssued, "Ready to issue")
	ready := kmsiapi.NewCondition(kmsiapi.ConditionReady, kmsiapi.ConditionTrue, kmsiapi.KMSIssuerReasonIssued, "")
	issuer.Status.SetCondition(&ready)
	return r.patchIssuerStatus(ctx, issuer)
}

// setNotReady marks the issuer not ready with the cause. It returns only the status
// write's error: configuration problems are not retried until the spec changes.
func (r *KMSIssuerReconciler) setNotReady(ctx context.Context, issuer *kmsiapi.KMSIssuer, message string, cause error) error {
	message = fmt.Sprintf("%s: %v", message, cause)
	r.Log.Error(cause, message, "kms-issuer", client.ObjectKeyFromObject(issuer))
	r.Recorder.Event(issuer, core.EventTypeWarning, kmsiapi.KMSIssuerReasonFailed, message)
	ready := kmsiapi.NewCondition(kmsiapi.ConditionReady, kmsiapi.ConditionFalse, kmsiapi.KMSIssuerReasonFailed, message)
	issuer.Status.SetCondition(&ready)
	return r.patchIssuerStatus(ctx, issuer)
}
