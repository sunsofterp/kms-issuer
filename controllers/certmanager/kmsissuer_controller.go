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
	"bytes"
	"context"
	"crypto/x509"
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
	// defaultMaxCertificateDuration is the default longest issued validity.
	defaultMaxCertificateDuration = time.Hour * 24 * 90
	// maxRequeue bounds how long the issuer goes unchecked.
	maxRequeue = 12 * time.Hour
	// expiryWarning is how long before the intermediate expires the issuer starts
	// warning that a new one is needed.
	expiryWarning = 90 * 24 * time.Hour

	eventIntermediateAccepted = "IntermediateAccepted"
	eventIntermediateExpiring = "IntermediateExpiringSoon"
	eventKMSError             = "KMSError"
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
	maxCertificateDuration time.Duration
}

func issuerSettings(issuer *kmsiapi.KMSIssuer) settings {
	s := settings{maxCertificateDuration: defaultMaxCertificateDuration}
	if d := issuer.Spec.MaxCertificateDuration; d != nil && d.Duration != 0 {
		s.maxCertificateDuration = d.Duration
	}
	return s
}

func (s settings) validate() error {
	if s.maxCertificateDuration%time.Second != 0 {
		return fmt.Errorf("maxCertificateDuration %s is not a whole number of seconds", s.maxCertificateDuration)
	}
	if s.maxCertificateDuration < time.Hour {
		return fmt.Errorf("maxCertificateDuration %s is shorter than 1h", s.maxCertificateDuration)
	}
	return nil
}

// errKMS marks a failure to reach KMS, as opposed to an issuer that is wrong.
type errKMS struct{ error }

func (e errKMS) Unwrap() error { return e.error }

// verifyIssuer returns the issuer's intermediate when the issuer may sign: allowed
// namespace and key, settings within the ceilings, and an intermediate that is for
// the issuer's KMS key, signed by the pinned root, constrained within the ceilings
// and covering the issuer's domains, and valid now. Errors wrapping errKMS are
// KMS failures (retry); others are the issuer's configuration.
func verifyIssuer(ctx context.Context, ca *kmsca.KMSCA, access *Access, issuer *kmsiapi.KMSIssuer, now time.Time) (*x509.Certificate, error) {
	s := issuerSettings(issuer)
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("invalid issuer settings: %w", err)
	}
	if err := access.CheckIssuer(issuer, s); err != nil {
		return nil, err
	}
	intermediate, err := kmsca.ParseCertificatePEM([]byte(issuer.Spec.IntermediateCertificate))
	if err != nil {
		return nil, fmt.Errorf("intermediateCertificate: %w", err)
	}
	pub, err := ca.PublicKey(ctx, issuer.Spec.KeyID)
	if err != nil {
		return intermediate, errKMS{fmt.Errorf("reading the KMS key's public key: %w", err)}
	}
	if err := kmsca.ValidateIntermediate(intermediate, kmsca.ExpectedIntermediate{
		Root: access.Root(), PublicKey: pub, AllowedDomains: access.AllowedDomains(), Now: now,
	}); err != nil {
		return nil, fmt.Errorf("intermediateCertificate: %w", err)
	}
	for _, d := range issuer.Spec.PermittedDNSDomains {
		if !kmsca.WithinDomains(d, intermediate.PermittedDNSDomains) {
			return nil, fmt.Errorf("permitted DNS domain %q is outside the intermediate's name constraints %v", d, intermediate.PermittedDNSDomains)
		}
	}
	return intermediate, nil
}

// Reconcile KMSIssuer resources.
//
// An issuer that is wrong (outside the operator's ceilings, or naming an
// intermediate that doesn't verify) is marked not ready until its spec changes. KMS
// errors are returned so the work queue retries with backoff; while the issuer's
// intermediate is still valid it stays ready through them, so a KMS blip never
// stops issuance.
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

	now := r.Clock.Now()
	intermediate, err := verifyIssuer(ctx, r.KMSCA, r.Access, issuer, now)
	var kmsErr errKMS
	switch {
	case errors.As(err, &kmsErr):
		r.Recorder.Event(issuer, core.EventTypeWarning, eventKMSError, err.Error())
		if issuer.Status.IsReady() && intermediate != nil && now.Before(intermediate.NotAfter) {
			log.Error(err, "KMS error; staying ready with the current intermediate")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, errors.Join(err, r.setNotReady(ctx, issuer, "KMS error", err))
	case err != nil:
		return ctrl.Result{}, r.setNotReady(ctx, issuer, "This KMSIssuer may not issue", err)
	}

	encoded := kmsca.EncodeCertificatePEM(intermediate)
	if !bytes.Equal(issuer.Status.Certificate, encoded) {
		issuer.Status.Certificate = encoded
		if err := r.patchIssuerStatus(ctx, issuer); err != nil {
			return ctrl.Result{}, err
		}
		r.Recorder.Event(issuer, core.EventTypeNormal, eventIntermediateAccepted, fmt.Sprintf(
			"Signing under intermediate %s, valid until %s", intermediate.SerialNumber.Text(16), intermediate.NotAfter.Format(time.RFC3339)))
		log.Info("intermediate accepted", "serial", intermediate.SerialNumber.Text(16), "notAfter", intermediate.NotAfter)
	}
	caNotAfter.WithLabelValues(issuer.Namespace, issuer.Name).Set(float64(intermediate.NotAfter.Unix()))
	if left := intermediate.NotAfter.Sub(now); left < expiryWarning {
		r.Recorder.Event(issuer, core.EventTypeWarning, eventIntermediateExpiring, fmt.Sprintf(
			"The intermediate expires %s (in %s): make a new one with `kms-ca intermediate` and update intermediateCertificate",
			intermediate.NotAfter.Format(time.RFC3339), left.Round(time.Hour)))
	}

	requeue := intermediate.NotAfter.Sub(now)
	if requeue > maxRequeue {
		requeue = maxRequeue
	}
	if requeue < time.Minute {
		requeue = time.Minute
	}
	return ctrl.Result{RequeueAfter: requeue}, r.setReady(ctx, issuer)
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
