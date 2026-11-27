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
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	kmsiapi "github.com/sunsofterp/kms-issuer/v5/apis/certmanager/v1alpha1"
	"github.com/sunsofterp/kms-issuer/v5/pkg/kmsca"
)

const (
	// defaultMaxCertificateDuration is the default longest issued validity. Leaves
	// renew automatically, so they are kept short.
	defaultMaxCertificateDuration = time.Hour * 24 * 30
	// maxRequeue bounds how long the issuer goes unchecked.
	maxRequeue = 12 * time.Hour
	// refusedRequeue is how soon a refused issuer is checked again: a refusal can be
	// time-dependent (an intermediate not valid yet) or fixed outside the spec.
	refusedRequeue = 10 * time.Minute
	// minExpiryWarning is the least warning before the intermediate expires. The
	// warning starts at twice the issuer's longest leaf (leaves are cut short in
	// the intermediate's last maxCertificateDuration), and never later than this.
	minExpiryWarning = 30 * 24 * time.Hour

	eventIntermediateAccepted = "IntermediateAccepted"
	eventIntermediateExpiring = "IntermediateExpiringSoon"
	eventKMSError             = "KMSError"

	// The actions events report (events.k8s.io/v1 requires one).
	actionSign      = "Sign"
	actionVerify    = "Verify"
	actionReconcile = "Reconcile"
)

// KMSIssuerReconciler reconciles a KMSIssuer object.
type KMSIssuerReconciler struct {
	client.Client
	// APIReader reads the issuer uncached. The controller ignores its own status
	// writes, so a pass must never decide from a cached copy that may predate the
	// last write (it would skip a write that is needed, and nothing would start
	// another pass to repair it).
	APIReader client.Reader
	Log       logr.Logger
	Scheme    *runtime.Scheme
	Recorder  events.EventRecorder
	KMSCA     *kmsca.KMSCA
	Access    *Access
	Clock     clock.Clock
}

// The RBAC the controller needs to write events (events.k8s.io/v1 only: the
// recorder has no core/v1 fallback). Nothing generates RBAC from these markers in
// this repository; the chart's templates/rbac.yaml is what grants it.
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// +kubebuilder:rbac:groups=cert-manager.skyscanner.net,resources=kmsissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.skyscanner.net,resources=kmsissuers/status,verbs=get;update;patch

// NewKMSIssuerReconciler Initialise a new KMSIssuerReconciler
func NewKMSIssuerReconciler(mgr manager.Manager, ca *kmsca.KMSCA, access *Access) *KMSIssuerReconciler {
	return &KMSIssuerReconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Log:       ctrl.Log.WithName("controllers").WithName("kmsissuer_controller"),
		Scheme:    mgr.GetScheme(),
		Recorder:  mgr.GetEventRecorder("kmsissuer_controller"),
		KMSCA:     ca,
		Access:    access,
		Clock:     clock.RealClock{},
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

// verifiedIssuer is an issuer that may sign: its intermediate, and the pinned root
// that intermediate chains to.
type verifiedIssuer struct {
	intermediate *x509.Certificate
	root         *x509.Certificate
}

// verifyIssuer returns the issuer's intermediate and root when the issuer may sign:
// allowed namespace and key, settings within the ceilings, and an intermediate that
// is for the issuer's KMS key, signed by a pinned root, constrained within the
// ceilings and the root and covering the issuer's domains, valid now and no
// longer-lived than allowed. Errors wrapping errKMS are KMS failures (retry); others
// are the issuer's configuration. On a KMS failure the parsed intermediate (not yet
// verified) is returned, for the caller to judge whether to keep serving.
func verifyIssuer(ctx context.Context, ca *kmsca.KMSCA, access *Access, issuer *kmsiapi.KMSIssuer, now time.Time) (verifiedIssuer, error) {
	s := issuerSettings(issuer)
	if err := s.validate(); err != nil {
		return verifiedIssuer{}, fmt.Errorf("invalid issuer settings: %w", err)
	}
	if err := access.CheckIssuer(issuer, s); err != nil {
		return verifiedIssuer{}, err
	}
	intermediate, err := kmsca.ParseCertificatePEM([]byte(issuer.Spec.IntermediateCertificate))
	if err != nil {
		return verifiedIssuer{}, fmt.Errorf("intermediateCertificate: %w", err)
	}
	pub, err := ca.PublicKey(ctx, issuer.Spec.KeyID)
	if err != nil {
		return verifiedIssuer{intermediate: intermediate}, errKMS{fmt.Errorf("reading the KMS key's public key: %w", err)}
	}
	root, err := kmsca.ValidateIntermediate(intermediate, &kmsca.ExpectedIntermediate{
		Roots: access.RootsAt(now), OtherRoots: access.Roots(), PublicKey: pub, AllowedDomains: access.AllowedDomains(),
		MaxDuration: access.MaxIntermediateDuration(), Now: now,
	})
	if err != nil {
		return verifiedIssuer{}, fmt.Errorf("intermediateCertificate: %w", err)
	}
	for _, d := range issuer.Spec.PermittedDNSDomains {
		if !kmsca.WithinDomains(d, intermediate.PermittedDNSDomains) {
			return verifiedIssuer{}, fmt.Errorf("permitted DNS domain %q is outside the intermediate's name constraints %v", d, intermediate.PermittedDNSDomains)
		}
	}
	return verifiedIssuer{intermediate: intermediate, root: root}, nil
}

// expiryWarning is how long before the intermediate expires the issuer warns.
func expiryWarning(s settings) time.Duration {
	if w := 2 * s.maxCertificateDuration; w > minExpiryWarning {
		return w
	}
	return minExpiryWarning
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
	if err := readerOr(r.APIReader, r.Client).Get(ctx, req.NamespacedName, issuer); err != nil {
		if apierrors.IsNotFound(err) {
			caNotAfter.DeleteLabelValues(req.Namespace, req.Name)
			leavesTruncated.DeleteLabelValues(req.Namespace, req.Name)
			return ctrl.Result{}, nil
		}
		log.Error(err, "failed to retrieve KMSIssuer resource")
		return ctrl.Result{}, err
	}

	now := r.Clock.Now()
	verified, err := verifyIssuer(ctx, r.KMSCA, r.Access, issuer, now)
	intermediate := verified.intermediate
	var kmsErr errKMS
	switch {
	case errors.As(err, &kmsErr):
		eventf(r.Recorder, issuer, core.EventTypeWarning, eventKMSError, actionVerify, "%s", eventText(err))
		if issuer.Status.IsReady() && intermediate != nil && now.Before(intermediate.NotAfter) {
			log.Error(err, "KMS error; staying ready with the current intermediate")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, errors.Join(err, r.setNotReady(ctx, issuer, "KMS error", err))
	case err != nil:
		// Checked again soon: a refusal can be time-dependent (an intermediate not
		// valid yet) or fixed outside the spec (the operator's flags, a new root).
		return ctrl.Result{RequeueAfter: refusedRequeue}, r.setNotReady(ctx, issuer, "This KMSIssuer may not issue", err)
	}

	s := issuerSettings(issuer)
	encoded := kmsca.EncodeCertificatePEM(intermediate)
	if !bytes.Equal(issuer.Status.Certificate, encoded) {
		issuer.Status.Certificate = encoded
		if err := r.patchIssuerStatus(ctx, issuer); err != nil {
			return ctrl.Result{}, err
		}
		eventf(r.Recorder, issuer, core.EventTypeNormal, eventIntermediateAccepted, actionVerify,
			"Signing under intermediate %s, valid until %s", intermediate.SerialNumber.Text(16), intermediate.NotAfter.Format(time.RFC3339))
		log.Info("intermediate accepted", "serial", intermediate.SerialNumber.Text(16), "notAfter", intermediate.NotAfter)
	}
	caNotAfter.WithLabelValues(issuer.Namespace, issuer.Name).Set(float64(intermediate.NotAfter.Unix()))
	left := intermediate.NotAfter.Sub(now)
	truncating := 0.0
	if left < s.maxCertificateDuration {
		truncating = 1
	}
	leavesTruncated.WithLabelValues(issuer.Namespace, issuer.Name).Set(truncating)
	if left < expiryWarning(s) {
		eventf(r.Recorder, issuer, core.EventTypeWarning, eventIntermediateExpiring, actionVerify,
			"The intermediate expires %s (in %s; certificates are cut short from %s before): make a new one with `kms-ca intermediate` and update intermediateCertificate",
			intermediate.NotAfter.Format(time.RFC3339), left.Round(time.Hour), s.maxCertificateDuration)
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

	if err := readerOr(r.APIReader, r.Client).Get(ctx, client.ObjectKeyFromObject(issuer), &latest); err != nil {
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

// SetupWithManager watches KMSIssuers for spec changes only: the controller's own
// status writes must not start a pass, or a failing one would retry at once
// instead of backing off. It re-checks each issuer on a timer.
func (r *KMSIssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kmsiapi.KMSIssuer{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

func (r *KMSIssuerReconciler) setReady(ctx context.Context, issuer *kmsiapi.KMSIssuer) error {
	if issuer.Status.IsReady() {
		return nil
	}
	eventf(r.Recorder, issuer, core.EventTypeNormal, kmsiapi.KMSIssuerReasonIssued, actionVerify, "Ready to issue")
	ready := kmsiapi.NewCondition(kmsiapi.ConditionReady, kmsiapi.ConditionTrue, kmsiapi.KMSIssuerReasonIssued, "")
	issuer.Status.SetCondition(&ready)
	return r.patchIssuerStatus(ctx, issuer)
}

// setNotReady marks the issuer not ready with the cause. It returns only the status
// write's error: configuration problems are not retried until the spec changes.
func (r *KMSIssuerReconciler) setNotReady(ctx context.Context, issuer *kmsiapi.KMSIssuer, message string, cause error) error {
	r.Log.Error(cause, message, "kms-issuer", client.ObjectKeyFromObject(issuer))
	eventf(r.Recorder, issuer, core.EventTypeWarning, kmsiapi.KMSIssuerReasonFailed, actionVerify, "%s: %s", message, eventText(cause))
	ready := kmsiapi.NewCondition(kmsiapi.ConditionReady, kmsiapi.ConditionFalse, kmsiapi.KMSIssuerReasonFailed, message+": "+stableText(cause))
	issuer.Status.SetCondition(&ready)
	return r.patchIssuerStatus(ctx, issuer)
}
