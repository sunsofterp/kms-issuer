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
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kmsiapi "github.com/sunsofterp/kms-issuer/v5/apis/certmanager/v1alpha1"
	"github.com/sunsofterp/kms-issuer/v5/pkg/domains"
	kmsca "github.com/sunsofterp/kms-issuer/v5/pkg/kmsca"
	"github.com/sunsofterp/kms-issuer/v5/pkg/policy"
)

const (
	levelDebug = 4
	// issuerKind is the only issuerRef kind this controller serves.
	issuerKind = "KMSIssuer"
)

// CertificateRequestReconciler signs approved cert-manager CertificateRequests that
// name a KMSIssuer, within the issuer's policy.
type CertificateRequestReconciler struct {
	client.Client
	// APIReader reads uncached, for the last check before signing.
	APIReader client.Reader
	Log       logr.Logger
	Recorder  record.EventRecorder
	KMSCA     *kmsca.KMSCA
	Access    *Access
	Clock     clock.Clock

	// signed holds certificates signed but not yet recorded, by request, so a
	// failed status write never leads to signing a second one.
	signed sync.Map
}

// signedCertificate is a certificate signed for the request with this UID, with
// the chain and root as they were when it was signed: if the issuer's intermediate
// is replaced before it is recorded, the leaf still goes out beside the
// intermediate that signed it.
type signedCertificate struct {
	uid     types.UID
	leaf    *x509.Certificate
	serial  string
	certPEM []byte // the leaf, then the intermediate that signed it
	rootPEM []byte // the pinned root that intermediate chains to
}

// newSignedCertificate encodes what is handed out for a leaf, from parsed
// certificates.
func newSignedCertificate(uid types.UID, leaf *x509.Certificate, verified verifiedIssuer) signedCertificate {
	return signedCertificate{
		uid:     uid,
		leaf:    leaf,
		serial:  leaf.SerialNumber.Text(16),
		certPEM: append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), kmsca.EncodeCertificatePEM(verified.intermediate)...),
		rootPEM: kmsca.EncodeCertificatePEM(verified.root),
	}
}

// Annotation for generating RBAC role for writing Events
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch

// Reconcile signs one CertificateRequest, if it is ours, approved, and within policy.
func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("certificaterequest", req.NamespacedName)

	cr := new(cmapi.CertificateRequest)
	if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
		if apierrors.IsNotFound(err) {
			r.signed.Delete(req.NamespacedName)
			return ctrl.Result{}, nil
		}
		log.Error(err, "failed to retrieve CertificateRequest resource")
		return ctrl.Result{}, err
	}

	// Only requests naming our group exactly are ours. An empty group means
	// cert-manager.io (cert-manager's own issuers), never this one.
	if cr.Spec.IssuerRef.Group != kmsiapi.GroupVersion.Group {
		log.V(levelDebug).Info("issuerRef group is not ours", "group", cr.Spec.IssuerRef.Group)
		return ctrl.Result{}, nil
	}

	shouldProcess, err := r.requestShouldBeProcessed(ctx, log, cr)
	if err != nil || !shouldProcess {
		if err == nil {
			// Finished (or not ours to sign yet): nothing kept for it is needed,
			// including a certificate whose write succeeded but reported an error.
			r.signed.Delete(req.NamespacedName)
		}
		return ctrl.Result{}, err
	}

	if len(cr.Status.Certificate) > 0 {
		log.V(levelDebug).Info("existing certificate data found in status, skipping already completed CertificateRequest")
		r.signed.Delete(req.NamespacedName)
		return ctrl.Result{}, nil
	}

	if cr.Spec.IssuerRef.Kind != issuerKind {
		return ctrl.Result{}, r.fail(ctx, cr, "issuerRef kind %q is not %s", cr.Spec.IssuerRef.Kind, issuerKind)
	}

	// The issuer is read uncached: a just-narrowed or just-deleted issuer must never
	// sign once more from a stale copy.
	issuer := kmsiapi.KMSIssuer{}
	issuerName := types.NamespacedName{Namespace: req.Namespace, Name: cr.Spec.IssuerRef.Name}
	if err = r.reader().Get(ctx, issuerName, &issuer); err != nil {
		log.Error(err, "failed to retrieve KMSIssuer resource", "issuer", issuerName)
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to retrieve KMSIssuer resource %s: %v", issuerName, err)
		return ctrl.Result{}, err
	}
	settings := issuerSettings(&issuer)
	if !issuer.Status.IsReady() {
		err = fmt.Errorf("KMSIssuer %s is not ready", issuerName)
		log.Error(err, "issuer not ready")
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "KMSIssuer %s is not Ready", issuerName)
		return ctrl.Result{}, err
	}

	// Verify the issuer here, at signing time, from its spec: never trust the issuer
	// controller's earlier verdict or anything in its status. It must be within the
	// operator's ceilings, and its intermediate for the KMS key, signed by a pinned
	// root and within the ceilings. A failure leaves the request pending (it may be
	// fixed), never failed.
	verified, err := verifyIssuer(ctx, r.KMSCA, r.Access, &issuer, r.Clock.Now())
	parent := verified.intermediate
	if err != nil {
		err = fmt.Errorf("KMSIssuer %s cannot sign now: %w", issuerName, err)
		log.Error(err, "not signing")
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "%v (will retry)", err)
		return ctrl.Result{}, err
	}

	// The cache may lag a signing that just happened: read the request fresh, so a
	// second certificate is never signed for it.
	if r.APIReader != nil {
		fresh := new(cmapi.CertificateRequest)
		if err := r.APIReader.Get(ctx, req.NamespacedName, fresh); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		if len(fresh.Status.Certificate) > 0 || fresh.ResourceVersion != cr.ResourceVersion {
			return ctrl.Result{Requeue: true}, nil
		}
	}

	// A certificate already signed for this request, whose recording failed, is
	// recorded now instead of signing a second one, if the issuer as it is now
	// would still sign it: at least an hour left, its names inside the issuer's
	// domains (wildcards only if allowed), no longer than the issuer's maximum.
	if pending, ok := r.signed.Load(req.NamespacedName); ok {
		p := pending.(signedCertificate)
		if p.uid == cr.UID {
			why := stillAcceptable(p.leaf, &issuer, settings, r.Clock.Now())
			if why == "" {
				return r.record(ctx, log, req, &issuer, p)
			}
			log.Info("kept certificate no longer acceptable, signing a new one", "serial", p.serial, "reason", why)
		}
		r.signed.Delete(req.NamespacedName)
	}

	serial, err := kmsca.RandomSerial()
	if err != nil {
		return ctrl.Result{}, err
	}
	var duration metav1.Duration
	if cr.Spec.Duration != nil {
		duration = *cr.Spec.Duration
	}
	usages := make([]string, 0, len(cr.Spec.Usages))
	for _, u := range cr.Spec.Usages {
		usages = append(usages, string(u))
	}
	template, publicKey, err := policy.Template(
		&policy.Request{
			CSR:             cr.Spec.Request,
			IsCA:            cr.Spec.IsCA,
			Usages:          usages,
			Duration:        duration.Duration,
			DefaultDuration: min(cmapi.DefaultCertificateDuration, settings.maxCertificateDuration),
		},
		&policy.Issuer{
			PermittedDNSDomains: issuer.Spec.PermittedDNSDomains,
			AllowWildcards:      issuer.Spec.AllowWildcards,
			MaxDuration:         settings.maxCertificateDuration,
		},
		parent, serial, r.Clock.Now(),
	)
	if err != nil {
		if errors.Is(err, policy.ErrDenied) {
			log.Info("request refused", "reason", err.Error(), "requester", cr.Spec.Username)
			requestsRefused.WithLabelValues(issuer.Namespace, issuer.Name).Inc()
			return ctrl.Result{}, r.fail(ctx, cr, "%v", err)
		}
		if errors.Is(err, policy.ErrWait) {
			log.Info("request waits", "reason", err.Error())
			_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "%v (will retry)", err)
		}
		return ctrl.Result{}, err
	}

	signed, err := r.KMSCA.SignCertificate(ctx, &kmsca.IssueCertificateInput{
		KeyID:     issuer.Spec.KeyID,
		Parent:    parent,
		Cert:      template,
		PublicKey: publicKey,
	})
	if err != nil {
		log.Error(err, "failed to sign certificate request")
		_ = r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to sign the certificate (will retry): %v", err)
		return ctrl.Result{}, err
	}

	// The audit record of every issuance.
	log.Info("issued certificate",
		"serial", signed.SerialNumber.Text(16),
		"dnsNames", signed.DNSNames,
		"notBefore", signed.NotBefore,
		"notAfter", signed.NotAfter,
		"issuer", issuerName.String(),
		"keyId", issuer.Spec.KeyID,
		"requester", cr.Spec.Username,
		"requesterGroups", cr.Spec.Groups,
	)
	p := newSignedCertificate(cr.UID, signed, verified)
	r.signed.Store(req.NamespacedName, p)
	return r.record(ctx, log, req, &issuer, p)
}

// stillAcceptable returns why a kept leaf may no longer be handed out by the
// issuer as it is now, or "" if it may.
func stillAcceptable(leaf *x509.Certificate, issuer *kmsiapi.KMSIssuer, s settings, now time.Time) string {
	if leaf.NotAfter.Sub(now) < time.Hour {
		return "less than an hour of validity left"
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > s.maxCertificateDuration {
		return "longer than the issuer's maximum"
	}
	for _, name := range leaf.DNSNames {
		host := name
		if strings.HasPrefix(name, "*.") {
			if !issuer.Spec.AllowWildcards {
				return "wildcards are no longer allowed"
			}
			host = name[2:]
		}
		if !domains.Within(host, issuer.Spec.PermittedDNSDomains) {
			return fmt.Sprintf("%q is outside the issuer's domains", name)
		}
	}
	return ""
}

// record writes a signed certificate into the request's status. A conflicting
// write is retried with the certificate already signed, and a failed one keeps it
// for the next attempt: signing again would issue a second certificate. The chain
// handed out is the leaf then the intermediate that signed it; ca.crt is the
// pinned root that intermediate chains to, the certificate clients trust. Both were
// fixed when the leaf was signed.
func (r *CertificateRequestReconciler) record(ctx context.Context, log logr.Logger, req ctrl.Request, issuer *kmsiapi.KMSIssuer, p signedCertificate) (ctrl.Result, error) {
	certPEM, rootPEM := p.certPEM, p.rootPEM
	var cr *cmapi.CertificateRequest
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := new(cmapi.CertificateRequest)
		if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
			return err
		}
		cr = latest
		if len(latest.Status.Certificate) > 0 {
			return nil
		}
		latest.Status.Certificate = certPEM
		latest.Status.CA = rootPEM
		apiutil.SetCertificateRequestCondition(latest, cmapi.CertificateRequestConditionReady, cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, "Certificate issued")
		return r.Status().Update(ctx, latest)
	})
	if err != nil {
		if apierrors.IsNotFound(err) {
			r.signed.Delete(req.NamespacedName)
			return ctrl.Result{}, nil
		}
		log.Error(err, "failed to record the issued certificate (kept for the next attempt)", "serial", p.serial)
		return ctrl.Result{}, err
	}
	r.signed.Delete(req.NamespacedName)
	certificatesIssued.WithLabelValues(issuer.Namespace, issuer.Name).Inc()
	r.Recorder.Event(cr, core.EventTypeNormal, cmapi.CertificateRequestReasonIssued, "Certificate issued")
	return ctrl.Result{}, nil
}

func (r *CertificateRequestReconciler) reader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// SetupWithManager initialises the CertificateRequest controller into the
// controller runtime.
func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}

// requestShouldBeProcessed returns false when the request is finished, denied, or
// not yet approved. Approval is always required. A denied request gets a
// Ready=False condition and a failure time.
func (r *CertificateRequestReconciler) requestShouldBeProcessed(ctx context.Context, log logr.Logger, cr *cmapi.CertificateRequest) (bool, error) {
	dbg := log.V(levelDebug)

	if apiutil.CertificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		dbg.Info("CertificateRequest is Ready. Ignoring.")
		return false, nil
	}
	if apiutil.CertificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonFailed,
	}) {
		dbg.Info("CertificateRequest is Failed. Ignoring.")
		return false, nil
	}
	if apiutil.CertificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonDenied,
	}) {
		dbg.Info("CertificateRequest already has a Ready condition with Denied Reason. Ignoring.")
		return false, nil
	}

	if apiutil.CertificateRequestIsDenied(cr) {
		dbg.Info("CertificateRequest has been denied. Marking as failed.")
		if cr.Status.FailureTime == nil {
			nowTime := metav1.NewTime(r.Clock.Now())
			cr.Status.FailureTime = &nowTime
		}
		return false, r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonDenied, "The CertificateRequest was denied by an approval controller")
	}

	if !apiutil.CertificateRequestIsApproved(cr) {
		dbg.Info("certificate request has not been approved")
		return false, nil
	}
	return true, nil
}

// fail marks the request failed for good.
func (r *CertificateRequestReconciler) fail(ctx context.Context, cr *cmapi.CertificateRequest, message string, args ...any) error {
	if cr.Status.FailureTime == nil {
		nowTime := metav1.NewTime(r.Clock.Now())
		cr.Status.FailureTime = &nowTime
	}
	return r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, message, args...)
}

func (r *CertificateRequestReconciler) setStatus(ctx context.Context, cr *cmapi.CertificateRequest, status cmmeta.ConditionStatus, reason, message string, args ...any) error {
	completeMessage := fmt.Sprintf(message, args...)
	apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady, status, reason, completeMessage)

	eventType := core.EventTypeNormal
	if status == cmmeta.ConditionFalse {
		eventType = core.EventTypeWarning
	}
	r.Recorder.Event(cr, eventType, reason, completeMessage)

	return r.Status().Update(ctx, cr)
}
