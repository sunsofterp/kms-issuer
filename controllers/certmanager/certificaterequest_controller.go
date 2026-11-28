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
	"k8s.io/client-go/tools/events"
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

// The reasons of the warning events for a request left pending (its Ready
// condition's reason is Pending for all of them). Events of one reason on one
// version of one request are merged by the events API, keeping the first note, so
// each cause has its own; the Ready condition's message is always the current one.
const (
	eventIssuerUnavailable = "IssuerUnavailable"
	eventIssuerNotReady    = "IssuerNotReady"
	eventIssuerCannotSign  = "IssuerCannotSign"
	eventWaiting           = "Waiting"
	eventSigningFailed     = "SigningFailed"
)

// CertificateRequestReconciler signs approved cert-manager CertificateRequests that
// name a KMSIssuer, within the issuer's policy.
type CertificateRequestReconciler struct {
	client.Client
	// APIReader reads uncached, for the last check before signing.
	APIReader client.Reader
	Log       logr.Logger
	Recorder  events.EventRecorder
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
	uid          types.UID
	leaf         *x509.Certificate
	intermediate *x509.Certificate // the intermediate that signed it
	root         *x509.Certificate // the pinned root that intermediate chains to
	serial       string
	certPEM      []byte // the leaf, then the intermediate that signed it
	rootPEM      []byte // the pinned root that intermediate chains to
}

// newSignedCertificate encodes what is handed out for a leaf, from parsed
// certificates.
func newSignedCertificate(uid types.UID, leaf *x509.Certificate, verified verifiedIssuer) signedCertificate {
	return signedCertificate{
		uid:          uid,
		leaf:         leaf,
		intermediate: verified.intermediate,
		root:         verified.root,
		serial:       leaf.SerialNumber.Text(16),
		certPEM:      append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), kmsca.EncodeCertificatePEM(verified.intermediate)...),
		rootPEM:      kmsca.EncodeCertificatePEM(verified.root),
	}
}

// The RBAC the controller needs to write events (events.k8s.io/v1 only).
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

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

	issuer, verified, err := r.signingIssuer(ctx, log, cr)
	if err != nil {
		return ctrl.Result{}, err
	}
	limits := issuerSettings(issuer)

	// The cache may lag a signing that just happened: read the request fresh, so a
	// second certificate is never signed for it.
	current, err := r.stillUnsigned(ctx, cr)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !current {
		// Retried through the rate limiter (backing off), not on a fixed delay:
		// each pass reads the issuer and asks KMS for its key before getting here.
		return ctrl.Result{}, fmt.Errorf("the cache is behind CertificateRequest %s: retrying once it catches up", req.NamespacedName)
	}

	if p := r.keptCertificate(log, req, cr, issuer, &verified, limits); p != nil {
		return r.record(ctx, log, req, issuer, p)
	}

	signed, err := r.sign(ctx, log, cr, issuer, verified.intermediate, limits)
	if err != nil || signed == nil {
		return ctrl.Result{}, err
	}
	p := newSignedCertificate(cr.UID, signed, verified)
	r.signed.Store(req.NamespacedName, p)
	return r.record(ctx, log, req, issuer, &p)
}

// signingIssuer returns the request's issuer and its verified chain, or an error
// (the request left pending) if it can't sign now. The issuer is read uncached:
// a just-narrowed or just-deleted issuer must never sign once more from a stale
// copy. It is verified here, at signing time, from its spec: never trust the
// issuer controller's earlier verdict or anything in its status. It must be
// within the operator's ceilings, and its intermediate for the KMS key, signed by
// a pinned root and within the ceilings. A failure leaves the request pending (it
// may be fixed), never failed.
func (r *CertificateRequestReconciler) signingIssuer(ctx context.Context, log logr.Logger, cr *cmapi.CertificateRequest) (*kmsiapi.KMSIssuer, verifiedIssuer, error) {
	issuer := &kmsiapi.KMSIssuer{}
	issuerName := types.NamespacedName{Namespace: cr.Namespace, Name: cr.Spec.IssuerRef.Name}
	if err := r.reader().Get(ctx, issuerName, issuer); err != nil {
		log.Error(err, "failed to retrieve KMSIssuer resource", "issuer", issuerName)
		_ = r.pending(ctx, cr, eventIssuerUnavailable, "Failed to retrieve KMSIssuer resource %s: %v", issuerName, err)
		return nil, verifiedIssuer{}, err
	}
	if !issuer.Status.IsReady() {
		err := fmt.Errorf("KMSIssuer %s is not ready", issuerName)
		log.Error(err, "issuer not ready")
		_ = r.pending(ctx, cr, eventIssuerNotReady, "KMSIssuer %s is not Ready", issuerName)
		return nil, verifiedIssuer{}, err
	}
	verified, err := verifyIssuer(ctx, r.KMSCA, r.Access, issuer, r.Clock.Now())
	if err != nil {
		err = fmt.Errorf("KMSIssuer %s cannot sign now: %w", issuerName, err)
		log.Error(err, "not signing")
		_ = r.pendingKMS(ctx, cr, eventIssuerCannotSign, "%s (will retry)", err)
		return nil, verifiedIssuer{}, err
	}
	return issuer, verified, nil
}

// stillUnsigned reads the request fresh (when an uncached reader is set) and
// reports whether it is unchanged and still has no certificate.
func (r *CertificateRequestReconciler) stillUnsigned(ctx context.Context, cr *cmapi.CertificateRequest) (bool, error) {
	if r.APIReader == nil {
		return true, nil
	}
	fresh := new(cmapi.CertificateRequest)
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(cr), fresh); err != nil {
		return false, err
	}
	return len(fresh.Status.Certificate) == 0 && fresh.ResourceVersion == cr.ResourceVersion, nil
}

// keptCertificate returns a certificate already signed for this request, whose
// recording failed, if the issuer as it is now would still hand it out: its chain
// current (keptChainCurrent), at least an hour left, its names inside the
// issuer's domains (wildcards only if allowed), no longer than the issuer's
// maximum. Otherwise it drops anything kept, and the request is signed again.
func (r *CertificateRequestReconciler) keptCertificate(log logr.Logger, req ctrl.Request, cr *cmapi.CertificateRequest,
	issuer *kmsiapi.KMSIssuer, verified *verifiedIssuer, limits settings) *signedCertificate {
	pending, ok := r.signed.Load(req.NamespacedName)
	if !ok {
		return nil
	}
	p := pending.(signedCertificate)
	if p.uid == cr.UID {
		why := keptChainCurrent(&p, verified, r.Access, r.Clock.Now())
		if why == "" {
			why = stillAcceptable(p.leaf, issuer, limits, r.Clock.Now())
		}
		if why == "" {
			return &p
		}
		log.Info("kept certificate no longer acceptable, signing a new one", "serial", p.serial, "reason", why)
	}
	r.signed.Delete(req.NamespacedName)
	return nil
}

// sign builds the certificate from the request under the issuer's policy and has
// the issuer's KMS key sign it. A request the policy refuses is failed for good
// (nil certificate, and the status write's error); one that must wait, or a
// signing failure, is left pending with an error, to be retried.
func (r *CertificateRequestReconciler) sign(ctx context.Context, log logr.Logger, cr *cmapi.CertificateRequest,
	issuer *kmsiapi.KMSIssuer, parent *x509.Certificate, limits settings) (*x509.Certificate, error) {
	serial, err := kmsca.RandomSerial()
	if err != nil {
		return nil, err
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
			DefaultDuration: min(cmapi.DefaultCertificateDuration, limits.maxCertificateDuration),
		},
		&policy.Issuer{
			PermittedDNSDomains: issuer.Spec.PermittedDNSDomains,
			AllowWildcards:      issuer.Spec.AllowWildcards,
			MaxDuration:         limits.maxCertificateDuration,
		},
		parent, serial, r.Clock.Now(),
	)
	if err != nil {
		if errors.Is(err, policy.ErrDenied) {
			log.Info("request refused", "reason", err.Error(), "requester", cr.Spec.Username)
			requestsRefused.WithLabelValues(issuer.Namespace, issuer.Name).Inc()
			return nil, r.fail(ctx, cr, "%v", err)
		}
		if errors.Is(err, policy.ErrWait) {
			log.Info("request waits", "reason", err.Error())
			_ = r.pending(ctx, cr, eventWaiting, "%v (will retry)", err)
		}
		return nil, err
	}

	signed, err := r.KMSCA.SignCertificate(ctx, &kmsca.IssueCertificateInput{
		KeyID:     issuer.Spec.KeyID,
		Parent:    parent,
		Cert:      template,
		PublicKey: publicKey,
	})
	if err != nil {
		log.Error(err, "failed to sign certificate request")
		_ = r.pendingKMS(ctx, cr, eventSigningFailed, "Failed to sign the certificate (will retry): %s", err)
		return nil, err
	}

	// The audit record of every issuance.
	log.Info("issued certificate",
		"serial", signed.SerialNumber.Text(16),
		"dnsNames", signed.DNSNames,
		"notBefore", signed.NotBefore,
		"notAfter", signed.NotAfter,
		"issuer", client.ObjectKeyFromObject(issuer).String(),
		"keyId", issuer.Spec.KeyID,
		"requester", cr.Spec.Username,
		"requesterGroups", cr.Spec.Groups,
	)
	return signed, nil
}

// keptChainCurrent returns why a kept certificate's chain no longer matches the
// issuer as it is now, or "" if it does: the leaf must be signed by the issuer's
// current key (it verifies against the current intermediate: a renewed
// intermediate on the same key is fine, another key is not), and the chain it is
// handed out with must still be valid: its intermediate unexpired, its root a
// pinned root valid now.
func keptChainCurrent(p *signedCertificate, verified *verifiedIssuer, access *Access, now time.Time) string {
	if err := p.leaf.CheckSignatureFrom(verified.intermediate); err != nil {
		return "not signed by the issuer's current key"
	}
	if !now.Before(p.intermediate.NotAfter) {
		return "the intermediate that signed it has expired"
	}
	for _, r := range access.RootsAt(now) {
		if r.Equal(p.root) {
			return ""
		}
	}
	return "the root it chains to is no longer a valid pinned root"
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
func (r *CertificateRequestReconciler) record(ctx context.Context, log logr.Logger, req ctrl.Request, issuer *kmsiapi.KMSIssuer, p *signedCertificate) (ctrl.Result, error) {
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
	eventf(r.Recorder, cr, core.EventTypeNormal, cmapi.CertificateRequestReasonIssued, actionSign, "Certificate issued")
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
		return false, r.setStatus(ctx, cr, cmapi.CertificateRequestReasonDenied, "The CertificateRequest was denied by an approval controller")
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
	return r.setStatus(ctx, cr, cmapi.CertificateRequestReasonFailed, message, args...)
}

// setStatus sets Ready=False with the reason and message, with a warning event of
// the same reason.
func (r *CertificateRequestReconciler) setStatus(ctx context.Context, cr *cmapi.CertificateRequest, reason, message string, args ...any) error {
	message = fmt.Sprintf(message, args...)
	return r.notReady(ctx, cr, reason, reason, message, message)
}

// pending sets Ready=False with reason Pending (the request is retried) and the
// message, with a warning event whose reason is the cause.
func (r *CertificateRequestReconciler) pending(ctx context.Context, cr *cmapi.CertificateRequest, cause, message string, args ...any) error {
	message = fmt.Sprintf(message, args...)
	return r.notReady(ctx, cr, cmapi.CertificateRequestReasonPending, cause, message, message)
}

// pendingKMS is pending for a KMS error, format holding one %s for it: the
// condition names the error's code only (stableText), so that a retry meeting the
// same failure writes the same status; the event also carries the AWS message.
func (r *CertificateRequestReconciler) pendingKMS(ctx context.Context, cr *cmapi.CertificateRequest, cause, format string, err error) error {
	return r.notReady(ctx, cr, cmapi.CertificateRequestReasonPending, cause, fmt.Sprintf(format, stableText(err)), fmt.Sprintf(format, eventText(err)))
}

// notReady writes Ready=False with message and records the warning event with
// note: every status it writes is a request not (yet) signed. An issued
// certificate is recorded by record.
func (r *CertificateRequestReconciler) notReady(ctx context.Context, cr *cmapi.CertificateRequest, reason, eventReason, message, note string) error {
	apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady, cmmeta.ConditionFalse, reason, message)
	eventf(r.Recorder, cr, core.EventTypeWarning, eventReason, actionSign, "%s", note)
	return r.Status().Update(ctx, cr)
}
