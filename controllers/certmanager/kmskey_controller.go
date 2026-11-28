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
	"errors"

	"github.com/go-logr/logr"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	kmsiapi "github.com/sunsofterp/kms-issuer/v5/apis/certmanager/v1alpha1"
	kmsca "github.com/sunsofterp/kms-issuer/v5/pkg/kmsca"
)

// NewKMSKeyReconciler Initialise a new NewKMSKeyReconciler
func NewKMSKeyReconciler(mgr manager.Manager, ca *kmsca.KMSCA) *KMSKeyReconciler {
	return &KMSKeyReconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Log:       ctrl.Log.WithName("controllers").WithName("kmskey_controller"),
		Scheme:    mgr.GetScheme(),
		Recorder:  mgr.GetEventRecorder("kmskey_controller"),
		KMSCA:     ca,
	}
}

// KMSKeyReconciler reconciles a KMSKey object
type KMSKeyReconciler struct {
	client.Client
	// APIReader reads the KMSKey, and the base of its status patch, uncached. A
	// cached copy that predates the last status write would be written back over
	// it: a failing pass would blank the key ID, and a copy that already matches
	// the new status would make an empty patch. The controller ignores its own
	// status writes, so nothing would repair either.
	APIReader client.Reader
	Log       logr.Logger
	Scheme    *runtime.Scheme
	Recorder  events.EventRecorder
	KMSCA     *kmsca.KMSCA
}

// The RBAC the controller needs to write events (events.k8s.io/v1 only).
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// +kubebuilder:rbac:groups=cert-manager.skyscanner.net,resources=kmskeys,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=cert-manager.skyscanner.net,resources=kmskeys/status,verbs=get;update;patch

func (r *KMSKeyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("kmskey", req.NamespacedName)

	// retrieve the KMSKey resource to reconcile.
	kmsKey := &kmsiapi.KMSKey{}
	if err := readerOr(r.APIReader, r.Client).Get(ctx, req.NamespacedName, kmsKey); err != nil {
		log.Error(err, "failed to retrieve KMSKey resource")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Register finalizer.
	if NeedToAddFinalizer(kmsKey) {
		log.Info("register finalizer")
		AddFinalizer(kmsKey)
		if err := r.Update(ctx, kmsKey); err != nil {
			return ctrl.Result{}, r.manageFailure(ctx, log, kmsKey, err, "Failed to add the object finalizer")
		}
	}

	// The object is being deleted
	if IsBeingDeleted(kmsKey) {
		// our finalizer is present, so lets handle any external dependency.
		if !NeedToAddFinalizer(kmsKey) {
			if kmsKey.Spec.DeletionPolicy == "Delete" {
				log.Info("delete KMSKey")
				err := r.KMSCA.DeleteKey(ctx, &kmsca.DeleteKeyInput{
					AliasName:           kmsKey.Spec.AliasName,
					OwnerUID:            string(kmsKey.UID),
					PendingWindowInDays: kmsKey.Spec.DeletionPendingWindowInDays,
				})
				switch {
				case errors.Is(err, kmsca.ErrNotOwned):
					// Never delete a key this KMSKey didn't create; let the object go.
					eventf(r.Recorder, kmsKey, core.EventTypeWarning, kmsiapi.KMSKeyReasonFailed, actionReconcile,
						"The alias points at a key this KMSKey did not create; the key was not deleted")
				case err != nil:
					return ctrl.Result{}, r.manageFailure(ctx, log, kmsKey, err, "Failed to delete the KMS key")
				}
			}
			// remove our finalizer from the list and update it.
			RemoveFinalizer(kmsKey)
			if err := r.Update(ctx, kmsKey); err != nil {
				return ctrl.Result{}, r.manageFailure(ctx, log, kmsKey, err, "Failed to remove the object finalizer")
			}
		}
		return ctrl.Result{}, nil
	}

	// Create the KMS key
	keyID, err := r.KMSCA.CreateKey(ctx, &kmsca.CreateKeyInput{
		AliasName:             kmsKey.Spec.AliasName,
		OwnerUID:              string(kmsKey.UID),
		Description:           kmsKey.Spec.Description,
		CustomerMasterKeySpec: kmsKey.Spec.CustomerMasterKeySpec,
		Policy:                kmsKey.Spec.Policy,
		Tags:                  kmsKey.Spec.Tags,
	})
	if err != nil {
		return ctrl.Result{}, r.manageFailure(ctx, log, kmsKey, err, "Failed to create the kms key")
	}
	kmsKey.Status.KeyID = keyID
	if err := r.patchKeyStatus(ctx, kmsKey); err != nil {
		return ctrl.Result{}, r.manageFailure(ctx, log, kmsKey, err, "Failed to update kmsKey.Status.KeyId")
	}
	return ctrl.Result{}, r.manageSuccess(ctx, log, kmsKey)
}

// SetupWithManager watches KMSKeys for spec changes and deletion only (deletion
// bumps the generation): the controller's own status writes must not start a pass,
// or a failing one would retry at once instead of backing off.
func (r *KMSKeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kmsiapi.KMSKey{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// patchStatus updates the kmsiapi.KMSIssuer using a MergeFrom strategy
func (r *KMSKeyReconciler) patchKeyStatus(ctx context.Context, issuer *kmsiapi.KMSKey) error {
	var latest kmsiapi.KMSKey

	if err := readerOr(r.APIReader, r.Client).Get(ctx, client.ObjectKeyFromObject(issuer), &latest); err != nil {
		return err
	}

	patch := client.MergeFrom(latest.DeepCopy())
	latest.Status = issuer.Status

	return r.Client.Status().Patch(ctx, &latest, patch)
}

// manageSuccess
func (r *KMSKeyReconciler) manageSuccess(ctx context.Context, log logr.Logger, kmskey *kmsiapi.KMSKey) error {
	reason := kmsiapi.KMSKeyReasonIssued
	msg := ""
	log.Info("successfully reconciled kms key")
	eventf(r.Recorder, kmskey, core.EventTypeNormal, reason, actionReconcile, "%s", msg)
	ready := kmsiapi.NewCondition(kmsiapi.ConditionReady, kmsiapi.ConditionTrue, reason, msg)
	kmskey.Status.SetCondition(&ready)
	return r.patchKeyStatus(ctx, kmskey)
}

// manageFailure marks the KMSKey not ready and returns the cause, so the work queue
// retries with backoff.
func (r *KMSKeyReconciler) manageFailure(ctx context.Context, log logr.Logger, kmskey *kmsiapi.KMSKey, issue error, msg string) error {
	reason := kmsiapi.KMSKeyReasonFailed
	log.Error(issue, msg)
	eventf(r.Recorder, kmskey, core.EventTypeWarning, reason, actionReconcile, "%s: %s", msg, eventText(issue))
	ready := kmsiapi.NewCondition(kmsiapi.ConditionReady, kmsiapi.ConditionFalse, reason, msg+": "+stableText(issue))
	kmskey.Status.SetCondition(&ready)
	return errors.Join(issue, r.patchKeyStatus(ctx, kmskey))
}
