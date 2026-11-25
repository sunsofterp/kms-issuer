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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Condition reasons
const (
	KMSIssuerReasonPending = "Pending"
	KMSIssuerReasonFailed  = "Failed"
	KMSIssuerReasonIssued  = "Issued"
)

// KMSIssuerSpec defines the desired state of KMSIssuer.
//
// The CA is two-tier. An offline root (its own KMS key, never usable by the
// controller) signs an intermediate certificate for this issuer's KMS key, by hand,
// with the kms-ca tool. The issuer signs leaves with that key, under that
// intermediate. The root it must chain to is the controller's --root-certificate,
// not anything here, so editing a KMSIssuer can never swap in another root.
type KMSIssuerSpec struct {
	// KeyID is the KMS key that signs leaves: a key ID or key ARN, never an alias (an
	// alias can be re-pointed at another key). The key must be an asymmetric
	// SIGN_VERIFY key, and the controller must be started with it in
	// --allowed-key-ids. Immutable: a different key needs a different intermediate.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^(arn:aws[a-zA-Z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/)?(mrk-)?[0-9a-fA-F-]{32,36}$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="keyId is immutable"
	KeyID string `json:"keyId"`

	// IntermediateCertificate is the PEM intermediate CA certificate for KeyID, made
	// with `kms-ca intermediate`. It must be for this KMS key, signed by the
	// controller's root, a CA with path length 0, and name-constrained (critically)
	// to domains inside the operator's ceilings. Replacing it renews the issuer.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	IntermediateCertificate string `json:"intermediateCertificate"`

	// PermittedDNSDomains are the DNS domains this issuer certifies: every request
	// must name only these domains or their subdomains. They must be inside both the
	// intermediate's name constraints and the operator's ceilings.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:Pattern=`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
	// +kubebuilder:validation:items:MaxLength=253
	PermittedDNSDomains []string `json:"permittedDNSDomains"`

	// AllowWildcards lets a request include wildcard names (*.example.internal).
	// Off by default, and only possible if the operator allows wildcards.
	// +optional
	AllowWildcards bool `json:"allowWildcards,omitempty"`

	// MaxCertificateDuration is the longest validity a request may ask for, in whole
	// seconds. Requests asking for longer are refused, not shortened. Issued
	// certificates also never outlive the intermediate. Defaults to 720h (30 days;
	// cert-manager renews them automatically); at most the operator's
	// --max-certificate-duration. A request without a duration gets this maximum or
	// cert-manager's default (90 days), whichever is shorter.
	// +optional
	MaxCertificateDuration *metav1.Duration `json:"maxCertificateDuration,omitempty"`
}

// KMSIssuerStatus defines the observed state of KMSIssuer
type KMSIssuerStatus struct {
	Status `json:",inline"`
	// Certificate is the intermediate certificate as last verified, PEM.
	// +optional
	Certificate []byte `json:"certificate,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// KMSIssuer is the Schema for the kmsissuers API
type KMSIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KMSIssuerSpec   `json:"spec,omitempty"`
	Status KMSIssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KMSIssuerList contains a list of KMSIssuer
type KMSIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KMSIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KMSIssuer{}, &KMSIssuerList{})
}
