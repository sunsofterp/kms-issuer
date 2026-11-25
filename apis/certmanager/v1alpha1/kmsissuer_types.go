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
// +kubebuilder:validation:XValidation:rule="!has(self.duration) || !has(self.renewBefore) || duration(self.renewBefore) < duration(self.duration)",message="renewBefore must be shorter than duration"
type KMSIssuerSpec struct {
	// KeyID is the KMS key that signs: a key ID or key ARN, never an alias (an alias
	// can be re-pointed at another key by anyone allowed to update it). The key must
	// be an asymmetric SIGN_VERIFY key, and the controller must be started with it in
	// --allowed-key-ids. Immutable: a different key is a different CA.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^(arn:aws[a-zA-Z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/)?(mrk-)?[0-9a-fA-F-]{32,36}$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="keyId is immutable"
	KeyID string `json:"keyId"`

	// CommonName is the CA certificate's subject common name. Immutable: devices that
	// trust the CA identify it by subject and key.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="commonName is immutable"
	CommonName string `json:"commonName"`

	// PermittedDNSDomains are the DNS domains this CA may ever certify. They are
	// written into the CA certificate as critical name constraints (so clients reject
	// any certificate under it for another name, however it was issued), and every
	// request must name only these domains or their subdomains.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:Pattern=`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
	// +kubebuilder:validation:items:MaxLength=253
	PermittedDNSDomains []string `json:"permittedDNSDomains"`

	// AllowWildcards lets a request include wildcard names (*.example.internal).
	// Off by default.
	// +optional
	AllowWildcards bool `json:"allowWildcards,omitempty"`

	// MaxCertificateDuration is the longest validity a request may ask for. Requests
	// asking for longer are refused, not shortened. Issued certificates also never
	// outlive the CA certificate. Defaults to 2160h (90 days, cert-manager's default).
	// +optional
	MaxCertificateDuration *metav1.Duration `json:"maxCertificateDuration,omitempty"`

	// Duration is the CA certificate's validity. Defaults to 87600h (10 years);
	// at least 24h.
	// +optional
	Duration *metav1.Duration `json:"duration,omitempty"`

	// RenewBefore is how long before the CA certificate's notAfter a new CA
	// certificate (same key, same subject) is made. Certificates issued before and
	// after chain to either, so devices holding the older copy keep working until that
	// copy expires. Defaults to 8760h (1 year); must be shorter than duration.
	// +optional
	RenewBefore *metav1.Duration `json:"renewBefore,omitempty"`
}

// KMSIssuerStatus defines the observed state of KMSIssuer
type KMSIssuerStatus struct {
	Status `json:",inline"`
	// Byte slice containing a PEM encoded signed certificate of the CA
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
