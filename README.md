# KMS Issuer

[![Build Status](https://github.com/sunsofterp/kms-issuer/actions/workflows/test-build.yml/badge.svg?branch=main)](https://github.com/sunsofterp/kms-issuer/actions)
[![E2E Tests](https://github.com/sunsofterp/kms-issuer/actions/workflows/e2e.yaml/badge.svg?branch=main)](https://github.com/sunsofterp/kms-issuer/actions)
[![Helm Chart Tests](https://github.com/sunsofterp/kms-issuer/actions/workflows/helm.yml/badge.svg?branch=main)](https://github.com/sunsofterp/kms-issuer/actions)

KMS issuer is a [cert-manager](https://cert-manager.io/) external issuer that signs certificates with an
[AWS KMS](https://aws.amazon.com/kms/) asymmetric key, so CA private keys never leave KMS.

This is a hardened fork of [Skyscanner/kms-issuer](https://github.com/Skyscanner/kms-issuer), meant to be a
private CA that devices trust.

## The CA: two tiers

- **Root** — its own KMS key, which the controller can never use (no IAM permission). Self-signed by hand with
  `kms-ca root`: path length 1, critically name-constrained to your domains, 20 years by default. This is the
  certificate devices trust. The controller pins it (`--root-certificate`).
- **Intermediate** — signed by the root key, by hand, with `kms-ca intermediate`, for the issuing KMS key:
  path length 0, critically name-constrained inside the root's, 2 years by default. A KMSIssuer names it.
- **Leaves** — signed by the controller with the issuing key, under the intermediate.

Every client enforces name constraints on an intermediate, so nothing the issuing key signs is trusted for a
name outside the intermediate's domains, whatever the client does with constraints on roots. Whoever can use
the issuing key (the controller, or its IAM role) can sign only what the intermediate allows; making another
intermediate takes the root key, which only administrators hold.

## What it will sign

Each issued certificate is built from fields the issuer has checked, never from the request's raw
extensions:

- **Server certificates only, never a CA.** `isCA` requests are refused. Usages may be only
  `digital signature`, `key encipherment` and `server auth`; the certificate gets server auth, and key
  encipherment only for RSA keys.
- **DNS names inside the issuer's `permittedDNSDomains` only.** IP addresses, URIs, email addresses and
  other name types are refused, as are wildcards unless `allowWildcards` is set. A common name must be one
  of the DNS names; the subject is the common name alone.
- **Bounded lifetime.** A request longer than `maxCertificateDuration` (default 90 days) is refused, and
  no certificate outlives the intermediate. Validity is exactly the requested duration.
- **Approved requests only.** A CertificateRequest must be approved; denied requests are failed. Approval
  should come from a policy approver such as cert-manager
  [approver-policy](https://cert-manager.io/docs/policy/approval/approver-policy/), not cert-manager's
  built-in approver (which approves everything). The chart grants the built-in approver rights only if
  `certManagerApprovalRBAC.enable` is set, and then only over the issuers it names.
- **Only from allowed issuers, within the operator's ceilings.** The controller's required
  `--allowed-issuer-namespaces` and `--allowed-key-ids` flags name the namespaces a KMSIssuer may live in
  and the KMS keys it may use (by ID or ARN, never alias). Its `--permitted-dns-domains` (required),
  `--allow-wildcards` and `--max-certificate-duration` flags bound every issuer: whoever can write a
  KMSIssuer can narrow its policy, never widen it past them. Any other KMSIssuer signs nothing.
- **Only under a verified intermediate.** At signing time, the issuer's intermediate must be for its KMS
  key, issued and signed by the pinned root (full path validation), path length 0, critically
  name-constrained inside the operator's domains and covering the issuer's, and valid now. A KMSIssuer
  cannot change the root: it is the controller's.

What is handed out: `tls.crt` is the leaf followed by the intermediate; `ca.crt` is the pinned root. Every
issuance is logged with its serial, names, validity, issuer, key and requester.

## Making the CA (by hand, with administrator credentials)

Create two asymmetric `SIGN_VERIFY` KMS keys (RSA 3072 or 4096) outside the cluster: the root key, which no
workload may use, and the issuing key. Then:

```console
go build -o kms-ca ./cmd/kms-ca
kms-ca root --key-id <root key ARN> --common-name "Example Root" --domains example.internal --out root.pem
kms-ca intermediate --root-key-id <root key ARN> --root-certificate root.pem \
  --key-id <issuing key ARN> --common-name "Example Issuing" --domains example.internal --out intermediate.pem
```

`kms-ca` never overwrites a file, checks the new intermediate exactly as the controller will, and prints
each certificate's details and SHA-256 fingerprint. `kms-ca show <file>` prints them again.

## Install

Give the controller's service account an AWS identity (e.g. EKS Pod Identity) allowed only `kms:Sign` and
`kms:GetPublicKey` on the issuing key, never on the root key. Recommended IAM conditions:
`kms:SigningAlgorithm` = `RSASSA_PKCS1_V1_5_SHA_256` and `kms:MessageType` = `DIGEST`.

```console
helm upgrade --install kms-issuer oci://ghcr.io/sunsofterp/charts/kms-issuer \
  --namespace kms-issuer-system --create-namespace \
  --set awsRegion=us-east-1 \
  --set-file rootCertificate=root.pem \
  --set "args.allowedIssuerNamespaces={my-ca-namespace}" \
  --set "args.allowedKeyIds={<issuing key ARN>}" \
  --set "args.permittedDNSDomains={example.internal}" \
  --set image.digest=sha256:...
```

`image.digest` is required: use the digest a release records. Release images and the chart are signed with
cosign (keyless); images also carry SBOM and provenance attestations.

The controller watches and has permissions in the allowed issuer namespaces only (a Role in each); it is
cluster-wide only for KMSKeys, when that controller is enabled. Keep the allowed namespaces to platform
administrators: whoever can create Certificates there and get them approved can obtain any name inside the
issuer's domains.

Metrics (authenticated; bind the `<release>-metrics-reader` ClusterRole to your scraper):
`kms_issuer_intermediate_not_after_timestamp_seconds` and `kms_issuer_root_not_after_timestamp_seconds`
(alert well before either expires), `kms_issuer_certificates_issued_total`,
`kms_issuer_requests_refused_total`.

## Create an issuer and a certificate

```yaml
apiVersion: cert-manager.skyscanner.net/v1alpha1
kind: KMSIssuer
metadata:
  name: internal-ca
  namespace: my-ca-namespace
spec:
  keyId: <issuing key ARN>   # immutable
  permittedDNSDomains: [example.internal]
  maxCertificateDuration: 2160h
  intermediateCertificate: |
    -----BEGIN CERTIFICATE-----
    ...the contents of intermediate.pem...
    -----END CERTIFICATE-----
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: svc
  namespace: my-ca-namespace
spec:
  secretName: svc-tls
  dnsNames: [svc.example.internal]
  issuerRef:
    name: internal-ca
    kind: KMSIssuer
    group: cert-manager.skyscanner.net
```

## Renewal

- **Intermediate:** make a new one with `kms-ca intermediate` and replace `intermediateCertificate`. The
  issuer raises an `IntermediateExpiringSoon` warning event from 90 days before expiry, and the expiry metric
  is there to alert on. Devices are unaffected: they trust the root.
- **Root:** a new root means distributing it to every device and pinning it in the controller (the chart
  restarts the controller when `rootCertificate` changes). Plan it well before the root's expiry.

A KMS error never makes an issuer stop issuing while its intermediate is still valid: the controller retries
with backoff and stays ready. There is no revocation (no CRL or OCSP): keep certificate lifetimes short.

## KMSKey (optional)

The KMSKey controller creates and deletes KMS keys from the cluster. It is off by default
(`--enable-kmskey-controller`); creating keys outside the cluster is recommended, and the root key must never
be created this way. When on, it tags each key it creates with the KMSKey's UID
(`kms-issuer.cert-manager.skyscanner.net/kmskey-uid`), and adopts or deletes only keys carrying that tag. A
key whose alias can't be created is scheduled for deletion again rather than left behind.

## API reference

The CRDs in `charts/kms-issuer/crds` document every field.

## Contributing

Kms-Issuer is built using the [Kubebuilder](https://book.kubebuilder.io/) framework. `make test` runs the unit
tests and the controller tests against a local API server (envtest); `make vulncheck` checks the built binary
for known vulnerabilities.

## Security

Check [SECURITY.md](SECURITY.md).
