# KMS Issuer

[![Build Status](https://github.com/sunsofterp/kms-issuer/actions/workflows/test-build.yml/badge.svg?branch=main)](https://github.com/sunsofterp/kms-issuer/actions)
[![E2E Tests](https://github.com/sunsofterp/kms-issuer/actions/workflows/e2e.yaml/badge.svg?branch=main)](https://github.com/sunsofterp/kms-issuer/actions)
[![Helm Chart Tests](https://github.com/sunsofterp/kms-issuer/actions/workflows/helm.yml/badge.svg?branch=main)](https://github.com/sunsofterp/kms-issuer/actions)

KMS issuer is a [cert-manager](https://cert-manager.io/) external issuer that signs certificates with an
[AWS KMS](https://aws.amazon.com/kms/) asymmetric key, so the CA's private key never leaves KMS.

This is a hardened fork of [Skyscanner/kms-issuer](https://github.com/Skyscanner/kms-issuer). The issuer is
meant to be a private CA that devices trust, so it refuses anything a private CA must never do; see
[What it will sign](#what-it-will-sign).

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
  no certificate outlives the CA certificate.
- **Approved requests only.** A CertificateRequest must be approved; denied requests are failed.
  Approval should come from a policy approver such as cert-manager
  [approver-policy](https://cert-manager.io/docs/policy/approval/approver-policy/), not cert-manager's
  built-in approver (which approves everything; the chart no longer grants it rights over KMSIssuers).
- **Only from allowed issuers.** The controller's required `--allowed-issuer-namespaces` and
  `--allowed-key-ids` flags name the namespaces a KMSIssuer may live in and the KMS keys it may use; any
  other KMSIssuer signs nothing. Keys are named by ID or ARN, never by alias.

The CA certificate itself is a root with **path length 0** (it can sign leaves only) and **critical name
constraints** limiting every name under it to `permittedDNSDomains` (no IP addresses at all), so clients
that enforce name constraints reject any certificate under it for another name, however it was issued.
Verify that the clients you care about enforce constraints on trust anchors.

Every issuance is logged with its serial, names, validity, issuer, key and requester.

## Install

Create an asymmetric `SIGN_VERIFY` KMS key (RSA 3072 or 4096 recommended) outside the cluster, and give
the controller's service account an AWS identity (e.g. EKS Pod Identity) allowed only `kms:Sign` and
`kms:GetPublicKey` on that key. Recommended IAM conditions: `kms:SigningAlgorithm` =
`RSASSA_PKCS1_V1_5_SHA_256` and `kms:MessageType` = `DIGEST`.

```console
helm upgrade --install kms-issuer oci://ghcr.io/sunsofterp/charts/kms-issuer \
  --namespace kms-issuer-system --create-namespace \
  --set awsRegion=us-east-1 \
  --set "args.allowedIssuerNamespaces={my-ca-namespace}" \
  --set "args.allowedKeyIds={arn:aws:kms:us-east-1:111122223333:key/...}" \
  --set image.digest=sha256:...
```

Pin `image.digest` to the digest a release records; release images are signed with cosign (keyless) and
carry SBOM and provenance attestations.

Keep the allowed issuer namespaces to platform administrators: whoever can create a KMSIssuer there, or run
a pod as the controller's service account, can use the CA.

## Create an issuer and a certificate

```yaml
apiVersion: cert-manager.skyscanner.net/v1alpha1
kind: KMSIssuer
metadata:
  name: internal-ca
  namespace: my-ca-namespace
spec:
  keyId: arn:aws:kms:us-east-1:111122223333:key/... # immutable
  commonName: Internal Root CA                       # immutable
  permittedDNSDomains:
    - example.internal
  duration: 87600h          # CA certificate validity, default 10 years
  renewBefore: 8760h        # default 1 year
  maxCertificateDuration: 2160h
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

Inspect the CA certificate (the copy devices should trust):

```bash
kubectl get kmsissuer internal-ca -n my-ca-namespace -o json | jq -r .status.certificate | base64 -d | openssl x509 -noout -text
```

### The CA certificate's lifecycle

The controller makes the CA certificate once and keeps it. It makes a new one (same key, same subject,
new serial and validity) only when renewal is due (`renewBefore` before expiry) or when
`permittedDNSDomains` or `duration` change. Certificates chain to any of them, since they share the key and
subject, so a device holding an older copy keeps working until **that copy** expires: plan distribution
of the CA certificate around the device copy's expiry. `keyId` and `commonName` cannot be changed; a
different key or name is a different CA.

There is no revocation (no CRL or OCSP): keep certificate lifetimes short.

## KMSKey (optional)

The KMSKey controller creates and deletes KMS keys from the cluster. It is off by default
(`--enable-kmskey-controller`); creating keys outside the cluster is recommended. When on, it never adopts
an alias that points at a key it did not create, and deletes only the key it recorded creating.

## API reference

The CRDs in `charts/kms-issuer/crds` document every field.

## Contributing

Kms-Issuer is built using the [Kubebuilder](https://book.kubebuilder.io/) framework. `make test` runs the
unit tests and the controller tests against a local API server (envtest).

## Security

Check [SECURITY.md](SECURITY.md).
