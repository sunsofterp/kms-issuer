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
  path length 0, server auth only, critically name-constrained inside the root's, at most (and by default)
  183 days. A KMSIssuer names it.
- **Leaves** — signed by the controller with the issuing key, under the intermediate: 30 days by default,
  renewed automatically by cert-manager.

Every client enforces name constraints on an intermediate, so nothing the issuing key signs is trusted for a
name outside the intermediate's domains, whatever the client does with constraints on roots. Whoever can use
the issuing key (the controller, or its IAM role) can sign only what the intermediate allows (TLS server
certificates, inside its domains), and only until it expires; making another intermediate takes the root
key, which only administrators hold.

## What it will sign

Each issued certificate is built from fields the issuer has checked, never from the request's raw
extensions:

- **Server certificates only, never a CA.** `isCA` requests are refused. Usages may be only
  `digital signature`, `key encipherment` and `server auth`; the certificate gets server auth, and key
  encipherment only for RSA keys.
- **DNS names inside the issuer's `permittedDNSDomains` only.** IP addresses, URIs, email addresses and
  other name types are refused, as are wildcards unless `allowWildcards` is set. A common name must be one
  of the DNS names and at most 64 characters; the subject is the common name alone.
- **Bounded lifetime.** A request longer than `maxCertificateDuration` (default 30 days) is refused, and
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
  KMSIssuer can narrow its policy, never widen it past them. Any other KMSIssuer signs nothing. Permitted
  domains must be lower-case names of two labels or more; `--max-intermediate-duration` must be above zero
  and at most 183 days, and `--max-certificate-duration` less than half of it (so a fresh full-length
  intermediate doesn't start inside its expiry-warning window; a shorter one may). Issuer domains must be
  lower-case names of two labels or more too: a wildcard or leading dot is refused, not left matching
  nothing.
- **Only under a verified intermediate.** At signing time, the issuer's intermediate must be for its KMS
  key, issued and signed by the pinned root (full path validation), path length 0, critically
  name-constrained inside the operator's domains and covering the issuer's, and valid now. A KMSIssuer
  cannot change the root: it is the controller's.

What is handed out: `tls.crt` is the leaf followed by the intermediate that signed it; `ca.crt` is the
pinned root that intermediate chains to. Every issuance is logged with its serial, names, validity, issuer,
key and requester.

A certificate signed but not yet recorded (a failed status write) is kept, with its chain, and recorded on
the next attempt rather than signed again, unless the issuer as it is by then would not sign it (under an
hour left, a name outside its domains, longer than its maximum, a wildcard it no longer allows) or its chain
is no longer current (the issuer now uses another key, the intermediate that signed it has expired, or its
root is no longer a pinned root valid now): then it is dropped and a new one signed. That holds within one
controller process: if the controller
restarts or loses leadership between signing and recording, the request is signed a second time. Both
certificates are in the issuance log; only the recorded one is handed out.

## Making the CA (by hand, with administrator credentials)

Create two asymmetric `SIGN_VERIFY` KMS keys (RSA 3072 or 4096) outside the cluster: the root key, which no
workload may use, and the issuing key. Then:

Use the `kms-ca` binary attached to the release you deploy, after verifying that the release workflow signed
it at that release's tag and commit (a signature from any other workflow, branch or commit is refused):

```console
TAG=v5.3.0                                   # the release you deploy
COMMIT=<the full commit hash the tag names>  # e.g. from `git rev-list -n 1 "${TAG}"` in a checkout
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/sunsofterp/kms-issuer/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-github-workflow-sha "${COMMIT}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
kms-ca root --key-id <root key ARN> --common-name "Example Root" --domains example.internal --out root.pem
kms-ca intermediate --root-key-id <root key ARN> --root-certificate root.pem \
  --key-id <issuing key ARN> --common-name "Example Issuing" --domains example.internal --out intermediate.pem
```

`kms-ca` refuses aliases (keys are named by ID or ARN), domains that aren't lower-case names of two labels or
more, an intermediate longer than 183 days, longer-lived than the root, wider than the root, named like the
root, or on the root key. It creates the output file before asking KMS to sign anything and never
overwrites one, checks a new intermediate exactly as the controller will, and prints what it made: subject,
validity, path length, usages, every constraint, the public key and certificate SHA-256 fingerprints, which
keys signed, and the AWS identity and KMS endpoint it used. The root key is only ever used through AWS's own
endpoints: `kms-ca` ignores proxy settings (`HTTPS_PROXY` and the like) for every AWS call it makes,
credential fetches included (a `credential_process` program is its own), and refuses to run with any `AWS_ENDPOINT_URL*` variable, an `endpoint_url` or `services`
section in the AWS profile, a custom CA bundle (`AWS_CA_BUNDLE`, `ca_bundle`), or `SSL_CERT_FILE` /
`SSL_CERT_DIR`. Where credentials come from (a profile, `credential_process`, the instance or container
metadata endpoint) is left to your AWS configuration; the identity they give is printed. Run it from a
clean environment on a machine you trust: it can't detect a CA added to the system trust store. Keep that
output as the ceremony record. `kms-ca show <file>` prints a certificate's details again.

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
cosign (keyless) by the release workflow; images also carry SBOM and provenance attestations. Verify (or
enforce at admission) that exact signer identity, never a pattern over the repository:

```console
cosign verify ghcr.io/sunsofterp/kms-issuer@sha256:... \
  --certificate-identity "https://github.com/sunsofterp/kms-issuer/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-github-workflow-sha "${COMMIT}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The controller watches and has permissions in the allowed issuer namespaces only (a Role in each); it is
cluster-wide only for KMSKeys, when that controller is enabled. Keep the allowed namespaces to platform
administrators: whoever can create Certificates there and get them approved can obtain any name inside the
issuer's domains.

Metrics (authenticated; bind the `<release>-metrics-reader` ClusterRole to your scraper):
`kms_issuer_intermediate_not_after_timestamp_seconds` and `kms_issuer_root_not_after_timestamp_seconds`
(alert well before either expires), `kms_issuer_leaves_truncated`, `kms_issuer_certificates_issued_total`,
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
  maxCertificateDuration: 720h
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

**Intermediate (by hand, every 183 days at most).** Make a new one with `kms-ca intermediate` and replace the
issuer's `intermediateCertificate`; devices are unaffected (they trust the root). Leaves are cut short to end
with the intermediate in its last `maxCertificateDuration`, so renew before then:

- the issuer raises `IntermediateExpiringSoon` warning events from twice `maxCertificateDuration` (at least
  30 days) before expiry;
- `kms_issuer_intermediate_not_after_timestamp_seconds` is the expiry to alert on, and
  `kms_issuer_leaves_truncated` turns 1 once leaves are being cut short (an overdue renewal);
- under an hour of intermediate left, requests wait (`Ready=False`, reason `Pending`, saying the intermediate
  must be renewed) rather than get a uselessly short certificate.

**Root replacement (planned, no hard cutover).**

1. Make the new root on a new KMS key (`kms-ca root`), and distribute it to every device that trusts the old
   one.
2. Pin both: set `rootCertificate` to the old and new roots concatenated. The controller accepts
   intermediates from either; each certificate's `ca.crt` is the root its intermediate chains to.
3. Make a new intermediate under the new root and replace each issuer's `intermediateCertificate`.
4. Once every certificate has renewed under the new root, remove the old root from `rootCertificate` and
   from devices, and schedule the old root key's deletion.

Intermediates may chain only to the pinned roots valid at the moment of signing: an expired root is never
used (the controller logs `PINNED ROOT EXPIRED` at startup: remove it), and a root not valid yet is used
from its notBefore, without a restart. The controller refuses to start only when no pinned root is valid
now. The key of every pinned root, valid or not, is refused as an issuing key. A root that is not a root of
this CA at all, or wider than `--permitted-dns-domains`, is always fatal.

`rootCertificate` lives in an immutable ConfigMap named by its content, so every change is a rollout.

**Revocation.** There is no CRL or OCSP. What contains a compromise is the lifetimes:

- A leaked leaf key: it stops working when the leaf expires (at most `maxCertificateDuration`). Replace the
  certificate (delete its Secret; cert-manager issues a new one) and fix the leak.
- Misuse of the issuing key (anything that could call `kms:Sign` on it): within the intermediate's
  constraints, certificates it signed can last until the intermediate expires (at most 183 days), and a
  self-issued sub-CA under the intermediate is accepted by some clients (OpenSSL) until then. Cut access
  (IAM), rotate the issuing key: new KMS key, new intermediate, new `keyId` (a new KMSIssuer), and expect
  the old intermediate's window to run out. If that window is unacceptable, replace the root (above).
- Root key compromise: replace the root, removing the old one from every device first.

**Watch the issuing key.** Alert (CloudTrail) on `kms:Sign` calls for the issuing key by any identity but the
controller's, and reconcile the controller's calls against its `issued certificate` log lines. Treat the
controller's namespace as CA-critical: nobody else creates pods or execs there, since its service account
can use the key.

A KMS error never makes an issuer stop issuing while its intermediate is still valid: the controller retries
with backoff and stays ready.

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
