# kms-issuer

![Version: 2.0.0](https://img.shields.io/badge/Version-2.0.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v5.3.0](https://img.shields.io/badge/AppVersion-v5.3.0-informational?style=flat-square)

A Helm chart to install kms-issuer

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` |  |
| args.allowWildcards | bool | `false` | Let KMSIssuers allow wildcard names. |
| args.allowedIssuerNamespaces | list | `[]` | Required. Namespaces a KMSIssuer may live in; KMSIssuers anywhere else sign nothing. Keep these namespaces to platform administrators. |
| args.allowedKeyIds | list | `[]` | Required. KMS key IDs or ARNs (never aliases) a KMSIssuer may sign with. |
| args.enableKMSKeyController | bool | `false` | Run the KMSKey controller, which creates and deletes KMS keys. Off: create keys outside the cluster and grant the controller only kms:Sign and kms:GetPublicKey on them. |
| args.healthProbeBindAddress | string | `":8081"` | The address the probe endpoint binds to |
| args.leaderElect | bool | `true` | Enable leader election for controller manager. |
| args.localAwsEndpoint | string | `""` | Test only: a local KMS endpoint, used with static test credentials. |
| args.maxCertificateDuration | string | `"720h"` | The longest issued validity any KMSIssuer may allow. Short: cert-manager renews automatically. Less than half maxIntermediateDuration. |
| args.maxIntermediateDuration | string | `"4392h"` | The longest an intermediate may be valid (at most 4392h, 183 days, which kms-ca also enforces). Renewing one is a manual step with the root key. |
| args.metricsBindAddress | string | `":8443"` | The address the metrics endpoint binds to ("0" disables it). |
| args.metricsSecure | bool | `true` | Serve metrics over HTTPS to authenticated, authorized callers only. |
| args.permittedDNSDomains | list | `[]` | Required. The DNS domains (two labels or more) no KMSIssuer may go beyond: every issuer's permittedDNSDomains must be inside them. |
| awsRegion | string | `""` | Required. The AWS region of the KMS key. |
| certManagerApprovalRBAC.enable | bool | `false` | Grant cert-manager's service account approval rights over the KMSIssuers listed in `issuers`. |
| certManagerApprovalRBAC.issuers | list | `[]` | Required when enabled: the KMSIssuers cert-manager may approve requests for, as namespace.name (never all of them). |
| certManagerApprovalRBAC.namespace | string | `"cert-manager"` | The namespace where cert-manager service account is deployed |
| certManagerApprovalRBAC.serviceAccountName | string | `"cert-manager"` | The service account name that cert-manager is using |
| env | list | `[]` | Extra environment variables for the controller. |
| fullnameOverride | string | `""` |  |
| image.allowTag | bool | `false` | Test only: pull by tag when no digest is set (tags can move). |
| image.digest | string | `""` | Required: the image digest (sha256:...) a release records. Releases are signed with cosign; verify the signature at admission. |
| image.pullPolicy | string | `"IfNotPresent"` |  |
| image.repository | string | `"ghcr.io/sunsofterp/kms-issuer"` |  |
| image.tag | string | `""` | The tag used with allowTag (default: the chart appVersion). |
| imagePullSecrets | list | `[]` |  |
| nameOverride | string | `""` |  |
| nodeSelector | object | `{}` |  |
| podAnnotations | object | `{}` |  |
| podDisruptionBudget.enable | bool | `false` |  |
| podDisruptionBudget.maxUnavailable | string | `""` |  |
| podDisruptionBudget.minAvailable | int | `1` |  |
| podSecurityContext.runAsNonRoot | bool | `true` |  |
| podSecurityContext.seccompProfile.type | string | `"RuntimeDefault"` |  |
| replicaCount | int | `1` |  |
| resources.limits.cpu | string | `"200m"` |  |
| resources.limits.memory | string | `"128Mi"` |  |
| resources.requests.cpu | string | `"10m"` |  |
| resources.requests.memory | string | `"64Mi"` |  |
| rootCertificate | string | `""` | Required. The root CA certificate (PEM), made with `kms-ca root` on a KMS key the controller cannot use. Every KMSIssuer's intermediate must chain to it, and it is the `ca.crt` handed out with each certificate: what clients trust. While replacing a root, list both (old and new, concatenated); intermediates may chain to either, and each certificate's `ca.crt` is the root its intermediate chains to. |
| securityContext.allowPrivilegeEscalation | bool | `false` |  |
| securityContext.capabilities.drop[0] | string | `"ALL"` |  |
| securityContext.readOnlyRootFilesystem | bool | `true` |  |
| serviceAccount.annotations | object | `{}` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.name | string | `""` |  |
| tolerations | list | `[]` |  |

