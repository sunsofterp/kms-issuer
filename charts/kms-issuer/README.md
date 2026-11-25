# kms-issuer

![Version: 2.0.0](https://img.shields.io/badge/Version-2.0.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v5.3.0](https://img.shields.io/badge/AppVersion-v5.3.0-informational?style=flat-square)

A Helm chart to install kms-issuer

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` |  |
| args.allowedIssuerNamespaces | list | `[]` | Required. Namespaces a KMSIssuer may live in; KMSIssuers anywhere else sign nothing. Keep these namespaces to platform administrators. |
| args.allowedKeyIds | list | `[]` | Required. KMS key IDs or ARNs (never aliases) a KMSIssuer may sign with. |
| args.enableKMSKeyController | bool | `false` | Run the KMSKey controller, which creates and deletes KMS keys. Off: create keys outside the cluster and grant the controller only kms:Sign and kms:GetPublicKey on them. |
| args.healthProbeBindAddress | string | `":8081"` | The address the probe endpoint binds to |
| args.leaderElect | bool | `true` | Enable leader election for controller manager. |
| args.localAwsEndpoint | string | `""` | Test only: a local KMS endpoint, used with static test credentials. |
| args.metricsBindAddress | string | `":8443"` | The address the metrics endpoint binds to ("0" disables it). |
| args.metricsSecure | bool | `true` | Serve metrics over HTTPS to authenticated, authorized callers only. |
| awsRegion | string | `""` | Required. The AWS region of the KMS key. |
| certManagerApprovalRBAC.enable | bool | `false` | Grant cert-manager's service account approval rights over all KMSIssuers. |
| certManagerApprovalRBAC.namespace | string | `"cert-manager"` | The namespace where cert-manager service account is deployed |
| certManagerApprovalRBAC.serviceAccountName | string | `"cert-manager"` | The service account name that cert-manager is using |
| env | list | `[]` | Extra environment variables for the controller. |
| fullnameOverride | string | `""` |  |
| image.digest | string | `""` | Image digest (sha256:...). When set, the image is pulled by digest and the tag is ignored. Set it for anything that matters: tags can move. |
| image.pullPolicy | string | `"IfNotPresent"` |  |
| image.repository | string | `"ghcr.io/sunsofterp/kms-issuer"` |  |
| image.tag | string | `""` | Overrides the image tag whose default is the chart appVersion. |
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
| securityContext.allowPrivilegeEscalation | bool | `false` |  |
| securityContext.capabilities.drop[0] | string | `"ALL"` |  |
| securityContext.readOnlyRootFilesystem | bool | `true` |  |
| serviceAccount.annotations | object | `{}` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.name | string | `""` |  |
| tolerations | list | `[]` |  |

