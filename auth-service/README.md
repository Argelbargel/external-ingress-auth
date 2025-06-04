# external-ldap-auth-service

![Version: 0.1.2](https://img.shields.io/badge/Version-0.1.2-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.1.1](https://img.shields.io/badge/AppVersion-0.1.1-informational?style=flat-square)

Installs an instance of the External LDAP Authentication Service that provides LDAP authentication for Kubernetes Ingress Controllers.
It works perfect with NGINX ingress controller via [External Authentication](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#external-authentication).

**Homepage:** <https://argelbargel.github.io/external-ldap-auth/>

## Source Code

* <https://github.com/Argelbargel/external-ldap-auth/>

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| commonAnnotations | object | `{}` | common annotations for all resources deployed by this chart |
| commonLabels | object | `{}` | common labels for all resources deployed by this chart |
| config.env | object | `{}` | environment-variables for configuration of the service; can be templated e.g to use helm-values    see https://github.com/Argelbargel/external-ldap-auth#environment-variables for allowed keys and values |
| config.envFrom | list | `[]` | further configuration-sources (e.g. secrets for manager-dn and password); can be templated e.g to use helm-values |
| deployment.annotations | object | `{}` | additional annotations specific to the deployment resource |
| deployment.initContainers | list | `[]` | initContainers for the deployment; can be templated e.g to use helm-values |
| deployment.labels | object | `{}` | additional labels specific to the deployment resource |
| deployment.replicas | int | `1` |  |
| deployment.resources.limits.memory | string | `"128Mi"` |  |
| deployment.resources.requests.cpu | string | `"50m"` |  |
| deployment.resources.requests.memory | string | `"128Mi"` |  |
| deployment.volumeMounts | list | `[]` | additional volume mounts for the external-ldap-auth-container; can be templated e.g to use helm-values |
| deployment.volumes | list | `[]` | additional volumes for the deployment; can be templated e.g to use helm-values |
| image.pullPolicy | string | `"IfNotPresent"` |  |
| image.pullSecrets | list | `[]` | image-pull-secrets; can be templated e.g to use helm-values |
| image.repo | string | `"ghcr.io/argelbargel/external-ldap-auth"` | overrides the image-repo for the deployed container-image  |
| image.tag | string | .Chart.AppVersion | overrides the image-tag for the deployed container-image  |
| ingress.annotations | object | `{}` | additional annotations specific to the ingress resource |
| ingress.enabled | bool | `false` |  |
| ingress.host | string | `""` |  |
| ingress.labels | object | `{}` | additional labels specific to the ingress resource |
| ingress.tls.enabled | bool | `false` |  |
| ingress.tls.secretName | string | `""` |  |
| service.annotations | object | `{}` | additional annotations specific to the service resource |
| service.labels | object | `{}` | additional labels specific to the service resource |
| service.type | string | `"ClusterIP"` |  |
| serviceMonitor.annotations | object | `{}` | additional annotations specific to the service-monitor resource |
| serviceMonitor.enabled | bool | `false` |  |
| serviceMonitor.labels | object | `{}` | additional labels specific to the service-monitor resource |

## License
- Source code is licensed under MIT
