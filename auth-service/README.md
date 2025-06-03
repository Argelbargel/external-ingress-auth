# auth-service

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.1.0](https://img.shields.io/badge/AppVersion-0.1.0-informational?style=flat-square)

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
| config.env.BRUTE_FORCE_EXPIRATION_SECONDS | int | `60` | window within which attempts get logged and for which further requests will be blocked  |
| config.env.BRUTE_FORCE_MAX_FAILURE_COUNT | int | `5` | number of failed authentication-attempts after which further requests are blocked |
| config.env.BRUTE_FORCE_PROTECTION_ENABLED | bool | `true` | enable/disable brute-force-protection when authenticating users |
| config.env.LDAP_BIND_DN | string | `"cn={username},{{ .Values.config.env.LDAP_SEARCH_BASE }}"` | the ldap bind-dn to used to authenticate users |
| config.env.LDAP_ENDPOINT | string | `"https://localhost:636"` | the ldap server used to authenticate and authorize users |
| config.env.LDAP_SEARCH_BASE | string | `"<search-base>"` | the ldap search-base used to search for users to determine their group membership |
| config.env.LDAP_SEARCH_FILTER | string | `"(sAMAccountName={username})"` | the ldap search-filter used to search for users to determine their group membership |
| config.env.LOG_FORMAT | string | `"JSON"` | log-format with which to log |
| config.env.LOG_LEVEL | string | `"INFO"` | log-level with which to log to the console |
| config.envFrom | list | `[]` | further configuration-sources (e.g. secrets for manager-dn and password) |
| deployment.annotations | object | `{}` | additional annotations specific to the deployment resource |
| deployment.initContainers | list | `[]` | initContainers for the deployment |
| deployment.labels | object | `{}` | additional labels specific to the deployment resource |
| deployment.replicas | int | `1` |  |
| deployment.resources.limits.memory | string | `"128Mi"` |  |
| deployment.resources.requests.cpu | string | `"50m"` |  |
| deployment.resources.requests.memory | string | `"128Mi"` |  |
| deployment.volumeMounts | list | `[]` | additional volume mounts for the external-ldap-auth-container |
| deployment.volumes | list | `[]` | additional volumes for the deployment |
| image.pullPolicy | string | `"IfNotPresent"` |  |
| image.pullSecrets | list | `[]` | image-pull-secrets |
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
