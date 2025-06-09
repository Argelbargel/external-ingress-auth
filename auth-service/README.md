# external-ldap-auth-service

![Version: 0.2.1](https://img.shields.io/badge/Version-0.2.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.2.1](https://img.shields.io/badge/AppVersion-0.2.1-informational?style=flat-square)

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
| config.rules | list | `[]` | authorization rules (see https://github.com/Argelbargel/external-ldap-auth/tree/main/charts/auth-service#authorization-rules) |
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

## Authorization Rules

Configuring [authorization rules](https://github.com/Argelbargel/external-ldap-auth#authorization-rules) for the service is much more readable when using this chart.
Rules are configured below the key `.config.rules`:

```yaml
config:
  rules:
  - hosts: [] # list of hosts for which the rule applies
    ranges: [] # list of ip-ranges for which the rule applies, e.g. 192.168.0.1/16
    methods: [] # list of methods for which the rule applies, e.g. GET
    paths: [] # list of paths for which the rule applies, e.g. GET
    public: false # whether access to the resource specified by the properties above is public (true) or restricted (false)
    # the properties below are ignored if public: true
    users: [] # list of users allowed access to the resource specified by the properties above
    groups: [] # list of groups allowed access to the resource specified by the properties above
    operators:
      groups: <AND or OR> # default: OR
      users-and-groups: <AND or OR> # default AND
```

## License
- Source code is licensed under MIT
