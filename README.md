[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/external-ldap-auth)](https://artifacthub.io/packages/search?repo=external-ldap-auth)
[![release](https://img.shields.io/github/v/release/argelbargel/external-ldap-auth)](https://github.com/argelbargel/external-ldap-auth/releases)
[![license](https://img.shields.io/badge/license-MIT-green)](https://github.com/argelbargel/external-ldap-auth/blob/master/LICENSE)

# External LDAP Authentication

External LDAP Authentication provides an external authentication-service for Kubernetes Ingress Controllers which allows to authenticate and authorize users via LDAP-Servers.

**External LDAP Authentication** works perfect with **NGINX ingress controller** via [External Authentication](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#external-authentication).

## Features

- Authentication and Authorization for applications.
- Authorization via LDAP groups, supports regex in groups list.
- Supports protocols `ldap://` and `ldaps://`.
- Supports configuration via headers or via environment variables.
- HTTP response headers with username and matched groups for the backend.
- Brute force protection.
- Log format in Plain-Text or JSON.

## Installation

The easiest way to install the External LDAP Authentication service in your Kubernetes cluster is to use the provided [Helm chart](./charts/external-ldap-auth/).

## Configuration

### Environment Variables

The service reads it's configuration from the following environment variables:

| Variable         | Required/Default-Value | Description                  |
|------------------|------------------------|------------------------------|
| LDAP_ENDPOINT    | required               | specifies the uri to the ldap-server (e.g. ldaps://example.com:636)            |
| LDAP_BIND_DN     | required               | specifies the ldap-query used to authenticate an user. Must contain the placeholder `{username}` which is replaced by the username (e.g. `cn={username},cn=Users,dn=example,dn=com`) |
| LDAP_SEARCH_BASE | required               | specifies the base-query used to search for users when determining their group membership (e.g. `cn=Users,dn=example,dn=com`) |
| LDAP_SEARCH_FILTER | `(sAMAccountName={username})` | specifies the filter used to query users when determing their group membership. Must contain the placeholder `{username}` which is replaced with the given username when authenticating |
| LDAP_MANAGER_DN | required | specifies the User-DN used to query the LDAP-server to determine group-membership (e.g. `cn=manager,dn=Users,dn=example,dn.com`) |
| LDAP_MANAGER_PASSWORD | required | specified the Password for the Manager-User given in LDAP_MANAGER_DN |
| BRUTE_FORCE_PROTECTION_ENABLED | `true` | enables/disables the brute-force-protection which prevents too many login-attempts |
| BRUTE_FORCE_PROTECTION_MAX_FAILURE_COUNT | `5` | specifies after how many failed login attempts the IP is blocked by the protection |
| BRUTE_FORCE_PROTECTION_EXPIRATION_SECONDS | `60` | specifies the time window within which failed login attempts are counted and for how long an IP gets blocked |
| TLS_CERT | optional | specifies the path to the certificate used for TLS/HTTPS. If no certificate is specified, the service communicates via unsecured HTTP |
| TLS_KEY | optional | specifies the key for the certificate specified in TLS_CERT  |
| GUNICORN_CMD_ARGS | optional | allows you to specify custom arguments for the [gunicorn-server](https://gunicorn.org/) used by the service |
| PAGE_FOOTER | optional | specifies the HTML in the footer of the error-pages rendered by the service. To disable the footer, set `PAGE_FOOTER=""` |

### Headers

The following options are either configured using environment variables or by configuring the ingress to pass them as HTTP-headers. If the environment variable is present it always take precedence and headers are ignored:

| Variable           | Header     | Default-Value       | Description                                  |
|--------------------|------------|---------------------|----------------------------------------------|
| AUTH_REALM         | Auth-Realm | LDAP Authentication | the Basic Auth Realm returned by the service |
| LDAP_ALLOWED_GROUPS| Ldap-Allowed-Groups |            | comma-separated list of groups the user must be member of to be allowed access. The given list is matched against the  CNs of the users ldap-groups (e.g. `groupA,groupB` matches `cn=groupA,cn=Users,dn=example,dn=com` and `cn=something,cn=groupB,dn=example,dn=com`) |
| LDAP_ALLOWED_USERS | Ldap-Allowed-Users |             | comma-separated lust of users the current user must be in to be allowed access |
| LDAP_CONDITIONAL_GROUPS | Ldap-Conditional-Groups | `or` | specifies whether the user must be in any group (`or`) or all groups (`and`) |
| LDAP_CONDITIONAL_USERS_GROUPS | Ldap-Conditional-User-Groups | `or` | specifies whether both the given user- and group-requirement must be met (`and`) or if access is granted when either the user or it's group matches (`or`) |

## Usage

After installing the service in your cluster you have to configure your Ingress-resource to use the service for external authentication. [Nginx Ingress Controllor provides a simple example for this setup](https://kubernetes.github.io/ingress-nginx/examples/auth/external-auth/).

The following assumes you're using ingress-nginx 0.9.0 or newer. For a detailed description of the annotations used see https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#external-authentication

### Authentication

For simple user-authentication without additional authorization restrictions to specific groups or users, you simple add the annotation `nginx.ingress.kubernetes.io/auth-url` to your ingress:

```yaml
---
kind: Ingress
metadata:
  name: external-auth-ingress
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/auth-url: <url to the service>
    # optional: add this if you want to pass the name of the authenticated user to the secured service
    nginx.ingress.kubernetes.io/auth-response-headers: x-user
spec:
  rules:
  - host: secured-service.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service: 
            name: secured-service
            port: 
              number: 80
```

### Authorization

If you want to restrict access to specific users or groups the configuration of the ingress is a bit more involved. Besides configuring the url of the auth-service you have to specify the restriction in a ConfigMap:

```yaml
---
kind: Ingress
metadata:
  name: external-auth-ingress
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/auth-url: <url to the service>
    nginx.ingress.kubernetes.io/auth-proxy-set-headers: default/auth-headers
    # optional: add this if you want to pass the name and groups of the authenticated user to the secured service
    nginx.ingress.kubernetes.io/auth-response-headers: x-user, x-groups
  spec:
  rules:
  - host: secured-service.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service: 
            name: secured-service
            port: 
              number: 80

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-headers
  namespace: default
data:
  # Configuration-Headers (see below)
  Ldap-Allowed-Groups: <comma-separated list groups>
```

Be aware that you have to reference the ConfigMap using `<namespace>/<name>` in `nginx.ingress.kubernetes.io/auth-proxy-set-headers` - otherwise the ConfigMap will be searched in the ingresses namespace.

### Passing user-information to the secured service

On successful authentication/authorization the service returns the username and the authorized groups within the HTTP-headers `X-User` and `X-Groups` which can be passed through the ingress using the annotation `nginx.ingress.kubernetes.io/auth-response-headers`.
