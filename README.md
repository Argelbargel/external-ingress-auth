[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/external-ldap-auth)](https://artifacthub.io/packages/search?repo=external-ldap-auth)
[![release](https://img.shields.io/github/v/release/argelbargel/external-ldap-auth)](https://github.com/argelbargel/external-ldap-auth/releases)
[![license](https://img.shields.io/badge/license-MIT-green)](https://github.com/argelbargel/external-ldap-auth/blob/master/LICENSE)

# External LDAP Authentication

External LDAP Authentication provides an external authentication-service for Kubernetes Ingress Controllers which allows to authenticate and authorize users via LDAP-Servers.

**External LDAP Authentication** works perfect with **NGINX ingress controller** via [External Authentication](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#external-authentication).

## Features

- Authentication and Authorization for kubernetes ingresses.
- Fine grained access control via flexible [authorization-rules](#authorization-rules)
- Centralized rule-management and/or ingress-specific configuration of rules
- Supports protocols `ldap://` and `ldaps://`.
- HTTP response headers with username and matched groups for the backend.
- Brute force protection.
- Log format in Plain-Text or JSON.

## Installation

The easiest way to install the External LDAP Authentication service in your Kubernetes cluster is to use the provided [Helm chart](./charts/auth-service/).

## Configuration

Except for authorization-rules, configuration is mainly done through environment-variables.

### Authentication Backend

| Variable         | Required/Default-Value | Description                  |
|------------------|------------------------|------------------------------|
| LDAP_ENDPOINT    | required               | specifies the uri to the ldap-server (e.g. ldaps://example.com:636)            |
| LDAP_BIND_DN     | required               | specifies the ldap-query used to authenticate an user. Must contain the placeholder `{username}` which is replaced by the username (e.g. `cn={username},cn=Users,dn=example,dn=com`) |
| LDAP_SEARCH_BASE | required               | specifies the base-query used to search for users when determining their group membership (e.g. `cn=Users,dn=example,dn=com`) |
| LDAP_SEARCH_FILTER | `(sAMAccountName={username})` | specifies the filter used to query users when determing their group membership. Must contain the placeholder `{username}` which is replaced with the given username when authenticating |
| LDAP_MANAGER_DN | required | specifies the User-DN used to query the LDAP-server to determine group-membership (e.g. `cn=manager,dn=Users,dn=example,dn.com`) |
| LDAP_MANAGER_PASSWORD | required | specified the Password for the Manager-User given in LDAP_MANAGER_DN |

### Authorization

| Variable         | Required/Default-Value | Description                          |
|--------------------------|------------------------|------------------------------|
| AUTHORIZATION_RULES_PATH | optional       | path to a file containing [authorization rules](#authorization-rules); if none is supplied the [default authorization-rule](#default-authorization-rule) is used unless additional rules are supplied by [ingress-configuration](#ingress-configuration-of-authorization-rules) |
| AUTHORIZATION_INGRESS_RULES | `disabled`  | whether [authorization](#authorization-rules) rules may be supplied by headers sent via headers through [ingress-configuration](#ingress-configuration-of-authorization-rules). When set to `disabled`, rules sent by the ingress are completely ignored. To allow an ingress to further restrict the rules provided the authorization file, set the value to `append`. To allow ingresses to override the default authorization file, set the value to `override`. |

### Brute-Force-Protection

| Variable         | Required/Default-Value | Description                  |
|------------------|------------------------|------------------------------|
| BRUTE_FORCE_PROTECTION_ENABLED | `true` | enables/disables the brute-force-protection which prevents too many login-attempts |
| BRUTE_FORCE_PROTECTION_MAX_FAILURE_COUNT | `5` | specifies after how many failed login attempts the IP is blocked by the protection |
| BRUTE_FORCE_PROTECTION_EXPIRATION_SECONDS | `60` | specifies the time window within which failed login attempts are counted and for how long an IP gets blocked |

### HTTPS/TLS

| Variable         | Required/Default-Value | Description                  |
|------------------|------------------------|------------------------------|
| TLS_CERT | optional | specifies the path to the certificate used for TLS/HTTPS. If no certificate is specified, the service communicates via unsecured HTTP |
| TLS_KEY | optional | specifies the key for the certificate specified in TLS_CERT  |

### Miscellaneous

| Variable               | Required/Default-Value | Description                  |
|------------------------|------------------------|------------------------------|
| AUTH_CACHE_TTL_SECONDS | `15` | specifies how long the authentication of users and selection of authorization-rules is cached within the service (see [below](#caching-authentication-authorization-rules-and-responses-from-the-authentication-service)) |
| GUNICORN_CMD_ARGS | optional | allows you to specify custom arguments for the [gunicorn-server](https://gunicorn.org/) used by the service |
| LOG_LEVEL | `INFO` | specifies the log-level. Valid values are `ERROR`, `WARN`, `INFO`, `DEBUG` and `TRACE`. |
| LOG_FORMAT | `JSON` | specifies the log-format |
| PAGE_FOOTER | optional | specifies the HTML in the footer of the error-pages rendered by the service. To disable the footer, set `PAGE_FOOTER=""` |

### Authorization Rules

The authentication backend is solely used to authenticate a user's credentials and to provide information about the user's group-membership. All further authorization-restrictions (or lack thereof) are configured authorization rules provided by the file specified in `AUTHORIZATION_RULES_PATH` or in the [ingress-configuration](#ingress-configuration-of-authorization-rules).

#### Authorization Rule Format

Authorization rules are declared in the format `<hosts>:<ip-ranges>:<methods>:<paths>:<users>:<groups>:<groups-operator>:<users-groups-operator>`. The parts have the following meaning:

| Rule element   | Default-Value | Description |
|----------------|---------------|-------------|
| `<hosts>`      | `**`          | comma-separated list of ingress-hosts the rule applies to. Use `*` to match subdomains, e.g. `*.example.com` matches `sub.example.com` (but not example.com itself). The default value `**` applies to all ingress-hosts |
| `<ip-ranges>`  | `**`          | comma-separated list of ip-ranges. For the rule to apply, the remote-ip from which the request is made must be within the given ranges. The default value `**` applies to any remote-ip |
| `<methods>`    | `**`          | comma-separated list of http-methods. The rule only applies if a request is made with the given methods. The default-value `**` applies to any method |
| `<paths>`      | `**`          | comma-separated list of requested paths the rule applies to. The pattern is evaluated using [PurePath#full_match()](https://docs.python.org/3/library/pathlib.html#pathlib.PurePath.full_match), so `/public/**` matches any path below `/public/` and `/downloads/*` matches for any file below the path `/downloads/`. The defaul-value `**` matches any path |
| `<users>`      | `**`          | comma-separated list of usernames. To be authorized, an authenticated user must be in this list and/or one of the groups specified (see `<users-groups-operator>`). To allow public/unauthenticated-access to a resource, use the special value `<public>`. If the list contains `<public>`, any further settings concerning group-membership etc. are ignored. The default-value `**` allows access for all authenticated users |
| `<groups>`     | `**`          | comma-separated list of groups. To be authorized, an authenticated user must be member of one or all of the specified groups - see `<groups-operator>` - and possibly in the list of users (see `<users-groups-operator>`). The default-value `**` allows access for all authenticated users |
| `<groups-operator>`| `OR`      | specifies whether an authenticated user must be member of all groups specified in `<groups>` (`AND`) or any of them (`OR`) |
| `<users-groups-operator>` | `AND` | specifies wheter an authenicated user match the `<users>` and `<groups>` part of the rule (`AND`) or only one of them (`OR`) |

Note that if any of the list-elements above contains the wildcard `**` any other element in the list is ignored (so `**,value` is equivalent to `**`).

#### Examples

##### Allow public, unauthenticated access

The rule `**:**:**:/public/**:<public>` grants public access to anything below `/public/` on any host.

##### Restrict access to users in some groups

The rule `**:**:**:**:**:group1,group2` restricts access to any resource to authenticated users who are member of `group1` *or* `group2`

The rule `**:**:**:**:**:group1,group2:AND` restricts access to any resource ot authenticated users who are member of `group1` *and* `group2`

##### Restrict access to specific users

The rule `**:**:POST,PUT,DELETE:/admin/**:admin,operator` restricts access for modifying requests below `/admin/` to the users `admin` or `operator`

##### Combine users and groups

The rule `**:**:PUT:/admin/**:admin,operator:editors` restricts access for `PUT`-requests below `/admin/` to either `admin` or `operator` *or* users in the group `editors`

The rule `**:**:DELETE:/admin/**:admin,operator:cleaners:OR:AND` allows access for `DELETE`-requests below `/admin/` only to users `admin` or `operator` if the are also in the group `cleaners`

##### Host-specific rules

The rule `example.com,*.example.com:172.100.0.1/24:**:**:<public>` allows public access to `example.com` and all direct subdomains from within the range `172.100.0.1 - 172.100.0.254`

The rule `example.com:**:**:**:**:Testers,Reviewers` restricts requests to `example.com` to users in either group `Testers` or `Reviewers`

#### Default Authorization Rule

The default authorization rule is always `**:**:**:**:**:**:OR:AND` - so unless other rules are supplied, all (and only) successfully authenticated users are authorized.

#### Authorization File Format

The authorization file may contain multiple rules separated by any ([unescaped](#escaping-of-separator-characters)) whitespace-character.

Thus you may either specify multiple rules on one line:

`**:**:**:/public:<public> **:**:**:/admin/**:admin`

Or one rule per line:

```plain
**:**:**:/public:<public>
**:**:**:/admin/**:admin
```

#### Escaping of separator characters

Any of the special separator characters used in the rules definition (`:`, `,` and whitespace) can be escaped using `\<character`, e.g. `User\ containing a \:\ colon`.

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
    nginx.ingress.kubernetes.io/auth-url: <url to the service>/ # MUST end with /
    # recommended: cache responses of the authentication-service (see below for details)
    nginx.ingress.kubernetes.io/auth-cache-key: $http_authorization
    nginx.ingress.kubernetes.io/auth-cache-duration: 200 401 403 1m
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

### Ingress Configuration of Authorization Rules

Depending on the [auth-service's configuration](#authorization) you can pass additional [authorization rules](#authorization-rules) from the ingress or override those provided by in the config-file of the service.

To provide additional rules, you have to specify them in a ConfigMap:

```yaml
---
kind: Ingress
metadata:
  name: external-auth-ingress
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/auth-url: <url to the service>/ # MUST end with / 
    nginx.ingress.kubernetes.io/auth-proxy-set-headers: default/auth-headers
    # recommended: cache responses of the authentication-service (see below for details)
    nginx.ingress.kubernetes.io/auth-cache-key: $http_authorization
    nginx.ingress.kubernetes.io/auth-cache-duration: 200 401 403 1m
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
data:"
  X-Authorization-Rules: "<rule1> <rule2>"
```

Be aware that you have to reference the ConfigMap using `<namespace>/<name>` in `nginx.ingress.kubernetes.io/auth-proxy-set-headers` - otherwise the ConfigMap will be searched in the ingresses namespace.

### Caching authentication, authorization rules and responses from the authentication service

The service itself can cache the *authentication* of credentials to prevent overloading the ldap-server with bind-requests and the selection of [authorization-rules](#authorization-rules); by default this cache has a TTL of 15 seconds. The cache stores whether the given credentials in the authorization-header are valid and the group-memberships of the authenticated user. Selection of the authorization rules is cached based on ingress-host, remote-ip, http-method and requested path. While the selected rule is cached, actual *authorization* is always re-evaluated for every request.

#### Caching Authorization Responses in the Ingress

To further improve performance you can configure the nginx ingress-controller to cache the responses of the authentication service so that no requests outside the ingress are required. In most use-cases enabling response-caching is recommended. To enable response-caching in the ingress, add the following annotations:

```yaml
nginx.ingress.kubernetes.io/auth-cache-key: $http_authorization # uses the value of the authorization-header as cache-key
nginx.ingress.kubernetes.io/auth-cache-duration: 200 401 403 1m # caches all responses for one minute
```

### Passing user-information to the secured service

On successful authentication/authorization the service returns the username and the authorized groups within the HTTP-headers `X-User` and `X-Groups` which can be passed through the ingress using the annotation `nginx.ingress.kubernetes.io/auth-response-headers`.
