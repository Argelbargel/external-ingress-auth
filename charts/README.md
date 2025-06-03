# External LDAP Auth Helm-Charts

[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/external-ldap-auth)](https://artifacthub.io/packages/search?repo=external-ldap-auth)

Helm-Charts for deployment of [External LDAP Auth](https://github.com/Argelbargel/external-ldap-auth) in your kubernetes cluster.

## Charts

### [External LDAP Auth Service](./auth-service/)

Installs the External LDAP Auth service. To install the chart:

```shell
helm repo add external-ldap-auth https://argelbargel.github.io/external-ldap-auth/
helm install external-ldap-auth/auth-service
```

See [chart-details](./auth-service/) for configuration details.

## License

- Source code is licensed under MIT
