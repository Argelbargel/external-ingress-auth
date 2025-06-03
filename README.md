# External LDAP Auth Helm-Charts

[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/external-ldap-auth)](https://artifacthub.io/packages/search?repo=external-ldap-auth)

Helm-Charts for deployment of [External LDAP Auth](https://github.com/Argelbargel/external-ldap-auth) in your kubernetes cluster.

## Charts

### [External LDAP Auth](./charts/external-ldap-auth/)

Installs the External LDAP Auth service. To install the chart:

```shell
helm repo add external-ldap-auth https://argelbargel.github.io/external-ldap-auth/
helm install external-ldap-auth/external-ldap-auth
```

See [chart-details](./charts/external-ldap-auth/) for configuration.

## License

- Source code is licensed under MIT
