# External Ingress Authentication Helm-Charts

[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/external-ingress-auth)](https://artifacthub.io/packages/search?repo=external-ingress-auth)

Helm-Charts for deployment of [External Ingress Authentication](https://github.com/Argelbargel/external-ingress-auth) in your kubernetes cluster.

## Charts

### [External Ingress Authentication Service](./auth-service/)

Installs the External LDAP Auth service. To install the chart:

```shell
helm repo add external-ingress-auth https://argelbargel.github.io/external-ingress-auth/
helm install external-ingress-auth/auth-service
```

See [chart-details](./auth-service/) for configuration details.

## License

- Source code is licensed under [MIT-License](https://github.com/Argelbargel/external-ingress-auth/blob/main/LICENSE)
