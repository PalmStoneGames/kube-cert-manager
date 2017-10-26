# Ingress Resources

Ingress resources are a Kubernetes concept that allow exposing, load
balancing and routing services in a cluster. Additionally, by
specifying a list of hosts and TLS secrets, Ingresses terminate TLS
connections.

When you add the right label and annotations to an Ingress resource,
kube-cert-manager will manage all TLS secrets and create certificates
for them. These secrets can either be existing secrets that were
created by Certificate resources, or they can be non-existent secrets.
In either case, kube-cert-manager will take care of using ACME to
request certificates.

## Required Label

- `stable.k8s.psg.io/kcm.class` - Set to `"default"` or the value you set with the `-class` argument.

## Optional Annotations

- `stable.k8s.psg.io/kcm.provider` - The same as `spec.provider` in [Certificate Resources](certificate-resources.md). Optional, if you set the `-default-provider` argument.
- `stable.k8s.psg.io/kcm.email` - The same as `spec.email` in [Certificate Resources](certificate-resources.md). Optional, if you set the `-default-email` argument.

## Example Ingress resource

The following example exposes a load balanced service on
example.com, managing the TLS certificate with kube-cert-manager and
storing the certificate in a secret named `hello-secret`:

```
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: ingress
  labels:
    stable.k8s.psg.io/kcm.class: "default"
  annotations:
    stable.k8s.psg.io/kcm.provider: "googlecloud"
    stable.k8s.psg.io/kcm.email: "admin@psg.io"
spec:
  tls:
  - hosts:
    - psg.io
    secretName: hello-secret
  rules:
  - host: "psg.io"
    http:
      paths:
      - path: /hello-world
        backend:
          serviceName: helloworld
          servicePort: 80
```

## Deprecated 'enabled' annotation

Releases before version 0.5 used an `enabled` annotation, instead of the `class` label, to identify 
which Ingress resources for which certificate secrets should be created.

Version 0.5 provides backward compatibility with the old behavior, if you set the `-class` argument to blank. 
The certificate manager will then look for the deprecated `enabled` annotation instead.

```
  annotations:
    stable.k8s.psg.io/kcm.enabled: "true"
    stable.k8s.psg.io/kcm.provider: "googlecloud"
    stable.k8s.psg.io/kcm.email: "admin@psg.io"
```

If the `-class` argument is set to any value, then the certificate manager will only handle all resources 
with the `class` label. Ingress resources without the `class` label will be ignored. If the `class` 
argument is not specified, the default `class` label is `default`. 
