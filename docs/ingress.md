# Ingress Resources

Ingress resources are a Kubernetes concept that allow exposing, load
balancing and routing services in a cluster. Additionally, by
specifying a list of hosts and TLS secrets, Ingresses terminate TLS
connections.

When you add the right annotations to an Ingress resource,
kube-cert-manager will manage all TLS secrets and create certificates
for them. These secrets can either be existing secrets that were
created by Certificate objects, or they can be non-existent secrets.
In either case, kube-cert-manager will take care of using ACME to
request certificates.

## Required Annotations

- `stable.k8s.psg.io/kcm.enabled` - has to be set to `"true"`
- `stable.k8s.psg.io/kcm.provider` - the same as `spec.provider` in [Certificate Objects](certificate-objects.md)
- `stable.k8s.psg.io/kcm.email` - the same as `spec.email` in [Certificate Objects](certificate-objects.md)

## Example

The following example exposes a load balanced service on
example.com, managing the TLS certificate with kube-cert-manager and
storing the certificate in a secret named `hello-secret`:

```
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: ingress
  annotations:
    stable.k8s.psg.io/kcm.enabled: "true"
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