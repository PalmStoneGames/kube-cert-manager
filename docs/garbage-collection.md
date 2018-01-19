# Garbage Collection

During its lifetime, kube-cert-manager will create secrets to store
TLS certificates. Each secret may be owned by zero or one Certificate
resource and used by zero or more Ingresses. When kube-cert-manager
detects that a secret it created is no longer needed, that is no
Certificate resource and no Ingress reference it anymore, it will be
deleted.

Garbage collection is a periodic operation. This means that there may
be a delay between deleting a resource and the secret being deleted.
In practice, this should not cause any problems. Reusing the secret
name in a Certificate resource or Ingress will work correctly. If you
wish to reuse the secret name yourself, you can manually delete the
secret first.

The interval at which garbage collection runs is controlled by the
`gc-interval` command line flag. It defaults to run at initial startup, and
then once every 7 days after.
