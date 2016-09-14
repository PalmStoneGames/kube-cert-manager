# Certificate Objects

Certificate objects are used to declare one or more Let's Encrypt issued TLS certificates. Certificate objects are consumed by the [Kubernetes Certificate Manager](https://github.com/PalmStoneGames/kube-cert-manager).

Before you can create a Certificate object you must create the [Certificate Third Party Resource](certificate-third-party-resource.md) in your Kubernetes cluster.

## Required Fields

* apiVersion - The Kubernetes API version. See Certificate Third Party Resource.
* kind - The Kubernetes object type.
* metadata.name - The name of the Certificate object.
* spec.domain - The DNS domain to obtain a Let's Encrypt certificate for.
* spec.email - The email address used for a Let's Encrypt registration.
* spec.provider - The name of the challenge provider plugin. (see [Configuring your challenge provider(s)](providers.md))

### Example

The following Kubernetes Certificate configuration assume the following:

* The necessary environment variables for the googlecloud provider are set.
* The `psg.io` domain is registered.
* The `psg.io` domain is managed by [Google Cloud DNS](https://cloud.google.com/dns)

Example Certificate Object

```
apiVersion: "stable.k8s.psg.io/v1"
kind: "Certificate"
metadata:
  name: "psg-dot-io"
spec:
  domain: "psg.io"
  email: "admin@psg.io"
  provider: "googlecloud"
```
