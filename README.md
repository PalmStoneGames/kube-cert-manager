# Kubernetes Certificate Manager

This project is loosely based on https://github.com/kelseyhightower/kube-cert-manager
It took over most of its documentation, license, as well as the general approach to how things work.

The code itself however, was entirely reimplemented to use xenolf/lego as the basis, instead of reimplementing an ACME client and DNS plugins.

## Special note for upgrading from earlier versions

If you are upgrading from a version before 0.5.0 then note that the default way to identify Ingress resources 
to be managed by the certificate manager has changed, from the `enabled` annotation, to the `class` label.
[Backwards compatible behaviour is available](docs/ingress.md) by setting the `-class` [argument](docs/deployment-arguments.md) to a blank value.

## Features

* Manage Kubernetes TLS secrets backed by Let's Encrypt issued certificates.
* Manage [Let's Encrypt](https://letsencrypt.org) issued certificates based on Kubernetes ThirdParty Resources.
* Manage [Let's Encrypt](https://letsencrypt.org) issued certificates based on Kubernetes Ingress Resources.
* Domain validation using ACME HTTP-01, SNI-TLS-01 or DNS-01 challenges.
* Support for multiple challenge providers.
* Support for subject alternative names in requested certificates.

## Project Goals

* Demonstrate how to build custom Kubernetes controllers.
* Demonstrate how to use Kubernetes [Third Party Resources](https://github.com/kubernetes/kubernetes/blob/release-1.3/docs/design/extending-api.md).
* Demonstrate how to interact with the Kubernetes API (watches, reconciliation, etc).
* Demonstrate how to write great documentation for Kubernetes add-ons and extensions.
* Promote the usage of Let's Encrypt for securing web applications running on Kubernetes.

## Requirements

* Kubernetes 1.3+
* At least one configured [challenge provider](docs/providers.md)
* A Kubectl with the same 1.x version as your cluster (ie. kubectl 1.3.x for a 1.3 cluster, and kubectl 1.4.x for a 1.4 cluster)

## Usage

* [Deployment Guide](docs/deployment-guide.md)
* [Creating a Certificate](docs/create-a-certificate.md)
* [Deleting a Certificate](docs/delete-a-certificate.md)
* [Consuming Certificates](docs/consume-certificates.md)
- [Managing Certificates for Ingress Resources](docs/ingress.md)
- [Garbage Collection of Secrets](docs/garbage-collection.md)
* [Secure Deployment using RBAC](docs/secure-deployment.md)

## Documentation

* [Deployment Arguments](docs/deployment-arguments.md)
* [Certificate Third Party Resources](docs/certificate-third-party-resource.md)
* [Certificate Resources](docs/certificate-resources.md)
* [Challenge Providers](docs/providers.md)
* [Building Container Image with AWS CodeBuild](codebuild/README.md)
