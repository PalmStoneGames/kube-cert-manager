# Deployment Guide

This guide will walk you through deploying the Kubernetes Certificate Manager.

By default `kube-cert-manager` obtains certificates from the Let's Encrypt staging environment. Set the `-amce-url` flag to `https://acme-v01.api.letsencrypt.org/directory` for production.

## High Level Tasks

* Create the Certificate Third Party Resource
* Create the Kubernetes Certificate Manager Deployment

## Deploying the Kubernetes Certificate Manager

### Create the Certificate Third Party Resource

The `kube-cert-manager` is driven by [Kubernetes Certificate Objects](certificate-objects.md). Certificates are not a core Kubernetes kind, but can be enabled with the [Certificate Third Party Resource](certificate-third-party-resource.md):

Create the Certificate Third Party Resource:

```
kubectl create -f k8s/certificate-type.yaml 
```


### Configure your DNS providers (if any)

If you want to use DNS challenges, you'll need to [Configure your DNS provider](providers.md)
If you do not do this, only http and tls challenges will be available.

### Configure your kubectl version

The deployment leverages `kubectl` running in proxy mode for API access. By default, the deployment is set to use kubectl 1.4.0 for this. If you are running in a 1.3 cluster, change this to 1.3.6.
For a list of available versions, check the [hub.docker.com page for kubectl-proxy](https://hub.docker.com/r/palmstonegames/kubectl-proxy/tags/)

### Create the Kubernetes Certificate Manager Deployment

The `kube-cert-manager` requires persistent storage to hold the following data:

* Let's Encrypt user accounts, private keys, and registrations
* Let's Encrypt issued certificates

Create a persistent disk which will store the `kube-cert-manager` database.
> [boltdb](https://github.com/boltdb/bolt) is used to persistent data.

```
gcloud compute disks create kube-cert-manager --size 10GB
```

> 10GB is the minimal disk size for a Google Compute Engine persistent disk.

The `kube-cert-manager` requires access to the Kubernetes API to perform the following tasks:

* Read secrets that hold Google cloud service accounts.
* Create, update, and delete Kubernetes TLS secrets backed by Let's Encrypt Issued certificates.

The `kube-cert-manager` leverages `kubectl` running in proxy mode for API access and both containers should be deployed in the same pod.

Create the `kube-cert-manager` deployment:

```
kubectl create -f k8s/deployment.yaml 
```
```
deployment "kube-cert-manager" created
```

Review the `kube-cert-manager` logs:

```
kubectl get pods
```
```
NAME                                 READY     STATUS    RESTARTS   AGE
kube-cert-manager-1999323568-op6nk   2/2       Running   0          25s
```

```
kubectl logs kube-cert-manager-1999323568-op6nk kube-cert-manager
```

```
2016/09/14 15:08:24 Starting Kubernetes Certificate Controller...
2016/09/14 15:08:24 Kubernetes Certificate Controller started successfully.
```
