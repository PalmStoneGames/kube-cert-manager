# Creating a Certificate

Let's Encrypt issued certificates are automatically created for each Kubernetes Certificate resource. 
This tutorial assumes that you've set the correct environment variables on the kube-cert-manager pod 
to make your DNS provider work (see [Configuring your challenge provider(s)](providers.md))

## Create a Kubernetes Certificate Resource

```
cat certs/psg-dot-io.yaml
```

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

```
kubectl create -f certs/psg-dot-io.yaml
```

```
certificate "psg-dot-io" created
```

After submitting the Certificate configuration to the Kubernetes API it will be processed by the `kube-cert-manager`:

Logs from the `kube-cert-manager`:

```
2016/09/14 15:10:36 Starting Kubernetes Certificate Controller...
2016/09/14 15:10:37 [INFO] acme: Registering account for admin@psg.io
2016/09/14 15:10:38 [INFO][psg.io] acme: Obtaining bundled SAN certificate
2016/09/14 15:10:38 [INFO][psg.io] acme: Could not find solver for: http-01
2016/09/14 15:10:38 [INFO][psg.io] acme: Could not find solver for: tls-sni-01
2016/09/14 15:10:38 [INFO][psg.io] acme: Trying to solve DNS-01
2016/09/14 15:10:42 [INFO][psg.io] Checking DNS record propagation...
2016/09/14 15:11:19 [INFO][psg.io] The server validated our request
2016/09/14 15:11:22 [INFO][psg.io] acme: Validations succeeded; requesting certificates
2016/09/14 15:11:22 [INFO][psg.io] Server responded with a certificate.
2016/09/14 15:11:27 [INFO] acme: Requesting issuer cert from https://acme-staging.api.letsencrypt.org/acme/issuer-cert
2016/09/14 15:11:28 Kubernetes Certificate Controller started successfully.
```

## Results

```
kubectl get secrets psg.io
```
```
NAME      TYPE                DATA      AGE
psg.io    kubernetes.io/tls   2         20m
```

```
kubectl describe secrets psg.io
```
```
Name:           psg.io
Namespace:      default
Labels:         domain=psg.io
Annotations:    <none>

Type:   kubernetes.io/tls

Data
====
tls.crt:        3411 bytes
tls.key:        1679 bytes
```
