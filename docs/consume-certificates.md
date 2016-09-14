# Consuming Certificates

Once you have the Kubernetes Certificate Manager up and running [create one or more certificates](create-a-certificate.md), which will give you a set of Kubernetes TLS secrets that you can consume in your applications.

This tutorial will walk you through creating a Pod manifest that consumes the certificates created by the Kubernetes Certificate Manager.

## Create a Deployment for your application

As part of your deploment, you'll need to mount the tls secret, you can do this using the following in your podspec:

```
spec:
  containers:
  - name: my-app
    image: ...
    args:
      - "-tls-cert=/etc/tls/psg.io/tls.crt"
      - "-tls-key=/etc/tls/psg.io/tls.key"
    volumeMounts:
      - name: psg-io
        mountPath: /etc/tls/psg.io
  volumes:
    - name: psg-io
      secret:
        secretName: psg.io
```

The key to consuming Kubernetes TLS secrets is to use a secret volume. Study the snippet above and notice how the `psg.io` secret is being mounted under the `/etc/tls/psg.io` directory. By default the Kubernetes Certificate Manager will store all certificates and privates key using the `tls.crt` and `tls.key` key names. This will result in two files under the `/etc/tls/psg.io/` directory at runtime.

Use kubectl to create the `my-app` deployment:

```
kubectl create -f my-app.yaml
```

```
deployment "my-app" created
```

#### Verify

```
kubectl port-forward my-app-1623907102-wg95k 10443:443
```
```
Forwarding from 127.0.0.1:10443 -> 443
Forwarding from [::1]:10443 -> 443
```

In another terminal grab the serial number of the current certificate:

```
openssl s_client -showcerts -connect 127.0.0.1:10443 2>&1 \
  | openssl x509 -noout -serial
```
```
serial=FA37E39A3368C72EF6F6E5FC4C9F3FA7BC26
```

### Getting a New Certificate

An easy way to force the Kubernetes Certificate Manager to generate a new Let's Encrypt issued certificate is to delete the `psg-dot-io` certificate object:

```
kubectl delete certificates psg-dot-io
```
```
certificate "psg-dot-io" deleted
```

Review the `kube-cert-manager` logs:

```
kubectl logs kube-cert-manager-1999323568-npjf5 kube-cert-manager -f
```

```
2016/09/14 15:08:30 [psg.io] Deleting secret psg.io
2016/09/14 15:08:30 [psg.io] Deleting user info and certificate details
```

Now recreate the psg-dot-io certificate:

```
kubectl create -f certs/psg-dot-io.yaml
```
``` 
certificate "psg-dot-io" created
```

This will cause the `kube-cert-manager` to create a new Let's Encrypt user account and aquire a new certificate.

Review the `kube-cert-manager` logs:

```
kubectl logs kube-cert-manager-1999323568-npjf5 kube-cert-manager -f
```

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

#### Verify

```
kubectl port-forward my-app-1623907102-wg95k 10443:443
```
```
Forwarding from 127.0.0.1:10443 -> 443
Forwarding from [::1]:10443 -> 443
```

In another terminal grab the serial number of the current certificate:

```
openssl s_client -showcerts -connect 127.0.0.1:10443 2>&1 \
  | openssl x509 -noout -serial
```
```
serial=FA7B2541F66889134DFAE8E2A4DD8DAE2345
```