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

