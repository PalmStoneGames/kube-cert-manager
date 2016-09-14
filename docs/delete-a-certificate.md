# Deleting a Certificate

Deleting a Kubernetes Certificate object will cause the `kube-cert-manager` to delete the following items:

* The Kubernetes TLS secret holding the Let's Encrypt certificate and private key.
* The Let's Encrypt user account registered for the domain.

## Delete a Certificate

```
kubectl delete certificates psg-dot-io
```
```
certificate "psg-dot-io" deleted
```

Logs from the `kube-cert-manager`:

```
2016/09/14 15:08:30 [psg.io] Deleting secret psg.io
2016/09/14 15:08:30 [psg.io] Deleting user info and certificate details
```