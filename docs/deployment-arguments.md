# Certificate Manager Deployment Arguments

The sample deployment in [`k8s/deployment.yaml`](../k8s/deployment.yaml) lets
you set various arguments, including important arguments like the ACME URL.

```
  args:
    - "-data-dir=/var/lib/cert-manager"
    - "-acme-url=https://acme-staging.api.letsencrypt.org/directory"
    # NOTE: the URL above points to the staging server, where you won't get real certs.
    # Uncomment the line below to use the production LetsEncrypt server:
    #- "-acme-url=https://acme-v01.api.letsencrypt.org/directory"
    # You can run multiple instances of kube-cert-manager for the same namespace(s),
    # each watching for a different value for the 'class' label
    #- "-class=default"
    # You can choose to monitor only some namespaces, otherwise all namespaces will be monitored
    #- "-namespaces=default,test"
    # If you set a default email, you can omit the field/annotation from Certificates/Ingresses
    #- "-default-email=me@example.com"
    # If you set a default provider, you can omit the field/annotation from Certificates/Ingresses
    #- "-default-provider=googlecloud"
```

## Required Arguments

- `-acme-url` - The URL to the ACME directory to use, this is required, there is no default

## Optional Argument

- `-cert-secret-prefix` - Prefix to add to the names of Secret resources, defaults to blank
- `-sync-interval` - How often to check for certificates to renew in seconds, e.g. "300"; defaults to 30
- `-gc-interval` - How often to garbage collect unused Secrets as a duration, e.g. "2h" for 2 hours; defaults to once a week
- `-data-dir` - Path for the 'boltdb' database, defaults to `/var/lib/cert-manager`
- `-namespaces` - Comma-separated list of namespaces to monitor, defaults to all namespaces
- `-class` - Class label value for Ingress resources managed by this certificate manager, defaults to `default`
- `-default-provider` - Default handler to handle ACME challenges, used if not specified in a resource annotation
- `-default-email` - Default email address for ACME registrations, used if not specified in a resource annotation

## Obscure Arguments

If you wish to build your own version of the certificate manager, you can optional use a different
label/annotation/resource namespace prefix. E.g. `-cert-namespace=example.com -tag-prefix=kcm.example.com`.
You need to ensure your registered Certficate Custom Resource Definition and Ingress labels/annotations match this setting.

- `-cert-namespace` - Namespace to Certificate Custom Resources, defaults to `stable.k8s.psg.io`
- `-tag-prefix` - Prefix added to labels and annotations, defaults to `stable.k8s.psg.io/kcm.`
