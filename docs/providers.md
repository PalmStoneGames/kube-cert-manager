# Configuring your challenge provider(s)

## HTTP

kube-cert-manager will answer HTTP challenges on port 8080,
you will need to setup a proxy or service definition that correctly directs requests on your domain on port 80 to the kube-cert-manager
If using a proxy, only `/.well-known/acme-challenge/` needs to be forwarded to the kube-cert-manager

## TLS

kube-cert-manager will answer TLS-SNI challenges on port 8081
You will need to setup a port forwarder or service definition that correctly directs packets on your domain on port 443 to the kube-cert-manager.
This provider is not very convenient when needing to serve a website on the actual domain, due to needing exclusive access on port 443.
As such, it is not recommended.


## DNS Providers

kube-cert-manager uses environment variables within the pod to fetch credentials required for various DNS providers.
Making those correctly accessible to kube-cert-manager will require editing the pod deployment spec at k8s/deployment.md

The recommended way to do this is to mount secrets as either environment variables or as files, depending on what the provider requires.
See [Using secrets as environment variables](http://kubernetes.io/docs/user-guide/secrets/#using-secrets-as-environment-variables) and [Using secrets as files from pods](http://kubernetes.io/docs/user-guide/secrets/#using-secrets-as-files-from-a-pod)

### Cloudflare

`CLOUDFLARE_EMAIL`: The email of the cloudflare user

`CLOUDFLARE_API_KEY`: The API key corresponding to the email

### Digital Ocean

`DO_AUTH_TOKEN`: The digital ocean authorization token

### DNSimple

`DNSIMPLE_EMAIL`: The email fo the DNSimple user

`DNSIMPLE_API_KEY`: The API key corresponding to the email

### DNS Made Easy

`DNSMADEEASY_API_KEY`: The API key for DNS Made Easy

`DNSMADEEASY_API_SECRET`: The api secret corresponding with the API key

`DNSMADEEASY_SANDBOX`: A boolean flag, if set to true or 1, requests will be sent to the sandbox API

### Dyn

`DYN_CUSTOMER_NAME`: The customer name of the Dyn user

`DYN_USER_NAME`: The user name of the Dyn user

`DYN_PASSWORD`: The password of the Dyn user

### Gandi

`GANDI_API_KEY`: The API key for Gandi

### Google Cloud

`GCE_PROJECT`: The name of the Google Cloud project to use

`GOOGLE_APPLICATION_CREDENTIALS`: A path to the credentials file to use

The credentials file itself should be mounted from a seperate secret to a file.

### Namecheap

`NAMECHEAP_API_USER`: The username of the namecheap user

`NAMECHEAP_API_KEY`: The API key corresponding with the namecheap user

### OVH

`OVH_ENDPOINT`: The URL of the API endpoint to use

`OVH_APPLICATION_KEY`: The application key

`OVH_APPLICATION_SECRET`: The secret corresponding to the application key

`OVH_CONSUMER_KEY`: The consumer key

### PDNS

`PDNS_API_KEY`: The API key to use

### RFC2136

The rfc2136 provider works with any DNS provider implementing the DNS Update rfc2136.
the TSIG variables need only be set if using TSIG authentication.

`RFC2136_NAMESERVER`: The network address of the provider, in the form of "host" or "host:port"

`RFC2136_TSIG_ALGORITHM`: The algorithm to use for TSIG authentication. 

`RFC2136_TSIG_KEY`: The key to use for TSIG authentication.

`RFC2136_TSIG_SECRET`: The secret to use for TSIG authentication.

### Amazon Route53

There are two ways to specify Route53 credentials. Either the credentials can be added to `~/.aws/credentials` by mounting the secret to a file.
Or the following environment variables can be set:

`AWS_ACCESS_KEY_ID`: The access key ID

`AWS_SECRET_ACCESS_KEY`: The secret corresponding to the access key

### Vultr

`VULTR_API_KEY`: The API key to use
