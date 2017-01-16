# Secure deployment of kube-cert-manager using RBAC

Most default kubernetes installs have authorization set to 'AlwaysAllow'.
This means the 'default' Service Account provided to every container you 
deploy has 'root' level access to the whole cluster. Containers can enter 
any other container, including priviledged containers, do and delete 
anything across the entire cluster.

Using an authorization plug-in is prudent. RBAC allow you to manage 
role-based access as kubernetes resources.

The [`rbac-example.yaml`](../k8s/rbac-example.yaml) file contains
Service Account and a Cluster Role to allow kube-cert-manager
to manage certificates across the whole cluster

To use this you first need [RBAC enabled for your cluster](https://kubernetes.io/docs/admin/authorization/).

You might also need some base RBAC roles installed so your cluster
can operate. Then create the Service Account and roles in [this file](../k8s/rbac-example.yaml):
```
kubectl create -f rbac-example.yaml
```

Then add to a `spec.template.spec.serviceAccount` to the deployment:
```
serviceAccount: kube-cert-manager
```

and deploy the kube-cert-manager as normal.
Check the kube-cert-manager logs for any permission errors:
```
kubectl logs <pod-name> --container kube-cert-manager
```
If you are deploying to a different namespace that 'default',
change the namespaces in `rbac-example.yaml` and in `deployment.yaml`.
