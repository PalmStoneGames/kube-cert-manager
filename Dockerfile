FROM gcr.io/distroless/base

EXPOSE 8080 8081

ADD kube-cert-manager /kube-cert-manager

ENTRYPOINT ["/kube-cert-manager"]
