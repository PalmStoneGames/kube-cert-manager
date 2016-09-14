#!/usr/bin/env bash
docker build -t palmstonegames/kube-cert-manager:0.1.0 $(dirname "$0")
docker push palmstonegames/kube-cert-manager:0.1.0