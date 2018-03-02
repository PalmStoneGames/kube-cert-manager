#!/usr/bin/env bash
docker build -t m0almallahi/kube-cert-manager:0.3.1 -t m0almallahi/kube-cert-manager:latest $(dirname "$0")
docker push m0almallahi/kube-cert-manager:0.3.1
docker push m0almallahi/kube-cert-manager:latest