#!/usr/bin/env bash

GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' -o kube-cert-manager .