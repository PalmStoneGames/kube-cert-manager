#!/usr/bin/env bash

docker build -t palmstonegames/kubectl-proxy:1.4.0 -t palmstonegames/kubectl-proxy:latest $(dirname "$0")
docker push palmstonegames/kubectl-proxy:1.4.0
docker push palmstonegames/kubectl-proxy:latest