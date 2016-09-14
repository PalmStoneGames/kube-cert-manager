#!/usr/bin/env bash

docker build -t palmstonegames/kubectl-proxy:1.3.6 $(dirname "$0")
docker push palmstonegames/kubectl-proxy:1.3.6