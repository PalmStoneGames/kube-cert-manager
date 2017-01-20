#!/bin/bash

#
# Display CloudWatch log for a CodeBuild build ID
# Aaron Roydhouse <aaron@roydhouse.com>
# https://github.com/whereisaaron/
#

: ${PROJECT_NAME:=kube-cert-manager}
: ${PROJECT_REGION:=us-east-1}

ID=$1
if [[ -z "${ID}" ]]; then
  echo "No CodeBuild build ID specified, displaying log for first build ID"
  ID=$(aws codebuild list-builds-for-project --project-name=${PROJECT_NAME} --region ${PROJECT_REGION} --query "ids[0]" --output text)
fi

LOG_GROUP="/aws/codebuild/${ID%%:*}"
LOG_STREAM="${ID##*:}"

if [[ -z "${LOG_GROUP}" || -z "${LOG_STREAM}" ]]; then
  echo "Usage: $0 <build.id>"
  echo "$0 kube-cert-manager:eb8ad990-11ee-4c16-b475-32b2dba84888"
  exit 1
fi

aws logs --region=us-east-1 get-log-events \
  --log-group=${LOG_GROUP} \
  --log-stream=${LOG_STREAM} \
  --query="events[].message" --output=text \
| sed 's/^[ \t]*\(\[Container\][ \t]*\)\?//'
