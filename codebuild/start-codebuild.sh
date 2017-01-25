#!/bin/bash
set -e

#
# CodeBuild makes it extremely awkward to specify which branch to build
# You can't specify it in the project, and you can't specify it on the command line
# You have to use a JSON options file, that you can't provide on stdin
# So have to make a temporary file, put the branch name there, and then pass file to CLI
# Usage: You can optionally specify a branch or commit id to build as an argument
#
# Aaron Roydhouse <aaron@roydhouse.com>
# https://github.com/whereisaaron/
#

: ${PROJECT_NAME:=kube-cert-manager}
: ${PROJECT_REGION:=us-east-1}
if [[ -n "$1" ]]; then
  SOURCE_VERSION=$1
fi

: ${CONTAINER_VERSION:="0.4.0"}
: ${DOCKER_REPO:=whereisaaron}
: ${DOCKER_HUB_USERNAME?"Must specify DOCKER_HUB_USERNAME"}
: ${DOCKER_HUB_PASSWORD?"Must specify DOCKER_HUB_PASSWORD"}

START_OPTS=$(mktemp)
cat - > ${START_OPTS} <<END 
{
    "projectName": "${PROJECT_NAME}",
    "sourceVersion": "${SOURCE_VERSION}",
    "environmentVariablesOverride": [
        {
            "name": "SOURCE_VERSION",
            "value": "${SOURCE_VERSION}"
        },
        {
            "name": "CONTAINER_VERSION",
            "value": "${CONTAINER_VERSION}"
        },
        {
            "name": "DOCKER_REPO",
            "value": "${DOCKER_REPO}"
        },
        {
            "name": "DOCKER_HUB_USERNAME",
            "value": "${DOCKER_HUB_USERNAME}"
        },
        {
            "name": "DOCKER_HUB_PASSWORD",
            "value": "${DOCKER_HUB_PASSWORD}"
        }
    ]
}
END

BUILD_ID=$(aws codebuild start-build --region ${PROJECT_REGION} --cli-input-json "file://${START_OPTS}" --query "build.id" --output=text)

rm "${START_OPTS}"

echo "${BUILD_ID}"
