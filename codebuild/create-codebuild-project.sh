#!/bin/bash

#
# AWS CodeBuild Project for kube-cert-manager
# Aaron Roydhouse <aaron@roydhouse.com>
#
# Before creating the project, you must have logged into AWS CodeBuild Console,
# created a Service Role for CodeBuild and linked your AWS account with Github.
# Then customise 'codebuild-project.json' as required and create the project
# with a command similar to below.
#

aws codebuild create-project --profile default --region=us-east-1 --cli-input-json file://codebuild-project.json
