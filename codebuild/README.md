# Building kube-cert-manager using AWS CodeBuild

You can use AWS CodeBuild to build this project and push the contianer image to Docker hub.
You can use the AWS console or the AWS CLI with the scripts in the `codebuild` folder.

## Console Set-up

Use the AWS CodeBuild console to create a CodeBuild project as follows

- Give the project a name
- Select the GitHub project to build
- Choose build image: 'aws/codebuild/docker:1.12.1'
- Opt to use the 'buildspec.yml' file
- Choose 'No Artifacts'
- Choose (or create) the AWS Service Account to use

## Console Build

Use the AWS CodeBuild console to start the build

1. Choose 'Start Build'
2. If necessary, enter the git branch or commit ID
3. Add or update the following environment variables
```
CONTAINER_VERSION
DOCKER_REPO
DOCKER_HUB_USERNAME
DOCKER_HUB_PASSWORD
```
4. Start the Build
5. Check the build logs afterwards

## CLI Set-up

This requires you have [AWS CLI installed](http://docs.aws.amazon.com/cli/latest/userguide/installing.html), 
a CodeBuild Service Account, and have linked CodeBuild to GitHub.

1. Update the GitHub URL and AWS Service Account in the `cloudbuild.json` file
2. Create the project, specifying your profile and the region if not your default
```
aws codebuild create-project --profile default --region=us-east-1 --cli-input-json file://codebuild-project.json
```

## CLI Build

1. Set the following environment variables or customise `build.env` and `source build.env`
```
export PROJECT_NAME="kube-cert-manager"
export PROJECT_REGION="us-east-1"
export SOURCE_VERSION=""
export CONTAINER_VERSION="0.5.0"
export DOCKER_REPO=<your Docker Hub repo name>
export DOCKER_HUB_USERNAME=<your username>
export DOCKER_HUB_PASSWORD=<your password>
```
2. Start the build with `start-codebuild.sh`
3. View the build log with `get-codebuild-log.sh`
