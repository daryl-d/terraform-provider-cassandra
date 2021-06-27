#!/bin/bash

set -ex

IMAGE_REPOSITORY='278521702583.dkr.ecr.us-west-2.amazonaws.com/iops/terraform-provider-cassandra'

if [ -n "$BUILDKITE" ]; then
  IMAGE_TAG="build-${BUILDKITE_BUILD_NUMBER}"

  docker build -f Dockerfile -t ${IMAGE_REPOSITORY}:${IMAGE_TAG} .

  docker push "${IMAGE_REPOSITORY}:${IMAGE_TAG}"

  if [ -n "$BUILDKITE_TAG" ]; then
    docker tag "${IMAGE_REPOSITORY}:${IMAGE_TAG}" "${IMAGE_REPOSITORY}:${BUILDKITE_TAG}"
    docker push "${IMAGE_REPOSITORY}:${BUILDKITE_TAG}"
  fi
fi
