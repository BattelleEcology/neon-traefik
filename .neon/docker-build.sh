#!/usr/bin/env bash

set -e

# Default build target
GOOS='linux'
GOARCH='amd64'

if [ -n "$1" ]; then
    echo "Version: $1"
    TAG="$1"
else
    echo "No tag set, exiting"
    exit
fi

if [ -n "$2" ]; then
    echo "Image: $2"
    IMAGE_TAG="$2"
else
    echo "No image tag set, exiting"
    exit
fi

docker buildx build --load --platform=${GOOS}/${GOARCH} --build-arg TAG=$TAG -t $IMAGE_TAG --file Dockerfile .
