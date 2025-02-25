#!/bin/bash
LOC=$(pwd)
cd ..

# Default build target
GOOS='linux'
GOARCH='amd64'

docker buildx build --load --platform=${GOOS}/${GOARCH} -t us-central1-docker.pkg.dev/neon-shared-service/bei/neon-traefik --file Dockerfile .

cd $LOC
