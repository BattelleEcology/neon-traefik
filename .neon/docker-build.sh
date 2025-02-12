#!/bin/bash
LOC=$(pwd)
cd ..

# Default build target
GOOS='linux'
GOARCH='amd64'

docker build \
  --no-cache \
  --build-arg TARGETPLATFORM=${GOOS}/${GOARCH} \
  -t quay.io/battelleecology/neon-traefik \
  --file Dockerfile .

cd $LOC
