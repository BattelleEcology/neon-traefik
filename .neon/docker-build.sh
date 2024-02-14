#!/bin/bash

# Default build target
GOOS='linux'
GOARCH='amd64'

cp ../dist/${GOOS}/${GOARCH}/traefik .
tar -czf traefik.tar.gz traefik

docker build --no-cache -t quay.io/battelleecology/neon-traefik \
  --file ./neon.Dockerfile .
