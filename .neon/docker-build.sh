#!/bin/bash

cp ../dist/traefik .
tar -czf traefik.tar.gz traefik

docker build --no-cache -t quay.io/battelleecology/neon-traefik \
  --file ./neon.Dockerfile .
