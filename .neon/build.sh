#!/bin/bash
LOC=$(pwd)
cd ..

# Build with go directly
make clean-webui generate-webui
go generate
go build ./cmd/traefik

# Build artifact using Docker
make generate-crd
make binary-linux-amd64

cd $LOC
