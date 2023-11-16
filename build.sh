#!/bin/bash

make clean-webui generate-webui
go generate
go build ./cmd/traefik

# Build artifact using Docker
make binary
