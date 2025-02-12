#!/bin/bash
LOC=$(pwd)
cd ..

# Build with go directly
echo "Make webui"
echo "========================================================================="
make clean-webui generate-webui
echo
echo
echo "Build with go"
echo "========================================================================="
go generate
go build ./cmd/traefik

# Build artifact using Docker
echo
echo
echo "Make generate-crd"
echo "========================================================================="
make generate-crd
echo
echo
echo "Make binary-linux-amd64"
echo "========================================================================="
make binary-linux-amd64

cd $LOC

echo
echo
echo "Copy binary"
echo "========================================================================="
rm traefik
rm traefik.tar.gz
cp ../dist/linux/amd64/traefik .
tar -czf traefik.tar.gz traefik
