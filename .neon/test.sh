#!/bin/bash

LOC=$(pwd)
cd ..

# go test ./...
# cd integration
# go test -integration ./...
# cd $LOC

# Test using Docker
make test

cd $LOC
