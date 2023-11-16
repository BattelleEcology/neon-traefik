#!/bin/bash

LOC=$(pwd)

# go test ./...
# cd integration
# go test -integration ./...
# cd $LOC

# Test using Docker
make test
