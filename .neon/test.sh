#!/bin/bash

LOC=$(pwd)
cd ..

# Test using Docker
make test-ui-unit
make test-unit

cd $LOC
