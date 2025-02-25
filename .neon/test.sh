#!/bin/bash

LOC=$(pwd)
cd ..

# Test using Docker
make test

cd $LOC
