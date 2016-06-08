#!/usr/bin/env bash

set -eu

mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DSODIUMPP_TEST=1 -DSODIUMPP_EXAMPLE=1 ..
make
