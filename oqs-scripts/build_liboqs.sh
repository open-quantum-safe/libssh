#!/bin/bash

###########
# Build liboqs
#
# Environment variables:
#  - PREFIX: path to install liboqs, default `pwd`/../oqs
###########

set -exo pipefail

PREFIX=${PREFIX:-"`pwd`/oqs"}

rm -rf oqs-scripts/tmp/liboqs/build
mkdir oqs-scripts/tmp/liboqs/build
pushd oqs-scripts/tmp/liboqs/build
cmake .. -GNinja -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX=${PREFIX}
ninja
ninja install
popd
