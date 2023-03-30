#!/bin/bash

###########
# Build OpenSSH
#
# Must be run after OQS has been installed
###########

set -exo pipefail

PREFIX=${PREFIX:-"`pwd`/oqs-test/tmp"}
LIBOQS_DIR="`pwd`/oqs"

pushd oqs-scripts/tmp/openssh

if [ -f Makefile ]; then
    make clean
else
    autoreconf -i
fi

./configure --prefix="${PREFIX}" --with-libs=-lm --with-liboqs-dir="${LIBOQS_DIR}" --sysconfdir="${PREFIX}" --with-pam

if [ "x${CIRCLECI}" == "xtrue" ] || [ "x${TRAVIS}" == "xtrue" ]; then
    make -j2
else
    make -j
fi

make install

popd
