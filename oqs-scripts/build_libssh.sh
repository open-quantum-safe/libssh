#!/bin/bash

###########
# Build libssh
#
# Must be run after OQS and OQS-OpenSSH have been installed
###########

set -exo pipefail

OPENSSH_BIN_PATH="`pwd`/oqs-test/tmp/bin"
OPENSSH_SBIN_PATH="`pwd`/oqs-test/tmp/sbin"
OQS_ROOT_DIR=${OQS_ROOT_DIR:-"`pwd`/oqs"}

# OQS-OpenSSH ssh(d) binaries must appear first in the path before any system-installed version when cmake is invoked, so that tests will call the OQS version.
# Build will succeed without this check, but then tests will fail because the system-installed ssh(d) doesn't know the algorithms.
if [ ! -f ${OPENSSH_BIN_PATH}/ssh ]; then
  echo Could not find OQS-OpenSSH ssh binary.
  exit 1
fi

if [ ! -f ${OPENSSH_SBIN_PATH}/sshd ]; then
  echo Could not find OQS-OpenSSH sshd binary.
  exit 1
fi

PATH="${OPENSSH_BIN_PATH}:${OPENSSH_SBIN_PATH}:${PATH}"

mkdir build && pushd build
cmake -DUNIT_TESTING=ON -DWITH_SERVER=ON -DSERVER_TESTING=ON -DCLIENT_TESTING=ON -DCMAKE_BUILD_TYPE=Debug -DWITH_POST_QUANTUM_CRYPTO=ON -DOQS_ROOT_DIR=${OQS_ROOT_DIR} ..

if [ "x${CIRCLECI}" == "xtrue" ] || [ "x${TRAVIS}" == "xtrue" ]; then
    make -j2
else
    make -j
fi

cd ..
