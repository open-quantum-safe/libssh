#!/bin/bash

###########
# Run the pkd_hello test suite
#
###########

set -exo pipefail

# pkd_hello uses the system path to find ssh-keygen, and so binaries for the OQS fork must appear first in the path.

OPENSSH_BIN_PATH="`pwd`/oqs-test/tmp/bin"

if [ ! -f ${OPENSSH_BIN_PATH}/ssh ]; then
  echo Could not find OQS-OpenSSH ssh binary.
  exit 1
fi

PATH="${OPENSSH_BIN_PATH}:${PATH}"

pushd build/tests/pkd

./pkd_hello

popd

