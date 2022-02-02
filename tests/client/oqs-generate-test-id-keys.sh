#!/bin/bash

# Run this from the tests/client directory. Make sure the OQS-OpenSSH version of ssh-keygen is first in your PATH.

##### OQS_TEMPLATE_FRAGMENT_GENERATE_ID_KEY_START
for value in \
       falcon512 \
       rsa3072-falcon512 \
       ecdsa-nistp256-falcon512 \
       falcon1024 \
       ecdsa-nistp521-falcon1024 \
       dilithium3 \
       ecdsa-nistp384-dilithium3 \
       dilithium2aes \
       rsa3072-dilithium2aes \
       ecdsa-nistp256-dilithium2aes \
       dilithium5aes \
       ecdsa-nistp521-dilithium5aes \
       picnicL1full \
       rsa3072-picnicL1full \
       ecdsa-nistp256-picnicL1full \
       picnicL3FS \
       ecdsa-nistp384-picnicL3FS \
       sphincsharaka128fsimple \
       rsa3072-sphincsharaka128fsimple \
       ecdsa-nistp256-sphincsharaka128fsimple \
       sphincsharaka192frobust \
       ecdsa-nistp384-sphincsharaka192frobust
##### OQS_TEMPLATE_FRAGMENT_GENERATE_ID_KEY_END
do	
	if [ ! -f ../keys/id_${value} ]; then
		echo "Generating keypair id_${value}."
		ssh-keygen -t ${value//-/_} -q -N "" -f ../keys/id_${value} -C bob@bob.com || exit 1
	fi
done
