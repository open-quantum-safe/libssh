#!/bin/bash

# Run this from the tests/client directory. Make sure the OQS-OpenSSH version of ssh-keygen is first in your PATH.

##### OQS_TEMPLATE_FRAGMENT_GENERATE_ID_KEY_START
for value in \
       falcon512 \
       rsa3072-falcon512 \
       ecdsa-nistp256-falcon512 \
       falcon1024 \
       ecdsa-nistp521-falcon1024 \
       dilithium2 \
       rsa3072-dilithium2 \
       ecdsa-nistp256-dilithium2 \
       dilithium3 \
       ecdsa-nistp384-dilithium3 \
       dilithium5 \
       ecdsa-nistp521-dilithium5 \
       sphincsharaka128fsimple \
       rsa3072-sphincsharaka128fsimple \
       ecdsa-nistp256-sphincsharaka128fsimple \
       sphincssha256128fsimple \
       rsa3072-sphincssha256128fsimple \
       ecdsa-nistp256-sphincssha256128fsimple \
       sphincssha256192srobust \
       ecdsa-nistp384-sphincssha256192srobust \
       sphincssha256256fsimple \
       ecdsa-nistp521-sphincssha256256fsimple
##### OQS_TEMPLATE_FRAGMENT_GENERATE_ID_KEY_END
do	
	if [ ! -f ../keys/id_${value} ]; then
		echo "Generating keypair id_${value}."
		ssh-keygen -t ${value//-/_} -q -N "" -f ../keys/id_${value} -C bob@bob.com || exit 1
	fi
done
