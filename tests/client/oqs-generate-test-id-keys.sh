#!/bin/bash

# Run this from the tests/client directory. Make sure the OQS-OpenSSH version of ssh-keygen is first in your PATH.

##### OQS_TEMPLATE_FRAGMENT_GENERATE_ID_KEY_START
for value in \
       oqsdefault \
       rsa3072-oqsdefault \
       p256-oqsdefault \
       dilithium2 \
       rsa3072-dilithium2 \
       p256-dilithium2 \
       falcon512 \
       rsa3072-falcon512 \
       p256-falcon512 \
       picnicl1full \
       rsa3072-picnicl1full \
       p256-picnicl1full \
       picnic3l1 \
       rsa3072-picnic3l1 \
       p256-picnic3l1 \
       sphincsharaka128frobust \
       rsa3072-sphincsharaka128frobust \
       p256-sphincsharaka128frobust \
       sphincssha256128frobust \
       rsa3072-sphincssha256128frobust \
       p256-sphincssha256128frobust \
       sphincsshake256128frobust \
       rsa3072-sphincsshake256128frobust \
       p256-sphincsshake256128frobust
##### OQS_TEMPLATE_FRAGMENT_GENERATE_ID_KEY_END
do	
	if [ ! -f ../keys/id_${value} ]; then
		echo "Generating keypair id_${value}."
		ssh-keygen -t ${value/-/_} -q -N "" -f ../keys/id_${value} -C bob@bob.com || exit 1
	fi
done
