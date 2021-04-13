#!/bin/bash

# Run this from the tests/client directory. Make sure the OQS-OpenSSH version of ssh-keygen is first in your PATH.

if [ ! -f torture_algorithms.c ]; then
	echo "Please run this script from the tests/client directory."
	exit 1
fi

KEMCASESFILE=torture_algorithms_oqs_cases.c
KEMFUNCSFILE=torture_algorithms_oqs_funcs.c

SIGCASESFILE=torture_auth_oqs_cases.c
SIGFUNCSFILE=torture_auth_oqs_funcs.c
SIGCMAKEFILE=../GenerateAndAuthorizePQKeys.cmake

# KEMs

rm -f $KEMCASESFILE
rm -f $KEMFUNCSFILE

generate_kem_testcase() {

	echo "         cmocka_unit_test_setup_teardown(torture_algorithms_${1,,},"
	echo "                                         session_setup,"
	echo "                                         session_teardown),"

}

generate_kem_testfunc() {
	echo "static void torture_algorithms_${1,,}(void** state)"
	echo "{"
	echo "    struct torture_state* s = *state;"
	echo ""
	echo "    if (ssh_fips_mode()) {"
	echo "        skip();"
	echo "    }"
	echo ""
	echo "    test_algorithm(s->ssh.session, KEX_${1}, NULL, NULL);"
	echo "}"
	echo ""
}

echo "#ifdef WITH_POST_QUANTUM_CRYPTO" >> $KEMCASESFILE
echo "#ifdef WITH_PURE_PQ_KEX" >> $KEMCASESFILE
echo "#ifdef WITH_POST_QUANTUM_CRYPTO" >> $KEMFUNCSFILE
echo "#ifdef WITH_PURE_PQ_KEX" >> $KEMFUNCSFILE

for value in \
	OQSDEFAULT_SHA384 \
	BIKE1_L1_CPA_SHA384 \
	BIKE1_L3_CPA_SHA384 \
	BIKE1_L1_FO_SHA384 \
	BIKE1_L3_FO_SHA384 \
	CLASSIC_MCELIECE_348864_SHA384 \
	CLASSIC_MCELIECE_348864F_SHA384 \
	CLASSIC_MCELIECE_460896_SHA384 \
	CLASSIC_MCELIECE_460896F_SHA384 \
	CLASSIC_MCELIECE_6688128_SHA384 \
	CLASSIC_MCELIECE_6688128F_SHA384 \
	CLASSIC_MCELIECE_6960119_SHA384 \
	CLASSIC_MCELIECE_6960119F_SHA384 \
	CLASSIC_MCELIECE_8192128_SHA384 \
	CLASSIC_MCELIECE_8192128F_SHA384 \
	FRODO_640_AES_SHA384 \
	FRODO_640_SHAKE_SHA384 \
	FRODO_976_AES_SHA384 \
	FRODO_976_SHAKE_SHA384 \
	FRODO_1344_AES_SHA384 \
	FRODO_1344_SHAKE_SHA384 \
	KYBER_512_SHA384 \
	KYBER_768_SHA384 \
	KYBER_1024_SHA384 \
	KYBER_512_90S_SHA384 \
	KYBER_768_90S_SHA384 \
	KYBER_1024_90S_SHA384 \
	NTRU_HPS_2048_509_SHA384 \
	NTRU_HPS_2048_677_SHA384 \
	NTRU_HRSS_701_SHA384 \
	NTRU_HPS_4096_821_SHA384 \
	SABER_LIGHTSABER_SHA384 \
	SABER_SABER_SHA384 \
	SABER_FIRESABER_SHA384 \
	SIDH_p434_SHA384 \
	SIDH_p503_SHA384 \
	SIDH_p610_SHA384 \
	SIDH_p751_SHA384 \
	SIDH_P434_COMPRESSED_SHA384 \
	SIDH_P503_COMPRESSED_SHA384 \
	SIDH_P610_COMPRESSED_SHA384 \
	SIDH_P751_COMPRESSED_SHA384 \
	SIKE_P434_SHA384 \
	SIKE_P503_SHA384 \
	SIKE_P610_SHA384 \
	SIKE_P751_SHA384 \
	SIKE_P434_COMPRESSED_SHA384 \
	SIKE_P503_COMPRESSED_SHA384 \
	SIKE_P610_COMPRESSED_SHA384 \
	SIKE_P751_COMPRESSED_SHA384 \
	HQC_128_SHA384 \
	HQC_192_SHA384 \
	HQC_256_SHA384 \
	NTRULPR_653_SHA384 \
	NTRULPR_761_SHA384 \
	NTRULPR_857_SHA384 \
	SNTRUP_653_SHA384 \
	SNTRUP_761_SHA384 \
	SNTRUP_857_SHA384
do
        generate_kem_testcase $value >> $KEMCASESFILE
        generate_kem_testfunc $value >> $KEMFUNCSFILE
done

echo "#endif /* WITH_PURE_PQ_KEX */" >> $KEMCASESFILE
echo "#endif /* WITH_PURE_PQ_KEX */" >> $KEMFUNCSFILE
echo "" >> $KEMFUNCSFILE

for value in \
	ECDH_NISTP384_OQSDEFAULT_SHA384 \
	ECDH_NISTP384_BIKE1_L1_CPA_SHA384 \
	ECDH_NISTP384_BIKE1_L3_CPA_SHA384 \
	ECDH_NISTP384_BIKE1_L1_FO_SHA384 \
	ECDH_NISTP384_BIKE1_L3_FO_SHA384 \
	ECDH_NISTP384_CLASSIC_MCELIECE_348864_SHA384 \
	ECDH_NISTP384_CLASSIC_MCELIECE_348864F_SHA384 \
	ECDH_NISTP384_CLASSIC_MCELIECE_460896_SHA384 \
	ECDH_NISTP384_CLASSIC_MCELIECE_460896F_SHA384 \
	ECDH_NISTP384_CLASSIC_MCELIECE_6688128_SHA384 \
	ECDH_NISTP384_CLASSIC_MCELIECE_6688128F_SHA384 \
	ECDH_NISTP384_CLASSIC_MCELIECE_6960119_SHA384 \
	ECDH_NISTP384_CLASSIC_MCELIECE_6960119F_SHA384 \
	ECDH_NISTP384_CLASSIC_MCELIECE_8192128_SHA384 \
	ECDH_NISTP384_CLASSIC_MCELIECE_8192128F_SHA384 \
	ECDH_NISTP384_FRODO_640_AES_SHA384 \
	ECDH_NISTP384_FRODO_640_SHAKE_SHA384 \
	ECDH_NISTP384_FRODO_976_AES_SHA384 \
	ECDH_NISTP384_FRODO_976_SHAKE_SHA384 \
	ECDH_NISTP384_FRODO_1344_AES_SHA384 \
	ECDH_NISTP384_FRODO_1344_SHAKE_SHA384 \
	ECDH_NISTP384_KYBER_512_SHA384 \
	ECDH_NISTP384_KYBER_768_SHA384 \
	ECDH_NISTP384_KYBER_1024_SHA384 \
	ECDH_NISTP384_KYBER_512_90S_SHA384 \
	ECDH_NISTP384_KYBER_768_90S_SHA384 \
	ECDH_NISTP384_KYBER_1024_90S_SHA384 \
	ECDH_NISTP384_NTRU_HPS_2048_509_SHA384 \
	ECDH_NISTP384_NTRU_HPS_2048_677_SHA384 \
	ECDH_NISTP384_NTRU_HRSS_701_SHA384 \
	ECDH_NISTP384_NTRU_HPS_4096_821_SHA384 \
	ECDH_NISTP384_SABER_LIGHTSABER_SHA384 \
	ECDH_NISTP384_SABER_SABER_SHA384 \
	ECDH_NISTP384_SABER_FIRESABER_SHA384 \
	ECDH_NISTP384_SIDH_p434_SHA384 \
	ECDH_NISTP384_SIDH_p503_SHA384 \
	ECDH_NISTP384_SIDH_p610_SHA384 \
	ECDH_NISTP384_SIDH_p751_SHA384 \
	ECDH_NISTP384_SIDH_P434_COMPRESSED_SHA384 \
	ECDH_NISTP384_SIDH_P503_COMPRESSED_SHA384 \
	ECDH_NISTP384_SIDH_P610_COMPRESSED_SHA384 \
	ECDH_NISTP384_SIDH_P751_COMPRESSED_SHA384 \
	ECDH_NISTP384_SIKE_P434_SHA384 \
	ECDH_NISTP384_SIKE_P503_SHA384 \
	ECDH_NISTP384_SIKE_P610_SHA384 \
	ECDH_NISTP384_SIKE_P751_SHA384 \
	ECDH_NISTP384_SIKE_P434_COMPRESSED_SHA384 \
	ECDH_NISTP384_SIKE_P503_COMPRESSED_SHA384 \
	ECDH_NISTP384_SIKE_P610_COMPRESSED_SHA384 \
	ECDH_NISTP384_SIKE_P751_COMPRESSED_SHA384 \
	ECDH_NISTP384_HQC_128_SHA384 \
	ECDH_NISTP384_HQC_192_SHA384 \
	ECDH_NISTP384_HQC_256_SHA384 \
	ECDH_NISTP384_NTRULPR_653_SHA384 \
	ECDH_NISTP384_NTRULPR_761_SHA384 \
	ECDH_NISTP384_NTRULPR_857_SHA384 \
	ECDH_NISTP384_SNTRUP_653_SHA384 \
	ECDH_NISTP384_SNTRUP_761_SHA384 \
	ECDH_NISTP384_SNTRUP_857_SHA384 
do
	generate_kem_testcase $value >> $KEMCASESFILE
	generate_kem_testfunc $value >> $KEMFUNCSFILE
done

echo "#endif /* WITH_POST_QUANTUM_CRYPTO */" >> $KEMCASESFILE
echo "#endif /* WITH_POST_QUANTUM_CRYPTO */" >> $KEMFUNCSFILE

# Signature algorithms (user keys)

rm -f $SIGCASESFILE
rm -f $SIGFUNCSFILE
rm -f $SIGCMAKEFILE

generate_sig_testcase() {
	echo "        cmocka_unit_test_setup_teardown(torture_auth_pubkey_types_${1/-/_},"
	echo "                                        session_setup,"
	echo "                                        session_teardown),"
	echo "        cmocka_unit_test_setup_teardown(torture_auth_pubkey_types_${1/-/_}_nonblocking,"
    echo "                                        session_setup,"
    echo "                                        session_teardown),"
}

generate_sig_testfunc() {
	echo "static void torture_auth_pubkey_types_${1/-/_}(void **state)"
	echo "{"
	echo "    torture_auth_pubkey_types_oqs_wrapper(state, \"${1}\");"
	echo "}"

    echo "static void torture_auth_pubkey_types_${1/-/_}_nonblocking(void **state)"
    echo "{"
    echo "    torture_auth_pubkey_types_oqs_nonblocking_wrapper(state, \"${1}\");"
    echo "}"
}

generate_sig_cmake() {
    echo "    # copy and authorize ${1} key pair"
	echo "    file(COPY keys/id_${1} DESTINATION \${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)"
	echo "    file(COPY keys/id_${1}.pub DESTINATION \${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)"
	echo "    file(READ keys/id_${1}.pub CONTENTS)"
	echo "    file(APPEND \${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys \"\${CONTENTS}\")"
	echo ""
}

echo "#ifdef WITH_POST_QUANTUM_CRYPTO" >> $SIGCASESFILE
echo "#ifdef WITH_POST_QUANTUM_CRYPTO" >> $SIGFUNCSFILE

for value in \
	oqsdefault \
	dilithium2 \
	falcon512 \
	picnicl1full \
	picnic3l1 \
	rainbowiclassic \
	rainbowiiiclassic \
	rainbowvclassic \
	sphincsharaka128frobust \
	sphincssha256128frobust \
	sphincsshake256128frobust \
	rsa3072-oqsdefault \
	p256-oqsdefault \
	rsa3072-dilithium2 \
	p256-dilithium2 \
	rsa3072-falcon512 \
	p256-falcon512 \
	rsa3072-picnicl1full \
	p256-picnicl1full \
	rsa3072-picnic3l1 \
	p256-picnic3l1 \
	rsa3072-rainbowiclassic \
	p256-rainbowiclassic \
	p384-rainbowiiiclassic \
	p521-rainbowvclassic \
	rsa3072-sphincsharaka128frobust \
	p256-sphincsharaka128frobust \
	rsa3072-sphincssha256128frobust \
	p256-sphincssha256128frobust \
	rsa3072-sphincsshake256128frobust \
	p256-sphincsshake256128frobust
do
	generate_sig_testcase $value >> $SIGCASESFILE
	generate_sig_testfunc $value >> $SIGFUNCSFILE
	generate_sig_cmake $value >> $SIGCMAKEFILE
	
	if [ ! -f ../keys/id_${value} ]; then
		echo "Generating keypair id_${value}."
		ssh-keygen -t ${value/-/_} -q -N "" -f ../keys/id_${value} -C bob@bob.com || exit 1
	fi
done

echo "#endif /* WITH_POST_QUANTUM_CRYPTO */" >> $SIGCASESFILE
echo "#endif /* WITH_POST_QUANTUM_CRYPTO */" >> $SIGFUNCSFILE

