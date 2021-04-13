#ifdef WITH_POST_QUANTUM_CRYPTO
#ifdef WITH_PURE_PQ_KEX
static void torture_algorithms_oqsdefault_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_OQSDEFAULT_SHA384, NULL, NULL);
}

static void torture_algorithms_bike1_l1_cpa_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_BIKE1_L1_CPA_SHA384, NULL, NULL);
}

static void torture_algorithms_bike1_l3_cpa_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_BIKE1_L3_CPA_SHA384, NULL, NULL);
}

static void torture_algorithms_bike1_l1_fo_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_BIKE1_L1_FO_SHA384, NULL, NULL);
}

static void torture_algorithms_bike1_l3_fo_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_BIKE1_L3_FO_SHA384, NULL, NULL);
}

static void torture_algorithms_classic_mceliece_348864_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_CLASSIC_MCELIECE_348864_SHA384, NULL, NULL);
}

static void torture_algorithms_classic_mceliece_348864f_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_CLASSIC_MCELIECE_348864F_SHA384, NULL, NULL);
}

static void torture_algorithms_classic_mceliece_460896_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_CLASSIC_MCELIECE_460896_SHA384, NULL, NULL);
}

static void torture_algorithms_classic_mceliece_460896f_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_CLASSIC_MCELIECE_460896F_SHA384, NULL, NULL);
}

static void torture_algorithms_classic_mceliece_6688128_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_CLASSIC_MCELIECE_6688128_SHA384, NULL, NULL);
}

static void torture_algorithms_classic_mceliece_6688128f_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_CLASSIC_MCELIECE_6688128F_SHA384, NULL, NULL);
}

static void torture_algorithms_classic_mceliece_6960119_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_CLASSIC_MCELIECE_6960119_SHA384, NULL, NULL);
}

static void torture_algorithms_classic_mceliece_6960119f_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_CLASSIC_MCELIECE_6960119F_SHA384, NULL, NULL);
}

static void torture_algorithms_classic_mceliece_8192128_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_CLASSIC_MCELIECE_8192128_SHA384, NULL, NULL);
}

static void torture_algorithms_classic_mceliece_8192128f_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_CLASSIC_MCELIECE_8192128F_SHA384, NULL, NULL);
}

static void torture_algorithms_frodo_640_aes_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_FRODO_640_AES_SHA384, NULL, NULL);
}

static void torture_algorithms_frodo_640_shake_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_FRODO_640_SHAKE_SHA384, NULL, NULL);
}

static void torture_algorithms_frodo_976_aes_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_FRODO_976_AES_SHA384, NULL, NULL);
}

static void torture_algorithms_frodo_976_shake_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_FRODO_976_SHAKE_SHA384, NULL, NULL);
}

static void torture_algorithms_frodo_1344_aes_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_FRODO_1344_AES_SHA384, NULL, NULL);
}

static void torture_algorithms_frodo_1344_shake_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_FRODO_1344_SHAKE_SHA384, NULL, NULL);
}

static void torture_algorithms_kyber_512_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_KYBER_512_SHA384, NULL, NULL);
}

static void torture_algorithms_kyber_768_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_KYBER_768_SHA384, NULL, NULL);
}

static void torture_algorithms_kyber_1024_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_KYBER_1024_SHA384, NULL, NULL);
}

static void torture_algorithms_kyber_512_90s_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_KYBER_512_90S_SHA384, NULL, NULL);
}

static void torture_algorithms_kyber_768_90s_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_KYBER_768_90S_SHA384, NULL, NULL);
}

static void torture_algorithms_kyber_1024_90s_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_KYBER_1024_90S_SHA384, NULL, NULL);
}

static void torture_algorithms_ntru_hps_2048_509_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_NTRU_HPS_2048_509_SHA384, NULL, NULL);
}

static void torture_algorithms_ntru_hps_2048_677_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_NTRU_HPS_2048_677_SHA384, NULL, NULL);
}

static void torture_algorithms_ntru_hrss_701_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_NTRU_HRSS_701_SHA384, NULL, NULL);
}

static void torture_algorithms_ntru_hps_4096_821_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_NTRU_HPS_4096_821_SHA384, NULL, NULL);
}

static void torture_algorithms_saber_lightsaber_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SABER_LIGHTSABER_SHA384, NULL, NULL);
}

static void torture_algorithms_saber_saber_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SABER_SABER_SHA384, NULL, NULL);
}

static void torture_algorithms_saber_firesaber_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SABER_FIRESABER_SHA384, NULL, NULL);
}

static void torture_algorithms_sidh_p434_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SIDH_p434_SHA384, NULL, NULL);
}

static void torture_algorithms_sidh_p503_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SIDH_p503_SHA384, NULL, NULL);
}

static void torture_algorithms_sidh_p610_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SIDH_p610_SHA384, NULL, NULL);
}

static void torture_algorithms_sidh_p751_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SIDH_p751_SHA384, NULL, NULL);
}

static void torture_algorithms_sidh_p434_compressed_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SIDH_P434_COMPRESSED_SHA384, NULL, NULL);
}

static void torture_algorithms_sidh_p503_compressed_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SIDH_P503_COMPRESSED_SHA384, NULL, NULL);
}

static void torture_algorithms_sidh_p610_compressed_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SIDH_P610_COMPRESSED_SHA384, NULL, NULL);
}

static void torture_algorithms_sidh_p751_compressed_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SIDH_P751_COMPRESSED_SHA384, NULL, NULL);
}

static void torture_algorithms_sike_p434_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SIKE_P434_SHA384, NULL, NULL);
}

static void torture_algorithms_sike_p503_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SIKE_P503_SHA384, NULL, NULL);
}

static void torture_algorithms_sike_p610_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SIKE_P610_SHA384, NULL, NULL);
}

static void torture_algorithms_sike_p751_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SIKE_P751_SHA384, NULL, NULL);
}

static void torture_algorithms_sike_p434_compressed_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SIKE_P434_COMPRESSED_SHA384, NULL, NULL);
}

static void torture_algorithms_sike_p503_compressed_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SIKE_P503_COMPRESSED_SHA384, NULL, NULL);
}

static void torture_algorithms_sike_p610_compressed_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SIKE_P610_COMPRESSED_SHA384, NULL, NULL);
}

static void torture_algorithms_sike_p751_compressed_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SIKE_P751_COMPRESSED_SHA384, NULL, NULL);
}

static void torture_algorithms_hqc_128_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_HQC_128_SHA384, NULL, NULL);
}

static void torture_algorithms_hqc_192_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_HQC_192_SHA384, NULL, NULL);
}

static void torture_algorithms_hqc_256_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_HQC_256_SHA384, NULL, NULL);
}

static void torture_algorithms_ntrulpr_653_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_NTRULPR_653_SHA384, NULL, NULL);
}

static void torture_algorithms_ntrulpr_761_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_NTRULPR_761_SHA384, NULL, NULL);
}

static void torture_algorithms_ntrulpr_857_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_NTRULPR_857_SHA384, NULL, NULL);
}

static void torture_algorithms_sntrup_653_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SNTRUP_653_SHA384, NULL, NULL);
}

static void torture_algorithms_sntrup_761_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SNTRUP_761_SHA384, NULL, NULL);
}

static void torture_algorithms_sntrup_857_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_SNTRUP_857_SHA384, NULL, NULL);
}

#endif /* WITH_PURE_PQ_KEX */

static void torture_algorithms_ecdh_nistp384_oqsdefault_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_OQSDEFAULT_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_bike1_l1_cpa_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_BIKE1_L1_CPA_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_bike1_l3_cpa_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_BIKE1_L3_CPA_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_bike1_l1_fo_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_BIKE1_L1_FO_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_bike1_l3_fo_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_BIKE1_L3_FO_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_classic_mceliece_348864_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_CLASSIC_MCELIECE_348864_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_classic_mceliece_348864f_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_CLASSIC_MCELIECE_348864F_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_classic_mceliece_460896_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_classic_mceliece_460896f_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896F_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_classic_mceliece_6688128_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_CLASSIC_MCELIECE_6688128_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_classic_mceliece_6688128f_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_CLASSIC_MCELIECE_6688128F_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_classic_mceliece_6960119_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_CLASSIC_MCELIECE_6960119_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_classic_mceliece_6960119f_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_CLASSIC_MCELIECE_6960119F_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_classic_mceliece_8192128_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_CLASSIC_MCELIECE_8192128_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_classic_mceliece_8192128f_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_CLASSIC_MCELIECE_8192128F_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_frodo_640_aes_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_FRODO_640_AES_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_frodo_640_shake_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_FRODO_640_SHAKE_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_frodo_976_aes_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_FRODO_976_AES_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_frodo_976_shake_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_FRODO_976_SHAKE_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_frodo_1344_aes_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_FRODO_1344_AES_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_frodo_1344_shake_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_FRODO_1344_SHAKE_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_kyber_512_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_KYBER_512_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_kyber_768_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_KYBER_768_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_kyber_1024_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_KYBER_1024_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_kyber_512_90s_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_KYBER_512_90S_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_kyber_768_90s_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_KYBER_768_90S_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_kyber_1024_90s_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_KYBER_1024_90S_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_ntru_hps_2048_509_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_NTRU_HPS_2048_509_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_ntru_hps_2048_677_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_NTRU_HPS_2048_677_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_ntru_hrss_701_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_NTRU_HRSS_701_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_ntru_hps_4096_821_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_NTRU_HPS_4096_821_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_saber_lightsaber_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SABER_LIGHTSABER_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_saber_saber_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SABER_SABER_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_saber_firesaber_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SABER_FIRESABER_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sidh_p434_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SIDH_p434_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sidh_p503_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SIDH_p503_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sidh_p610_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SIDH_p610_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sidh_p751_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SIDH_p751_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sidh_p434_compressed_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SIDH_P434_COMPRESSED_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sidh_p503_compressed_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SIDH_P503_COMPRESSED_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sidh_p610_compressed_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SIDH_P610_COMPRESSED_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sidh_p751_compressed_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SIDH_P751_COMPRESSED_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sike_p434_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SIKE_P434_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sike_p503_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SIKE_P503_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sike_p610_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SIKE_P610_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sike_p751_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SIKE_P751_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sike_p434_compressed_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SIKE_P434_COMPRESSED_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sike_p503_compressed_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SIKE_P503_COMPRESSED_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sike_p610_compressed_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SIKE_P610_COMPRESSED_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sike_p751_compressed_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SIKE_P751_COMPRESSED_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_hqc_128_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_HQC_128_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_hqc_192_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_HQC_192_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_hqc_256_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_HQC_256_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_ntrulpr_653_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_NTRULPR_653_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_ntrulpr_761_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_NTRULPR_761_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_ntrulpr_857_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_NTRULPR_857_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sntrup_653_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SNTRUP_653_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sntrup_761_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SNTRUP_761_SHA384, NULL, NULL);
}

static void torture_algorithms_ecdh_nistp384_sntrup_857_sha384(void** state)
{
    struct torture_state* s = *state;

    if (ssh_fips_mode()) {
        skip();
    }

    test_algorithm(s->ssh.session, KEX_ECDH_NISTP384_SNTRUP_857_SHA384, NULL, NULL);
}

#endif /* WITH_POST_QUANTUM_CRYPTO */
