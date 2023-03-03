/*
 * pkd_keyutil.c -- pkd test key utilities
 *
 * (c) 2014 Jon Simons
 */

#include "config.h"

#include <setjmp.h> // for cmocka
#include <stdarg.h> // for cmocka
#include <unistd.h> // for cmocka
#include <cmocka.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "torture.h" // for ssh_fips_mode()

#include "pkd_client.h"
#include "pkd_keyutil.h"
#include "pkd_util.h"

void setup_rsa_key() {
    int rc = 0;
    if (access(LIBSSH_RSA_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t rsa -q -N \"\" -f "
                            LIBSSH_RSA_TESTKEY);
    }
    assert_int_equal(rc, 0);
}

void setup_ed25519_key() {
    int rc = 0;
    if (access(LIBSSH_ED25519_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ed25519 -q -N \"\" -f "
                            LIBSSH_ED25519_TESTKEY);
    }
    assert_int_equal(rc, 0);
}

#ifdef HAVE_DSA
void setup_dsa_key() {
    int rc = 0;
    if (access(LIBSSH_DSA_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t dsa -q -N \"\" -f "
                            LIBSSH_DSA_TESTKEY);
    }
    assert_int_equal(rc, 0);
}
#endif

void setup_ecdsa_keys() {
    int rc = 0;

    if (access(LIBSSH_ECDSA_256_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ecdsa -b 256 -q -N \"\" -f "
                            LIBSSH_ECDSA_256_TESTKEY);
        assert_int_equal(rc, 0);
    }
    if (access(LIBSSH_ECDSA_384_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ecdsa -b 384 -q -N \"\" -f "
                            LIBSSH_ECDSA_384_TESTKEY);
        assert_int_equal(rc, 0);
    }
    if (access(LIBSSH_ECDSA_521_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ecdsa -b 521 -q -N \"\" -f "
                            LIBSSH_ECDSA_521_TESTKEY);
        assert_int_equal(rc, 0);
    }
}

#ifdef WITH_POST_QUANTUM_CRYPTO
void setup_post_quantum_keys() {
    int rc = 0;
///// OQS_TEMPLATE_FRAGMENT_SETUP_PQ_KEYS_START
    if (access(LIBSSH_FALCON_512_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t FALCON512 -q -N \"\" -f "
                            LIBSSH_FALCON_512_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_RSA3072_FALCON_512_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t RSA3072_FALCON512 -q -N \"\" -f "
                            LIBSSH_RSA3072_FALCON_512_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_ECDSA_NISTP256_FALCON_512_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP256_FALCON512 -q -N \"\" -f "
                            LIBSSH_ECDSA_NISTP256_FALCON_512_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_FALCON_1024_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t FALCON1024 -q -N \"\" -f "
                            LIBSSH_FALCON_1024_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_ECDSA_NISTP521_FALCON_1024_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP521_FALCON1024 -q -N \"\" -f "
                            LIBSSH_ECDSA_NISTP521_FALCON_1024_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_DILITHIUM_2_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t DILITHIUM2 -q -N \"\" -f "
                            LIBSSH_DILITHIUM_2_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_RSA3072_DILITHIUM_2_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t RSA3072_DILITHIUM2 -q -N \"\" -f "
                            LIBSSH_RSA3072_DILITHIUM_2_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_ECDSA_NISTP256_DILITHIUM_2_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP256_DILITHIUM2 -q -N \"\" -f "
                            LIBSSH_ECDSA_NISTP256_DILITHIUM_2_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_DILITHIUM_3_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t DILITHIUM3 -q -N \"\" -f "
                            LIBSSH_DILITHIUM_3_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_ECDSA_NISTP384_DILITHIUM_3_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP384_DILITHIUM3 -q -N \"\" -f "
                            LIBSSH_ECDSA_NISTP384_DILITHIUM_3_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_DILITHIUM_5_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t DILITHIUM5 -q -N \"\" -f "
                            LIBSSH_DILITHIUM_5_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_ECDSA_NISTP521_DILITHIUM_5_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP521_DILITHIUM5 -q -N \"\" -f "
                            LIBSSH_ECDSA_NISTP521_DILITHIUM_5_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t SPHINCSHARAKA128FSIMPLE -q -N \"\" -f "
                            LIBSSH_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_RSA3072_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t RSA3072_SPHINCSHARAKA128FSIMPLE -q -N \"\" -f "
                            LIBSSH_RSA3072_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_ECDSA_NISTP256_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP256_SPHINCSHARAKA128FSIMPLE -q -N \"\" -f "
                            LIBSSH_ECDSA_NISTP256_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_SPHINCS_SHA256_128F_SIMPLE_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t SPHINCSSHA256128FSIMPLE -q -N \"\" -f "
                            LIBSSH_SPHINCS_SHA256_128F_SIMPLE_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_RSA3072_SPHINCS_SHA256_128F_SIMPLE_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t RSA3072_SPHINCSSHA256128FSIMPLE -q -N \"\" -f "
                            LIBSSH_RSA3072_SPHINCS_SHA256_128F_SIMPLE_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_ECDSA_NISTP256_SPHINCS_SHA256_128F_SIMPLE_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP256_SPHINCSSHA256128FSIMPLE -q -N \"\" -f "
                            LIBSSH_ECDSA_NISTP256_SPHINCS_SHA256_128F_SIMPLE_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_SPHINCS_SHA256_192S_ROBUST_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t SPHINCSSHA256192SROBUST -q -N \"\" -f "
                            LIBSSH_SPHINCS_SHA256_192S_ROBUST_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_ECDSA_NISTP384_SPHINCS_SHA256_192S_ROBUST_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP384_SPHINCSSHA256192SROBUST -q -N \"\" -f "
                            LIBSSH_ECDSA_NISTP384_SPHINCS_SHA256_192S_ROBUST_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_SPHINCS_SHA256_256F_SIMPLE_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t SPHINCSSHA256256FSIMPLE -q -N \"\" -f "
                            LIBSSH_SPHINCS_SHA256_256F_SIMPLE_TESTKEY);
    }
    assert_int_equal(rc, 0);
    if (access(LIBSSH_ECDSA_NISTP521_SPHINCS_SHA256_256F_SIMPLE_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP521_SPHINCSSHA256256FSIMPLE -q -N \"\" -f "
                            LIBSSH_ECDSA_NISTP521_SPHINCS_SHA256_256F_SIMPLE_TESTKEY);
    }
    assert_int_equal(rc, 0);
///// OQS_TEMPLATE_FRAGMENT_SETUP_PQ_KEYS_END
}
#endif

void cleanup_rsa_key() {
    cleanup_key(LIBSSH_RSA_TESTKEY);
}

void cleanup_ed25519_key() {
    cleanup_key(LIBSSH_ED25519_TESTKEY);
}

#ifdef HAVE_DSA
void cleanup_dsa_key() {
    cleanup_key(LIBSSH_DSA_TESTKEY);
}
#endif

void cleanup_ecdsa_keys() {
    cleanup_key(LIBSSH_ECDSA_256_TESTKEY);
    cleanup_key(LIBSSH_ECDSA_384_TESTKEY);
    cleanup_key(LIBSSH_ECDSA_521_TESTKEY);
}

#ifdef WITH_POST_QUANTUM_CRYPTO
void cleanup_post_quantum_keys() {
///// OQS_TEMPLATE_FRAGMENT_CLEANUP_PQ_KEYS_START
    cleanup_key(LIBSSH_FALCON_512_TESTKEY);
    cleanup_key(LIBSSH_RSA3072_FALCON_512_TESTKEY);
    cleanup_key(LIBSSH_ECDSA_NISTP256_FALCON_512_TESTKEY);
    cleanup_key(LIBSSH_FALCON_1024_TESTKEY);
    cleanup_key(LIBSSH_ECDSA_NISTP521_FALCON_1024_TESTKEY);
    cleanup_key(LIBSSH_DILITHIUM_2_TESTKEY);
    cleanup_key(LIBSSH_RSA3072_DILITHIUM_2_TESTKEY);
    cleanup_key(LIBSSH_ECDSA_NISTP256_DILITHIUM_2_TESTKEY);
    cleanup_key(LIBSSH_DILITHIUM_3_TESTKEY);
    cleanup_key(LIBSSH_ECDSA_NISTP384_DILITHIUM_3_TESTKEY);
    cleanup_key(LIBSSH_DILITHIUM_5_TESTKEY);
    cleanup_key(LIBSSH_ECDSA_NISTP521_DILITHIUM_5_TESTKEY);
    cleanup_key(LIBSSH_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY);
    cleanup_key(LIBSSH_RSA3072_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY);
    cleanup_key(LIBSSH_ECDSA_NISTP256_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY);
    cleanup_key(LIBSSH_SPHINCS_SHA256_128F_SIMPLE_TESTKEY);
    cleanup_key(LIBSSH_RSA3072_SPHINCS_SHA256_128F_SIMPLE_TESTKEY);
    cleanup_key(LIBSSH_ECDSA_NISTP256_SPHINCS_SHA256_128F_SIMPLE_TESTKEY);
    cleanup_key(LIBSSH_SPHINCS_SHA256_192S_ROBUST_TESTKEY);
    cleanup_key(LIBSSH_ECDSA_NISTP384_SPHINCS_SHA256_192S_ROBUST_TESTKEY);
    cleanup_key(LIBSSH_SPHINCS_SHA256_256F_SIMPLE_TESTKEY);
    cleanup_key(LIBSSH_ECDSA_NISTP521_SPHINCS_SHA256_256F_SIMPLE_TESTKEY);
///// OQS_TEMPLATE_FRAGMENT_CLEANUP_PQ_KEYS_END
}
#endif

void setup_openssh_client_keys() {
    int rc = 0;

    if (access(OPENSSH_CA_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t rsa -q -N \"\" -f "
                            OPENSSH_CA_TESTKEY);
    }
    assert_int_equal(rc, 0);

    if (access(OPENSSH_RSA_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t rsa -q -N \"\" -f "
                            OPENSSH_RSA_TESTKEY);
    }
    assert_int_equal(rc, 0);

    if (access(OPENSSH_RSA_TESTKEY "-cert.pub", F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -I ident -s " OPENSSH_CA_TESTKEY " "
                            OPENSSH_RSA_TESTKEY ".pub 2>/dev/null");
    }
    assert_int_equal(rc, 0);

    if (access(OPENSSH_RSA_TESTKEY "-sha256-cert.pub", F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -I ident -t rsa-sha2-256 "
                            "-s " OPENSSH_CA_TESTKEY " "
                            OPENSSH_RSA_TESTKEY ".pub 2>/dev/null");
    }
    assert_int_equal(rc, 0);

    if (access(OPENSSH_ECDSA256_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ecdsa -b 256 -q -N \"\" -f "
                            OPENSSH_ECDSA256_TESTKEY);
    }
    assert_int_equal(rc, 0);

    if (access(OPENSSH_ECDSA256_TESTKEY "-cert.pub", F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -I ident -s " OPENSSH_CA_TESTKEY " "
                            OPENSSH_ECDSA256_TESTKEY ".pub 2>/dev/null");
    }
    assert_int_equal(rc, 0);

    if (access(OPENSSH_ECDSA384_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ecdsa -b 384 -q -N \"\" -f "
                            OPENSSH_ECDSA384_TESTKEY);
    }
    assert_int_equal(rc, 0);

    if (access(OPENSSH_ECDSA384_TESTKEY "-cert.pub", F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -I ident -s " OPENSSH_CA_TESTKEY " "
                            OPENSSH_ECDSA384_TESTKEY ".pub 2>/dev/null");
    }
    assert_int_equal(rc, 0);

    if (access(OPENSSH_ECDSA521_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ecdsa -b 521 -q -N \"\" -f "
                            OPENSSH_ECDSA521_TESTKEY);
    }
    assert_int_equal(rc, 0);

    if (access(OPENSSH_ECDSA521_TESTKEY "-cert.pub", F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -I ident -s " OPENSSH_CA_TESTKEY " "
                            OPENSSH_ECDSA521_TESTKEY ".pub 2>/dev/null");
    }
    assert_int_equal(rc, 0);

    if (!ssh_fips_mode()) {
#ifdef HAVE_DSA
        if (access(OPENSSH_DSA_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t dsa -q -N \"\" -f "
                    OPENSSH_DSA_TESTKEY);
        }
        assert_int_equal(rc, 0);

        if (access(OPENSSH_DSA_TESTKEY "-cert.pub", F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -I ident -s " OPENSSH_CA_TESTKEY
                    " " OPENSSH_DSA_TESTKEY ".pub 2>/dev/null");
        }
        assert_int_equal(rc, 0);
#endif

        if (access(OPENSSH_ED25519_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t ed25519 -q -N \"\" -f "
                    OPENSSH_ED25519_TESTKEY);
        }
        assert_int_equal(rc, 0);

        if (access(OPENSSH_ED25519_TESTKEY "-cert.pub", F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -I ident -s " OPENSSH_CA_TESTKEY " "
                    OPENSSH_ED25519_TESTKEY ".pub 2>/dev/null");
        }
        assert_int_equal(rc, 0);
    }

#ifdef WITH_POST_QUANTUM_CRYPTO
    if (!ssh_fips_mode()) {
        /*
         * As of this time, ssh-keygen's usage text hasn't been updated with the correct list of key types. Newer key types have not been
         * added, and removed types are still listed. For the authoritative list of options, see the second field
         * in the keytypes struct as sshkey.c:119 in OpenSSH for the correct string to pass to ssh-keygen's -t parameter.
         */
///// OQS_TEMPLATE_FRAGMENT_SETUP_CLIENT_PQ_KEYS_START
        if (access(OPENSSH_FALCON_512_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t FALCON512 -q -N \"\" -f "
                                OPENSSH_FALCON_512_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_RSA3072_FALCON_512_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t RSA3072_FALCON512 -q -N \"\" -f "
                                OPENSSH_RSA3072_FALCON_512_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_ECDSA_NISTP256_FALCON_512_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP256_FALCON512 -q -N \"\" -f "
                                OPENSSH_ECDSA_NISTP256_FALCON_512_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_FALCON_1024_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t FALCON1024 -q -N \"\" -f "
                                OPENSSH_FALCON_1024_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_ECDSA_NISTP521_FALCON_1024_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP521_FALCON1024 -q -N \"\" -f "
                                OPENSSH_ECDSA_NISTP521_FALCON_1024_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_DILITHIUM_2_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t DILITHIUM2 -q -N \"\" -f "
                                OPENSSH_DILITHIUM_2_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_RSA3072_DILITHIUM_2_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t RSA3072_DILITHIUM2 -q -N \"\" -f "
                                OPENSSH_RSA3072_DILITHIUM_2_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_ECDSA_NISTP256_DILITHIUM_2_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP256_DILITHIUM2 -q -N \"\" -f "
                                OPENSSH_ECDSA_NISTP256_DILITHIUM_2_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_DILITHIUM_3_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t DILITHIUM3 -q -N \"\" -f "
                                OPENSSH_DILITHIUM_3_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_ECDSA_NISTP384_DILITHIUM_3_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP384_DILITHIUM3 -q -N \"\" -f "
                                OPENSSH_ECDSA_NISTP384_DILITHIUM_3_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_DILITHIUM_5_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t DILITHIUM5 -q -N \"\" -f "
                                OPENSSH_DILITHIUM_5_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_ECDSA_NISTP521_DILITHIUM_5_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP521_DILITHIUM5 -q -N \"\" -f "
                                OPENSSH_ECDSA_NISTP521_DILITHIUM_5_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t SPHINCSHARAKA128FSIMPLE -q -N \"\" -f "
                                OPENSSH_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_RSA3072_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t RSA3072_SPHINCSHARAKA128FSIMPLE -q -N \"\" -f "
                                OPENSSH_RSA3072_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_ECDSA_NISTP256_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP256_SPHINCSHARAKA128FSIMPLE -q -N \"\" -f "
                                OPENSSH_ECDSA_NISTP256_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_SPHINCS_SHA256_128F_SIMPLE_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t SPHINCSSHA256128FSIMPLE -q -N \"\" -f "
                                OPENSSH_SPHINCS_SHA256_128F_SIMPLE_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_RSA3072_SPHINCS_SHA256_128F_SIMPLE_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t RSA3072_SPHINCSSHA256128FSIMPLE -q -N \"\" -f "
                                OPENSSH_RSA3072_SPHINCS_SHA256_128F_SIMPLE_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_ECDSA_NISTP256_SPHINCS_SHA256_128F_SIMPLE_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP256_SPHINCSSHA256128FSIMPLE -q -N \"\" -f "
                                OPENSSH_ECDSA_NISTP256_SPHINCS_SHA256_128F_SIMPLE_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_SPHINCS_SHA256_192S_ROBUST_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t SPHINCSSHA256192SROBUST -q -N \"\" -f "
                                OPENSSH_SPHINCS_SHA256_192S_ROBUST_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_ECDSA_NISTP384_SPHINCS_SHA256_192S_ROBUST_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP384_SPHINCSSHA256192SROBUST -q -N \"\" -f "
                                OPENSSH_ECDSA_NISTP384_SPHINCS_SHA256_192S_ROBUST_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_SPHINCS_SHA256_256F_SIMPLE_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t SPHINCSSHA256256FSIMPLE -q -N \"\" -f "
                                OPENSSH_SPHINCS_SHA256_256F_SIMPLE_TESTKEY);
        }
        assert_int_equal(rc, 0);
        if (access(OPENSSH_ECDSA_NISTP521_SPHINCS_SHA256_256F_SIMPLE_TESTKEY, F_OK) != 0) {
            rc = system_checked(OPENSSH_KEYGEN " -t ECDSA_NISTP521_SPHINCSSHA256256FSIMPLE -q -N \"\" -f "
                                OPENSSH_ECDSA_NISTP521_SPHINCS_SHA256_256F_SIMPLE_TESTKEY);
        }
        assert_int_equal(rc, 0);
///// OQS_TEMPLATE_FRAGMENT_SETUP_CLIENT_PQ_KEYS_END
    }
#endif

}

void cleanup_openssh_client_keys() {
    cleanup_key(OPENSSH_CA_TESTKEY);
    cleanup_key(OPENSSH_RSA_TESTKEY);
    cleanup_file(OPENSSH_RSA_TESTKEY "-sha256-cert.pub");
    cleanup_key(OPENSSH_ECDSA256_TESTKEY);
    cleanup_key(OPENSSH_ECDSA384_TESTKEY);
    cleanup_key(OPENSSH_ECDSA521_TESTKEY);
    if (!ssh_fips_mode()) {
        cleanup_key(OPENSSH_ED25519_TESTKEY);
#ifdef HAVE_DSA
        cleanup_key(OPENSSH_DSA_TESTKEY);
#endif
    }
#ifdef WITH_POST_QUANTUM_CRYPTO
    if (!ssh_fips_mode()) {
///// OQS_TEMPLATE_FRAGMENT_CLEANUP_CLIENT_PQ_KEYS_START
        cleanup_key(OPENSSH_FALCON_512_TESTKEY);
        cleanup_key(OPENSSH_RSA3072_FALCON_512_TESTKEY);
        cleanup_key(OPENSSH_ECDSA_NISTP256_FALCON_512_TESTKEY);
        cleanup_key(OPENSSH_FALCON_1024_TESTKEY);
        cleanup_key(OPENSSH_ECDSA_NISTP521_FALCON_1024_TESTKEY);
        cleanup_key(OPENSSH_DILITHIUM_2_TESTKEY);
        cleanup_key(OPENSSH_RSA3072_DILITHIUM_2_TESTKEY);
        cleanup_key(OPENSSH_ECDSA_NISTP256_DILITHIUM_2_TESTKEY);
        cleanup_key(OPENSSH_DILITHIUM_3_TESTKEY);
        cleanup_key(OPENSSH_ECDSA_NISTP384_DILITHIUM_3_TESTKEY);
        cleanup_key(OPENSSH_DILITHIUM_5_TESTKEY);
        cleanup_key(OPENSSH_ECDSA_NISTP521_DILITHIUM_5_TESTKEY);
        cleanup_key(OPENSSH_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY);
        cleanup_key(OPENSSH_RSA3072_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY);
        cleanup_key(OPENSSH_ECDSA_NISTP256_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY);
        cleanup_key(OPENSSH_SPHINCS_SHA256_128F_SIMPLE_TESTKEY);
        cleanup_key(OPENSSH_RSA3072_SPHINCS_SHA256_128F_SIMPLE_TESTKEY);
        cleanup_key(OPENSSH_ECDSA_NISTP256_SPHINCS_SHA256_128F_SIMPLE_TESTKEY);
        cleanup_key(OPENSSH_SPHINCS_SHA256_192S_ROBUST_TESTKEY);
        cleanup_key(OPENSSH_ECDSA_NISTP384_SPHINCS_SHA256_192S_ROBUST_TESTKEY);
        cleanup_key(OPENSSH_SPHINCS_SHA256_256F_SIMPLE_TESTKEY);
        cleanup_key(OPENSSH_ECDSA_NISTP521_SPHINCS_SHA256_256F_SIMPLE_TESTKEY);
///// OQS_TEMPLATE_FRAGMENT_CLEANUP_CLIENT_PQ_KEYS_END
    }
#endif
}

void setup_dropbear_client_rsa_key() {
    int rc = 0;
    if (access(DROPBEAR_RSA_TESTKEY, F_OK) != 0) {
        rc = system_checked(DROPBEAR_KEYGEN " -t rsa -f "
                            DROPBEAR_RSA_TESTKEY " 1>/dev/null 2>/dev/null");
    }
    assert_int_equal(rc, 0);
}

void cleanup_dropbear_client_rsa_key() {
    unlink(DROPBEAR_RSA_TESTKEY);
}
