/*
 * pkd_daemon.h -- tests use this interface to start, stop pkd
 *                 instances and get results
 *
 * (c) 2014 Jon Simons
 */

#ifndef __PKD_DAEMON_H__
#define __PKD_DAEMON_H__

#include "config.h"

enum pkd_hostkey_type_e {
    PKD_RSA,
#ifdef HAVE_DSA
    PKD_DSA,
#endif
    PKD_ED25519,
    PKD_ECDSA,
#ifdef WITH_POST_QUANTUM_CRYPTO
///// OQS_TEMPLATE_FRAGMENT_ADD_HOSTKEY_TYPES_START
    PKD_FALCON_512,
    PKD_RSA3072_FALCON_512,
    PKD_ECDSA_NISTP256_FALCON_512,
    PKD_FALCON_1024,
    PKD_ECDSA_NISTP521_FALCON_1024,
    PKD_DILITHIUM_2,
    PKD_RSA3072_DILITHIUM_2,
    PKD_ECDSA_NISTP256_DILITHIUM_2,
    PKD_DILITHIUM_3,
    PKD_ECDSA_NISTP384_DILITHIUM_3,
    PKD_DILITHIUM_5,
    PKD_ECDSA_NISTP521_DILITHIUM_5,
    PKD_SPHINCS_HARAKA_128F_SIMPLE,
    PKD_RSA3072_SPHINCS_HARAKA_128F_SIMPLE,
    PKD_ECDSA_NISTP256_SPHINCS_HARAKA_128F_SIMPLE,
    PKD_SPHINCS_SHA256_128F_SIMPLE,
    PKD_RSA3072_SPHINCS_SHA256_128F_SIMPLE,
    PKD_ECDSA_NISTP256_SPHINCS_SHA256_128F_SIMPLE,
    PKD_SPHINCS_SHA256_192S_ROBUST,
    PKD_ECDSA_NISTP384_SPHINCS_SHA256_192S_ROBUST,
    PKD_SPHINCS_SHA256_256F_SIMPLE,
    PKD_ECDSA_NISTP521_SPHINCS_SHA256_256F_SIMPLE,
///// OQS_TEMPLATE_FRAGMENT_ADD_HOSTKEY_TYPES_END
#endif
};

///// OQS_TEMPLATE_FRAGMENT_DEFINE_HYBRID_MACROS_START


#define IS_RSA_HYBRID(alg) ( \
                             (alg) == PKD_RSA3072_FALCON_512 || \
                             (alg) == PKD_RSA3072_DILITHIUM_2 || \
                             (alg) == PKD_RSA3072_SPHINCS_HARAKA_128F_SIMPLE || \
                             (alg) == PKD_RSA3072_SPHINCS_SHA256_128F_SIMPLE)

#define IS_ECDSA_HYBRID(alg) ( \
                               (alg) == PKD_ECDSA_NISTP256_FALCON_512 || \
                               (alg) == PKD_ECDSA_NISTP521_FALCON_1024 || \
                               (alg) == PKD_ECDSA_NISTP256_DILITHIUM_2 || \
                               (alg) == PKD_ECDSA_NISTP384_DILITHIUM_3 || \
                               (alg) == PKD_ECDSA_NISTP521_DILITHIUM_5 || \
                               (alg) == PKD_ECDSA_NISTP256_SPHINCS_HARAKA_128F_SIMPLE || \
                               (alg) == PKD_ECDSA_NISTP256_SPHINCS_SHA256_128F_SIMPLE || \
                               (alg) == PKD_ECDSA_NISTP384_SPHINCS_SHA256_192S_ROBUST || \
                               (alg) == PKD_ECDSA_NISTP521_SPHINCS_SHA256_256F_SIMPLE)
///// OQS_TEMPLATE_FRAGMENT_DEFINE_HYBRID_MACROS_END

#define IS_HYBRID(alg) (IS_RSA_HYBRID(alg) || IS_ECDSA_HYBRID(alg))

///// OQS_TEMPLATE_FRAGMENT_ASSIGN_PQ_KT_START
#define IS_OQS_KEY_TYPE(type) ( \
                                (type) == PKD_FALCON_512 || \
                                (type) == PKD_FALCON_1024 || \
                                (type) == PKD_DILITHIUM_2 || \
                                (type) == PKD_DILITHIUM_3 || \
                                (type) == PKD_DILITHIUM_5 || \
                                (type) == PKD_SPHINCS_HARAKA_128F_SIMPLE || \
                                (type) == PKD_SPHINCS_SHA256_128F_SIMPLE || \
                                (type) == PKD_SPHINCS_SHA256_192S_ROBUST || \
                                (type) == PKD_SPHINCS_SHA256_256F_SIMPLE || \
                                IS_HYBRID(type))
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_PQ_KT_END

struct pkd_daemon_args {
    enum pkd_hostkey_type_e type;
    const char *hostkeypath;

    struct {
        const uint8_t *buf;
        size_t len;
    } payload;

    uint64_t rekey_data_limit;

    struct {
        int list;

        int log_stdout;
        int log_stderr;
        int libssh_log_level;
        int preserve_keys;

        const char *testname;
        const char *testmatch;
        unsigned int iterations;

        struct {
            char *mkdtemp_str;
        } socket_wrapper;
    } opts;
};

struct pkd_result {
    int ok;
};

int pkd_start(struct pkd_daemon_args *args);
void pkd_stop(struct pkd_result *out);

#endif /* __PKD_DAEMON_H__ */
