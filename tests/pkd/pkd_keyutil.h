/*
 * pkd_keyutil.h --
 *
 * (c) 2014 Jon Simons
 */

#ifndef __PKD_KEYUTIL_H__
#define __PKD_KEYUTIL_H__

#include "config.h"

/* Server keys. */
#ifdef HAVE_DSA
#define LIBSSH_DSA_TESTKEY        "libssh_testkey.id_dsa"
#endif
#define LIBSSH_RSA_TESTKEY        "libssh_testkey.id_rsa"
#define LIBSSH_ED25519_TESTKEY    "libssh_testkey.id_ed25519"
#define LIBSSH_ECDSA_256_TESTKEY  "libssh_testkey.id_ecdsa256"
#define LIBSSH_ECDSA_384_TESTKEY  "libssh_testkey.id_ecdsa384"
#define LIBSSH_ECDSA_521_TESTKEY  "libssh_testkey.id_ecdsa521"
#ifdef WITH_POST_QUANTUM_CRYPTO
#define LIBSSH_OQSDEFAULT_TESTKEY                              "libssh_testkey.id_oqsdefault"
#define LIBSSH_DILITHIUM_2_TESTKEY                             "libssh_testkey.id_dilithium_2"
#define LIBSSH_FALCON_512_TESTKEY                              "libssh_testkey.id_falcon_512"
#define LIBSSH_PICNIC_L1FULL_TESTKEY                           "libssh_testkey.id_picnic_l1full"
#define LIBSSH_PICNIC3_L1_TESTKEY                              "libssh_testkey.id_picnic3_l1"
#define LIBSSH_RAINBOW_I_CLASSIC_TESTKEY                       "libssh_testkey.id_rainbow_i_classic"
#define LIBSSH_RAINBOW_III_CLASSIC_TESTKEY                     "libssh_testkey.id_rainbow_iii_classic"
#define LIBSSH_RAINBOW_V_CLASSIC_TESTKEY                       "libssh_testkey.id_rainbow_v_classic"
#define LIBSSH_SPHINCS_HARAKA_128F_ROBUST_TESTKEY              "libssh_testkey.id_sphincs_haraka_128f_robust"
#define LIBSSH_SPHINCS_SHA256_128F_ROBUST_TESTKEY              "libssh_testkey.id_sphincs_sha256_128f_robust"
#define LIBSSH_SPHINCS_SHAKE256_128F_ROBUST_TESTKEY            "libssh_testkey.id_sphincs_shake256_128f_robust"
#define LIBSSH_RSA3072_OQSDEFAULT_TESTKEY                      "libssh_testkey.id_rsa3072_oqsdefault"
#define LIBSSH_P256_OQSDEFAULT_TESTKEY                         "libssh_testkey.id_p256_oqsdefault"
#define LIBSSH_RSA3072_DILITHIUM_2_TESTKEY                     "libssh_testkey.id_rsa3072_dilithium_2"
#define LIBSSH_P256_DILITHIUM_2_TESTKEY                        "libssh_testkey.id_p256_dilithium_2"
#define LIBSSH_RSA3072_FALCON_512_TESTKEY                      "libssh_testkey.id_rsa3072_falcon_512"
#define LIBSSH_P256_FALCON_512_TESTKEY                         "libssh_testkey.id_p256_falcon_512"
#define LIBSSH_RSA3072_PICNIC_L1FULL_TESTKEY                   "libssh_testkey.id_rsa3072_picnic_l1full"
#define LIBSSH_P256_PICNIC_L1FULL_TESTKEY                      "libssh_testkey.id_p256_picnic_l1full"
#define LIBSSH_RSA3072_PICNIC3_L1_TESTKEY                      "libssh_testkey.id_rsa3072_picnic3_l1"
#define LIBSSH_P256_PICNIC3_L1_TESTKEY                         "libssh_testkey.id_p256_picnic3_l1"
#define LIBSSH_RSA3072_RAINBOW_I_CLASSIC_TESTKEY               "libssh_testkey.id_rsa3072_rainbow_i_classic"
#define LIBSSH_P256_RAINBOW_I_CLASSIC_TESTKEY                  "libssh_testkey.id_p256_rainbow_i_classic"
#define LIBSSH_P384_RAINBOW_III_CLASSIC_TESTKEY                "libssh_testkey.id_p384_rainbow_iii_classic"
#define LIBSSH_P521_RAINBOW_V_CLASSIC_TESTKEY                  "libssh_testkey.id_p521_rainbow_v_classic"
#define LIBSSH_RSA3072_SPHINCS_HARAKA_128F_ROBUST_TESTKEY      "libssh_testkey.id_rsa3072_sphincs_haraka_128f_robust"
#define LIBSSH_P256_SPHINCS_HARAKA_128F_ROBUST_TESTKEY         "libssh_testkey.id_p256_sphincs_haraka_128f_robust"
#define LIBSSH_RSA3072_SPHINCS_SHA256_128F_ROBUST_TESTKEY      "libssh_testkey.id_rsa3072_sphincs_sha256_128f_robust"
#define LIBSSH_P256_SPHINCS_SHA256_128F_ROBUST_TESTKEY         "libssh_testkey.id_p256_sphincs_sha256_128f_robust"
#define LIBSSH_RSA3072_SPHINCS_SHAKE256_128F_ROBUST_TESTKEY    "libssh_testkey.id_rsa3072_sphincs_shake256_128f_robust"
#define LIBSSH_P256_SPHINCS_SHAKE256_128F_ROBUST_TESTKEY       "libssh_testkey.id_p256_sphincs_shae256_128f_robust"
#endif

#ifdef HAVE_DSA
void setup_dsa_key(void);
#endif
void setup_rsa_key(void);
void setup_ed25519_key(void);
void setup_ecdsa_keys(void);
#ifdef WITH_POST_QUANTUM_CRYPTO
void setup_post_quantum_keys(void);
#endif
#ifdef HAVE_DSA
void cleanup_dsa_key(void);
#endif
void cleanup_rsa_key(void);
void cleanup_ed25519_key(void);
void cleanup_ecdsa_keys(void);
#ifdef WITH_POST_QUANTUM_CRYPTO
void cleanup_post_quantum_keys(void);
#endif

/* Client keys. */
#ifdef HAVE_DSA
#define OPENSSH_DSA_TESTKEY       "openssh_testkey.id_dsa"
#endif
#define OPENSSH_RSA_TESTKEY       "openssh_testkey.id_rsa"
#define OPENSSH_ECDSA256_TESTKEY  "openssh_testkey.id_ecdsa256"
#define OPENSSH_ECDSA384_TESTKEY  "openssh_testkey.id_ecdsa384"
#define OPENSSH_ECDSA521_TESTKEY  "openssh_testkey.id_ecdsa521"
#define OPENSSH_ED25519_TESTKEY   "openssh_testkey.id_ed25519"
#ifdef WITH_POST_QUANTUM_CRYPTO
#define OPENSSH_OQSDEFAULT_TESTKEY                              "openssh_testkey.id_oqsdefault"
#define OPENSSH_DILITHIUM_2_TESTKEY                             "openssh_testkey.id_dilithium_2"
#define OPENSSH_FALCON_512_TESTKEY                              "openssh_testkey.id_falcon_512"
#define OPENSSH_PICNIC_L1FULL_TESTKEY                           "openssh_testkey.id_picnic_l1full"
#define OPENSSH_PICNIC3_L1_TESTKEY                              "openssh_testkey.id_picnic3_l1"
#define OPENSSH_RAINBOW_I_CLASSIC_TESTKEY                       "openssh_testkey.id_rainbow_i_classic"
#define OPENSSH_RAINBOW_III_CLASSIC_TESTKEY                     "openssh_testkey.id_rainbow_iii_classic"
#define OPENSSH_RAINBOW_V_CLASSIC_TESTKEY                       "openssh_testkey.id_rainbow_v_classic"
#define OPENSSH_SPHINCS_HARAKA_128F_ROBUST_TESTKEY              "openssh_testkey.id_sphincs_haraka_128f_robust"
#define OPENSSH_SPHINCS_SHA256_128F_ROBUST_TESTKEY              "openssh_testkey.id_sphincs_sha256_128f_robust"
#define OPENSSH_SPHINCS_SHAKE256_128F_ROBUST_TESTKEY            "openssh_testkey.id_sphincs_shake256_128f_robust"
#define OPENSSH_RSA3072_OQSDEFAULT_TESTKEY                      "openssh_testkey.id_rsa3072_oqsdefault"
#define OPENSSH_P256_OQSDEFAULT_TESTKEY                         "openssh_testkey.id_p256_oqsdefault"
#define OPENSSH_RSA3072_DILITHIUM_2_TESTKEY                     "openssh_testkey.id_rsa3072_dilithium_2"
#define OPENSSH_P256_DILITHIUM_2_TESTKEY                        "openssh_testkey.id_p256_dilithium_2"
#define OPENSSH_RSA3072_FALCON_512_TESTKEY                      "openssh_testkey.id_rsa3072_falcon_512"
#define OPENSSH_P256_FALCON_512_TESTKEY                         "openssh_testkey.id_p256_falcon_512"
#define OPENSSH_RSA3072_PICNIC_L1FULL_TESTKEY                   "openssh_testkey.id_rsa3072_picnic_l1full"
#define OPENSSH_P256_PICNIC_L1FULL_TESTKEY                      "openssh_testkey.id_p256_picnic_l1full"
#define OPENSSH_RSA3072_PICNIC3_L1_TESTKEY                      "openssh_testkey.id_rsa3072_picnic3_l1"
#define OPENSSH_P256_PICNIC3_L1_TESTKEY                         "openssh_testkey.id_p256_picnic3_l1"
#define OPENSSH_RSA3072_RAINBOW_I_CLASSIC_TESTKEY               "openssh_testkey.id_rsa3072_rainbow_i_classic"
#define OPENSSH_P256_RAINBOW_I_CLASSIC_TESTKEY                  "openssh_testkey.id_p256_rainbow_i_classic"
#define OPENSSH_P384_RAINBOW_III_CLASSIC_TESTKEY                "openssh_testkey.id_p384_rainbow_iii_classic"
#define OPENSSH_P521_RAINBOW_V_CLASSIC_TESTKEY                  "openssh_testkey.id_p521_rainbow_v_classic"
#define OPENSSH_RSA3072_SPHINCS_HARAKA_128F_ROBUST_TESTKEY      "openssh_testkey.id_rsa3072_sphincs_haraka_128f_robust"
#define OPENSSH_P256_SPHINCS_HARAKA_128F_ROBUST_TESTKEY         "openssh_testkey.id_p256_sphincs_haraka_128f_robust"
#define OPENSSH_RSA3072_SPHINCS_SHA256_128F_ROBUST_TESTKEY      "openssh_testkey.id_rsa3072_sphincs_sha256_128f_robust"
#define OPENSSH_P256_SPHINCS_SHA256_128F_ROBUST_TESTKEY         "openssh_testkey.id_p256_sphincs_sha256_128f_robust"
#define OPENSSH_RSA3072_SPHINCS_SHAKE256_128F_ROBUST_TESTKEY    "openssh_testkey.id_rsa3072_sphincs_shake256_128f_robust"
#define OPENSSH_P256_SPHINCS_SHAKE256_128F_ROBUST_TESTKEY       "openssh_testkey.id_p256_sphincs_shake256_128f_robust"
#endif
#define OPENSSH_CA_TESTKEY        "libssh_testkey.ca"

#define DROPBEAR_RSA_TESTKEY      "dropbear_testkey.id_rsa"

void setup_openssh_client_keys(void);
void cleanup_openssh_client_keys(void);

void setup_dropbear_client_rsa_key(void);
void cleanup_dropbear_client_rsa_key(void);

#define cleanup_file(name) do {\
    if (access((name), F_OK) != -1) {\
        unlink((name));\
    }} while (0)

#define cleanup_key(name) do {\
        cleanup_file((name));\
        cleanup_file((name ".pub"));\
        cleanup_file((name "-cert.pub"));\
    } while (0)

#endif /* __PKD_KEYUTIL_H__ */
