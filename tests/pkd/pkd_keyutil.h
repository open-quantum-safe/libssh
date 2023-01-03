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
///// OQS_TEMPLATE_FRAGMENT_DEFINE_LIBSSH_TESTKEYS_START
#define LIBSSH_FALCON_512_TESTKEY "libssh_testkey.id_falcon_512"
#define LIBSSH_RSA3072_FALCON_512_TESTKEY "libssh_testkey.id_rsa3072_falcon_512"
#define LIBSSH_ECDSA_NISTP256_FALCON_512_TESTKEY "libssh_testkey.id_ecdsa_nistp256_falcon_512"
#define LIBSSH_FALCON_1024_TESTKEY "libssh_testkey.id_falcon_1024"
#define LIBSSH_ECDSA_NISTP521_FALCON_1024_TESTKEY "libssh_testkey.id_ecdsa_nistp521_falcon_1024"
#define LIBSSH_DILITHIUM_3_TESTKEY "libssh_testkey.id_dilithium_3"
#define LIBSSH_ECDSA_NISTP384_DILITHIUM_3_TESTKEY "libssh_testkey.id_ecdsa_nistp384_dilithium_3"
#define LIBSSH_DILITHIUM_2_AES_TESTKEY "libssh_testkey.id_dilithium_2_aes"
#define LIBSSH_RSA3072_DILITHIUM_2_AES_TESTKEY "libssh_testkey.id_rsa3072_dilithium_2_aes"
#define LIBSSH_ECDSA_NISTP256_DILITHIUM_2_AES_TESTKEY "libssh_testkey.id_ecdsa_nistp256_dilithium_2_aes"
#define LIBSSH_DILITHIUM_5_AES_TESTKEY "libssh_testkey.id_dilithium_5_aes"
#define LIBSSH_ECDSA_NISTP521_DILITHIUM_5_AES_TESTKEY "libssh_testkey.id_ecdsa_nistp521_dilithium_5_aes"
#define LIBSSH_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY "libssh_testkey.id_sphincs_haraka_128f_simple"
#define LIBSSH_RSA3072_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY "libssh_testkey.id_rsa3072_sphincs_haraka_128f_simple"
#define LIBSSH_ECDSA_NISTP256_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY "libssh_testkey.id_ecdsa_nistp256_sphincs_haraka_128f_simple"
#define LIBSSH_SPHINCS_HARAKA_192F_ROBUST_TESTKEY "libssh_testkey.id_sphincs_haraka_192f_robust"
#define LIBSSH_ECDSA_NISTP384_SPHINCS_HARAKA_192F_ROBUST_TESTKEY "libssh_testkey.id_ecdsa_nistp384_sphincs_haraka_192f_robust"
///// OQS_TEMPLATE_FRAGMENT_DEFINE_LIBSSH_TESTKEYS_END
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
///// OQS_TEMPLATE_FRAGMENT_DEFINE_CLIENT_TESTKEYS_START
#define OPENSSH_FALCON_512_TESTKEY "openssh_testkey.id_falcon_512"
#define OPENSSH_RSA3072_FALCON_512_TESTKEY "openssh_testkey.id_rsa3072_falcon_512"
#define OPENSSH_ECDSA_NISTP256_FALCON_512_TESTKEY "openssh_testkey.id_ecdsa_nistp256_falcon_512"
#define OPENSSH_FALCON_1024_TESTKEY "openssh_testkey.id_falcon_1024"
#define OPENSSH_ECDSA_NISTP521_FALCON_1024_TESTKEY "openssh_testkey.id_ecdsa_nistp521_falcon_1024"
#define OPENSSH_DILITHIUM_3_TESTKEY "openssh_testkey.id_dilithium_3"
#define OPENSSH_ECDSA_NISTP384_DILITHIUM_3_TESTKEY "openssh_testkey.id_ecdsa_nistp384_dilithium_3"
#define OPENSSH_DILITHIUM_2_AES_TESTKEY "openssh_testkey.id_dilithium_2_aes"
#define OPENSSH_RSA3072_DILITHIUM_2_AES_TESTKEY "openssh_testkey.id_rsa3072_dilithium_2_aes"
#define OPENSSH_ECDSA_NISTP256_DILITHIUM_2_AES_TESTKEY "openssh_testkey.id_ecdsa_nistp256_dilithium_2_aes"
#define OPENSSH_DILITHIUM_5_AES_TESTKEY "openssh_testkey.id_dilithium_5_aes"
#define OPENSSH_ECDSA_NISTP521_DILITHIUM_5_AES_TESTKEY "openssh_testkey.id_ecdsa_nistp521_dilithium_5_aes"
#define OPENSSH_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY "openssh_testkey.id_sphincs_haraka_128f_simple"
#define OPENSSH_RSA3072_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY "openssh_testkey.id_rsa3072_sphincs_haraka_128f_simple"
#define OPENSSH_ECDSA_NISTP256_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY "openssh_testkey.id_ecdsa_nistp256_sphincs_haraka_128f_simple"
#define OPENSSH_SPHINCS_HARAKA_192F_ROBUST_TESTKEY "openssh_testkey.id_sphincs_haraka_192f_robust"
#define OPENSSH_ECDSA_NISTP384_SPHINCS_HARAKA_192F_ROBUST_TESTKEY "openssh_testkey.id_ecdsa_nistp384_sphincs_haraka_192f_robust"
///// OQS_TEMPLATE_FRAGMENT_DEFINE_CLIENT_TESTKEYS_END
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
