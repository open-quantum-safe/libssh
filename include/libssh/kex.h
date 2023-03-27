/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef KEX_H_
#define KEX_H_

#include "libssh/priv.h"
#include "libssh/callbacks.h"

#ifdef WITH_POST_QUANTUM_CRYPTO
#include <oqs/oqs.h>

/* These must match their counterparts in OQS-OpenSSH's kex.h.
 * OpenSSH v7 appended "@openquantumsafe.org" to the kex algorithm names, and these macros were used to easily append that.
 * OpenSSH v8 removed this suffix, so these macros are now the identity, but we retain them in code in case this changes again in the future.
 */
#define HYBRID_ECDH_OQS_KEX_SUFFIX(X) X
#define PQ_OQS_KEX_SUFFIX(X) X

/* These strings must match their counterparts in OQS-OpenSSH's kex.c.*/

/* Pure-PQ key exchange algorithms. */
///// OQS_TEMPLATE_FRAGMENT_DEFINE_PQ_KEXS_START
#define KEX_FRODOKEM_640_AES_SHA256 PQ_OQS_KEX_SUFFIX("frodokem-640-aes-sha256")
#define KEX_FRODOKEM_976_AES_SHA384 PQ_OQS_KEX_SUFFIX("frodokem-976-aes-sha384")
#define KEX_FRODOKEM_1344_AES_SHA512 PQ_OQS_KEX_SUFFIX("frodokem-1344-aes-sha512")
#define KEX_FRODOKEM_640_SHAKE_SHA256 PQ_OQS_KEX_SUFFIX("frodokem-640-shake-sha256")
#define KEX_FRODOKEM_976_SHAKE_SHA384 PQ_OQS_KEX_SUFFIX("frodokem-976-shake-sha384")
#define KEX_FRODOKEM_1344_SHAKE_SHA512 PQ_OQS_KEX_SUFFIX("frodokem-1344-shake-sha512")
#define KEX_KYBER_512_SHA256 PQ_OQS_KEX_SUFFIX("kyber-512-sha256")
#define KEX_KYBER_768_SHA384 PQ_OQS_KEX_SUFFIX("kyber-768-sha384")
#define KEX_KYBER_1024_SHA512 PQ_OQS_KEX_SUFFIX("kyber-1024-sha512")
#define KEX_KYBER_512_90S_SHA256 PQ_OQS_KEX_SUFFIX("kyber-512-90s-sha256")
#define KEX_KYBER_768_90S_SHA384 PQ_OQS_KEX_SUFFIX("kyber-768-90s-sha384")
#define KEX_KYBER_1024_90S_SHA512 PQ_OQS_KEX_SUFFIX("kyber-1024-90s-sha512")
#define KEX_BIKE_L1_SHA512 PQ_OQS_KEX_SUFFIX("bike-l1-sha512")
#define KEX_BIKE_L3_SHA512 PQ_OQS_KEX_SUFFIX("bike-l3-sha512")
#define KEX_CLASSIC_MCELIECE_348864_SHA256 PQ_OQS_KEX_SUFFIX("classic-mceliece-348864-sha256")
#define KEX_CLASSIC_MCELIECE_348864F_SHA256 PQ_OQS_KEX_SUFFIX("classic-mceliece-348864f-sha256")
#define KEX_CLASSIC_MCELIECE_460896_SHA512 PQ_OQS_KEX_SUFFIX("classic-mceliece-460896-sha512")
#define KEX_CLASSIC_MCELIECE_460896F_SHA512 PQ_OQS_KEX_SUFFIX("classic-mceliece-460896f-sha512")
#define KEX_CLASSIC_MCELIECE_6688128_SHA512 PQ_OQS_KEX_SUFFIX("classic-mceliece-6688128-sha512")
#define KEX_CLASSIC_MCELIECE_6688128F_SHA512 PQ_OQS_KEX_SUFFIX("classic-mceliece-6688128f-sha512")
#define KEX_CLASSIC_MCELIECE_6960119_SHA512 PQ_OQS_KEX_SUFFIX("classic-mceliece-6960119-sha512")
#define KEX_CLASSIC_MCELIECE_6960119F_SHA512 PQ_OQS_KEX_SUFFIX("classic-mceliece-6960119f-sha512")
#define KEX_CLASSIC_MCELIECE_8192128_SHA512 PQ_OQS_KEX_SUFFIX("classic-mceliece-8192128-sha512")
#define KEX_CLASSIC_MCELIECE_8192128F_SHA512 PQ_OQS_KEX_SUFFIX("classic-mceliece-8192128f-sha512")
#define KEX_HQC_128_SHA256 PQ_OQS_KEX_SUFFIX("hqc-128-sha256")
#define KEX_HQC_192_SHA384 PQ_OQS_KEX_SUFFIX("hqc-192-sha384")
#define KEX_HQC_256_SHA512 PQ_OQS_KEX_SUFFIX("hqc-256-sha512")
///// OQS_TEMPLATE_FRAGMENT_DEFINE_PQ_KEXS_END

/* Hybrid classical/PQ key exchange algorithms. */
///// OQS_TEMPLATE_FRAGMENT_DEFINE_HYBRID_KEXS_START
#define KEX_ECDH_NISTP256_FRODOKEM_640_AES_SHA256 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp256-frodokem-640-aesr2-sha256@openquantumsafe.org")
#define KEX_ECDH_NISTP384_FRODOKEM_976_AES_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodokem-976-aesr2-sha384@openquantumsafe.org")
#define KEX_ECDH_NISTP521_FRODOKEM_1344_AES_SHA512 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp521-frodokem-1344-aesr2-sha512@openquantumsafe.org")
#define KEX_ECDH_NISTP256_FRODOKEM_640_SHAKE_SHA256 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp256-frodokem-640-shaker2-sha256@openquantumsafe.org")
#define KEX_ECDH_NISTP384_FRODOKEM_976_SHAKE_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodokem-976-shaker2-sha384@openquantumsafe.org")
#define KEX_ECDH_NISTP521_FRODOKEM_1344_SHAKE_SHA512 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp521-frodokem-1344-shaker2-sha512@openquantumsafe.org")
#define KEX_ECDH_NISTP256_KYBER_512_SHA256 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp256-kyber-512r3-sha256-d00@openquantumsafe.org")
#define KEX_ECDH_NISTP384_KYBER_768_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-768r3-sha384-d00@openquantumsafe.org")
#define KEX_ECDH_NISTP521_KYBER_1024_SHA512 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp521-kyber-1024r3-sha512-d00@openquantumsafe.org")
#define KEX_ECDH_NISTP256_KYBER_512_90S_SHA256 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp256-kyber-512-90sr3-sha256@openquantumsafe.org")
#define KEX_ECDH_NISTP384_KYBER_768_90S_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-768-90sr3-sha384@openquantumsafe.org")
#define KEX_ECDH_NISTP521_KYBER_1024_90S_SHA512 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp521-kyber-1024-90sr3-sha512@openquantumsafe.org")
#define KEX_ECDH_NISTP256_BIKE_L1_SHA512 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp256-bike-l1r3-sha512@openquantumsafe.org")
#define KEX_ECDH_NISTP384_BIKE_L3_SHA512 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-bike-l3r3-sha512@openquantumsafe.org")
#define KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864_SHA256 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp256-classic-mceliece-348864r3-sha256@openquantumsafe.org")
#define KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864F_SHA256 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp256-classic-mceliece-348864fr3-sha256@openquantumsafe.org")
#define KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896_SHA512 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-classic-mceliece-460896r3-sha512@openquantumsafe.org")
#define KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896F_SHA512 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-classic-mceliece-460896fr3-sha512@openquantumsafe.org")
#define KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128_SHA512 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp521-classic-mceliece-6688128r3-sha512@openquantumsafe.org")
#define KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128F_SHA512 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp521-classic-mceliece-6688128fr3-sha512@openquantumsafe.org")
#define KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119_SHA512 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp521-classic-mceliece-6960119r3-sha512@openquantumsafe.org")
#define KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119F_SHA512 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp521-classic-mceliece-6960119fr3-sha512@openquantumsafe.org")
#define KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128_SHA512 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp521-classic-mceliece-8192128r3-sha512@openquantumsafe.org")
#define KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128F_SHA512 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp521-classic-mceliece-8192128fr3-sha512@openquantumsafe.org")
#define KEX_ECDH_NISTP256_HQC_128_SHA256 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp256-hqc-128r3-sha256@openquantumsafe.org")
#define KEX_ECDH_NISTP384_HQC_192_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-hqc-192r3-sha384@openquantumsafe.org")
#define KEX_ECDH_NISTP521_HQC_256_SHA512 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp521-hqc-256r3-sha512@openquantumsafe.org")
///// OQS_TEMPLATE_FRAGMENT_DEFINE_HYBRID_KEXS_END
#endif

#define SSH_KEX_METHODS 10

struct ssh_kex_struct {
    unsigned char cookie[16];
    char *methods[SSH_KEX_METHODS];
};

SSH_PACKET_CALLBACK(ssh_packet_kexinit);

int ssh_send_kex(ssh_session session, int server_kex);
void ssh_list_kex(struct ssh_kex_struct *kex);
int ssh_set_client_kex(ssh_session session);
int ssh_kex_select_methods(ssh_session session);
int ssh_verify_existing_algo(enum ssh_kex_types_e algo, const char *name);
char *ssh_keep_known_algos(enum ssh_kex_types_e algo, const char *list);
char *ssh_keep_fips_algos(enum ssh_kex_types_e algo, const char *list);
char **ssh_space_tokenize(const char *chain);
int ssh_get_kex1(ssh_session session);
char *ssh_find_matching(const char *in_d, const char *what_d);
const char *ssh_kex_get_supported_method(uint32_t algo);
const char *ssh_kex_get_default_methods(uint32_t algo);
const char *ssh_kex_get_fips_methods(uint32_t algo);
const char *ssh_kex_get_description(uint32_t algo);
char *ssh_client_select_hostkeys(ssh_session session);
int ssh_send_rekex(ssh_session session);
int server_set_kex(ssh_session session);
int ssh_make_sessionid(ssh_session session);
/* add data for the final cookie */
int ssh_hashbufin_add_cookie(ssh_session session, unsigned char *cookie);
int ssh_hashbufout_add_cookie(ssh_session session);
int ssh_generate_session_keys(ssh_session session);

#endif /* KEX_H_ */
