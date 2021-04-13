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

/* These must match their counterparts in OQS-OpenSSH's kex.h. */
#define HYBRID_ECDH_OQS_NAMESPACE_SUFFIX "@openquantumsafe.org"
#define HYBRID_ECDH_OQS_KEX_SUFFIX(X) X HYBRID_ECDH_OQS_NAMESPACE_SUFFIX

#define PQ_OQS_NAMESPACE_SUFFIX "@openquantumsafe.org"
#define PQ_OQS_KEX_SUFFIX(X) X PQ_OQS_NAMESPACE_SUFFIX

/* These strings must match their counterparts in OQS-OpenSSH's kex.c.*/

/* Pure-PQ key exchange algorithms. */
#ifdef WITH_PURE_PQ_KEX
#define KEX_OQSDEFAULT_SHA384 PQ_OQS_KEX_SUFFIX("oqsdefault-sha384")
#define KEX_BIKE1_L1_CPA_SHA384 PQ_OQS_KEX_SUFFIX("bike1-l1-cpa-sha384")
#define KEX_BIKE1_L3_CPA_SHA384 PQ_OQS_KEX_SUFFIX("bike1-l3-cpa-sha384")
#define KEX_BIKE1_L1_FO_SHA384 PQ_OQS_KEX_SUFFIX("bike1-l1-fo-sha384")
#define KEX_BIKE1_L3_FO_SHA384 PQ_OQS_KEX_SUFFIX("bike1-l3-fo-sha384")
#define KEX_CLASSIC_MCELIECE_348864_SHA384  PQ_OQS_KEX_SUFFIX("classic-mceliece-348864-sha384")
#define KEX_CLASSIC_MCELIECE_348864F_SHA384 PQ_OQS_KEX_SUFFIX("classic-mceliece-348864f-sha384")
#define KEX_CLASSIC_MCELIECE_460896_SHA384 PQ_OQS_KEX_SUFFIX("classic-mceliece-460896-sha384")
#define KEX_CLASSIC_MCELIECE_460896F_SHA384 PQ_OQS_KEX_SUFFIX("classic-mceliece-460896f-sha384")
#define KEX_CLASSIC_MCELIECE_6688128_SHA384 PQ_OQS_KEX_SUFFIX("classic-mceliece-6688128-sha384")
#define KEX_CLASSIC_MCELIECE_6688128F_SHA384 PQ_OQS_KEX_SUFFIX("classic-mceliece-6688128f-sha384")
#define KEX_CLASSIC_MCELIECE_6960119_SHA384 PQ_OQS_KEX_SUFFIX("classic-mceliece-6960119-sha384")
#define KEX_CLASSIC_MCELIECE_6960119F_SHA384 PQ_OQS_KEX_SUFFIX("classic-mceliece-6960119f-sha384")
#define KEX_CLASSIC_MCELIECE_8192128_SHA384 PQ_OQS_KEX_SUFFIX("classic-mceliece-8192128-sha384")
#define KEX_CLASSIC_MCELIECE_8192128F_SHA384 PQ_OQS_KEX_SUFFIX("classic-mceliece-8192128f-sha384")
#define KEX_FRODO_640_AES_SHA384 PQ_OQS_KEX_SUFFIX("frodo-640-aes-sha384")
#define KEX_FRODO_640_SHAKE_SHA384 PQ_OQS_KEX_SUFFIX("frodo-640-shake-sha384")
#define KEX_FRODO_976_AES_SHA384 PQ_OQS_KEX_SUFFIX("frodo-976-aes-sha384")
#define KEX_FRODO_976_SHAKE_SHA384 PQ_OQS_KEX_SUFFIX("frodo-976-shake-sha384")
#define KEX_FRODO_1344_AES_SHA384 PQ_OQS_KEX_SUFFIX("frodo-1344-aes-sha384")
#define KEX_FRODO_1344_SHAKE_SHA384 PQ_OQS_KEX_SUFFIX("frodo-1344-shake-sha384")
#define KEX_KYBER_512_SHA384 PQ_OQS_KEX_SUFFIX("kyber-512-sha384")
#define KEX_KYBER_768_SHA384 PQ_OQS_KEX_SUFFIX("kyber-768-sha384")
#define KEX_KYBER_1024_SHA384 PQ_OQS_KEX_SUFFIX("kyber-1024-sha384")
#define KEX_KYBER_512_90S_SHA384 PQ_OQS_KEX_SUFFIX("kyber-512-90s-sha384")
#define KEX_KYBER_768_90S_SHA384 PQ_OQS_KEX_SUFFIX("kyber-768-90s-sha384")
#define KEX_KYBER_1024_90S_SHA384 PQ_OQS_KEX_SUFFIX("kyber-1024-90s-sha384")
#define KEX_NTRU_HPS_2048_509_SHA384 PQ_OQS_KEX_SUFFIX("ntru-hps-2048-509-sha384")
#define KEX_NTRU_HPS_2048_677_SHA384 PQ_OQS_KEX_SUFFIX("ntru-hps-2048-677-sha384")
#define KEX_NTRU_HRSS_701_SHA384 PQ_OQS_KEX_SUFFIX("ntru-hrss-701-sha384")
#define KEX_NTRU_HPS_4096_821_SHA384 PQ_OQS_KEX_SUFFIX("ntru-hps-4096-821-sha384")
#define KEX_SABER_LIGHTSABER_SHA384 PQ_OQS_KEX_SUFFIX("saber-lightsaber-sha384")
#define KEX_SABER_SABER_SHA384 PQ_OQS_KEX_SUFFIX("saber-saber-sha384")
#define KEX_SABER_FIRESABER_SHA384 PQ_OQS_KEX_SUFFIX("saber-firesaber-sha384")
#define KEX_SIDH_p434_SHA384 PQ_OQS_KEX_SUFFIX("sidh-p434-sha384")
#define KEX_SIDH_p503_SHA384 PQ_OQS_KEX_SUFFIX("sidh-p503-sha384")
#define KEX_SIDH_p610_SHA384 PQ_OQS_KEX_SUFFIX("sidh-p610-sha384")
#define KEX_SIDH_p751_SHA384 PQ_OQS_KEX_SUFFIX("sidh-p751-sha384")
#define KEX_SIDH_P434_COMPRESSED_SHA384 PQ_OQS_KEX_SUFFIX("sidh-p434-compressed-sha384")
#define KEX_SIDH_P503_COMPRESSED_SHA384 PQ_OQS_KEX_SUFFIX("sidh-p503-compressed-sha384")
#define KEX_SIDH_P610_COMPRESSED_SHA384 PQ_OQS_KEX_SUFFIX("sidh-p610-compressed-sha384")
#define KEX_SIDH_P751_COMPRESSED_SHA384 PQ_OQS_KEX_SUFFIX("sidh-p751-compressed-sha384")
#define KEX_SIKE_P434_SHA384 PQ_OQS_KEX_SUFFIX("sike-p434-sha384")
#define KEX_SIKE_P503_SHA384 PQ_OQS_KEX_SUFFIX("sike-p503-sha384")
#define KEX_SIKE_P610_SHA384 PQ_OQS_KEX_SUFFIX("sike-p610-sha384")
#define KEX_SIKE_P751_SHA384 PQ_OQS_KEX_SUFFIX("sike-p751-sha384")
#define KEX_SIKE_P434_COMPRESSED_SHA384 PQ_OQS_KEX_SUFFIX("sike-p434-compressed-sha384")
#define KEX_SIKE_P503_COMPRESSED_SHA384 PQ_OQS_KEX_SUFFIX("sike-p503-compressed-sha384")
#define KEX_SIKE_P610_COMPRESSED_SHA384 PQ_OQS_KEX_SUFFIX("sike-p610-compressed-sha384")
#define KEX_SIKE_P751_COMPRESSED_SHA384 PQ_OQS_KEX_SUFFIX("sike-p751-compressed-sha384")
#define KEX_HQC_128_SHA384 PQ_OQS_KEX_SUFFIX("hqc-128-sha384")
#define KEX_HQC_192_SHA384 PQ_OQS_KEX_SUFFIX("hqc-192-sha384")
#define KEX_HQC_256_SHA384 PQ_OQS_KEX_SUFFIX("hqc-256-sha384")
#define KEX_NTRULPR_653_SHA384 PQ_OQS_KEX_SUFFIX("ntrulpr-653-sha384")
#define KEX_NTRULPR_761_SHA384 PQ_OQS_KEX_SUFFIX("ntrulpr-761-sha384")
#define KEX_NTRULPR_857_SHA384 PQ_OQS_KEX_SUFFIX("ntrulpr-857-sha384")
#define KEX_SNTRUP_653_SHA384 PQ_OQS_KEX_SUFFIX("sntrup-653-sha384")
#define KEX_SNTRUP_761_SHA384 PQ_OQS_KEX_SUFFIX("sntrup-761-sha384")
#define KEX_SNTRUP_857_SHA384 PQ_OQS_KEX_SUFFIX("sntrup-857-sha384")
#endif /* WITH_PURE_PQ_KEX */

/* Hybrid classical/PQ key exchange algorithms. */
#define KEX_ECDH_NISTP384_OQSDEFAULT_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-oqsdefault-sha384")
#define KEX_ECDH_NISTP384_BIKE1_L1_CPA_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-bike1-l1-cpa-sha384")
#define KEX_ECDH_NISTP384_BIKE1_L3_CPA_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-bike1-l3-cpa-sha384")
#define KEX_ECDH_NISTP384_BIKE1_L1_FO_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-bike1-l1-fo-sha384")
#define KEX_ECDH_NISTP384_BIKE1_L3_FO_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-bike1-l3-fo-sha384")
#define KEX_ECDH_NISTP384_CLASSIC_MCELIECE_348864_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-classic-mceliece-348864-sha384")
#define KEX_ECDH_NISTP384_CLASSIC_MCELIECE_348864F_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-classic-mceliece-348864f-sha384")
#define KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-classic-mceliece-460896-sha384")
#define KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896F_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-classic-mceliece-460896f-sha384")
#define KEX_ECDH_NISTP384_CLASSIC_MCELIECE_6688128_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-classic-mceliece-6688128-sha384")
#define KEX_ECDH_NISTP384_CLASSIC_MCELIECE_6688128F_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-classic-mceliece-6688128f-sha384")
#define KEX_ECDH_NISTP384_CLASSIC_MCELIECE_6960119_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-classic-mceliece-6960119-sha384")
#define KEX_ECDH_NISTP384_CLASSIC_MCELIECE_6960119F_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-classic-mceliece-6960119f-sha384")
#define KEX_ECDH_NISTP384_CLASSIC_MCELIECE_8192128_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-classic-mceliece-8192128-sha384")
#define KEX_ECDH_NISTP384_CLASSIC_MCELIECE_8192128F_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-classic-mceliece-8192128f-sha384")
#define KEX_ECDH_NISTP384_FRODO_640_AES_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-640-aes-sha384")
#define KEX_ECDH_NISTP384_FRODO_640_SHAKE_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-640-shake-sha384")
#define KEX_ECDH_NISTP384_FRODO_976_AES_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-976-aes-sha384")
#define KEX_ECDH_NISTP384_FRODO_976_SHAKE_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-976-shake-sha384")
#define KEX_ECDH_NISTP384_FRODO_1344_AES_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-1344-aes-sha384")
#define KEX_ECDH_NISTP384_FRODO_1344_SHAKE_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-1344-shake-sha384")
#define KEX_ECDH_NISTP384_KYBER_512_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-512-sha384")
#define KEX_ECDH_NISTP384_KYBER_768_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-768-sha384")
#define KEX_ECDH_NISTP384_KYBER_1024_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-1024-sha384")
#define KEX_ECDH_NISTP384_KYBER_512_90S_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-512-90s-sha384")
#define KEX_ECDH_NISTP384_KYBER_768_90S_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-768-90s-sha384")
#define KEX_ECDH_NISTP384_KYBER_1024_90S_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-1024-90s-sha384")
#define KEX_ECDH_NISTP384_NTRU_HPS_2048_509_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-ntru-hps-2048-509-sha384")
#define KEX_ECDH_NISTP384_NTRU_HPS_2048_677_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-ntru-hps-2048-677-sha384")
#define KEX_ECDH_NISTP384_NTRU_HRSS_701_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-ntru-hrss-701-sha384")
#define KEX_ECDH_NISTP384_NTRU_HPS_4096_821_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-ntru-hps-4096-821-sha384")
#define KEX_ECDH_NISTP384_SABER_LIGHTSABER_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-saber-lightsaber-sha384")
#define KEX_ECDH_NISTP384_SABER_SABER_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-saber-saber-sha384")
#define KEX_ECDH_NISTP384_SABER_FIRESABER_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-saber-firesaber-sha384")
#define KEX_ECDH_NISTP384_SIDH_p434_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p434-sha384")
#define KEX_ECDH_NISTP384_SIDH_p503_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p503-sha384")
#define KEX_ECDH_NISTP384_SIDH_p610_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p610-sha384")
#define KEX_ECDH_NISTP384_SIDH_p751_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p751-sha384")
#define KEX_ECDH_NISTP384_SIDH_P434_COMPRESSED_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p434-compressed-sha384")
#define KEX_ECDH_NISTP384_SIDH_P503_COMPRESSED_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p503-compressed-sha384")
#define KEX_ECDH_NISTP384_SIDH_P610_COMPRESSED_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p610-compressed-sha384")
#define KEX_ECDH_NISTP384_SIDH_P751_COMPRESSED_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p751-compressed-sha384")
#define KEX_ECDH_NISTP384_SIKE_P434_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p434-sha384")
#define KEX_ECDH_NISTP384_SIKE_P503_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p503-sha384")
#define KEX_ECDH_NISTP384_SIKE_P610_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p610-sha384")
#define KEX_ECDH_NISTP384_SIKE_P751_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p751-sha384")
#define KEX_ECDH_NISTP384_SIKE_P434_COMPRESSED_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p434-compressed-sha384")
#define KEX_ECDH_NISTP384_SIKE_P503_COMPRESSED_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p503-compressed-sha384")
#define KEX_ECDH_NISTP384_SIKE_P610_COMPRESSED_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p610-compressed-sha384")
#define KEX_ECDH_NISTP384_SIKE_P751_COMPRESSED_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p751-compressed-sha384")
#define KEX_ECDH_NISTP384_HQC_128_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-hqc-128-sha384")
#define KEX_ECDH_NISTP384_HQC_192_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-hqc-192-sha384")
#define KEX_ECDH_NISTP384_HQC_256_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-hqc-256-sha384")
#define KEX_ECDH_NISTP384_NTRULPR_653_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-ntrulpr-653-sha384")
#define KEX_ECDH_NISTP384_NTRULPR_761_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-ntrulpr-761-sha384")
#define KEX_ECDH_NISTP384_NTRULPR_857_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-ntrulpr-857-sha384")
#define KEX_ECDH_NISTP384_SNTRUP_653_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sntrup-653-sha384")
#define KEX_ECDH_NISTP384_SNTRUP_761_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sntrup-761-sha384")
#define KEX_ECDH_NISTP384_SNTRUP_857_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sntrup-857-sha384")
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
