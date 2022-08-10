/*
 * oqs-utils.c - liboqs utility functions
 *
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All rights reserved.
 * Copyright (c) 2021 Microsoft Corporation
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT},
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE},
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston},
 * MA 02111-1307, USA.
 */

#include "config.h"

#ifdef WITH_POST_QUANTUM_CRYPTO

#include "libssh/oqs-utils.h"
#include "libssh/crypto.h"
#include "libssh/kex.h"
#include "libssh/session.h"

#include <oqs/oqs.h>

/*
 * Mapping that maps relevant named SSH key exchange methods to the needed
 * corresponding liboqs key exchange scheme
 */

static const OQS_ALG oqs_alg_mapping[] = {
    /* Hybrid key exchange methods */
///// OQS_TEMPLATE_FRAGMENT_DEFINE_HYBRID_KEXS_START
    {SSH_KEX_ECDH_NISTP256_FRODOKEM_640_AES_SHA256, KEX_ECDH_NISTP256_FRODOKEM_640_AES_SHA256, OQS_KEM_alg_frodokem_640_aes},
    {SSH_KEX_ECDH_NISTP384_FRODOKEM_976_AES_SHA384, KEX_ECDH_NISTP384_FRODOKEM_976_AES_SHA384, OQS_KEM_alg_frodokem_976_aes},
    {SSH_KEX_ECDH_NISTP521_FRODOKEM_1344_AES_SHA512, KEX_ECDH_NISTP521_FRODOKEM_1344_AES_SHA512, OQS_KEM_alg_frodokem_1344_aes},
    {SSH_KEX_ECDH_NISTP256_FRODOKEM_640_SHAKE_SHA256, KEX_ECDH_NISTP256_FRODOKEM_640_SHAKE_SHA256, OQS_KEM_alg_frodokem_640_shake},
    {SSH_KEX_ECDH_NISTP384_FRODOKEM_976_SHAKE_SHA384, KEX_ECDH_NISTP384_FRODOKEM_976_SHAKE_SHA384, OQS_KEM_alg_frodokem_976_shake},
    {SSH_KEX_ECDH_NISTP521_FRODOKEM_1344_SHAKE_SHA512, KEX_ECDH_NISTP521_FRODOKEM_1344_SHAKE_SHA512, OQS_KEM_alg_frodokem_1344_shake},
    {SSH_KEX_ECDH_NISTP256_SABER_LIGHTSABER_SHA256, KEX_ECDH_NISTP256_SABER_LIGHTSABER_SHA256, OQS_KEM_alg_saber_lightsaber},
    {SSH_KEX_ECDH_NISTP384_SABER_SABER_SHA384, KEX_ECDH_NISTP384_SABER_SABER_SHA384, OQS_KEM_alg_saber_saber},
    {SSH_KEX_ECDH_NISTP521_SABER_FIRESABER_SHA512, KEX_ECDH_NISTP521_SABER_FIRESABER_SHA512, OQS_KEM_alg_saber_firesaber},
    {SSH_KEX_ECDH_NISTP256_KYBER_512_SHA256, KEX_ECDH_NISTP256_KYBER_512_SHA256, OQS_KEM_alg_kyber_512},
    {SSH_KEX_ECDH_NISTP384_KYBER_768_SHA384, KEX_ECDH_NISTP384_KYBER_768_SHA384, OQS_KEM_alg_kyber_768},
    {SSH_KEX_ECDH_NISTP521_KYBER_1024_SHA512, KEX_ECDH_NISTP521_KYBER_1024_SHA512, OQS_KEM_alg_kyber_1024},
    {SSH_KEX_ECDH_NISTP256_KYBER_512_90S_SHA256, KEX_ECDH_NISTP256_KYBER_512_90S_SHA256, OQS_KEM_alg_kyber_512_90s},
    {SSH_KEX_ECDH_NISTP384_KYBER_768_90S_SHA384, KEX_ECDH_NISTP384_KYBER_768_90S_SHA384, OQS_KEM_alg_kyber_768_90s},
    {SSH_KEX_ECDH_NISTP521_KYBER_1024_90S_SHA512, KEX_ECDH_NISTP521_KYBER_1024_90S_SHA512, OQS_KEM_alg_kyber_1024_90s},
    {SSH_KEX_ECDH_NISTP256_BIKE_L1_SHA512, KEX_ECDH_NISTP256_BIKE_L1_SHA512, OQS_KEM_alg_bike_l1},
    {SSH_KEX_ECDH_NISTP384_BIKE_L3_SHA512, KEX_ECDH_NISTP384_BIKE_L3_SHA512, OQS_KEM_alg_bike_l3},
    {SSH_KEX_ECDH_NISTP256_NTRU_HPS2048509_SHA512, KEX_ECDH_NISTP256_NTRU_HPS2048509_SHA512, OQS_KEM_alg_ntru_hps2048509},
    {SSH_KEX_ECDH_NISTP384_NTRU_HPS2048677_SHA512, KEX_ECDH_NISTP384_NTRU_HPS2048677_SHA512, OQS_KEM_alg_ntru_hps2048677},
    {SSH_KEX_ECDH_NISTP521_NTRU_HPS4096821_SHA512, KEX_ECDH_NISTP521_NTRU_HPS4096821_SHA512, OQS_KEM_alg_ntru_hps4096821},
    {SSH_KEX_ECDH_NISTP521_NTRU_HPS40961229_SHA512, KEX_ECDH_NISTP521_NTRU_HPS40961229_SHA512, OQS_KEM_alg_ntru_hps40961229},
    {SSH_KEX_ECDH_NISTP384_NTRU_HRSS701_SHA512, KEX_ECDH_NISTP384_NTRU_HRSS701_SHA512, OQS_KEM_alg_ntru_hrss701},
    {SSH_KEX_ECDH_NISTP521_NTRU_HRSS1373_SHA512, KEX_ECDH_NISTP521_NTRU_HRSS1373_SHA512, OQS_KEM_alg_ntru_hrss1373},
    {SSH_KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864_SHA256, KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864_SHA256, OQS_KEM_alg_classic_mceliece_348864},
    {SSH_KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864F_SHA256, KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864F_SHA256, OQS_KEM_alg_classic_mceliece_348864f},
    {SSH_KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896_SHA512, KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896_SHA512, OQS_KEM_alg_classic_mceliece_460896},
    {SSH_KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896F_SHA512, KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896F_SHA512, OQS_KEM_alg_classic_mceliece_460896f},
    {SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128_SHA512, KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128_SHA512, OQS_KEM_alg_classic_mceliece_6688128},
    {SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128F_SHA512, KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128F_SHA512, OQS_KEM_alg_classic_mceliece_6688128f},
    {SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119_SHA512, KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119_SHA512, OQS_KEM_alg_classic_mceliece_6960119},
    {SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119F_SHA512, KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119F_SHA512, OQS_KEM_alg_classic_mceliece_6960119f},
    {SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128_SHA512, KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128_SHA512, OQS_KEM_alg_classic_mceliece_8192128},
    {SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128F_SHA512, KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128F_SHA512, OQS_KEM_alg_classic_mceliece_8192128f},
    {SSH_KEX_ECDH_NISTP256_HQC_128_SHA256, KEX_ECDH_NISTP256_HQC_128_SHA256, OQS_KEM_alg_hqc_128},
    {SSH_KEX_ECDH_NISTP384_HQC_192_SHA384, KEX_ECDH_NISTP384_HQC_192_SHA384, OQS_KEM_alg_hqc_192},
    {SSH_KEX_ECDH_NISTP521_HQC_256_SHA512, KEX_ECDH_NISTP521_HQC_256_SHA512, OQS_KEM_alg_hqc_256},
    {SSH_KEX_ECDH_NISTP256_NTRUPRIME_NTRULPR653_SHA256, KEX_ECDH_NISTP256_NTRUPRIME_NTRULPR653_SHA256, OQS_KEM_alg_ntruprime_ntrulpr653},
    {SSH_KEX_ECDH_NISTP256_NTRUPRIME_SNTRUP653_SHA256, KEX_ECDH_NISTP256_NTRUPRIME_SNTRUP653_SHA256, OQS_KEM_alg_ntruprime_sntrup653},
    {SSH_KEX_ECDH_NISTP384_NTRUPRIME_NTRULPR761_SHA384, KEX_ECDH_NISTP384_NTRUPRIME_NTRULPR761_SHA384, OQS_KEM_alg_ntruprime_ntrulpr761},
    {SSH_KEX_ECDH_NISTP384_NTRUPRIME_SNTRUP761_SHA384, KEX_ECDH_NISTP384_NTRUPRIME_SNTRUP761_SHA384, OQS_KEM_alg_ntruprime_sntrup761},
    {SSH_KEX_ECDH_NISTP384_NTRUPRIME_NTRULPR857_SHA384, KEX_ECDH_NISTP384_NTRUPRIME_NTRULPR857_SHA384, OQS_KEM_alg_ntruprime_ntrulpr857},
    {SSH_KEX_ECDH_NISTP384_NTRUPRIME_SNTRUP857_SHA384, KEX_ECDH_NISTP384_NTRUPRIME_SNTRUP857_SHA384, OQS_KEM_alg_ntruprime_sntrup857},
    {SSH_KEX_ECDH_NISTP521_NTRUPRIME_NTRULPR1277_SHA512, KEX_ECDH_NISTP521_NTRUPRIME_NTRULPR1277_SHA512, OQS_KEM_alg_ntruprime_ntrulpr1277},
    {SSH_KEX_ECDH_NISTP521_NTRUPRIME_SNTRUP1277_SHA512, KEX_ECDH_NISTP521_NTRUPRIME_SNTRUP1277_SHA512, OQS_KEM_alg_ntruprime_sntrup1277},
///// OQS_TEMPLATE_FRAGMENT_DEFINE_HYBRID_KEXS_END
    /* PQ-only key exchange methods */
///// OQS_TEMPLATE_FRAGMENT_DEFINE_PQ_KEXS_START
    {SSH_KEX_FRODOKEM_640_AES_SHA256, KEX_FRODOKEM_640_AES_SHA256, OQS_KEM_alg_frodokem_640_aes},
    {SSH_KEX_FRODOKEM_976_AES_SHA384, KEX_FRODOKEM_976_AES_SHA384, OQS_KEM_alg_frodokem_976_aes},
    {SSH_KEX_FRODOKEM_1344_AES_SHA512, KEX_FRODOKEM_1344_AES_SHA512, OQS_KEM_alg_frodokem_1344_aes},
    {SSH_KEX_FRODOKEM_640_SHAKE_SHA256, KEX_FRODOKEM_640_SHAKE_SHA256, OQS_KEM_alg_frodokem_640_shake},
    {SSH_KEX_FRODOKEM_976_SHAKE_SHA384, KEX_FRODOKEM_976_SHAKE_SHA384, OQS_KEM_alg_frodokem_976_shake},
    {SSH_KEX_FRODOKEM_1344_SHAKE_SHA512, KEX_FRODOKEM_1344_SHAKE_SHA512, OQS_KEM_alg_frodokem_1344_shake},
    {SSH_KEX_SABER_LIGHTSABER_SHA256, KEX_SABER_LIGHTSABER_SHA256, OQS_KEM_alg_saber_lightsaber},
    {SSH_KEX_SABER_SABER_SHA384, KEX_SABER_SABER_SHA384, OQS_KEM_alg_saber_saber},
    {SSH_KEX_SABER_FIRESABER_SHA512, KEX_SABER_FIRESABER_SHA512, OQS_KEM_alg_saber_firesaber},
    {SSH_KEX_KYBER_512_SHA256, KEX_KYBER_512_SHA256, OQS_KEM_alg_kyber_512},
    {SSH_KEX_KYBER_768_SHA384, KEX_KYBER_768_SHA384, OQS_KEM_alg_kyber_768},
    {SSH_KEX_KYBER_1024_SHA512, KEX_KYBER_1024_SHA512, OQS_KEM_alg_kyber_1024},
    {SSH_KEX_KYBER_512_90S_SHA256, KEX_KYBER_512_90S_SHA256, OQS_KEM_alg_kyber_512_90s},
    {SSH_KEX_KYBER_768_90S_SHA384, KEX_KYBER_768_90S_SHA384, OQS_KEM_alg_kyber_768_90s},
    {SSH_KEX_KYBER_1024_90S_SHA512, KEX_KYBER_1024_90S_SHA512, OQS_KEM_alg_kyber_1024_90s},
    {SSH_KEX_BIKE_L1_SHA512, KEX_BIKE_L1_SHA512, OQS_KEM_alg_bike_l1},
    {SSH_KEX_BIKE_L3_SHA512, KEX_BIKE_L3_SHA512, OQS_KEM_alg_bike_l3},
    {SSH_KEX_NTRU_HPS2048509_SHA512, KEX_NTRU_HPS2048509_SHA512, OQS_KEM_alg_ntru_hps2048509},
    {SSH_KEX_NTRU_HPS2048677_SHA512, KEX_NTRU_HPS2048677_SHA512, OQS_KEM_alg_ntru_hps2048677},
    {SSH_KEX_NTRU_HPS4096821_SHA512, KEX_NTRU_HPS4096821_SHA512, OQS_KEM_alg_ntru_hps4096821},
    {SSH_KEX_NTRU_HPS40961229_SHA512, KEX_NTRU_HPS40961229_SHA512, OQS_KEM_alg_ntru_hps40961229},
    {SSH_KEX_NTRU_HRSS701_SHA512, KEX_NTRU_HRSS701_SHA512, OQS_KEM_alg_ntru_hrss701},
    {SSH_KEX_NTRU_HRSS1373_SHA512, KEX_NTRU_HRSS1373_SHA512, OQS_KEM_alg_ntru_hrss1373},
    {SSH_KEX_CLASSIC_MCELIECE_348864_SHA256, KEX_CLASSIC_MCELIECE_348864_SHA256, OQS_KEM_alg_classic_mceliece_348864},
    {SSH_KEX_CLASSIC_MCELIECE_348864F_SHA256, KEX_CLASSIC_MCELIECE_348864F_SHA256, OQS_KEM_alg_classic_mceliece_348864f},
    {SSH_KEX_CLASSIC_MCELIECE_460896_SHA512, KEX_CLASSIC_MCELIECE_460896_SHA512, OQS_KEM_alg_classic_mceliece_460896},
    {SSH_KEX_CLASSIC_MCELIECE_460896F_SHA512, KEX_CLASSIC_MCELIECE_460896F_SHA512, OQS_KEM_alg_classic_mceliece_460896f},
    {SSH_KEX_CLASSIC_MCELIECE_6688128_SHA512, KEX_CLASSIC_MCELIECE_6688128_SHA512, OQS_KEM_alg_classic_mceliece_6688128},
    {SSH_KEX_CLASSIC_MCELIECE_6688128F_SHA512, KEX_CLASSIC_MCELIECE_6688128F_SHA512, OQS_KEM_alg_classic_mceliece_6688128f},
    {SSH_KEX_CLASSIC_MCELIECE_6960119_SHA512, KEX_CLASSIC_MCELIECE_6960119_SHA512, OQS_KEM_alg_classic_mceliece_6960119},
    {SSH_KEX_CLASSIC_MCELIECE_6960119F_SHA512, KEX_CLASSIC_MCELIECE_6960119F_SHA512, OQS_KEM_alg_classic_mceliece_6960119f},
    {SSH_KEX_CLASSIC_MCELIECE_8192128_SHA512, KEX_CLASSIC_MCELIECE_8192128_SHA512, OQS_KEM_alg_classic_mceliece_8192128},
    {SSH_KEX_CLASSIC_MCELIECE_8192128F_SHA512, KEX_CLASSIC_MCELIECE_8192128F_SHA512, OQS_KEM_alg_classic_mceliece_8192128f},
    {SSH_KEX_HQC_128_SHA256, KEX_HQC_128_SHA256, OQS_KEM_alg_hqc_128},
    {SSH_KEX_HQC_192_SHA384, KEX_HQC_192_SHA384, OQS_KEM_alg_hqc_192},
    {SSH_KEX_HQC_256_SHA512, KEX_HQC_256_SHA512, OQS_KEM_alg_hqc_256},
    {SSH_KEX_NTRUPRIME_NTRULPR653_SHA256, KEX_NTRUPRIME_NTRULPR653_SHA256, OQS_KEM_alg_ntruprime_ntrulpr653},
    {SSH_KEX_NTRUPRIME_SNTRUP653_SHA256, KEX_NTRUPRIME_SNTRUP653_SHA256, OQS_KEM_alg_ntruprime_sntrup653},
    {SSH_KEX_NTRUPRIME_NTRULPR761_SHA384, KEX_NTRUPRIME_NTRULPR761_SHA384, OQS_KEM_alg_ntruprime_ntrulpr761},
    {SSH_KEX_NTRUPRIME_SNTRUP761_SHA384, KEX_NTRUPRIME_SNTRUP761_SHA384, OQS_KEM_alg_ntruprime_sntrup761},
    {SSH_KEX_NTRUPRIME_NTRULPR857_SHA384, KEX_NTRUPRIME_NTRULPR857_SHA384, OQS_KEM_alg_ntruprime_ntrulpr857},
    {SSH_KEX_NTRUPRIME_SNTRUP857_SHA384, KEX_NTRUPRIME_SNTRUP857_SHA384, OQS_KEM_alg_ntruprime_sntrup857},
    {SSH_KEX_NTRUPRIME_NTRULPR1277_SHA512, KEX_NTRUPRIME_NTRULPR1277_SHA512, OQS_KEM_alg_ntruprime_ntrulpr1277},
    {SSH_KEX_NTRUPRIME_SNTRUP1277_SHA512, KEX_NTRUPRIME_SNTRUP1277_SHA512, OQS_KEM_alg_ntruprime_sntrup1277},
///// OQS_TEMPLATE_FRAGMENT_DEFINE_PQ_KEXS_END
    {0, NULL, NULL} /* End of list */
};

/*
 * @brief Maps the named SSH key exchange method's PQ kex algorithm as a string
 * to liboqs key exchange algorithm
 */
const OQS_ALG *ssh_kex_str_to_oqs_kex(const char *ssh_kex_name)
{
    const OQS_ALG *alg = NULL;

    for (alg = oqs_alg_mapping; alg->ssh_kex_name != NULL; alg++) {
        if (strcmp(alg->ssh_kex_name, ssh_kex_name) == 0) {
            return alg;
        }
    }

    return NULL;
}

/*
 * @brief Maps the named SSH key exchange method's PQ kex algorithm as a member of the ssh_kex_types_e enum
 * to liboqs key exchange algorithm
 */
const OQS_ALG *ssh_kex_type_to_oqs_kex(enum ssh_kex_types_e ssh_kex)
{
    const OQS_ALG* alg = NULL;

    for (alg = oqs_alg_mapping; alg->ssh_kex_name != NULL; alg++) {
        if (alg->ssh_kex_type == ssh_kex) {
            return alg;
        }
    }

    return NULL;
}

/*
 * @brief Generates the local key pair for the liboqs key exchange
 */
int ssh_oqs_kex_keypair_gen(ssh_session session)
{
    OQS_KEM *oqs_kem = NULL;
    uint8_t *oqs_sk = NULL;
    uint8_t *oqs_pk = NULL;
    int oqs_rc;

    const OQS_ALG *oqs_alg = ssh_kex_type_to_oqs_kex(session->next_crypto->kex_type);
    if (oqs_alg == NULL) {
        ssh_set_error(session, SSH_FATAL,
                      "Unknown OQS KEM type: %d",
                      session->next_crypto->kex_type);
        return SSH_ERROR;
    }

    /* Make sure old data isn't still there. */
    ssh_oqs_kex_free(session);

    oqs_kem = OQS_KEM_new(oqs_alg->oqs_kex_name);
    if (oqs_kem == NULL) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }

    oqs_sk = malloc(oqs_kem->length_secret_key);
    if (oqs_sk == NULL) {
        ssh_set_error_oom(session);
        goto error;
    }


    oqs_pk = malloc(oqs_kem->length_public_key);
    if (oqs_pk == NULL) {
        ssh_set_error_oom(session);
        goto error;
    }

    /* Generate client side part of kex */
    oqs_rc = OQS_KEM_keypair(oqs_kem, oqs_pk, oqs_sk);
    if (oqs_rc != OQS_SUCCESS) {
        ssh_set_error(session, SSH_FATAL, "OQS_KEM_keypair failed: %d", oqs_rc);
        goto error;
    }

    session->next_crypto->oqs_kem = oqs_kem;
    session->next_crypto->oqs_sk = oqs_sk;
    session->next_crypto->oqs_pk = oqs_pk;

    return SSH_OK;

error:

    if (oqs_kem != NULL) {
        if (oqs_sk != NULL) {
            explicit_bzero(oqs_sk, oqs_kem->length_secret_key);
            SAFE_FREE(oqs_sk);
        }
        if (oqs_pk != NULL) {
            SAFE_FREE(oqs_pk);
        }
        OQS_KEM_free(oqs_kem);
    }

    return SSH_ERROR;
}

/*
 * @brief Frees the local data used for key exchange. This only frees the members of next_crypto.
 */
void ssh_oqs_kex_free(ssh_session session)
{
    if (session->next_crypto->oqs_kem != NULL) {
        if (session->next_crypto->oqs_sk != NULL) {
            explicit_bzero(session->next_crypto->oqs_sk, session->next_crypto->oqs_kem->length_secret_key);
        }
        OQS_KEM_free(session->next_crypto->oqs_kem);
        session->next_crypto->oqs_kem = NULL;
    }

    SAFE_FREE(session->next_crypto->oqs_sk);
    SAFE_FREE(session->next_crypto->oqs_pk);
}

#endif /* WITH_POST_QUANTUM_CRYPTO */
