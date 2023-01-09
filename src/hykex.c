/*
 * hykex.c - Hybrid classical/post-quantum cryptography functions for key exchange
 *
 * Copyright (c) 2021 Microsoft Corporation
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
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#include "libssh/hykex.h"
#include "libssh/ecdh.h"

#if defined(WITH_POST_QUANTUM_CRYPTO) && defined(HAVE_ECDH)

#include "libssh/ssh2.h"
#include "libssh/buffer.h"
#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/crypto.h"
#include "libssh/dh.h"
#include "libssh/pki.h"
#include "libssh/oqs-utils.h"

#include <oqs/oqs.h>
#include <openssl/ecdh.h>

static SSH_PACKET_CALLBACK(ssh_packet_client_hykex_reply);

static ssh_packet_callback hykex_client_callbacks[] = {
    ssh_packet_client_hykex_reply
};

struct ssh_packet_callbacks_struct ssh_hykex_client_callbacks = {
    .start = SSH2_MSG_KEX_HY_REPLY,
    .n_callbacks = 1,
    .callbacks = hykex_client_callbacks,
    .user = NULL
};

static int hykex_type_to_curve(enum ssh_key_exchange_e kex_type) {
    switch (kex_type) {
///// OQS_TEMPLATE_FRAGMENT_HYKEX_TYPE_TO_CURVE_CASES_START
    case SSH_KEX_ECDH_NISTP256_FRODOKEM_640_AES_SHA256:
        return NID_X9_62_prime256v1;
    case SSH_KEX_ECDH_NISTP384_FRODOKEM_976_AES_SHA384:
        return NID_secp384r1;
    case SSH_KEX_ECDH_NISTP521_FRODOKEM_1344_AES_SHA512:
        return NID_secp521r1;
    case SSH_KEX_ECDH_NISTP256_FRODOKEM_640_SHAKE_SHA256:
        return NID_X9_62_prime256v1;
    case SSH_KEX_ECDH_NISTP384_FRODOKEM_976_SHAKE_SHA384:
        return NID_secp384r1;
    case SSH_KEX_ECDH_NISTP521_FRODOKEM_1344_SHAKE_SHA512:
        return NID_secp521r1;
    case SSH_KEX_ECDH_NISTP256_KYBER_512_SHA256:
        return NID_X9_62_prime256v1;
    case SSH_KEX_ECDH_NISTP384_KYBER_768_SHA384:
        return NID_secp384r1;
    case SSH_KEX_ECDH_NISTP521_KYBER_1024_SHA512:
        return NID_secp521r1;
    case SSH_KEX_ECDH_NISTP256_KYBER_512_90S_SHA256:
        return NID_X9_62_prime256v1;
    case SSH_KEX_ECDH_NISTP384_KYBER_768_90S_SHA384:
        return NID_secp384r1;
    case SSH_KEX_ECDH_NISTP521_KYBER_1024_90S_SHA512:
        return NID_secp521r1;
    case SSH_KEX_ECDH_NISTP256_BIKE_L1_SHA512:
        return NID_X9_62_prime256v1;
    case SSH_KEX_ECDH_NISTP384_BIKE_L3_SHA512:
        return NID_secp384r1;
    case SSH_KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864_SHA256:
        return NID_X9_62_prime256v1;
    case SSH_KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864F_SHA256:
        return NID_X9_62_prime256v1;
    case SSH_KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896_SHA512:
        return NID_secp384r1;
    case SSH_KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896F_SHA512:
        return NID_secp384r1;
    case SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128_SHA512:
        return NID_secp521r1;
    case SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128F_SHA512:
        return NID_secp521r1;
    case SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119_SHA512:
        return NID_secp521r1;
    case SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119F_SHA512:
        return NID_secp521r1;
    case SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128_SHA512:
        return NID_secp521r1;
    case SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128F_SHA512:
        return NID_secp521r1;
    case SSH_KEX_ECDH_NISTP256_HQC_128_SHA256:
        return NID_X9_62_prime256v1;
    case SSH_KEX_ECDH_NISTP384_HQC_192_SHA384:
        return NID_secp384r1;
    case SSH_KEX_ECDH_NISTP521_HQC_256_SHA512:
        return NID_secp521r1;
///// OQS_TEMPLATE_FRAGMENT_HYKEX_TYPE_TO_CURVE_CASES_END
    default:
        /* Anything else is an invalid input. */
        return SSH_ERROR;
    }
}

/* When we need to hash the shared secret buffer to arrive at the final hybrid shared secret, session->next_crypto->digest_type hasn't yet been set, so we can't use it to determine the hash function to use.
 * That gets set later in ssh_make_sessionid.
 * 
 * hashed_shared_secret is a new buffer allocated by this function. Caller is responsible for freeing it.
 */
static int hash_shared_secret(const ssh_buffer shared_secret, ssh_buffer *hashed_shared_secret, enum ssh_key_exchange_e kex_type) {
    int rc = SSH_OK;
    uint8_t hashbuf[SHA512_DIGEST_LENGTH];
    size_t digest_length = 0;
    ssh_buffer buf;

    switch (kex_type) {
///// OQS_TEMPLATE_FRAGMENT_HASH_SHARED_SECRET_SHA256_CASES_START
    case SSH_KEX_FRODOKEM_640_AES_SHA256:
    case SSH_KEX_ECDH_NISTP256_FRODOKEM_640_AES_SHA256:
    case SSH_KEX_FRODOKEM_640_SHAKE_SHA256:
    case SSH_KEX_ECDH_NISTP256_FRODOKEM_640_SHAKE_SHA256:
    case SSH_KEX_KYBER_512_SHA256:
    case SSH_KEX_ECDH_NISTP256_KYBER_512_SHA256:
    case SSH_KEX_KYBER_512_90S_SHA256:
    case SSH_KEX_ECDH_NISTP256_KYBER_512_90S_SHA256:
    case SSH_KEX_CLASSIC_MCELIECE_348864_SHA256:
    case SSH_KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864_SHA256:
    case SSH_KEX_CLASSIC_MCELIECE_348864F_SHA256:
    case SSH_KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864F_SHA256:
    case SSH_KEX_HQC_128_SHA256:
    case SSH_KEX_ECDH_NISTP256_HQC_128_SHA256:
///// OQS_TEMPLATE_FRAGMENT_HASH_SHARED_SECRET_SHA256_CASES_END
        digest_length = SHA256_DIGEST_LENGTH;
        sha256(ssh_buffer_get(shared_secret), ssh_buffer_get_len(shared_secret), hashbuf);
        break;
///// OQS_TEMPLATE_FRAGMENT_HASH_SHARED_SECRET_SHA384_CASES_START
    case SSH_KEX_FRODOKEM_976_AES_SHA384:
    case SSH_KEX_ECDH_NISTP384_FRODOKEM_976_AES_SHA384:
    case SSH_KEX_FRODOKEM_976_SHAKE_SHA384:
    case SSH_KEX_ECDH_NISTP384_FRODOKEM_976_SHAKE_SHA384:
    case SSH_KEX_KYBER_768_SHA384:
    case SSH_KEX_ECDH_NISTP384_KYBER_768_SHA384:
    case SSH_KEX_KYBER_768_90S_SHA384:
    case SSH_KEX_ECDH_NISTP384_KYBER_768_90S_SHA384:
    case SSH_KEX_HQC_192_SHA384:
    case SSH_KEX_ECDH_NISTP384_HQC_192_SHA384:
///// OQS_TEMPLATE_FRAGMENT_HASH_SHARED_SECRET_SHA384_CASES_END
        digest_length = SHA384_DIGEST_LENGTH;
        sha384(ssh_buffer_get(shared_secret), ssh_buffer_get_len(shared_secret), hashbuf);
        break;
///// OQS_TEMPLATE_FRAGMENT_HASH_SHARED_SECRET_SHA512_CASES_START
    case SSH_KEX_FRODOKEM_1344_AES_SHA512:
    case SSH_KEX_ECDH_NISTP521_FRODOKEM_1344_AES_SHA512:
    case SSH_KEX_FRODOKEM_1344_SHAKE_SHA512:
    case SSH_KEX_ECDH_NISTP521_FRODOKEM_1344_SHAKE_SHA512:
    case SSH_KEX_KYBER_1024_SHA512:
    case SSH_KEX_ECDH_NISTP521_KYBER_1024_SHA512:
    case SSH_KEX_KYBER_1024_90S_SHA512:
    case SSH_KEX_ECDH_NISTP521_KYBER_1024_90S_SHA512:
    case SSH_KEX_BIKE_L1_SHA512:
    case SSH_KEX_ECDH_NISTP256_BIKE_L1_SHA512:
    case SSH_KEX_BIKE_L3_SHA512:
    case SSH_KEX_ECDH_NISTP384_BIKE_L3_SHA512:
    case SSH_KEX_CLASSIC_MCELIECE_460896_SHA512:
    case SSH_KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896_SHA512:
    case SSH_KEX_CLASSIC_MCELIECE_460896F_SHA512:
    case SSH_KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896F_SHA512:
    case SSH_KEX_CLASSIC_MCELIECE_6688128_SHA512:
    case SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128_SHA512:
    case SSH_KEX_CLASSIC_MCELIECE_6688128F_SHA512:
    case SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128F_SHA512:
    case SSH_KEX_CLASSIC_MCELIECE_6960119_SHA512:
    case SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119_SHA512:
    case SSH_KEX_CLASSIC_MCELIECE_6960119F_SHA512:
    case SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119F_SHA512:
    case SSH_KEX_CLASSIC_MCELIECE_8192128_SHA512:
    case SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128_SHA512:
    case SSH_KEX_CLASSIC_MCELIECE_8192128F_SHA512:
    case SSH_KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128F_SHA512:
    case SSH_KEX_HQC_256_SHA512:
    case SSH_KEX_ECDH_NISTP521_HQC_256_SHA512:
///// OQS_TEMPLATE_FRAGMENT_HASH_SHARED_SECRET_SHA512_CASES_END
        digest_length = SHA512_DIGEST_LENGTH;
        sha512(ssh_buffer_get(shared_secret), ssh_buffer_get_len(shared_secret), hashbuf);
        break;
    default:
        return SSH_ERROR;
    }

    if ((buf = ssh_buffer_new()) == NULL) {
        return SSH_ERROR;
    }

    ssh_buffer_set_secure(buf);

    /* Coding note: OQS-OpenSSH internally stores the shared_secret as a buffer with the 4-byte length already prepended, and that's given to kex_gen_hash and kex_derive_keys.
     * libssh stores it as a bignum in the crypto structure. So, hashed_shared_secret comes back without the length prepended, but whenever it
     * gets serialized into bytes to compute the session hash (ssh_make_sessionid) or derived keys (ssh_generate_session_keys), the length will get prepended at that point to make it
     * an mpint.
     */
    rc = ssh_buffer_pack(buf,
                         "P",
                         digest_length, hashbuf);

    explicit_bzero(hashbuf, sizeof(hashbuf));

    if (rc != SSH_OK) {
        ssh_buffer_free(buf);
        return rc;
    }

    *hashed_shared_secret = buf;

    return SSH_OK;
}

int ssh_client_hykex_init(ssh_session session)
{
    int rc;
    int curve;
    int len;
    EC_KEY *key;
    const EC_GROUP *group;
    const EC_POINT *pubkey;
    ssh_string client_pubkey;
    ssh_buffer hybrid_pubkey;
    bignum_CTX ctx;

    /* Generate ephemeral key pairs for client. */
    
    /* Generate ECDH key pair. Much of this comes from ssh_client_ecdh_init in ecdh_crypto.c. */
    curve = hykex_type_to_curve(session->next_crypto->kex_type);
    if (curve == SSH_ERROR) {
        return SSH_ERROR;
    }

    key = EC_KEY_new_by_curve_name(curve);
    if (key == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Out of memory");
        return SSH_ERROR;
    }

    group = EC_KEY_get0_group(key);
    if (!EC_KEY_generate_key(key)) {
        EC_KEY_free(key);
        return SSH_ERROR;
    }

    ctx = BN_CTX_new();

    if (ctx == NULL) {
        EC_KEY_free(key);
        SSH_LOG(SSH_LOG_TRACE, "Out of memory");
        return SSH_ERROR;
    }

    pubkey = EC_KEY_get0_public_key(key);
    len = EC_POINT_point2oct(group, pubkey, POINT_CONVERSION_UNCOMPRESSED,
        NULL, 0, ctx);

    client_pubkey = ssh_string_new(len);
    if (client_pubkey == NULL) {
        BN_CTX_free(ctx);
        EC_KEY_free(key);
        return SSH_ERROR;
    }

    if (EC_POINT_point2oct(group, pubkey, POINT_CONVERSION_UNCOMPRESSED,
        ssh_string_data(client_pubkey), len, ctx) != (size_t)len) {
        /* This should not be possible, given we just asked EC_POINT_point2oct for the correct length. */
        BN_CTX_free(ctx);
        EC_KEY_free(key);
        return SSH_ERROR;
    }

    BN_CTX_free(ctx);

    session->next_crypto->ecdh_privkey = key;
    session->next_crypto->ecdh_client_pubkey = client_pubkey;

    /* Generate PQ key pair. */
    rc = ssh_oqs_kex_keypair_gen(session);
    if (rc < 0) {
        return rc;
    }

    /* Create the SSH2_MSG_KEX_HY_INIT message. Local message for client is OQS key + ECDH key. */
    hybrid_pubkey = ssh_buffer_new();
    if (hybrid_pubkey == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Out of memory");
        return SSH_ERROR;
    }

    rc = ssh_buffer_pack(hybrid_pubkey,
                         "PP",
                         session->next_crypto->oqs_kem->length_public_key, session->next_crypto->oqs_pk,
                         ssh_string_len(session->next_crypto->ecdh_client_pubkey), ssh_string_data(session->next_crypto->ecdh_client_pubkey));
    if (rc < 0) {
        ssh_buffer_free(hybrid_pubkey);
        return rc;
    }

    session->next_crypto->oqs_local_msg = ssh_string_new(ssh_buffer_get_len(hybrid_pubkey));
    if (session->next_crypto->oqs_local_msg == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Out of memory");
        ssh_buffer_free(hybrid_pubkey);
        return SSH_ERROR;
    }

    rc = ssh_string_fill(session->next_crypto->oqs_local_msg, ssh_buffer_get(hybrid_pubkey), ssh_buffer_get_len(hybrid_pubkey));
    ssh_buffer_free(hybrid_pubkey);
    if (rc < 0) {
        return rc;
    }

    rc = ssh_buffer_pack(session->out_buffer,
                         "bS",
                         SSH2_MSG_KEX_HY_INIT,
                         session->next_crypto->oqs_local_msg);
    if (rc < 0) {
        return rc;
    }

    /* Set callbacks for when we get the server's reply */
    ssh_packet_set_callbacks(session, &ssh_hykex_client_callbacks);
    session->dh_handshake_state = DH_STATE_INIT_SENT;

    /* Send SSH2_MSG_KEX_HY_INIT message */
    rc = ssh_packet_send(session);

    return rc;
}

/** @internal
 * @brief parses a SSH2_MSG_KEX_HY_REPLY packet and sends back
 * a SSH_MSG_NEWKEYS
 */
static SSH_PACKET_CALLBACK(ssh_packet_client_hykex_reply) {
    int rc, oqs_rc;
    ssh_string hostkey = NULL;
    uint8_t *oqs_shared_secret = NULL;
    ssh_buffer hybrid_shared_secret = NULL;
    ssh_buffer hashed_shared_secret = NULL;

    (void)type;
    (void)user;

    ssh_packet_remove_callbacks(session, &ssh_hykex_client_callbacks);

    if (session->next_crypto->oqs_kem == NULL ||
        session->next_crypto->oqs_pk == NULL ||
        session->next_crypto->oqs_sk == NULL) {
        ssh_set_error(session, SSH_FATAL, "ssh_packet_client_hykex_reply called without OQS keys being ready");
        rc = SSH_ERROR;
        goto exit;
    }

    /* Read server's SSH2_MSG_KEX_HY_REPLY message */
    hostkey = ssh_buffer_get_ssh_string(packet);
    if (hostkey == NULL) {
        ssh_set_error(session, SSH_FATAL, "Could not get hostkey from packet");
        rc = SSH_ERROR;
        goto exit;
    }

    rc = ssh_dh_import_next_pubkey_blob(session, hostkey);
    SSH_STRING_FREE(hostkey);
    if (rc < 0) {
        ssh_set_error(session, SSH_FATAL, "Could not import host key");
        rc = SSH_ERROR;
        goto exit;
    }

    session->next_crypto->oqs_remote_msg = ssh_buffer_get_ssh_string(packet);
    if (session->next_crypto->oqs_remote_msg == NULL) {
        ssh_set_error(session, SSH_FATAL, "Could not get oqs_remote_msg from packet");
        rc = SSH_ERROR;
        goto exit;
    }

    /* Deserialize ECDH public key. ECDH public key is after the PQ key of known length in the remote message. */
    session->next_crypto->ecdh_server_pubkey = ssh_string_new(ssh_string_len(session->next_crypto->oqs_remote_msg) - session->next_crypto->oqs_kem->length_ciphertext);
    if (session->next_crypto->ecdh_server_pubkey == NULL) {
        ssh_set_error_oom(session);
        rc = SSH_ERROR;
        goto exit;
    }

    rc = ssh_string_fill(session->next_crypto->ecdh_server_pubkey,
                         ((const unsigned char *)ssh_string_data(session->next_crypto->oqs_remote_msg)) + session->next_crypto->oqs_kem->length_ciphertext,
                         ssh_string_len(session->next_crypto->oqs_remote_msg) - session->next_crypto->oqs_kem->length_ciphertext);
    if (rc < 0) {
        ssh_set_error(session, SSH_FATAL, "Could not copy Q_C");
        rc = SSH_ERROR;
        goto exit;
    }

    session->next_crypto->dh_server_signature = ssh_buffer_get_ssh_string(packet);
    if (session->next_crypto->dh_server_signature == NULL) {
        ssh_set_error(session, SSH_FATAL, "Could not get signature from packet");
        rc = SSH_ERROR;
        goto exit;
    }

    /** Compute shared secret **/

    /* Compute ECDH shared secret */
    if (ecdh_build_k(session) < 0) {
        ssh_set_error(session, SSH_FATAL, "Cannot build k number");
        rc = SSH_ERROR;
        goto exit;
    }

    /* At this point, the ECDH shared secret is in the shared_secret bignum. */
    oqs_shared_secret = malloc(session->next_crypto->oqs_kem->length_shared_secret);
    if (oqs_shared_secret == NULL) {
        ssh_set_error_oom(session);
        rc = SSH_ERROR;
        goto exit;
    }

    /* Compute the PQ shared secret. */
    oqs_rc = OQS_KEM_decaps(session->next_crypto->oqs_kem,
                            oqs_shared_secret,
                            ssh_string_data(session->next_crypto->oqs_remote_msg),
                            session->next_crypto->oqs_sk);
    if (oqs_rc != OQS_SUCCESS) {
        ssh_set_error(session, SSH_FATAL, "OQS_KEM_decaps failed: %d", oqs_rc);
        rc = SSH_ERROR;
        goto exit;
    }

    /* Assemble hybrid shared secret. */
    hybrid_shared_secret = ssh_buffer_new();
    if (hybrid_shared_secret == NULL) {
        ssh_set_error_oom(session);
        rc = SSH_ERROR;
        goto exit;
    }

    ssh_buffer_set_secure(hybrid_shared_secret);

    rc = ssh_buffer_pack(hybrid_shared_secret,
                         "PB",
                         session->next_crypto->oqs_kem->length_shared_secret, oqs_shared_secret,
                         session->next_crypto->shared_secret);

    if (rc != SSH_OK) {
        goto exit;
    }

    /* Hash contents of shared_secret and convert that to bignum for later key derivation. */
    rc = hash_shared_secret(hybrid_shared_secret, &hashed_shared_secret, session->next_crypto->kex_type);
    if (rc < 0) {
        ssh_set_error(session, SSH_FATAL, "Could not hash inputs to shared secret");
        goto exit;
    }

    bignum_bin2bn(ssh_buffer_get(hashed_shared_secret), ssh_buffer_get_len(hashed_shared_secret), &session->next_crypto->shared_secret);
    session->next_crypto->oqs_shared_secret_len = ssh_buffer_get_len(hashed_shared_secret);
    if (session->next_crypto->shared_secret == NULL) {
        ssh_set_error_oom(session);
        rc = SSH_ERROR;
        goto exit;
    }

    /* Send SSH2_MSG_NEWKEYS message */
    rc = ssh_buffer_add_u8(session->out_buffer, SSH2_MSG_NEWKEYS);
    if (rc < 0) {
        ssh_set_error(session, SSH_FATAL, "Could not add SSH2_MSG_NEWKEYS to buffer");
        goto exit;
    }

    rc = ssh_packet_send(session);
    if (rc < 0) {
        ssh_set_error(session, SSH_FATAL, "Could not send packet");
        goto exit;
    }

    SSH_LOG(SSH_LOG_PROTOCOL, "SSH2_MSG_NEWKEYS sent");
    session->dh_handshake_state = DH_STATE_NEWKEYS_SENT;

    rc = SSH_PACKET_USED;

exit:

    if (oqs_shared_secret != NULL) {
        explicit_bzero(oqs_shared_secret, session->next_crypto->oqs_kem->length_shared_secret);
        SAFE_FREE(oqs_shared_secret);
    }

    /* ssh_buffer_free will zero the contents since the buffer was marked secure at creation time. */
    ssh_buffer_free(hybrid_shared_secret);
    ssh_buffer_free(hashed_shared_secret);

    ssh_oqs_kex_free(session);

    if (rc != SSH_PACKET_USED) {
        session->session_state = SSH_SESSION_STATE_ERROR;
    }

    return SSH_PACKET_USED;
}

#ifdef WITH_SERVER

static ssh_packet_callback hykex_server_callbacks[] = {
    ssh_packet_server_hykex_init
};

struct ssh_packet_callbacks_struct ssh_hykex_server_callbacks = {
    .start = SSH2_MSG_KEX_HY_INIT,
    .n_callbacks = 1,
    .callbacks = hykex_server_callbacks,
    .user = NULL
};

void ssh_server_hykex_init(ssh_session session)
{
    ssh_packet_set_callbacks(session, &ssh_hykex_server_callbacks);
}

SSH_PACKET_CALLBACK(ssh_packet_server_hykex_init) {
    int rc, oqs_rc, curve, len;
    enum ssh_digest_e digest = SSH_DIGEST_AUTO;
    ssh_string sig_blob = NULL;
    ssh_string q_c_string = NULL;
    ssh_string q_s_string = NULL;
    ssh_string pq_pubkey_blob = NULL;
    uint8_t *oqs_shared_secret = NULL;
    ssh_buffer hybrid_shared_secret = NULL;
    ssh_buffer hashed_shared_secret = NULL;
    ssh_key privkey = NULL;
    bignum_CTX ctx = NULL;
    EC_KEY *ecdh_key;
    const EC_GROUP *group;
    const EC_POINT *ecdh_pubkey;

    ssh_packet_remove_callbacks(session, &ssh_hykex_server_callbacks);

    /* oqs_remote_msg is concatenated PQ key + ECDH key as mpint */
    session->next_crypto->oqs_remote_msg = ssh_buffer_get_ssh_string(packet);
    if (session->next_crypto->oqs_remote_msg == NULL) {
        ssh_set_error(session, SSH_FATAL, "Could not get client public key from packet");
        goto error;
    }

    /* Generate server PQ key pair. We do this first so we can sanity check the length of the client's presented public key 
     * before generating the ECDH key pair. */
    rc = ssh_oqs_kex_keypair_gen(session);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Could not generate PQ key pair");
        goto error;
    }

    /* Read client's ECDH public key */
    q_c_string = ssh_string_new(ssh_string_len(session->next_crypto->oqs_remote_msg) - session->next_crypto->oqs_kem->length_public_key);
    if (q_c_string == NULL) {
        ssh_set_error_oom(session);
        goto error;
    }

    rc = ssh_string_fill(q_c_string,
                         ((unsigned char *)ssh_string_data(session->next_crypto->oqs_remote_msg)) + session->next_crypto->oqs_kem->length_public_key,
                         ssh_string_len(session->next_crypto->oqs_remote_msg) - session->next_crypto->oqs_kem->length_public_key);
    if (rc < 0) {
        ssh_string_free(q_c_string);
        ssh_set_error(session, SSH_FATAL, "Could not copy Q_C");
        goto error;
    }

    session->next_crypto->ecdh_client_pubkey = q_c_string;

    /* Generate server ECDH key pair */
    ctx = BN_CTX_new();
    if (ctx == NULL) {
        ssh_set_error_oom(session);
        goto error;
    }

    curve = hykex_type_to_curve(session->next_crypto->kex_type);
    if (curve == SSH_ERROR) {
        BN_CTX_free(ctx);
        ssh_set_error(session, SSH_FATAL, "Invalid hykex type");
        goto error;
    }

    ecdh_key = EC_KEY_new_by_curve_name(curve);
    if (ecdh_key == NULL) {
        ssh_set_error_oom(session);
        BN_CTX_free(ctx);
        goto error;
    }

    group = EC_KEY_get0_group(ecdh_key);
    EC_KEY_generate_key(ecdh_key);

    ecdh_pubkey = EC_KEY_get0_public_key(ecdh_key);
    len = EC_POINT_point2oct(group,
                             ecdh_pubkey,
                             POINT_CONVERSION_UNCOMPRESSED,
                             NULL,
                             0,
                             ctx);

    q_s_string = ssh_string_new(len);
    if (q_s_string == NULL) {
        EC_KEY_free(ecdh_key);
        BN_CTX_free(ctx);
        goto error;
    }

    if (EC_POINT_point2oct(group,
                           ecdh_pubkey,
                           POINT_CONVERSION_UNCOMPRESSED,
                           ssh_string_data(q_s_string),
                           len,
                           ctx) != (size_t)len) {
        /* This should not be possible. */
        EC_KEY_free(ecdh_key);
        BN_CTX_free(ctx);
        goto error;
    }

    BN_CTX_free(ctx);

    session->next_crypto->ecdh_privkey = ecdh_key;
    session->next_crypto->ecdh_server_pubkey = q_s_string;

    /* Compute ECDH shared secret */
    rc = ecdh_build_k(session);
    if (rc < 0) {
        ssh_set_error(session, SSH_FATAL, "Cannot build k number");
        goto error;
    }

    /* At this point, the ECDH shared secret is in the shared_secret bignum. */
    oqs_shared_secret = malloc(session->next_crypto->oqs_kem->length_shared_secret);
    if (oqs_shared_secret == NULL) {
        ssh_set_error_oom(session);
        goto error;
    }

    /* Compute local message, shared secret, and session id */
    session->next_crypto->oqs_local_msg = ssh_string_new(session->next_crypto->oqs_kem->length_ciphertext + ssh_string_len(session->next_crypto->ecdh_server_pubkey));
    if (session->next_crypto->oqs_local_msg == NULL) {
        explicit_bzero(oqs_shared_secret, session->next_crypto->oqs_kem->length_shared_secret);
        SAFE_FREE(oqs_shared_secret);
        ssh_set_error_oom(session);
        goto error;
    }

    oqs_rc = OQS_KEM_encaps(session->next_crypto->oqs_kem,
                            ssh_string_data(session->next_crypto->oqs_local_msg),
                            oqs_shared_secret,
                            ssh_string_data(session->next_crypto->oqs_remote_msg));
    if (oqs_rc != OQS_SUCCESS) {
        explicit_bzero(oqs_shared_secret, session->next_crypto->oqs_kem->length_shared_secret);
        SAFE_FREE(oqs_shared_secret);

        ssh_set_error(session, SSH_FATAL, "OQS_KEM_encaps failed: %d", oqs_rc);
        goto error;
    }

    /* Append ECDH public key to local message after OQS ciphertext. */
    memcpy(((unsigned char*)ssh_string_data(session->next_crypto->oqs_local_msg)) + session->next_crypto->oqs_kem->length_ciphertext,
        ssh_string_data(session->next_crypto->ecdh_server_pubkey),
        ssh_string_len(session->next_crypto->ecdh_server_pubkey));

    /* Assemble hybrid shared secret. */
    hybrid_shared_secret = ssh_buffer_new();
    if (hybrid_shared_secret == NULL) {
        explicit_bzero(oqs_shared_secret, session->next_crypto->oqs_kem->length_shared_secret);
        SAFE_FREE(oqs_shared_secret);

        ssh_set_error_oom(session);
        goto error;
    }

    ssh_buffer_set_secure(hybrid_shared_secret);

    rc = ssh_buffer_pack(hybrid_shared_secret,
                         "PB",
                         session->next_crypto->oqs_kem->length_shared_secret, oqs_shared_secret,
                         session->next_crypto->shared_secret);

    explicit_bzero(oqs_shared_secret, session->next_crypto->oqs_kem->length_shared_secret);
    SAFE_FREE(oqs_shared_secret);

    if (rc != SSH_OK) {
        ssh_buffer_free(hybrid_shared_secret);
        ssh_set_error(session, SSH_FATAL, "Could not assemble hybrid shared secret buffer");
        goto error;
    }

    /* Hash contents of shared_secret and convert to bignum for later use in key derivation.
     * hashed_shared_secret is allocated inside the function and the caller takes ownership and must free.
     */
    rc = hash_shared_secret(hybrid_shared_secret, &hashed_shared_secret, session->next_crypto->kex_type);

    /* ssh_buffer_free will zero the contents of a buffer marked secure. */
    ssh_buffer_free(hybrid_shared_secret);

    if (rc < 0) {
        ssh_set_error(session, SSH_FATAL, "Could not hash inputs to shared secret");
        goto error;
    }

    /* PQ data no longer required now. */
    ssh_oqs_kex_free(session);

    /* Clear previous contents of shared_secret, which was only the ECDH shared secret. */
    bignum_safe_free(session->next_crypto->shared_secret);

    /* Convert hashed shared secret into a bignum for later key derivation. */
    bignum_bin2bn(ssh_buffer_get(hashed_shared_secret), ssh_buffer_get_len(hashed_shared_secret), &session->next_crypto->shared_secret);
    session->next_crypto->oqs_shared_secret_len = ssh_buffer_get_len(hashed_shared_secret);

    /* ssh_buffer_free will zero the contents of a buffer marked secure. */
    ssh_buffer_free(hashed_shared_secret);

    if (session->next_crypto->shared_secret == NULL) {
        ssh_set_error_oom(session);
        goto error;
    }

    rc = ssh_get_key_params(session, &privkey, &digest);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Could not get private key");
        goto error;
    }

    rc = ssh_make_sessionid(session);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Could not create a session id");
        goto error;
    }

    sig_blob = ssh_srv_pki_do_sign_sessionid(session, privkey, digest);
    if (sig_blob == NULL) {
        ssh_set_error(session, SSH_FATAL, "Could not sign the session id");
        goto error;
    }

    /* Create SSH2_MSG_KEX_HY_REPLY message: host key, server public key, signature */
    rc = ssh_dh_get_next_server_publickey_blob(session, &pq_pubkey_blob);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Could not export server public key");
        SSH_STRING_FREE(sig_blob);
        goto error;
    }

    rc = ssh_buffer_pack(session->out_buffer,
                         "bSSS",
                         SSH2_MSG_KEX_HY_REPLY,
                         pq_pubkey_blob, /* host key */
                         session->next_crypto->oqs_local_msg, /* server PQ kex message + ECDH public key */
                         sig_blob); /* signature blob */

    SSH_STRING_FREE(sig_blob);
    SSH_STRING_FREE(pq_pubkey_blob);

    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Could not build SSH2_MSG_KEX_HY_REPLY packet");
        goto error;
    }

    /* Send SSH2_MSG_KEX_HY_REPLY message */
    rc = ssh_packet_send(session);
    if (rc != SSH_OK) {
        goto error;
    }
    SSH_LOG(SSH_LOG_PROTOCOL, "SSH2_MSG_KEX_HY_REPLY sent");

    /* Send the SSH2_MSG_NEWKEYS message */
    rc = ssh_buffer_add_u8(session->out_buffer, SSH2_MSG_NEWKEYS);
    if (rc != SSH_OK) {
        goto error;
    }

    session->dh_handshake_state = DH_STATE_NEWKEYS_SENT;
    rc = ssh_packet_send(session);
    if (rc != SSH_OK) {
        goto error;
    }
    SSH_LOG(SSH_LOG_PROTOCOL, "SSH2_MSG_NEWKEYS sent");

    return SSH_PACKET_USED;

error:

    ssh_buffer_reinit(session->out_buffer);
    session->session_state = SSH_SESSION_STATE_ERROR;
    return SSH_PACKET_USED;
}

#endif /* WITH_SERVER */

#endif /* defined(WITH_POST_QUANTUM_CRYPTO) && defined(HAVE_ECDH) */
