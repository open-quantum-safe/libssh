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
///// OQS_TEMPLATE_FRAGMENT_HYKEX_TYPE_TO_CURVE_CASES_END
    default:
        /* Anything else is an invalid input. */
        return SSH_ERROR;
    }
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
    bignum_CTX ctx = BN_CTX_new();

    if (ctx == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Out of memory");
        return SSH_ERROR;
    }

    /* Generate ephemeral key pairs for client. */
    
    /* Generate ECDH key pair. Much of this comes from ssh_client_ecdh_init in ecdh_crypto.c. */
    curve = hykex_type_to_curve(session->next_crypto->kex_type);
    if (curve == SSH_ERROR) {
        BN_CTX_free(ctx);
        return SSH_ERROR;
    }

    key = EC_KEY_new_by_curve_name(curve);
    if (key == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Out of memory");
        BN_CTX_free(ctx);
        return SSH_ERROR;
    }

    group = EC_KEY_get0_group(key);
    if (!EC_KEY_generate_key(key)) {
        EC_KEY_free(key);
        BN_CTX_free(ctx);
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

    EC_POINT_point2oct(group, pubkey, POINT_CONVERSION_UNCOMPRESSED,
        ssh_string_data(client_pubkey), len, ctx);
    BN_CTX_free(ctx);

    session->next_crypto->ecdh_privkey = key;
    session->next_crypto->ecdh_client_pubkey = client_pubkey;

    /* Generate PQ key pair. */
    rc = ssh_oqs_kex_keypair_gen(session);
    if (rc < 0) {
        return rc;
    }

    /* Create the SSH2_MSG_KEX_HY_INIT message. Local message for client is just the two public keys. */
    session->next_crypto->oqs_local_msg = ssh_string_new(session->next_crypto->oqs_kem->length_public_key);
    if (session->next_crypto->oqs_local_msg == NULL) {
        SSH_LOG(SSH_LOG_TRACE, "Out of memory");
        return SSH_ERROR;
    }

    rc = ssh_string_fill(session->next_crypto->oqs_local_msg,
                         session->next_crypto->oqs_pk, 
                         session->next_crypto->oqs_kem->length_public_key);
    if (rc < 0) {
        return rc;
    }

    rc = ssh_buffer_pack(session->out_buffer,
                         "bSS",
                         SSH2_MSG_KEX_HY_INIT,
                         session->next_crypto->ecdh_client_pubkey,
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
    int rc, oqs_rc, ecdh_secret_len;
    ssh_string hostkey = NULL;
    uint8_t *shared_secret = NULL;

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

    /* Deserialize ECDH public key. This code comes from ssh_packet_client_ecdh_reply in ecdh.c */
    session->next_crypto->ecdh_server_pubkey = ssh_buffer_get_ssh_string(packet);
    if (session->next_crypto->ecdh_server_pubkey == NULL) {
        ssh_set_error(session, SSH_FATAL, "No Q_S ECC point in packet");
        rc = SSH_ERROR;
        goto exit;
    }

    session->next_crypto->oqs_remote_msg = ssh_buffer_get_ssh_string(packet);
    if (session->next_crypto->oqs_remote_msg == NULL) {
        ssh_set_error(session, SSH_FATAL, "Could not get oqs_remote_msg from packet");
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

    /* Compute length of ECDH secret before we call ecdh_build_k, because it frees the private key, and by extension, group */
    ecdh_secret_len = (EC_GROUP_get_degree(EC_KEY_get0_group(session->next_crypto->ecdh_privkey)) + 7) / 8;

    /* Compute ECDH shared secret */
    if (ecdh_build_k(session) < 0) {
        ssh_set_error(session, SSH_FATAL, "Cannot build k number");
        rc = SSH_ERROR;
        goto exit;
    }

    /* At this point, the ECDH shared secret is in the shared_secret bignum. We need to pull it back out as bytes and pad it with leading zeroes
     * so that it combines correctly with the PQ shared secret later.
     */
    session->next_crypto->oqs_shared_secret_len = ecdh_secret_len + session->next_crypto->oqs_kem->length_shared_secret;
    shared_secret = malloc(session->next_crypto->oqs_shared_secret_len);
    if (shared_secret == NULL) {
        ssh_set_error_oom(session);
        rc = SSH_ERROR;
        goto exit;
    }
    memset(shared_secret, 0, session->next_crypto->oqs_shared_secret_len);
    /* Copy the ECDH shared secret, shifting it past any leading zeroes that will have been removed by the bignum library. */
    bignum_bn2bin(session->next_crypto->shared_secret, 
                  ecdh_secret_len,
                  &shared_secret[ecdh_secret_len - bignum_num_bytes(session->next_crypto->shared_secret)]);

    bignum_safe_free(session->next_crypto->shared_secret);

    /* Compute the PQ shared secret, writing it immediately after the ECDH shared secret. */
    oqs_rc = OQS_KEM_decaps(session->next_crypto->oqs_kem,
                            &shared_secret[ecdh_secret_len],
                            ssh_string_data(session->next_crypto->oqs_remote_msg),
                            session->next_crypto->oqs_sk);
    if (oqs_rc != OQS_SUCCESS) {
        ssh_set_error(session, SSH_FATAL, "OQS_KEM_decaps failed: %d", oqs_rc);
        rc = SSH_ERROR;
        goto exit;
    }

    /* PQ data no longer required after calling decaps. */
    ssh_oqs_kex_free(session);

    /* The two shared secrets are now concatenated in shared_secret buffer. Convert to bignum for later use in deriving keys. */
    bignum_bin2bn(shared_secret, session->next_crypto->oqs_shared_secret_len, &session->next_crypto->shared_secret);
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

    if (shared_secret != NULL) {
        explicit_bzero(shared_secret, session->next_crypto->oqs_shared_secret_len);
        SAFE_FREE(shared_secret);
    }

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
    int rc, oqs_rc, curve, ecdh_secret_len, len;
    enum ssh_digest_e digest = SSH_DIGEST_AUTO;
    ssh_string sig_blob = NULL;
    ssh_string q_c_string = NULL;
    ssh_string q_s_string = NULL;
    ssh_string pq_pubkey_blob = NULL;
    uint8_t *shared_secret = NULL;
    ssh_key privkey = NULL;
    bignum_CTX ctx = NULL;
    EC_KEY *ecdh_key;
    const EC_GROUP *group;
    const EC_POINT *ecdh_pubkey;

    ssh_packet_remove_callbacks(session, &ssh_hykex_server_callbacks);

    /* Read client's ECDH public key */
    q_c_string = ssh_buffer_get_ssh_string(packet);
    if (q_c_string == NULL) {
        ssh_set_error(session, SSH_FATAL, "No Q_C ECC point in packet");
        goto error;
    }
    session->next_crypto->ecdh_client_pubkey = q_c_string;

    /* Read client's PQ public key */
    session->next_crypto->oqs_remote_msg = ssh_buffer_get_ssh_string(packet);
    if (session->next_crypto->oqs_remote_msg == NULL) {
        ssh_set_error(session, SSH_FATAL, "No remote PQ public key in packet");
        goto error;
    }

    /** Generate key pairs for server **/
    /* Generate PQ key pair. We do this first so we can sanity check the length of the client's presented public key 
     * before generating the ECDH key pair. */
    rc = ssh_oqs_kex_keypair_gen(session);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Could not generate PQ key pair");
        goto error;
    }

    /* Make sure the client's public key is the length we expect. This must be done after OQS_KEM_new so length_public_key is available,
     * and so must happen after ssh_oqs_kex_keypair_gen which calls it.
     */
    if (ssh_string_len(session->next_crypto->oqs_remote_msg) != session->next_crypto->oqs_kem->length_public_key) {
        ssh_set_error(session, SSH_FATAL, "Remote public key is incorrect length; expected %zu, got %zu",
                      session->next_crypto->oqs_kem->length_public_key,
                      ssh_string_len(session->next_crypto->oqs_remote_msg));
        goto error;
    }

    /* Generate ECDH key pair */
    ctx = BN_CTX_new();
    if (ctx == NULL) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
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

    EC_POINT_point2oct(group,
                       ecdh_pubkey,
                       POINT_CONVERSION_UNCOMPRESSED,
                       ssh_string_data(q_s_string),
                       len,
                       ctx);
    BN_CTX_free(ctx);

    session->next_crypto->ecdh_privkey = ecdh_key;
    session->next_crypto->ecdh_server_pubkey = q_s_string;

    /* Compute length of ECDH secret before we call ecdh_build_k, because it frees the private key, and by extension, group */
    ecdh_secret_len = (EC_GROUP_get_degree(group) + 7) / 8;

    /* Compute ECDH shared secret */
    rc = ecdh_build_k(session);
    if (rc < 0) {
        ssh_set_error(session, SSH_FATAL, "Cannot build k number");
        goto error;
    }

    /* At this point, the ECDH shared secret is in the shared_secret bignum. We need to pull it back out as bytes and pad it with leading zeroes
     * so that it combines correctly with the PQ shared secret later.
     */
    session->next_crypto->oqs_shared_secret_len = ecdh_secret_len + session->next_crypto->oqs_kem->length_shared_secret;
    shared_secret = malloc(session->next_crypto->oqs_shared_secret_len);
    if (shared_secret == NULL) {
        ssh_set_error_oom(session);
        goto error;
    }
    memset(shared_secret, 0, session->next_crypto->oqs_shared_secret_len);
    /* Copy the ECDH shared secret, shifting it past any leading zeroes that will have been removed by the bignum library. */
    bignum_bn2bin(session->next_crypto->shared_secret, 
                  ecdh_secret_len,
                  &shared_secret[ecdh_secret_len - bignum_num_bytes(session->next_crypto->shared_secret)]);

    bignum_safe_free(session->next_crypto->shared_secret);

    /* Compute local message, shared secret, and session id */
    session->next_crypto->oqs_local_msg = ssh_string_new(session->next_crypto->oqs_kem->length_ciphertext);
    if (session->next_crypto->oqs_local_msg == NULL) {
        ssh_set_error_oom(session);
        goto error;
    }

    oqs_rc = OQS_KEM_encaps(session->next_crypto->oqs_kem,
                            ssh_string_data(session->next_crypto->oqs_local_msg),
                            &shared_secret[ecdh_secret_len],
                            ssh_string_data(session->next_crypto->oqs_remote_msg));
    if (oqs_rc != OQS_SUCCESS) {
        explicit_bzero(shared_secret, session->next_crypto->oqs_shared_secret_len);
        SAFE_FREE(shared_secret);

        ssh_set_error(session, SSH_FATAL, "OQS_KEM_encaps failed: %d", oqs_rc);
        goto error;
    }

    /* PQ data no longer required after calling encaps. */
    ssh_oqs_kex_free(session);

    /* Both shared secrets are now concatenated in shared_secret. Convert to bignum for later use in key derivation. */
    bignum_bin2bn(shared_secret, session->next_crypto->oqs_shared_secret_len, &session->next_crypto->shared_secret);

    explicit_bzero(shared_secret, session->next_crypto->oqs_shared_secret_len);
    SAFE_FREE(shared_secret);

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
                         "bSSSS",
                         SSH2_MSG_KEX_HY_REPLY,
                         pq_pubkey_blob, /* host key */
                         session->next_crypto->ecdh_server_pubkey, /* server ECDH public key */
                         session->next_crypto->oqs_local_msg, /* server PQ kex message */
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
