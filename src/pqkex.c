/*
 * pqkex.c - Post-quantum cryptography functions for key exchange
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

#include "libssh/pqkex.h"

#ifdef WITH_POST_QUANTUM_CRYPTO

#include "libssh/ssh2.h"
#include "libssh/buffer.h"
#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/crypto.h"
#include "libssh/dh.h"
#include "libssh/pki.h"
#include "libssh/oqs-utils.h"

#include <oqs/oqs.h>

static SSH_PACKET_CALLBACK(ssh_packet_client_pqkex_reply);

static ssh_packet_callback pqkex_client_callbacks[] = {
    ssh_packet_client_pqkex_reply
};

struct ssh_packet_callbacks_struct ssh_pqkex_client_callbacks = {
    .start = SSH2_MSG_KEX_PQ_REPLY,
    .n_callbacks = 1,
    .callbacks = pqkex_client_callbacks,
    .user = NULL
};

int ssh_client_pqkex_init(ssh_session session)
{
    int rc;

    /* Create ephemeral key pair for client */
    rc = ssh_oqs_kex_keypair_gen(session);
    if (rc < 0) {
        return rc;
    }

    /* Create the SSH2_MSG_KEX_PQ_INIT message. Local message for client is just the public key. */
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
                         "bS",
                         SSH2_MSG_KEX_PQ_INIT,
                         session->next_crypto->oqs_local_msg);

    if (rc < 0) {
        return rc;
    }

    /* Set callbacks for when we get the server's reply */
    ssh_packet_set_callbacks(session, &ssh_pqkex_client_callbacks);
    session->dh_handshake_state = DH_STATE_INIT_SENT;

    /* Send SSH2_MSG_KEX_PQ_INIT message */
    rc = ssh_packet_send(session);

    return rc;
}

/** @internal
 * @brief parses a SSH2_MSG_KEX_PQ_REPLY packet and sends back
 * a SSH2_MSG_NEWKEYS
 */
static SSH_PACKET_CALLBACK(ssh_packet_client_pqkex_reply) {
    int rc, oqs_rc;
    ssh_string hostkey = NULL, signature = NULL;
    uint8_t *shared_secret = NULL;

    (void)type;
    (void)user;

    ssh_packet_remove_callbacks(session, &ssh_pqkex_client_callbacks);

    if (session->next_crypto->oqs_kem == NULL ||
        session->next_crypto->oqs_pk == NULL ||
        session->next_crypto->oqs_sk == NULL) {
        ssh_set_error(session, SSH_FATAL, "ssh_packet_client_pqkex_reply called without OQS keys being ready");
        rc = SSH_ERROR;
        goto exit;
    }

    /* Read server's SSH2_MSG_KEX_PQ_REPLY message */
    hostkey = ssh_buffer_get_ssh_string(packet);
    if (hostkey == NULL) {
        ssh_set_error(session, SSH_FATAL, "Could not get hostkey from packet");
        rc = SSH_ERROR;
        goto exit;
    }

    rc = ssh_dh_import_next_pubkey_blob(session, hostkey);
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

    signature = ssh_buffer_get_ssh_string(packet);
    if (signature == NULL) {
        ssh_set_error(session, SSH_FATAL, "Could not get signature from packet");
        rc = SSH_ERROR;
        goto exit;
    }

    session->next_crypto->dh_server_signature = signature;
    signature = NULL; /* ownership changed */

    /* Compute shared secret */
    shared_secret = malloc(session->next_crypto->oqs_kem->length_shared_secret);
    if (shared_secret == NULL) {
        ssh_set_error(session, SSH_FATAL, "Out of memory allocating shared_secret");
        rc = SSH_ERROR;
        goto exit;
    }

    oqs_rc = OQS_KEM_decaps(session->next_crypto->oqs_kem,
                            shared_secret,
                            ssh_string_data(session->next_crypto->oqs_remote_msg),
                            session->next_crypto->oqs_sk);
    if (oqs_rc != OQS_SUCCESS) {
        ssh_set_error(session, SSH_FATAL, "OQS_KEM_decaps failed: %d", oqs_rc);
        rc = SSH_ERROR;
        goto exit;
    }

    session->next_crypto->oqs_shared_secret_len = session->next_crypto->oqs_kem->length_shared_secret;

    /* PQ data not needed after calling decaps. */
    ssh_oqs_kex_free(session);

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

    ssh_string_burn(hostkey);
    SSH_STRING_FREE(hostkey);
    ssh_string_burn(signature);
    SSH_STRING_FREE(signature);

    if (shared_secret != NULL) {
        explicit_bzero(shared_secret, session->next_crypto->oqs_kem->length_shared_secret);
        SAFE_FREE(shared_secret);
    }

    if (rc != SSH_PACKET_USED) {
        session->session_state = SSH_SESSION_STATE_ERROR;
    }

    return SSH_PACKET_USED;
}

#ifdef WITH_SERVER

static ssh_packet_callback pqkex_server_callbacks[] = {
    ssh_packet_server_pqkex_init
};

struct ssh_packet_callbacks_struct ssh_pqkex_server_callbacks = {
    .start = SSH2_MSG_KEX_PQ_INIT,
    .n_callbacks = 1,
    .callbacks = pqkex_server_callbacks,
    .user = NULL
};

void ssh_server_pqkex_init(ssh_session session)
{
    ssh_packet_set_callbacks(session, &ssh_pqkex_server_callbacks);
}

SSH_PACKET_CALLBACK(ssh_packet_server_pqkex_init) {
    int rc, oqs_rc;
    enum ssh_digest_e digest = SSH_DIGEST_AUTO;
    ssh_string sig_blob = NULL;
    ssh_string pubkey_blob = NULL;
    uint8_t *oqs_shared_secret = NULL;
    ssh_key privkey = NULL;

    ssh_packet_remove_callbacks(session, &ssh_pqkex_server_callbacks);

    /* Read client's kex message (just its public key) */
    session->next_crypto->oqs_remote_msg = ssh_buffer_get_ssh_string(packet);
    if (session->next_crypto->oqs_remote_msg == NULL) {
        ssh_set_error(session, SSH_FATAL, "No remote public key in packet");
        goto error;
    }

    /* Generate key pair for server */
    rc = ssh_oqs_kex_keypair_gen(session);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Could not generate key pair");
        goto error;
    }

    /* Make sure the client's public key is the length we expect. This must be done after OQS_KEM_new so length_public_key is available,
     * and so must happen after oqs_keypair_gen which calls it.
     */
    if (ssh_string_len(session->next_crypto->oqs_remote_msg) != session->next_crypto->oqs_kem->length_public_key) {
        ssh_set_error(session, SSH_FATAL, "Remote public key is incorrect length; expected %zu, got %zu",
                      session->next_crypto->oqs_kem->length_public_key,
                      ssh_string_len(session->next_crypto->oqs_remote_msg));
        goto error;
    }

    /* Compute local message, shared secret, and session id */
    session->next_crypto->oqs_local_msg = ssh_string_new(session->next_crypto->oqs_kem->length_ciphertext);
    if (session->next_crypto->oqs_local_msg == NULL) {
        ssh_set_error_oom(session);
        goto error;
    }

    oqs_shared_secret = malloc(session->next_crypto->oqs_kem->length_shared_secret);
    if (oqs_shared_secret == NULL) {
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

    session->next_crypto->oqs_shared_secret_len = session->next_crypto->oqs_kem->length_shared_secret;

    /* PQ data not needed after calling encaps. */
    ssh_oqs_kex_free(session);

    bignum_bin2bn(oqs_shared_secret, session->next_crypto->oqs_shared_secret_len, &session->next_crypto->shared_secret);

    explicit_bzero(oqs_shared_secret, session->next_crypto->oqs_shared_secret_len);
    SAFE_FREE(oqs_shared_secret);

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

    /* Create SSH2_MSG_KEX_PQ_REPLY message: host key, server public key, signature */
    rc = ssh_dh_get_next_server_publickey_blob(session, &pubkey_blob);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Could not export server public key");
        SSH_STRING_FREE(sig_blob);
        goto error;
    }

    rc = ssh_buffer_pack(session->out_buffer,
                         "bSSS",
                         SSH2_MSG_KEX_PQ_REPLY,
                         pubkey_blob, /* host key */
                         session->next_crypto->oqs_local_msg, /* server kex message */
                         sig_blob); /* signature blob */

    SSH_STRING_FREE(sig_blob);
    SSH_STRING_FREE(pubkey_blob);

    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Could not build SSH2_MSG_KEX_PQ_REPLY packet");
        goto error;
    }

    /* Send SSH2_MSG_KEX_PQ_REPLY message */
    rc = ssh_packet_send(session);
    if (rc != SSH_OK) {
        goto error;
    }
    SSH_LOG(SSH_LOG_PROTOCOL, "SSH2_MSG_KEX_PQ_REPLY sent");

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

#endif /* WITH_POST_QUANTUM_CRYPTO */
