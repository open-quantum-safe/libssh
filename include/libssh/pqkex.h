/*
 * pqkex.h - Post-quantum cryptography header file for key exchange
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

#ifndef PQKEX_H_
#define PQKEX_H_

#include "config.h"

#if defined(WITH_POST_QUANTUM_CRYPTO) && defined(WITH_PURE_PQ_KEX)

#include "libssh/session.h"

extern struct ssh_packet_callbacks_struct ssh_pqkex_client_callbacks;
int ssh_client_pqkex_init(ssh_session session);

#ifdef WITH_SERVER
extern struct ssh_packet_callbacks_struct ssh_pqkex_server_callbacks;
void ssh_server_pqkex_init(ssh_session session);
SSH_PACKET_CALLBACK(ssh_packet_server_pqkex_init);
#endif /* WITH_SERVER */

#endif /* defined(WITH_POST_QUANTUM_CRYPTO) && defined(WITH_PURE_PQ_KEX) */

#endif /* PQKEX_H_ */
