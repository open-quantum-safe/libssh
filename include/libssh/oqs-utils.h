/*
 * oqs-utils.h - liboqs utility function headers
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

#ifndef OQS_UTILS_H_
#define OQS_UTILS_H_

#include "config.h"

#ifdef WITH_POST_QUANTUM_CRYPTO

#include "libssh/kex.h"

typedef struct oqs_alg {
	enum ssh_kex_types_e ssh_kex_type;
	const char *ssh_kex_name;
	const char *oqs_kex_name;
} OQS_ALG;

const OQS_ALG *ssh_kex_str_to_oqs_kex(const char *ssh_kex_name);
const OQS_ALG *ssh_kex_type_to_oqs_kex(enum ssh_kex_types_e ssh_kex);
int ssh_oqs_kex_keypair_gen(ssh_session session);
void ssh_oqs_kex_free(ssh_session session);

#endif /* WITH_POST_QUANTUM_CRYPTO */

#endif /* OQS_UTILS_H_ */
