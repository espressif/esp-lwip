/*
 * pppcrypt.c - PPP/DES linkage for MS-CHAP and EAP SRP-SHA1
 *
 * Extracted from chap_ms.c by James Carlson.
 *
 * Copyright (c) 1995 Eric Rosenquist.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "netif/ppp/ppp_opts.h"
#if PPP_SUPPORT /* don't build if not configured for use in lwipopts.h */

/* This header file is included in all PPP modules needing hashes and/or ciphers */

#ifndef PPPCRYPT_H
#define	PPPCRYPT_H

/*
 * If included PolarSSL copy is not used, user is expected to include
 * external libraries in arch/cc.h (which is included by lwip/arch.h).
 */
#include "lwip/arch.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Map hashes and ciphers functions to PolarSSL
 */
#if !LWIP_USE_EXTERNAL_MBEDTLS

#include "netif/ppp/polarssl/md4.h"
#define lwip_md4_context md4_context
#define lwip_md4_init(context)
#define lwip_md4_starts md4_starts
#define lwip_md4_update md4_update
#define lwip_md4_finish md4_finish
#define lwip_md4_free(context)

#include "netif/ppp/polarssl/md5.h"
#define lwip_md5_context md5_context
#define lwip_md5_init(context)
#define lwip_md5_starts md5_starts
#define lwip_md5_update md5_update
#define lwip_md5_finish md5_finish
#define lwip_md5_free(context)

#include "netif/ppp/polarssl/sha1.h"
#define lwip_sha1_context sha1_context
#define lwip_sha1_init(context)
#define lwip_sha1_starts sha1_starts
#define lwip_sha1_update sha1_update
#define lwip_sha1_finish sha1_finish
#define lwip_sha1_free(context)

#include "netif/ppp/polarssl/des.h"
#define lwip_des_context des_context
#define lwip_des_init(context)
#define lwip_des_setkey_enc des_setkey_enc
#define lwip_des_crypt_ecb des_crypt_ecb
#define lwip_des_free(context)

#include "netif/ppp/polarssl/arc4.h"
#define lwip_arc4_context arc4_context
#define lwip_arc4_init(context)
#define lwip_arc4_setup arc4_setup
#define lwip_arc4_crypt arc4_crypt
#define lwip_arc4_free(context)

#endif /* !LWIP_USE_EXTERNAL_MBEDTLS */

/*
 * Map hashes and ciphers functions to mbed TLS
 */
#if LWIP_USE_EXTERNAL_MBEDTLS

#include "mbedtls/build_info.h"

#if MBEDTLS_VERSION_MAJOR >= 4
/*
 * mbedtls 4.x: Use PSA Crypto API for MD5/SHA1.
 * Note: DES and ARC4 have been removed in mbedtls 4.x, so MS-CHAP and MPPE
 * are not supported with mbedtls 4.x.
 */
#include "psa/crypto.h"

/* PSA MD5 wrapper functions */
void lwip_psa_md5_init(psa_hash_operation_t *ctx);
void lwip_psa_md5_starts(psa_hash_operation_t *ctx);
void lwip_psa_md5_update(psa_hash_operation_t *ctx, const unsigned char *input, size_t ilen);
void lwip_psa_md5_finish(psa_hash_operation_t *ctx, unsigned char *output);
void lwip_psa_md5_free(psa_hash_operation_t *ctx);

#define lwip_md5_context psa_hash_operation_t
#define lwip_md5_init lwip_psa_md5_init
#define lwip_md5_starts lwip_psa_md5_starts
#define lwip_md5_update lwip_psa_md5_update
#define lwip_md5_finish lwip_psa_md5_finish
#define lwip_md5_free lwip_psa_md5_free

/* PSA SHA1 wrapper functions */
void lwip_psa_sha1_init(psa_hash_operation_t *ctx);
void lwip_psa_sha1_starts(psa_hash_operation_t *ctx);
void lwip_psa_sha1_update(psa_hash_operation_t *ctx, const unsigned char *input, size_t ilen);
void lwip_psa_sha1_finish(psa_hash_operation_t *ctx, unsigned char *output);
void lwip_psa_sha1_free(psa_hash_operation_t *ctx);

#define lwip_sha1_context psa_hash_operation_t
#define lwip_sha1_init lwip_psa_sha1_init
#define lwip_sha1_starts lwip_psa_sha1_starts
#define lwip_sha1_update lwip_psa_sha1_update
#define lwip_sha1_finish lwip_psa_sha1_finish
#define lwip_sha1_free lwip_psa_sha1_free

/* DES/ARC4 not available via PSA - MS-CHAP/MPPE not supported */

#else /* MBEDTLS_VERSION_MAJOR < 4 - use legacy mbedtls APIs */

#include "mbedtls/des.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"

/* MD4 has been removed from mbedtls >= 3.0 as weak.
 * Therefore, we do not support authentications that require MD4: MS-CHAP
#define lwip_md4_context mbedtls_md4_context
#define lwip_md4_init mbedtls_md4_init
#define lwip_md4_starts mbedtls_md4_starts
#define lwip_md4_update mbedtls_md4_update
#define lwip_md4_finish mbedtls_md4_finish
#define lwip_md4_free mbedtls_md4_free
 */

#define lwip_md5_context mbedtls_md5_context
#define lwip_md5_init mbedtls_md5_init
#define lwip_md5_starts mbedtls_md5_starts
#define lwip_md5_update mbedtls_md5_update
#define lwip_md5_finish mbedtls_md5_finish
#define lwip_md5_free mbedtls_md5_free

#define lwip_sha1_context mbedtls_sha1_context
#define lwip_sha1_init mbedtls_sha1_init
#define lwip_sha1_starts mbedtls_sha1_starts
#define lwip_sha1_update mbedtls_sha1_update
#define lwip_sha1_finish mbedtls_sha1_finish
#define lwip_sha1_free mbedtls_sha1_free

#define lwip_des_context mbedtls_des_context
#define lwip_des_init mbedtls_des_init
#define lwip_des_setkey_enc mbedtls_des_setkey_enc
#define lwip_des_crypt_ecb mbedtls_des_crypt_ecb
#define lwip_des_free mbedtls_des_free

/* ARC4 has been removed from mbedtls >= 3.0 as weak.
 * Therefore, we do not support authentications that require ARC4: MPPE
#define lwip_arc4_context mbedtls_arc4_context
#define lwip_arc4_init mbedtls_arc4_init
#define lwip_arc4_setup mbedtls_arc4_setup
#define lwip_arc4_crypt(context, buffer, length) mbedtls_arc4_crypt(context, length, buffer, buffer)
#define lwip_arc4_free mbedtls_arc4_free
 */

#endif /* MBEDTLS_VERSION_MAJOR >= 4 */

#endif /* LWIP_USE_EXTERNAL_MBEDTLS */

void pppcrypt_56_to_64_bit_key(u_char *key, u_char *des_key);

#ifdef __cplusplus
}
#endif

#endif /* PPPCRYPT_H */

#endif /* PPP_SUPPORT */
