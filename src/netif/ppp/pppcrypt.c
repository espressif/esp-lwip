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

#include "netif/ppp/ppp_impl.h"
#include "netif/ppp/pppcrypt.h"

/*
 * PSA Crypto wrapper implementations for mbedtls 4.x
 */
#if LWIP_USE_EXTERNAL_MBEDTLS
#include "mbedtls/build_info.h"
#if MBEDTLS_VERSION_MAJOR >= 4
#include "psa/crypto.h"

void lwip_psa_md5_init(psa_hash_operation_t *ctx)
{
	*ctx = psa_hash_operation_init();
	psa_crypto_init();
	psa_hash_setup(ctx, PSA_ALG_MD5);
}

void lwip_psa_md5_starts(psa_hash_operation_t *ctx)
{
	/* No-op: setup done in init */
	(void)ctx;
}

void lwip_psa_md5_update(psa_hash_operation_t *ctx, const unsigned char *input, size_t ilen)
{
	psa_hash_update(ctx, input, ilen);
}

void lwip_psa_md5_finish(psa_hash_operation_t *ctx, unsigned char *output)
{
	size_t output_length;
	psa_hash_finish(ctx, output, 16, &output_length);
}

void lwip_psa_md5_free(psa_hash_operation_t *ctx)
{
	psa_hash_abort(ctx);
}

void lwip_psa_sha1_init(psa_hash_operation_t *ctx)
{
	*ctx = psa_hash_operation_init();
	psa_crypto_init();
	psa_hash_setup(ctx, PSA_ALG_SHA_1);
}

void lwip_psa_sha1_starts(psa_hash_operation_t *ctx)
{
	/* No-op: setup done in init */
	(void)ctx;
}

void lwip_psa_sha1_update(psa_hash_operation_t *ctx, const unsigned char *input, size_t ilen)
{
	psa_hash_update(ctx, input, ilen);
}

void lwip_psa_sha1_finish(psa_hash_operation_t *ctx, unsigned char *output)
{
	size_t output_length;
	psa_hash_finish(ctx, output, 20, &output_length);
}

void lwip_psa_sha1_free(psa_hash_operation_t *ctx)
{
	psa_hash_abort(ctx);
}

#endif /* MBEDTLS_VERSION_MAJOR >= 4 */
#endif /* LWIP_USE_EXTERNAL_MBEDTLS */

#if MSCHAP_SUPPORT /* DES key functions only needed for MSCHAP */

static u_char pppcrypt_get_7bits(u_char *input, int startBit) {
	unsigned int word;

	word  = (unsigned)input[startBit / 8] << 8;
	word |= (unsigned)input[startBit / 8 + 1];

	word >>= 15 - (startBit % 8 + 7);

	return word & 0xFE;
}

/* IN  56 bit DES key missing parity bits
 * OUT 64 bit DES key with parity bits added
 */
void pppcrypt_56_to_64_bit_key(u_char *key, u_char * des_key) {
	des_key[0] = pppcrypt_get_7bits(key,  0);
	des_key[1] = pppcrypt_get_7bits(key,  7);
	des_key[2] = pppcrypt_get_7bits(key, 14);
	des_key[3] = pppcrypt_get_7bits(key, 21);
	des_key[4] = pppcrypt_get_7bits(key, 28);
	des_key[5] = pppcrypt_get_7bits(key, 35);
	des_key[6] = pppcrypt_get_7bits(key, 42);
	des_key[7] = pppcrypt_get_7bits(key, 49);
}

#endif /* MSCHAP_SUPPORT */

#endif /* PPP_SUPPORT */
