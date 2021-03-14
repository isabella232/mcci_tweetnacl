/*

Module:	mcci_tweetnacl_stream.h

Function:
	MCCI TweetNaCl equivalent of "crypto_stream.h"

Copyright and License:
	This file copyright (C) 2021 by

		MCCI Corporation
		3520 Krums Corners Road
		Ithaca, NY  14850

	See accompanying LICENSE file for copyright and license information.

Author:
	Terry Moore, MCCI Corporation	March 2021

*/

#ifndef _mcci_tweetnacl_stream_h_
#define _mcci_tweetnacl_stream_h_	/* prevent multiple includes */

#pragma once

#include "mcci_tweetnacl.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************\
|
|	Meta
|
\****************************************************************************/

/// \addtogroup secret-key-crypto 	Secret-key cryptography
/// @{
///	\addtogroup crypto-stream	Encryption
///	@{

/****************************************************************************\
|
|	Forward Types
|
\****************************************************************************/

/// \brief abstract type for crypto keys
typedef struct mcci_tweetnacl_stream_key__s
	{
	/// the bytes of the key
	unsigned char bytes[32];
	} mcci_tweetnacl_stream_key_t;

/// \brief abstract type for crypto nonces
typedef struct mcci_tweetnacl_stream_nonce_s
	{
	/// the bytes of the nonce
	unsigned char bytes[32];
	} mcci_tweetnacl_stream_nonce_t;

///
/// \brief perform a core hash round of Salsa20 encryption.
///
/// \param[out]	out	pointer to a 64-byte buffer
/// \param[in]	in	pointer to a 16-byte input value
/// \param[in]	key 	pointer to the 32-byte key
/// \param[in]	expansion pointer to a 16-byte expansion vector, normally either
///			"expand 32-byte k" or "expand 16-byte k"
///
/// \note Rarely used directly, but exported for convenience.
///
/// \see http://www.crypto-it.net/eng/symmetric/salsa20.html
///
static inline void
mcci_tweetnacl_core_salsa20(
	unsigned char *out,
	const unsigned char *in,
	const mcci_tweetnacl_stream_key_t *key,
	const unsigned char *expansion
	)
	{
	extern int crypto_core_salsa20_tweet(unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);
	(void) crypto_core_salsa20_tweet(out, in, key->bytes, expansion);
	}

///
/// \brief perform a core hash round of Salsa20 encryption.
///
/// \param[out]	out	pointer to a 64-byte buffer
/// \param[in]	in	pointer to a 16-byte input value
/// \param[in]	key 	pointer to the 32-byte key
/// \param[in]	expansion pointer to a 16-byte expansion vector, normally
///			"expand 32-byte k"
///
/// \note Rarely used directly, but exported for convenience.
///
/// \see http://www.crypto-it.net/eng/symmetric/salsa20.html
///
static inline void
mcci_tweetnacl_core_hsalsa20(
	unsigned char *out,
	const unsigned char *in,
	const mcci_tweetnacl_stream_key_t *key,
	const unsigned char *expansion
	)
	{
	extern int crypto_core_hsalsa20_tweet(unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);
	(void) crypto_core_hsalsa20_tweet(
		out,
		in,
		key->bytes,
		expansion
		);
	}

///
/// \brief encrypt or decrypt text using Salsa20
///
/// \param[out]	pOutText  pointer to buffer of size \p sizeText bytes.
/// \param[in]	pInText	  pointer to buffer of size \p sizeText bytes. If NULL,
///			  a string of zero bytes will be substituted.
/// \param[in]	sizeText  size of the input and output text buffers
/// \param[in]	pNonce	  pointer to 8-byte nonce buffer
/// \param[in]	pKey	  pointer to 32-byte key buffer.
///
/// \note generally not used directly; use \ref mcci_tweetnacl_stream_xor() instead.
///
/// \see http://www.crypto-it.net/eng/symmetric/salsa20.html
///
static inline void
mcci_tweetnacl_stream_salsa20_xor(
	unsigned char *pOutText,
	const unsigned char *pInText,
	size_t sizeText,
	const mcci_tweetnacl_stream_nonce_t *pNonce,
	const mcci_tweetnacl_stream_key_t *pKey
	)
	{
	extern int crypto_stream_salsa20_tweet_xor(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
	(void) crypto_stream_salsa20_tweet_xor(
		pOutText,
		pInText,
		sizeText,
		pNonce->bytes,
		pKey->bytes
		);
	}

///
/// \brief Generate stream of Salsa20 bytes
///
/// \param[out]	pOutText  pointer to buffer of size \p sizeText bytes.
/// \param[in]	sizeText  size of the input and output text buffers
/// \param[in]	pNonce	  pointer to 8-byte nonce buffer
/// \param[in]	pKey	  pointer to 32-byte key buffer.
///
/// \note generally not used directly; use \ref mcci_tweetnacl_stream() instead.
///
/// \see http://www.crypto-it.net/eng/symmetric/salsa20.html
///
static inline void
mcci_tweetnacl_stream_salsa20(
	unsigned char *pOutText,
	size_t sizeText,
	const mcci_tweetnacl_stream_nonce_t *pNonce,
	const mcci_tweetnacl_stream_key_t *pKey
	)
	{
	extern int crypto_stream_salsa20_tweet(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
	(void) crypto_stream_salsa20_tweet(pOutText, sizeText, pNonce->bytes, pKey->bytes);
	}

///
/// \brief Generate stream of crypto bytes
///
/// \param[out]	pOutText  pointer to buffer of size \p sizeText bytes.
/// \param[in]	sizeText  size of the output text buffer
/// \param[in]	pNonce	  pointer to 8-byte nonce, followed by 8-byte index buffer
/// \param[in]	pKey	  pointer to 32-byte key buffer.
///
/// \see https://nacl.cr.yp.to/stream.html
/// \see https://www.xsalsa20.com/
///
static inline void
mcci_tweetnacl_stream(
	unsigned char *pOutText,
	size_t sizeText,
	const mcci_tweetnacl_stream_nonce_t *pNonce,
	const mcci_tweetnacl_stream_key_t *pKey
	)
	{
	extern int crypto_stream_xsalsa20_tweet(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
	(void) crypto_stream_xsalsa20_tweet(
		pOutText,
		sizeText,
		pNonce->bytes,
		pKey->bytes
		);
	}

///
/// \brief Encrypt or decrypt text (using xsalsa20)
///
/// \param[out]	pOutText  pointer to buffer of size \p sizeText bytes.
/// \param[in]	pInText	  pointer to buffer of size \p sizeText bytes.
/// \param[in]	sizeText  size of the output text buffer
/// \param[in]	pNonce	  pointer to 8-byte nonce, followed by 8-byte index buffer
/// \param[in]	pKey	  pointer to 32-byte key buffer.
///
/// \see https://nacl.cr.yp.to/stream.html
/// \see https://www.xsalsa20.com/
/// \see crypto_onetimeauth 
///

static inline void
mcci_tweetnacl_stream_xor(
	unsigned char *pOutText,
	const unsigned char *pInText,
	size_t sizeText,
	const mcci_tweetnacl_stream_nonce_t *pNonce,
	const mcci_tweetnacl_stream_key_t *pKey
	)
	{
	extern int crypto_stream_xsalsa20_tweet_xor(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
	(void) crypto_stream_xsalsa20_tweet_xor(
		pOutText,
		pInText,
		sizeText,
		pNonce->bytes,
		pKey->bytes
		);
	}

/****************************************************************************\
|
|	Post-Meta
|
\****************************************************************************/

//--- close groups ---
///	@}
///  @}

#ifdef __cplusplus
}
#endif

#endif /* _mcci_tweetnacl_stream_h_ */
