/*

Module:	mcci_tweetnacl_onetimeauth.h

Function:
	MCCI TweetNaCl equivalent of "crypto_onetimeauth.h"

Copyright and License:
	This file copyright (C) 2021 by

		MCCI Corporation
		3520 Krums Corners Road
		Ithaca, NY  14850

	See accompanying LICENSE file for copyright and license information.

Author:
	fullname, MCCI Corporation	March 2021

*/

#ifndef _mcci_tweetnacl_onetimeauth_h_
#define _mcci_tweetnacl_onetimeauth_h_	/* prevent multiple includes */

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
///	\addtogroup crypto-stream	One-time authentication
///	@{

/****************************************************************************\
|
|	Forward types
|
\****************************************************************************/

/// \brief abstract type for crypto keys
typedef struct
	{
	/// the bytes of the key
	unsigned char bytes[32];
	} mcci_tweetnacl_onetimeauth_key_t;

/// \brief abstract type for crypto authenticators
typedef struct
	{
	/// bytes of the authenticator
	unsigned char bytes[16];
	} mcci_tweetnacl_onetimeauth_authenticator_t;

///
/// \brief Generate one-time authenticator for a given message and secret key
///
/// \param[out]	pAuth		set to the authenticator code.
/// \param[in]	pMessage 	the message to be authenticated.
/// \param[in]	nMessage	number of bytes in the message.
/// \param[in]	pKey		the secret key
///
/// \see https://nacl.cr.yp.to/onetimeauth.html
///
static inline void
mcci_tweetnacl_onetimeauth(
	mcci_tweetnacl_onetimeauth_authenticator_t *pAuth,
	const unsigned char *pMessage,
	size_t nMessage,
	const mcci_tweetnacl_onetimeauth_key_t *pKey
	)
	{
	extern int crypto_onetimeauth_poly1305_tweet(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
	(void) crypto_onetimeauth_poly1305_tweet(
		pAuth->bytes,
		pMessage,
		nMessage,
		pKey->bytes
		);
	}

///
/// \brief Verify message given one-time authenticator and secret key
///
/// \param[out]	pAuth		set to the authenticator code.
/// \param[in]	pMessage 	the message to be authenticated.
/// \param[in]	nMessage	number of bytes in the message.
/// \param[in]	pKey		the secret key
///
/// \returns zero if valid, non-zero otherwise.
///
/// \see https://nacl.cr.yp.to/onetimeauth.html
///
static inline mcci_tweetnacl_result_t
mcci_tweetnacl_onetimeauth_verify(
	const mcci_tweetnacl_onetimeauth_authenticator_t *pAuth,
	const unsigned char *pMessage,
	size_t nMessage,
	const mcci_tweetnacl_onetimeauth_key_t *pKey
	)
	{
	extern int crypto_onetimeauth_poly1305_tweet_verify(const unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
	return crypto_onetimeauth_poly1305_tweet_verify(
		pAuth->bytes,
		pMessage,
		nMessage,
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

#endif /* _mcci_tweetnacl_onetimeauth_h_ */
