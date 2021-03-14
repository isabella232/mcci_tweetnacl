/*

Module:	mcci_tweetnacl_auth.h

Function:
	Like NaCl "crypto_auth.h" for MCCI TweetNaCl

Copyright and License:
	This file copyright (C) 2021 by

		MCCI Corporation
		3520 Krums Corners Road
		Ithaca, NY  14850

	See accompanying LICENSE file for copyright and license information.

Author:
	Terry Moore, MCCI Corporation	March 2021

*/

#ifndef _mcci_tweetnacl_auth_h_
#define _mcci_tweetnacl_auth_h_	/* prevent multiple includes */

#pragma once

#ifndef _mcci_tweetnacl_h_
# include "mcci_tweetnacl.h"
#endif

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
///	\addtogroup crypto-auth		Authentication
///	@{

/****************************************************************************\
|
|	Forward types
|
\****************************************************************************/

/// \brief abstract type for auth keys
typedef struct mcci_tweetnacl_auth_key_s mcci_tweetnacl_auth_key_t;
struct mcci_tweetnacl_auth_key_s
	{
	/// the private key for generating auth keys.
	unsigned char bytes[32];
	};

/// \brief abstract type for authenticators
typedef struct mcci_tweetnacl_auth_authenticator_s
	{
	unsigned char bytes[64];
	} mcci_tweetnacl_auth_authenticator_t;

/****************************************************************************\
|
|	APIs
|
\****************************************************************************/

///
/// \brief Secret-key message authentication: generate authenticator (HMAC)
///
/// \param[out] pAuth is set to the authenticator
/// \param[in] pMessage is the message to be hashed
/// \param[in] nMessage is the length of the message in bytes
/// \param[in] pKey is the secret key to be used for generating the authenticator.
///
/// \see https://nacl.cr.yp.to/auth.html
///
static inline void
mcci_tweetnacl_auth(
	mcci_tweetnacl_auth_authenticator_t *pAuth,
	const unsigned char *pMessage,
	size_t nMessage,
	const mcci_tweetnacl_auth_key_t *pKey
	)
	{
	extern int crypto_auth_hmacsha512256_tweet(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
	(void) crypto_auth_hmacsha512256_tweet(
		pAuth->bytes,
		pMessage,
		nMessage,
		pKey->bytes
		);
	}

///
/// \brief Secret-key message authentication: verify authenticity (HMAC)
///
/// \param[in] pAuth is the authenticator
/// \param[in] pMessage is the message to be checked
/// \param[in] nMessage is the length of the message in bytes
/// \param[in] pKey is the secret key that was used to generate the authenticator.
///
/// \returns true if message passes the test, false otherwise.
///
/// \see https://nacl.cr.yp.to/auth.html
///
static inline bool
mcci_tweetnacl_auth_verify(
	const mcci_tweetnacl_auth_authenticator_t *pAuth,
	const unsigned char *pMessage,
	size_t nMessage,
	const mcci_tweetnacl_auth_key_t *pKey
	)
	{
	extern int crypto_auth_hmacsha512256_tweet_verify(const unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
	return crypto_auth_hmacsha512256_tweet_verify(
		pAuth->bytes,
		pMessage,
		nMessage,
		pKey->bytes
		) == 0;
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

#endif /* _mcci_tweetnacl_auth_h_ */
