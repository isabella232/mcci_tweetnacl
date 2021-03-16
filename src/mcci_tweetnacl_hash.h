/*

Module:	mcci_tweetnacl_hash.h

Function:
	Like NaCl "crypto_hash.h" for MCCI TweetNaCl

Copyright and License:
	This file copyright (C) 2021 by

		MCCI Corporation
		3520 Krums Corners Road
		Ithaca, NY  14850

	See accompanying LICENSE file for copyright and license information.

Author:
	Terry Moore, MCCI Corporation	March 2021

*/

#ifndef _mcci_tweetnacl_hash_h_
#define _mcci_tweetnacl_hash_h_	/* prevent multiple includes */

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

/// \addtogroup low-level-functions 	Low-level functions
/// @{
///	\addtogroup crypto-hash		Hashing
///	@{

/****************************************************************************\
|
|	Forward types
|
\****************************************************************************/

/// \brief abstract type for SHA512 signature blocks
typedef struct mcci_tweetnacl_sha512_s mcci_tweetnacl_sha512_t;
struct mcci_tweetnacl_sha512_s
	{
	/// the bytes of the SHA512 signature.
	unsigned char bytes[512 / 8];
	};

/****************************************************************************\
|
|	APIs
|
\****************************************************************************/

///
/// \brief Calculate sha512 hash of message
///
/// \param[out] pOut is set to the signature
/// \param[in] pMessage is the message to be hashed
/// \param[in] nMessage is the length of the message in bytes
///
/// \see https://nacl.cr.yp.to/hash.html
///
static inline void
mcci_tweetnacl_hash_sha512(
	mcci_tweetnacl_sha512_t *pOut,
	const unsigned char *pMessage,
	size_t nMessage
	)
	{
	extern int crypto_hash_sha512_tweet(unsigned char *,const unsigned char *,unsigned long long);
	(void) crypto_hash_sha512_tweet(pOut->bytes, pMessage, nMessage);
	}

///
/// \brief Partial calculation of sha512 hash of message
///
/// \param[inout] pState carries the current state
/// \param[in] pMessage is the message to be hashed
/// \param[in] nMessage is the length of the message in bytes
///
/// \return number of bytes not processed.
///
/// \see https://nacl.cr.yp.to/hash.html
///
static inline size_t mcci_tweetnacl_hashblocks_sha512(
	mcci_tweetnacl_sha512_t *pState,
	const unsigned char *pMessage,
	size_t nMessage
	)
	{
	extern int crypto_hashblocks_sha512_tweet(unsigned char *,const unsigned char *,unsigned long long);
	return (size_t) crypto_hashblocks_sha512_tweet(
		pState->bytes,
		pMessage,
		nMessage
		);
	}

///
/// \brief Partial calculation of sha512 hash of message
///
/// \param[out] pState is set to the initialization vector
///
/// \see https://nacl.cr.yp.to/hash.html
///
static inline void mcci_tweetnacl_hashblocks_sha512_init(
	mcci_tweetnacl_sha512_t *pState
	)
	{
	extern int crypto_hashblocks_sha512_tweet_mcci_init(unsigned char *);
	(void) crypto_hashblocks_sha512_tweet_mcci_init(
		pState->bytes
		);
	}

///
/// \brief Finish partial calculation of sha512 hash of message
///
/// \param[inout] pHash carries the current state
/// \param[in] pMessage is the message to be hashed
/// \param[in] nMessage is the length of the message in bytes
///
/// \details SHA512 processes the message in 128-byte chunks. 
///	To accomodate variable-length text, SHA512 always appends
///	some bytes, containing enough info to unambigiously represent the
///	size of the message, even though its padding. This routine does
///	that, assuming that all but nMessage % 128 bytes have already been
///	incorporated in the hash.
///
/// \see https://nacl.cr.yp.to/hash.html
///
static inline void mcci_tweetnacl_hashblocks_sha512_finish(
	mcci_tweetnacl_sha512_t *pHash,
	const unsigned char *pMessage,
	size_t nMessage
	)
	{
	extern int crypto_hashblocks_sha512_tweet_mcci_finish(unsigned char *,const unsigned char *,unsigned long long);
	(void) crypto_hashblocks_sha512_tweet_mcci_finish(
		pHash->bytes,
		pMessage,
		nMessage
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

#endif /* _mcci_tweetnacl_hash_h_ */
