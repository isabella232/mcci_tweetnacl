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

// /// \brief internal state of SHA512 engine
// typedef struct mcci_tweetnacl_sha512_state_s
// 	{
// 	unsigned char bytes[64];
// 	} mcci_tweetnacl_sha512_state_t;

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

// ///
// /// \brief Partial calculation of sha512 hash of message
// ///
// /// \param[inout] pState carries the current state
// /// \param[in] pMessage is the message to be hashed
// /// \param[in] nMessage is the length of the message in bytes
// ///
// /// \return number of bytes not processed.
// ///
// /// \note Not very useful, as there's neither a way to initalize the state, nor
// ///	a way to compute the final result from the state.
// ///
// /// \see https://nacl.cr.yp.to/hash.html
// ///
// static inline size_t mcci_tweetnacl_hashblocks_sha512(
// 	mcci_tweetnacl_sha512_state_t *pState,
// 	const unsigned char *pMessage,
// 	size_t nMessage
// 	)
// 	{
// 	extern int crypto_hashblocks_sha512_tweet(unsigned char *,const unsigned char *,unsigned long long);
// 	return (size_t) crypto_hashblocks_sha512_tweet(
// 		pState->bytes,
// 		pMessage,
// 		nMessage
// 		);
// 	}

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
