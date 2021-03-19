/*

Module:	mcci_tweetnacl_sign.h

Function:
	Equivalent of NaCl "crypto_sign.h" for MCCI TweetNaCl.

Copyright and License:
	This file copyright (C) 2021 by

		MCCI Corporation
		3520 Krums Corners Road
		Ithaca, NY  14850

	See accompanying LICENSE file for copyright and license information.

Author:
	Terry Moore, MCCI Corporation	March 2021

*/

#ifndef _mcci_tweetnacl_sign_h_
#define _mcci_tweetnacl_sign_h_	/* prevent multiple includes */

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

/// \addtogroup public-key-crypto 	Public-key cryptography
/// @{
///	\defgroup crypto-sign		Signatures
///	@{

/****************************************************************************\
|
|	Forward types
|
\****************************************************************************/

/// \brief Public Key for TweetNaCl sign operations
typedef struct mcci_tweetnacl_sign_publickey_s
	{
	/// the public key value. Note that this is shorter than the private key.
	unsigned char bytes[32];
	} mcci_tweetnacl_sign_publickey_t;

/// \brief Private Key for TweetNaCl sign operations
typedef struct mcci_tweetnacl_sign_privatekey_s
	{
	/// the private key value. Note that this is longer than the public key.
	unsigned char bytes[64];
	} mcci_tweetnacl_sign_privatekey_t;

/// \brief Signature block for TweetNaCl sign operations
typedef struct mcci_tweetnacl_sign_signature_s
	{
	/// the signature block bytes. Per API, this is the maximum size.
	unsigned char bytes[64];
	} mcci_tweetnacl_sign_signature_t;

/****************************************************************************\
|
|	APIs
|
\****************************************************************************/

///
/// \brief generate a private key and a corresponding public key
///
/// \param[out]	pPublicKey is set to the generated public key.
/// \param[in]	pPrivateKey is set to the generated private key.
///
/// \returns 0 for success, non-zero error code for failure.
///
/// \note this function requires that \c randombytes() be implemented and
///	successful. Further, it requires a cryptographically secure string
///	of bytes when \c randombytes() succeeds.
///
/// \see https://nacl.cr.yp.to/sign.html
///
mcci_tweetnacl_randombytes_error_t
mcci_tweetnacl_sign_keypair(
	mcci_tweetnacl_sign_publickey_t *pPublicKey,
	mcci_tweetnacl_sign_privatekey_t *pPrivateKey
	);

///
/// \brief Return size of signature, in bytes
///
#define mcci_tweetnacl_sign_signature_size()	\
	sizeof(((mcci_tweetnacl_sign_signature_t *)NULL)->bytes)

///
/// \brief sign a message (typically a hash of the real message)
///
/// \param[out]	pSignedMessage 		points to buffer to received signed message.
/// \param[out]	pSignedMessageSize	points to cell to receive size of signed message.
/// \param[in]	pMessage		input message
/// \param[in]	messageSize		size of input message, in bytes
/// \param[in]	pPrivateKey		private key to be used to sign message.
///
/// \returns true if successfully signed; in which case \p *pSignedMessageSize is set to
///		the size. Otherwise false, in which case \p *pSignedMessageSize is zero.
///
/// \details
///	This is a wrapper for TweetNaCl's `crypto_sign()`, enforcing a few adjustments.
///	Size is a `size_t` rather than `unsigned long long`; if the input size is so
///	large that it would wrap around, we refuse to sign, and return a failure. Because
///	`crypto_sign()` productes an `unsigned long long` by reference, we have to stage
///	the result and narrow it when copying back to the client. We are careful to avoid
///	overflow, although overflow arguably is impossible.
///
/// \note
///	The buffer at `pSignedMessage` must be at least `messageSize + mcci_tweetnacl_sign_signature_size()`
///	bytes long.
///
bool
mcci_tweetnacl_sign(
	unsigned char *pSignedMessage,
	size_t *pSignedMessageSize,
	const unsigned char *pMessage,
	size_t messageSize,
	const mcci_tweetnacl_sign_privatekey_t *pPrivateKey
	);

/// \brief given a signed message, verify and output signed contents
///
/// \param[out]	pMessage 	points to buffer to received verified message.
/// \param[out]	pMessageSize	points to cell to receive size of verified message.
/// \param[in]	pSignedMessage	input signed (opaque) message
/// \param[in]	messageSize	size of signed message, in bytes
/// \param[in]	pPublicKey	public key to be used to verify message.
///
/// \returns true if successfully verified; in which case \p pMessage[] is set to the
///		validated contents, and \p *pMessageSize is set to
///		the size. Otherwise false, in which case \p pMessage[] may be changed
///		but should be ignored.
///
/// \details
///	This is a wrapper for TweetNaCl's `crypto_sign_open()`, enforcing a few adjustments.
///	Size is a `size_t` rather than `unsigned long long`. Because
///	`crypto_sign_out()` productes an `unsigned long long` by reference, we have to stage
///	the result and narrow it when copying back to the client.
///
/// \note
////	messageSize must be at least 64.
///	The buffer at `pMessage` must be at least `messageSize` - 64 bytes long.
///
static inline bool
mcci_tweetnacl_sign_open(
	unsigned char *pMessage,
	size_t *pMessageSize,
	const unsigned char *pSignedMessage,
	size_t messageSize,
	const mcci_tweetnacl_sign_publickey_t *pPublicKey
	)
	{
	extern int crypto_sign_ed25519_tweet_open(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
	unsigned long long ullMessageSize;
	int result;

	ullMessageSize = 0;

	result = crypto_sign_ed25519_tweet_open(
		pMessage,
		&ullMessageSize,
		pSignedMessage,
		messageSize,
		pPublicKey->bytes
		);

	*pMessageSize = (size_t) ullMessageSize;
	return result == 0;
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

#endif /* _mcci_tweetnacl_sign_h_ */
