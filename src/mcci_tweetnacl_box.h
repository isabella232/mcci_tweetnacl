/*

Module:	mcci_tweetnacl_box.h

Function:
	Equivalent of NaCl "crypto_box.h" for MCCI TweetNaCl.

Copyright and License:
	This file copyright (C) 2021 by

		MCCI Corporation
		3520 Krums Corners Road
		Ithaca, NY  14850

	See accompanying LICENSE file for copyright and license information.

Author:
	Terry Moore, MCCI Corporation	March 2021

*/

#ifndef _mcci_tweetnacl_box_h_
#define _mcci_tweetnacl_box_h_	/* prevent multiple includes */

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

/// \addtogroup public-key-crypto 	Public-key cryptography
/// @{
///	\addtogroup crypto-box		Authenticated encryption
///	@{

/****************************************************************************\
|
|	Forward types
|
\****************************************************************************/

/// \brief Reference structure for public key
typedef struct mcci_tweetnacl_box_publickey_s
	{
	unsigned char bytes[32];
	} mcci_tweetnacl_box_publickey_t;

/// \brief Reference structure for private key
typedef struct mcci_tweetnacl_box_privatekey_s
	{
	unsigned char bytes[32];
	} mcci_tweetnacl_box_privatekey_t;


/// \brief Reference structure for bytes required to be zero at front of plaintext
typedef struct mcci_tweetnacl_box_messagezero_s
	{
	unsigned char bytes[32];
	} mcci_tweetnacl_box_messagezero_t;

/// \brief Reference structure for bytes required to be zero at front of cihper text
typedef struct mcci_tweetnacl_box_cipherzero_s
	{
	unsigned char bytes[16];
	} mcci_tweetnacl_box_cipherzero_t;

/// \brief Reference structure for nonce bytes for box.
typedef struct mcci_tweetnacl_box_nonce_s
	{
	unsigned char bytes[24];
	} mcci_tweetnacl_box_nonce_t;

/// \brief Reference structure for precomputation bytes for box.
typedef struct mcci_tweetnacl_box_beforenm_s
	{
	unsigned char bytes[32];
	} mcci_tweetnacl_box_beforenm_t;

/****************************************************************************\
|
|	APIs
|
\****************************************************************************/

///
/// \brief Generate a public/private key pair.
///
/// \param[out] pPublicKey is set to the public key
/// \param[in] pPrivateKey is set to the private key
///
/// \returns error code; zero for success, non-zero for failure.
///
/// \note depends on an implementation of randombytes().
/// \see https://nacl.cr.yp.to/box.html
///
mcci_tweetnacl_randombytes_error_t
mcci_tweetnacl_box_keypair(
	mcci_tweetnacl_box_publickey_t *pPublicKey,
	mcci_tweetnacl_box_privatekey_t *pPrivateKey
	);

///
/// \brief Precompute for public-key authenticated cryptographic operations
///
/// \param[out]	k is set to the context
/// \param[in] pPublicKey, pPrivateKey are the public and private keys to be used for this operation.
///
/// \see https://nacl.cr.yp.to/box.html
///
static inline 
void mcci_tweetnacl_box_beforenm(
	mcci_tweetnacl_box_beforenm_t *k,
	const mcci_tweetnacl_box_publickey_t *pPublicKey,
	const mcci_tweetnacl_box_privatekey_t *pPrivateKey
	)
	{
	extern int crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(unsigned char *,const unsigned char *,const unsigned char *);
	(void) crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(
		k->bytes,
		pPublicKey->bytes,
		pPrivateKey->bytes
		);
	}

///
/// \brief Public-key authenticated encryption (precomputed)
///
/// \param[out]	pCipherText  	pointer to buffer of size \p sizeText bytes.
/// \param[in]	pPlainText   	pointer to buffer of size \p sizeText bytes.
/// \param[in]	sizeText  	size of the output text buffer
/// \param[in]	pNonce	  	pointer to 24-byte nonce
/// \param[in]	pPrecomputed	pointer to 32-byte precomputed buffer.
///
/// \return true for successful encryption, false for parameter validation failure.
///
/// \note \p pPlainText must start with a string of 
///	`sizeof(mcci_tweetnacl_box_messagezero_t::bytes)` bytes of zero. The
///	first `sizeof(mcci_tweetnacl_box_cipherzero_t::bytes)` bytes of 
///	\p pCipherText will be zero. Thus, the real ciphertext data is from
///	`pCipherText + sizeof(mcci_tweetnacl_box_cipherzero_t::bytes)` to
///	`pCipherText + sizeText - 1`.
///
/// \return true if successful, false for failures [due to parameter problems only].
///
/// \see https://nacl.cr.yp.to/box.html
///

static inline bool
mcci_tweetnacl_box_afternm(
	unsigned char *pCipherText,
	const unsigned char *pPlainText,
	size_t sizeText,
	const mcci_tweetnacl_box_nonce_t *pNonce,
	const mcci_tweetnacl_box_beforenm_t *pPrecomputed
	)
	{
	extern int crypto_box_curve25519xsalsa20poly1305_tweet_afternm(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
	return crypto_box_curve25519xsalsa20poly1305_tweet_afternm(
		pCipherText,
		pPlainText,
		sizeText,
		pNonce->bytes,
		pPrecomputed->bytes
		) == 0;
	}

///
/// \brief Public-key authenticated decryption (precomputed))
///
/// \param[out]	pPlainText   	pointer to buffer of size \p sizeText bytes.
/// \param[in]	pCipherText  	pointer to buffer of size \p sizeText bytes.
/// \param[in]	sizeText  	size of the output text buffer
/// \param[in]	pNonce	  	pointer to 24-byte nonce
/// \param[in]	pPrecomputed	pointer to 32-byte precomputed buffer.
///
/// \returns true for successful decryption and authenticaion, false otherwise.
///
/// \note \p pCipherText must start with a string of 
///	`sizeof(mcci_tweetnacl_box_cipherzero_t::bytes)` bytes of zero. The
///	first `sizeof(mcci_tweetnacl_box_messagezero_t::bytes)` bytes of 
///	\p pPlainText will be zero.  Thus, the real plaintext data is from
///	`pPlainText + sizeof(mcci_tweetnacl_box_messagezero_t::bytes)` to
///	`pPlainText + sizeText - 1`.
///
/// \see https://nacl.cr.yp.to/box.html
///

static inline bool
mcci_tweetnacl_box_open_afternm(
	unsigned char *pPlainText,
	const unsigned char *pCipherText,
	size_t sizeText,
	const mcci_tweetnacl_box_nonce_t *pNonce,
	const mcci_tweetnacl_box_beforenm_t *pPrecomputed
	)
	{
	extern int crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
	return crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(
		pPlainText,
		pCipherText,
		sizeText,
		pNonce->bytes,
		pPrecomputed->bytes
		) == 0;
	}

///
/// \brief Public-key authenticated encryption
///
/// \param[out]	pCipherText  	pointer to buffer of size \p sizeText bytes.
/// \param[in]	pPlainText	pointer to buffer of size \p sizeText bytes.
/// \param[in]	sizeText	size of the output text buffer
/// \param[in]	pNonce		pointer to 24-byte nonce
/// \param[in]	pPublicKey	pointer to 32-byte public key of receiver
/// \param[in]	pPrivateKey	pointer to 32-byte private key of sender
///
/// \return true for successful encryption, false for parameter validation failure.
///
/// \note \p pPlainText must start with a string of 
///	`sizeof(mcci_tweetnacl_box_messagezero_t::bytes)` bytes of zero. The
///	first `sizeof(mcci_tweetnacl_box_cipherzero_t::bytes)` bytes of 
///	\p pCipherText will be zero. Thus, the real ciphertext data is from
///	`pCipherText + sizeof(mcci_tweetnacl_box_cipherzero_t::bytes)` to
///	`pCihperText + sizeText - 1`.
///
/// \see https://nacl.cr.yp.to/box.html
///

static inline bool
mcci_tweetnacl_box(
	unsigned char *pCipherText,
	const unsigned char *pPlainText,
	size_t sizeText,
	const mcci_tweetnacl_box_nonce_t *pNonce,
	const mcci_tweetnacl_box_publickey_t *pPublicKey,
	const mcci_tweetnacl_box_privatekey_s *pPrivateKey
	)
	{
	extern int crypto_box_curve25519xsalsa20poly1305_tweet(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *,const unsigned char *);
	return crypto_box_curve25519xsalsa20poly1305_tweet(
		pCipherText,
		pPlainText,
		sizeText,
		pNonce->bytes,
		pPublicKey->bytes,
		pPrivateKey->bytes
		) == 0;
	}

///
/// \brief Public-key authenticated decryption
///
/// \param[out]	pPlainText	pointer to buffer of size \p sizeText bytes.
/// \param[in]	pCipherText	pointer to buffer of size \p sizeText bytes.
/// \param[in]	sizeText	size of the output text buffer
/// \param[in]	pNonce		pointer to 24-byte nonce
/// \param[in]	pPublicKey	pointer to 32-byte public key of sender
/// \param[in]	pPrivateKey	pointer to 32-byte private key of receiver
///
/// \returns true for successful decryption and authenticaion, false otherwise.
///
/// \note \p pCipherText must start with a string of 
///	`sizeof(mcci_tweetnacl_secretbox_cipherzero_t::bytes)` bytes of zero. The
///	first `sizeof(mcci_tweetnacl_secretbox_messagezero_t::bytes)` bytes of 
///	\p pPlainText will be zero.  Thus, the real plaintext data is from
///	`pPlainText + sizeof(mcci_tweetnacl_secretbox_messagezero_t::bytes)` to
///	`pPlainText + sizeText - 1`.
///
/// \see https://nacl.cr.yp.to/box.html
///

static inline bool
mcci_tweetnacl_box_open(
	unsigned char *pPlainText,
	const unsigned char *pCipherText,
	size_t sizeText,
	const mcci_tweetnacl_box_nonce_t *pNonce,
	const mcci_tweetnacl_box_publickey_t *pPublicKey,
	const mcci_tweetnacl_box_privatekey_s *pPrivateKey
	)
	{
	extern int crypto_box_curve25519xsalsa20poly1305_tweet_open(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *,const unsigned char *);
	return crypto_box_curve25519xsalsa20poly1305_tweet_open(
		pPlainText,
		pCipherText,
		sizeText,
		pNonce->bytes,
		pPublicKey->bytes,
		pPrivateKey->bytes
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

#endif /* _mcci_tweetnacl_box_h_ */
