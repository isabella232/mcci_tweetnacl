/*

Module:	mcci_tweetnacl_secretbox.h

Function:
	MCCI TweetNaCl equivalent of NaCl "crypto_secretbox.h"

Copyright and License:
	This file copyright (C) 2021 by

		MCCI Corporation
		3520 Krums Corners Road
		Ithaca, NY  14850

	See accompanying LICENSE file for copyright and license information.

Author:
	fullname, MCCI Corporation	March 2021

*/

#ifndef _mcci_tweetnacl_secretbox_h_
#define _mcci_tweetnacl_secretbox_h_	/* prevent multiple includes */

#pragma once

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
///	\addtogroup crypto-secretbox	Authenticated encryptions
///	@{

/****************************************************************************\
|
|	Forward types
|
\****************************************************************************/

/// \brief Reference structure for bytes requried to be zero at front of plaintext
typedef struct mcci_tweetnacl_secretbox_messagezero_s
	{
	unsigned char bytes[32];
	} mcci_tweetnacl_secretbox_messagezero_t;

/// \brief Reference structure for bytes required to be zero at front of cihper text
typedef struct mcci_tweetnacl_secretbox_cipherzero_s
	{
	unsigned char bytes[16];
	} mcci_tweetnacl_secretbox_cipherzero_t;

/// \brief Reference structure for nonce bytes for secretbox.
typedef struct mcci_tweetnacl_secretbox_nonce_s
	{
	unsigned char bytes[24];
	} mcci_tweetnacl_secretbox_nonce_t;

/// \brief Reference structure for key bytes for secretbox.
typedef struct mcci_tweetnacl_secretbox_key_s
	{
	unsigned char bytes[32];
	} mcci_tweetnacl_secretbox_key_t;

/****************************************************************************\
|
|	APIs
|
\****************************************************************************/

///
/// \brief Secret-key authenticated encryption (using xsalsa20)
///
/// \param[out]	pCipherText  pointer to buffer of size \p sizeText bytes.
/// \param[in]	pPlainText   pointer to buffer of size \p sizeText bytes.
/// \param[in]	sizeText  size of the output text buffer
/// \param[in]	pNonce	  pointer to 24-byte nonce
/// \param[in]	pKey	  pointer to 32-byte key buffer.
///
/// \return zero for successful encryption, non-zero for parameter validation failure.
///
/// \note \p pPlainText must start with a string of 
///	`sizeof(mcci_tweetnacl_secretbox_messagezero_t::bytes)` bytes of zero. The
///	first `sizeof(mcci_tweetnacl_secretbox_cipherzero_t::bytes)` bytes of 
///	\p pCipherText will be zero. Thus, the real ciphertext data is from
///	`pCipherText + sizeof(mcci_tweetnacl_secretbox_cipherzero_t::bytes)` to
///	`pCihperText + sizeText - 1`.
///
/// \see https://nacl.cr.yp.to/secretbox.html
///

static inline mcci_tweetnacl_result_t
mcci_tweetnacl_secretbox(
	unsigned char *pCipherText,
	const unsigned char *pPlainText,
	size_t sizeText,
	const mcci_tweetnacl_secretbox_nonce_t *pNonce,
	const mcci_tweetnacl_secretbox_key_t *pKey
	)
	{
	extern int crypto_secretbox_xsalsa20poly1305_tweet(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
	return crypto_secretbox_xsalsa20poly1305_tweet(
		pCipherText,
		pPlainText,
		sizeText,
		pNonce->bytes,
		pKey->bytes
		);
	}

///
/// \brief Secret-key authenticated decryption (using xsalsa20)
///
/// \param[out]	pPlainText   pointer to buffer of size \p sizeText bytes.
/// \param[in]	pCipherText  pointer to buffer of size \p sizeText bytes.
/// \param[in]	sizeText  size of the output text buffer
/// \param[in]	pNonce	  pointer to 24-byte nonce
/// \param[in]	pKey	  pointer to 32-byte key buffer.
///
/// \returns zero for successful decryption and authenticaion, non-zero otherwise.
///
/// \note \p pCipherText must start with a string of 
///	`sizeof(mcci_tweetnacl_secretbox_cipherzero_t::bytes)` bytes of zero. The
///	first `sizeof(mcci_tweetnacl_secretbox_messagezero_t::bytes)` bytes of 
///	\p pPlainText will be zero.  Thus, the real plaintext data is from
///	`pPlainText + sizeof(mcci_tweetnacl_secretbox_messagezero_t::bytes)` to
///	`pPlainText + sizeText - 1`.
///
/// \see https://nacl.cr.yp.to/secretbox.html
///

static inline mcci_tweetnacl_result_t
mcci_tweetnacl_secretbox_open(
	unsigned char *pPlainText,
	const unsigned char *pCipherText,
	size_t sizeText,
	const mcci_tweetnacl_secretbox_nonce_t *pNonce,
	const mcci_tweetnacl_secretbox_key_t *pKey
	)
	{
	extern int crypto_secretbox_xsalsa20poly1305_tweet_open(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
	return crypto_secretbox_xsalsa20poly1305_tweet_open(
		pPlainText,
		pCipherText,
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

#endif /* _mcci_tweetnacl_secretbox_h_ */
