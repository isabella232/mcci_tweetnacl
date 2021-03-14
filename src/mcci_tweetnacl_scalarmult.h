/*

Module:	mcci_tweetnacl_scalarmult.h

Function:
	MCCI TweetNacl equivalent of NaCl "crypto_scalarmult.h"

Copyright and License:
	This file copyright (C) 2021 by

		MCCI Corporation
		3520 Krums Corners Road
		Ithaca, NY  14850

	See accompanying LICENSE file for copyright and license information.

Author:
	fullname, MCCI Corporation	March 2021

*/

#ifndef _mcci_tweetnacl_scalarmult_h_
#define _mcci_tweetnacl_scalarmult_h_	/* prevent multiple includes */

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
///	\defgroup crypto-scalarmult	Scalar multiplication
///	@{

/****************************************************************************\
|
|	Forward types
|
\****************************************************************************/

/// \brief curve25519 group element
/// \see https://nacl.cr.yp.to/scalarmult.html
typedef struct
	{
	/// bytes of the group element
	unsigned char group_bytes[32];
	} mcci_tweetnacl_curve25519_group_element_t;

/// \brief curve25519 scalar integer
/// \see https://nacl.cr.yp.to/scalarmult.html
typedef struct
	{
	/// bytes of the scalar
	unsigned char scalar_bytes[32];
	} mcci_tweetnacl_curve25519_scalar_t;

/****************************************************************************\
|
|	APIs
|
\****************************************************************************/

///
/// \brief do a scalar multiplication of a curve255129 group element by an integer
///
/// \param[out] q is set to the result
/// \param[in] p is the input group element,
/// \param[in] n is the input integer scalalar.
///
/// \see https://nacl.cr.yp.to/scalarmult.html
///
static inline void
mcci_tweetnacl_scalarmult_curve25519(
	mcci_tweetnacl_curve25519_group_element_t *q,
	const mcci_tweetnacl_curve25519_group_element_t *p,
	const mcci_tweetnacl_curve25519_scalar_t *n
	)
	{
	extern int crypto_scalarmult_curve25519_tweet(unsigned char *,const unsigned char *,const unsigned char *);
	(void) crypto_scalarmult_curve25519_tweet(
		q->group_bytes,
		p->group_bytes,
		n->scalar_bytes
		);
	}

///
/// \brief do a scalar multiplication of the well known group element by an integer
///
/// \param[out] q is set to the result
/// \param[in] n is the input integer scalalar.
///
/// \see https://nacl.cr.yp.to/scalarmult.html
///
static inline void
mcci_tweetnacl_scalarmult_curve25519_base(
	mcci_tweetnacl_curve25519_group_element_t *q,
	const mcci_tweetnacl_curve25519_scalar_t *n
	)
	{
	extern int crypto_scalarmult_curve25519_tweet_base(unsigned char *,const unsigned char *);
	(void) crypto_scalarmult_curve25519_tweet_base(
		q->group_bytes,
		n->scalar_bytes
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

#endif /* _mcci_tweetnacl_scalarmult_h_ */
