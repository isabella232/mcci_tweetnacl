/*

Module:	mcci_tweetnacl.h

Function:
	Equivalent wrapper for tweetnacl.h minimizing namespace pollution

Copyright and License:
	This file copyright (C) 2021 by

		MCCI Corporation
		3520 Krums Corners Road
		Ithaca, NY  14850

	See accompanying LICENSE file for copyright and license information.

Author:
	Terry Moore, MCCI Corporation	March 2021

*/

#ifndef _mcci_tweetnacl_h_
#define _mcci_tweetnacl_h_	/* prevent multiple includes */

#pragma once

#include <stdbool.h>
#include <stdlib.h>

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
///	\addtogroup mcci-tweetnacl	Framework
///	\addtogroup string-comparison	String Comparison

/****************************************************************************\
|
|	Forward Types
|
\****************************************************************************/

///
/// \brief abstract type for randombytes driver context
///
/// This abstract type simply is passed through unmodified, and may be used
/// for any needed dynamic context for the random bytes implementation.
///
/// \ingroup mcci-tweetnacl
///
typedef struct mcci_tweetnacl_randombytes_driver_s *mcci_tweetnacl_randombytes_handle_t;

///
/// \brief error codes from mcci_tweetnacl_randombytes_fn_t implementations errors
///
/// \ingroup mcci-tweetnacl
///
typedef enum mcci_tweetnacl_randombytes_error_e
	{
	MCCI_TWEETNACL_RANDOMBYTES_ERROR_SUCCESS = 0,			///< success (not an error)
	MCCI_TWEETNACL_RANDOMBYTES_ERROR_UNKNOWN = 1,			///< bad param to mcci_tweetnacl_hal_randombytes_raise()
	MCCI_TWEETNACL_RANDOMBYTES_ERROR_NOT_INITIALIZED = 2,		///< random number driver not intialized
	MCCI_TWEETNACL_RANDOMBYTES_ERROR_INVALID_PARAMETER = 3,		///< invalid parameter
	MCCI_TWEETNACL_RANDOMBYTES_ERROR_CRYPTO_API_FAILED = 4,		///< the related crypto API failed
	} mcci_tweetnacl_randombytes_error_t;


///
/// \brief symbolic type for local random-number generator
///
/// \param[in] hDriver is the driver handle supplied to MCCI TweetNaCl at initialization.
/// \param[out] pOutBuffer points to the buffer to be filled
/// \param[in] nBuffer specifies the size of \p pOutBuffer.
///
/// \returns error code; 0 for success, non-zero for failure.
///
/// \note This function must provide a cryptographically strong RNG.
/// If not provided, mcci_tweetnacl_sign_keypair() and mcci_tweetnacl_box_kaypair()
/// will not be available.
///
/// \ingroup mcci-tweetnacl
///
typedef mcci_tweetnacl_randombytes_error_t 
(mcci_tweetnacl_randombytes_fn_t)(
	mcci_tweetnacl_randombytes_handle_t hDriver,
	unsigned char *pOutBuffer,
	size_t nBuffer
	);

/****************************************************************************\
|
|	APIs
|
\****************************************************************************/

///
/// \brief Compare two 16-byte buffers, in a time-invariant fashion
///
/// \param[in] x,y buffers to be compared.
///	
/// \return true if the two buffers are equal, otherwise false.
///
/// \see https://nacl.cr.yp.to/verify.html
///
/// \ingroup string-comparison
///
static inline bool
mcci_tweetnacl_verify_16(
	const unsigned char *x,
	const unsigned char *y
	)
	{
	extern int crypto_verify_16_tweet(const unsigned char *,const unsigned char *);
	return crypto_verify_16_tweet(x, y) == 0;
	}

///
/// \brief Compare two 32-byte buffers, in a time-invariant fashion
///
/// \param[in] x,y buffers to be compared.
///	
/// \see https://nacl.cr.yp.to/verify.html
///
/// \ingroup string-comparison
///
static inline bool
mcci_tweetnacl_verify_32(
	const unsigned char *x,
	const unsigned char *y
	)
	{
	extern int crypto_verify_32_tweet(const unsigned char *,const unsigned char *);
	return crypto_verify_32_tweet(x, y) == 0;
	}

///
/// \brief setup the random number generator connection
///
/// \param[in]	pRandomBytesFn points to the function to be called by `randombytes`.
/// \param[in]	hDriver is an optional driver handle to be passed to the random
///		byte generator.
///
/// \returns \c true if the random number generator was set, \c false if the driver
///		could not be established.
///
/// \ingroup mcci-tweetnacl
///
bool
mcci_tweetnacl_configure_randombytes(
	mcci_tweetnacl_randombytes_fn_t *pRandomBytesFn,
	mcci_tweetnacl_randombytes_handle_t hDriver
	);

///
/// \brief Get the last error reported in the \c randombytes() mechanism.
///
/// \returns	last error code posted.
///
/// \note	The client must explicity call
///		mcci_tweetnacl_hal_randombytes_setlasterror() to clear the
///		last error if desired.
///
/// \ingroup mcci-tweetnacl
///
/// \see mcci_tweetnacl_hal_randombytes_setlasterror()
///

mcci_tweetnacl_randombytes_error_t
mcci_tweetnacl_hal_randombytes_getlasterror(void);

///
/// \brief Change the last error cell for the \c randombytes() mechanism.
///
/// \ingroup mcci-tweetnacl
///
/// \see mcci_tweetnacl_hal_randombytes_getlasterror()
///

void
mcci_tweetnacl_hal_randombytes_setlasterror(
	mcci_tweetnacl_randombytes_error_t lastError
	);


/****************************************************************************\
|
|	Post-Meta
|
\****************************************************************************/

//--- close groups ---
///  @}

#ifdef __cplusplus
}
#endif

#endif /* _mcci_tweetnacl_h_ */
