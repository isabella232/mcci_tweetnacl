/*

Module:	mcci_tweetnacl_hal.h

Function:
	MCCI TweetNaCl HAL APIs.

Copyright and License:
	This file copyright (C) 2021 by

		MCCI Corporation
		3520 Krums Corners Road
		Ithaca, NY  14850

	See accompanying LICENSE file for copyright and license information.

Author:
	fullname, MCCI Corporation	March 2021

*/

#ifndef _mcci_tweetnacl_hal_h_
#define _mcci_tweetnacl_hal_h_	/* prevent multiple includes */

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

/// \addtogroup low-level-functions 	Low-level functions
/// @{
///	\addtogroup mcci-tweetnacl
///	@{

///
/// \brief generate stream of random bytes
///
/// \param[out]	pBuffer	pointer to buffer to be filled
/// \param[in]  nBuffer number of bytes in buffer to be filled.
///
/// \note This must return cryptographically random numbers; don't try to use
///	  your own RNG unless you've tested extensively.
///
/// \note If the RNG can't generate a suitable value, the default implementation
///	  will use \c longjmp() to bail out. This means that this function can't
///	  be used directly by clients.
///

void
mcci_tweetnacl_hal_randombytes(
	unsigned char *pBuffer,
	unsigned long long nBuffer
	);


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

#endif /* _mcci_tweetnacl_hal_h_ */
