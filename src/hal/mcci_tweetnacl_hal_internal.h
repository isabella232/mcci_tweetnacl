/*

Module:	mcci_tweetnacl_hal_internal.h

Function:
	Internal APIs for HAL implementation

Copyright and License:
	This file copyright (C) 2021 by

		MCCI Corporation
		3520 Krums Corners Road
		Ithaca, NY  14850

	See accompanying LICENSE file for copyright and license information.

Author:
	Terry Moore, MCCI Corporation	March 2021

*/

#ifndef _mcci_tweetnacl_hal_internal_h_
#define _mcci_tweetnacl_hal_internal_h_	/* prevent multiple includes */

#pragma once

#include "../mcci_tweetnacl_hal.h"

#include <setjmp.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
# define MCCI_TWEETNACL_NORETURN_PFX	__declspec(noreturn)
# define MCCI_TWEETNACL_NORETURN_SFX	/* nothing */
#else
# define MCCI_TWEETNACL_NORETURN_PFX	/* nothing */
# define MCCI_TWEETNACL_NORETURN_SFX	__attribute__((__noreturn__))
#endif

/****************************************************************************\
|
|	Meta
|
\****************************************************************************/

/// \addtogroup low-level-functions 	Low-level functions
/// @{
///	\addtogroup mcci-tweetnacl-hal	Internal HAL functions
///	@{

/****************************************************************************\
|
|	Forward types
|
\****************************************************************************/

///
/// \brief carrier for jmp_buf values
///
typedef struct
	{
	void *pJmpBuf;
	} mcci_tweetnacl_hal_jmp_buf_t;

///
/// \brief convert a jmp_buf to a mcci_tweetnacl_jmp_buf_t.
///
static inline
mcci_tweetnacl_hal_jmp_buf_t
mcc_tweetnacl_hal_wrap_jmp_buf(
	jmp_buf env
	)
	{
	mcci_tweetnacl_hal_jmp_buf_t result;

	result.pJmpBuf = env;
	return result;
	}

///
/// \brief set the abort pointer and return previous value.
///
/// \return	previous value of abort pointer.
///
mcci_tweetnacl_hal_jmp_buf_t
mcci_tweetnacl_hal_randombytes_set_abort(
	jmp_buf pEnv
	);

///
/// \brief report an error.
///
/// \param[in]	error	The error code to report. If zero,
///			MCCI_TWEETNACL_RANDOMBYTES_ERROR_UNKNOWN is reported
///			instead.
///
/// \note This function does not return.
///
MCCI_TWEETNACL_NORETURN_PFX
void
mcci_tweetnacl_hal_randombytes_raise(
	mcci_tweetnacl_randombytes_error_t error
	) MCCI_TWEETNACL_NORETURN_SFX;

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

#endif /* _mcci_tweetnacl_hal_internal_h_ */
