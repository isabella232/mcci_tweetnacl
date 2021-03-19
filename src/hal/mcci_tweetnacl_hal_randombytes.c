/*

Module:	mcci_tweetnacl_hal_randombytes.c

Function:
	HAL interface for randombytes API

Copyright and License:
	This file copyright (C) 2021 by

		MCCI Corporation
		3520 Krums Corners Road
		Ithaca, NY  14850

	See accompanying LICENSE file for copyright and license information.

Author:
	Terry Moore, MCCI Corporation	March 2021

*/


#include "mcci_tweetnacl.h"
#include "mcci_tweetnacl_hal.h"
#include "mcci_tweetnacl_hal_internal.h"
#include <setjmp.h>
#include <stdint.h>

/****************************************************************************\
|
|	Manifest constants & typedefs.
|
\****************************************************************************/

/// \brief Structure of context object for interface to random number source
///
/// \ingroup mcci-tweetnacl
///
typedef struct
	{
	/// \brief pointer to provider function
	mcci_tweetnacl_randombytes_fn_t	*pProvider;

	/// \brief driver context handle
	mcci_tweetnacl_randombytes_handle_t hDriver;

	/// \brief the random number failure stack link (if non-NULL)
	mcci_tweetnacl_hal_jmp_buf_t Abort;
	int lastError;
	} mcci_tweetnacl_hal_randombytes_linkage_t;

/****************************************************************************\
|
|	Read-only data.
|
\****************************************************************************/



/****************************************************************************\
|
|	Variables.
|
\****************************************************************************/

/// \brief interface to random number source
static mcci_tweetnacl_hal_randombytes_linkage_t sRandomInterface;

mcci_tweetnacl_hal_jmp_buf_t
mcci_tweetnacl_hal_randombytes_set_abort(
	jmp_buf pEnv
	)
	{
	mcci_tweetnacl_hal_jmp_buf_t const result = sRandomInterface.Abort;

	sRandomInterface.Abort = mcc_tweetnacl_hal_wrap_jmp_buf(pEnv);
	return result;
	}

mcci_tweetnacl_result_t
mcci_tweetnacl_configure_randombytes(
	mcci_tweetnacl_randombytes_fn_t *pRandomBytesFn,
	mcci_tweetnacl_randombytes_handle_t hDriver
	)
	{
	sRandomInterface.pProvider = pRandomBytesFn;
	sRandomInterface.hDriver = hDriver;
	return MCCI_TWEETNACL_RESULT_SUCCESS;
	}

void
mcci_tweetnacl_hal_randombytes_raise(
	mcci_tweetnacl_randombytes_error_t error
	)
	{
	if (error == 0)
		error = -1;

	sRandomInterface.lastError = error;
	longjmp((void *)sRandomInterface.Abort.pJmpBuf, error);
	}

mcci_tweetnacl_randombytes_error_t
mcci_tweetnacl_hal_randombytes_getlasterror()
	{
	return sRandomInterface.lastError;
	}

void
mcci_tweetnacl_hal_randombytes_setlasterror(
	mcci_tweetnacl_randombytes_error_t lastError
	)
	{
	sRandomInterface.lastError = lastError;
	}

void
mcci_tweetnacl_hal_randombytes(
	unsigned char *pBuffer,
	unsigned long long nBuffer
	)
	{
	if (nBuffer > SIZE_MAX)
		mcci_tweetnacl_hal_randombytes_raise(
			MCCI_TWEETNACL_RANDOMBYTES_ERROR_INVALID_PARAMETER
			);

	mcci_tweetnacl_randombytes_fn_t * const pProvider =
		sRandomInterface.pProvider;

	if (pProvider == NULL)
		mcci_tweetnacl_hal_randombytes_raise(
			MCCI_TWEETNACL_RANDOMBYTES_ERROR_NOT_INITIALIZED
			);

	mcci_tweetnacl_randombytes_error_t const result =
		(*pProvider)(sRandomInterface.hDriver, pBuffer, (size_t) nBuffer);

	if (result != MCCI_TWEETNACL_RANDOMBYTES_ERROR_SUCCESS)
		mcci_tweetnacl_hal_randombytes_raise(result);
	}

/**** end of mcci_tweetnacl_hal_randombytes.c ****/
