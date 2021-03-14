/*

Module:	mcci_tweetnacl.c

Function:
	Wrapper for tweetnacl.c.

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

/****************************************************************************\
|
|	Manifest constants & typedefs.
|
\****************************************************************************/



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

// define this so that we don't pollute the namespace with `randombytes`.
#define	randombytes	mcci_tweetnacl_hal_randombytes

#include "../../extra/reference_tweetnacl/tweetnacl.c"

/**** end of mcci_tweetnacl.c ****/
