/*

Module:	mcci_tweetnacl_box_keypair.c

Function:
	mcci_tweetnacl_box_keypair()

Copyright and License:
	This file copyright (C) 2021 by

		MCCI Corporation
		3520 Krums Corners Road
		Ithaca, NY  14850

	See accompanying LICENSE file for copyright and license information.

Author:
	Terry Moore, MCCI Corporation	March 2021

*/

#include "../mcci_tweetnacl_box.h"

#include "mcci_tweetnacl_hal_internal.h"

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


mcci_tweetnacl_randombytes_error_t
mcci_tweetnacl_box_keypair(
	mcci_tweetnacl_box_publickey_t *pPublicKey,
	mcci_tweetnacl_box_privatekey_t *pPrivateKey
	)
	{
	extern int crypto_box_curve25519xsalsa20poly1305_tweet_keypair(unsigned char *,unsigned char *);
	jmp_buf env;
	volatile mcci_tweetnacl_hal_jmp_buf_t save_env;

	save_env = mcci_tweetnacl_hal_randombytes_set_abort(env);

	if (! setjmp(env))
		{
		// call the TweetNaCl API.
		int const rc = crypto_box_curve25519xsalsa20poly1305_tweet_keypair(
			pPublicKey->bytes,
			pPrivateKey->bytes
			);
		
		// restore old abort
		mcci_tweetnacl_hal_randombytes_set_abort(save_env.pJmpBuf);

		// return code.
		return rc == 0 ? MCCI_TWEETNACL_RANDOMBYTES_ERROR_SUCCESS 
			       : MCCI_TWEETNACL_RANDOMBYTES_ERROR_CRYPTO_API_FAILED
			       ;
		}

	// restore old abort
	mcci_tweetnacl_hal_randombytes_set_abort(save_env.pJmpBuf);

	return mcci_tweetnacl_hal_randombytes_getlasterror();
	}

/**** end of mcci_tweetnacl_box_keypair.c ****/
