/*

Module:	mcci_tweetnacl_sign.c

Function:
	mcci_tweetnacl_sign();

Copyright and License:
	This file copyright (C) 2021 by

		MCCI Corporation
		3520 Krums Corners Road
		Ithaca, NY  14850

	See accompanying LICENSE file for copyright and license information.

Author:
	Terry Moore, MCCI Corporation	March 2021

*/

#include "../mcci_tweetnacl_sign.h"

#include <stdint.h>

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

bool
mcci_tweetnacl_sign(
	unsigned char *pSignedMessage,
	size_t *pSignedMessageSize,
	const unsigned char *pMessage,
	size_t messageSize,
	const mcci_tweetnacl_sign_privatekey_t *pPrivateKey
	)
	{
	extern int crypto_sign_ed25519_tweet(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
	unsigned long long sizeOut;

	if (messageSize > SIZE_MAX - sizeof(mcci_tweetnacl_sign_signature_size()))
		{
		*pSignedMessageSize = 0;
		return false;
		}

	(void) crypto_sign_ed25519_tweet(
		pSignedMessage,
		&sizeOut,
		pMessage,
		messageSize,
		pPrivateKey->bytes
		);

	*pSignedMessageSize = (size_t) sizeOut;
	return true;
	}


/**** end of mcci_tweetnacl_sign.c ****/
