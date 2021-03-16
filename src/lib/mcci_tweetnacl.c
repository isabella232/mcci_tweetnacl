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

int crypto_verify_64_tweet_mcci(const unsigned char *x,const unsigned char *y);
int crypto_hashblocks_sha512_tweet_mcci_init(unsigned char *pOut);
int crypto_hashblocks_sha512_tweet_mcci_finish(unsigned char *h,const unsigned char *m, unsigned long long n);

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

int crypto_verify_64_tweet_mcci(const u8 *x,const u8 *y)
{
  return vn(x,y,64);
}

int crypto_hashblocks_sha512_tweet_mcci_init(u8 *pOut)
{
  int i;
  FOR(i,64) pOut[i] = iv[i];
  return 0;
}

int crypto_hashblocks_sha512_tweet_mcci_finish(u8 *h,const u8 *m,u64 n)
{
  u8 x[256];
  u64 i,b = n;
  
  m += n;
  n &= 127;
  m -= n;

  FOR(i,256) x[i] = 0;
  FOR(i,n) x[i] = m[i];
  x[n] = 128;

  n = 256-128*(n<112);
  x[n-9] = b >> 61;
  ts64(x+n-8,b<<3);
  crypto_hashblocks(h,x,n);

  return 0;
}
/**** end of mcci_tweetnacl.c ****/
