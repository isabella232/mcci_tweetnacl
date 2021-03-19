##############################################################################
#
# Module:	ed25519.awk
#
# Function:
# 	Equivalent of NaCl "crypto_sign.h" for MCCI TweetNaCl.
#
# Copyright and License:
# 	This file copyright (C) 2021 by
#
# 		MCCI Corporation
# 		3520 Krums Corners Road
# 		Ithaca, NY  14850
#
# 	See accompanying LICENSE file for copyright and license information.
#
# Author:
# 	Terry Moore, MCCI Corporation	March 2021
#
##############################################################################

BEGIN {
	# input lines contain fields separated by colons.
	FS = ":";
}

##
## convert packed hex bytes to C initializer
## \param [in] x   String, packed hex bytes, two characters per
##                 byte.
##
## Example:  hex("012345") returns "0x01, 0x23, 0x45,".
##
function hex(x) {
	gsub(/../, "0x&, ", x);
	return x;
}

##
## output a raw structure initializer
## \param [in] n   String, name of field to emit
## \param [in] x   String, value.
##
## This routine prints ".n = x," on a line by itself, indented.
##
function rawfield(n,x) {
	printf("\t.%s = %s,\n", n, x);
}

##
## output a byte string initializer
## \param [in] n   String, name of field to emit
## \param [in] x   packed hex bytes to be output
##
## This routine prints ".n = { 0xaa, 0xbb, ... , },", suitably
## indented. 0xaa, 0xbb etc. come from breaking up x using
## hex().
##
function field(n,x) {
	rawfield(n, "{\n\t" hex(x) "\n\t}");
}

##
## output a constant byte buffer
## \param [in] n   String, name of buffer.
## \param [in] x   packed hex bytes of initializer
##
function cbuf(n,x) {
	printf("const uint8_t %s[] = {\n\t%s\n};\n", n, hex(x));
}

### the loop outputting the test vectors
{
	# output vectors 1-9 and 65.  65 is special because
	# it's our key use case.  (The vectors are
	# sorted in ascending order of message length,
	# from 0 bytes to 8 bytes and then 64 bytes.)
	if (NR <= 9 || NR == 65) {
		++out;
		printf("// %d\n", out);
		cbuf("m" out, $3);
		cbuf("s" out, $4);
		printf("const ed25519_test_t v%d = {\n", out);
		field("Secret", $1);
		field("Public", $2);
		rawfield("pMessage", "m" out);
		rawfield("nMessage", "sizeof(m" out ")");
		rawfield("pSignature", "s" out);
		rawfield("nSignature", "sizeof(s" out ")" );
		printf("};\n\n");
		}
}

### when done, output a table of pointers
END {
	printf("const ed25519_test_t * const vecs[] = {\n\t");
	for (i = 1; i <= out; ++i) {
		printf("&v%d, ", i);
	}
	printf("\n};\n");
}
