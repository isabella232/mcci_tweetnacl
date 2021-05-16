# MCCI TweetNaCl for embedded systems and Arduino

[NaCl](https://nacl.cr.yp.to/index.html) ("Networking and Cryptography Library", pronounced "salt") is a public-domain, light-weight library of important cryptographic algorigthm implementations, designed to avoid the fundamental sources of security failures in larger cryptography libraries.

TweetNaCl ("tweet salt") is a concise version of NaCl that fits into a hundred 2014-era tweets, roughly 16,000 characters of source.

MCCI TweetNaCl is a curated version of TweetNaCl, extended with `crypto_auth()` from [NaCl](http://nacl.cr.yp.to/auth.html) and a few other helpful wrappers. It supports Arduino use, but also can be used in more general ways.

## References

The article "[Securing Communication](https://nacl.cr.yp.to/securing-communication.pdf)" gives a good overview of the background of the NaCl library.

The NaCl project home page: https://nacl.cr.yp.to/index.html.

The TweetNaCl project home page: https://tweetnacl.cr.yp.to/index.html.

The TweetNaCl paper: https://tweetnacl.cr.yp.to/tweetnacl-20140917.pdf.

A detailed description of the APIs is available by running [`doxygen`](https://www.doxygen.nl/) using `Doxyfile` from the top-level directory.

## Approach

MCCI's experience with portability issues, especially working with large libraries in environments like Arduino, caused us to make the following architectural decisions.

The directory structure was chosen to be Arduino IDE-friendly. In particular:

* The client `.h` files are placed in `src`
* The library source files specific to this wrapper are placed in `src/lib`.
* The reference files (`tweetnacl.h`, `tweetnacl.c`) are placed in `extra/reference_tweetnacl`, thereby avoiding automatic compilation.

The header file `tweetnacl.h` and source file `tweetnacl.c` are used unchanged. (A separate repository, [`reference_tweetnacl`](https://github.com/mcci-catena/reference_tweetnacl) is included as a git subtree.

`tweetnacl.h` includes, but `tweetnacl.c` does not implement, HMAC functions defined by NaCl `crypto_auth.h`. The NaCl equivalents were easy to grab and have been added to the library.)

All names in the namespace are prefixed with "`mcci_tweetnacl_...`"

All routines are wrapped by `mcci_tweetnacl` wrappers. Where possible, these are static inline functions for efficiency. In a few cases, external wrappers functions are provided.

We added a structured lower edge providing a random number generation API.  (A source of cryptographic randomness is not provided by TweetNaCl, but is required by key generation APIs.) This API is integrated into `tweetnacl.c` without changes, using the following steps.

* Rather than compile `tweetnacl.c` directly, we `#include` it from `src/lib/mcci_tweetnacl.c`.
* `mcci_tweetnacl.c` defines `randombytes` as a macro that resolves to `mcci_tweetnacl_hal_randombytes`.
* `src/hal/mcci_tweetnacl_hal_randombytes.c` declares two functions, `mcci_tweetnacl_hal_randombytes()` and `mcci_tweetnacl_configure_randombytes()`. The latter allows the client to establish a random number driver at initialization time; the former uses the pointer given by the user to call the random number driver.
* `tweetnacl.c` has no provision for the random number generator failing. However, they can fail. The wrappers for the library routines that call `randombytes` therefore use `setjmp()` and `longjmp()` to implement a simple abort system. 

## Meta

### License

The top-level wrappers, documentation, and examples are released under the [MIT](./LICENSE.md) license. Commercial licenses and support are also available from MCCI Corporation. This covers all content other than `extra/reference_nacl`, `extra/reference_tweetnacl`, and `extra/seatest`, which have their own licenses.

The TweetNaCl and NaCl code in directories `extra/reference_tweetnacl` and `extra/reference_nacl` is all public domain (including MCCI contributions in those directories).

The `seatest` code in directory `extra/seatest` is covered by its own MIT license.

### Support Open Source Hardware and Software

MCCI invests time and resources providing this open source code, please support MCCI and open-source hardware by purchasing products from MCCI, Adafruit and other open-source hardware/software vendors!

For information about MCCI's products, please visit [store.mcci.com](https://store.mcci.com/).

### Trademarks

MCCI and MCCI Catena are registered trademarks of MCCI Corporation. All other marks are the property of their respective owners.
