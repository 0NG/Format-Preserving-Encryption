# FPE - Format Preserving Encryption Implementation in C

An implementation of the NIST approved Format Preserving Encryption (FPE) FF1 and FF3 algorithms in C.

[NIST Recommendation SP 800-38G](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)

This follows the FF1 and FF3 schemes for Format Preserving Encryption outlined in the NIST Recommendation, released in March 2016. For FF1, it builds on and formalizes (differing from but remaining mathematically equivalent to) the FFX-A10 scheme by Bellare, Rogaway and Spies as defined [here](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec.pdf) and [here](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec2.pdf). For FF3, it formalizes the BPS scheme.

A note about FF3: There was some [recent cryptanalysis](https://beta.csrc.nist.gov/News/2017/Recent-Cryptanalysis-of-FF3) about the FF3 algorithm that is important to review. NIST has concluded that FF3 is no longer suitable as a general-purpose FPE method.

A note about FF2: FF2 was originally NOT recommended by NIST, but it is under review again as DFF. You can read about it [here](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/dff/dff-ff2-fpe-scheme-update.pdf).

## Example Usage

This implementation is based on openssl's BIGNUM and AES, so you need to install openssl first.

I have provide two function for FF1 and FF2 algorithm, respectively.

void FPE_ff1_encrypt(unsigned int *in, unsigned int *out, const unsigned char *key, const unsigned char *tweak, unsigned int radix, unsigned int inlen, unsigned int tweaklen, const int enc)

| name     | description                              |
| -------- | ---------------------------------------- |
| in       | numeral string to be encrypted, represented as an array of integers |
| out      | encrypted numeral string, represented as an array of integers |
| key      | encryption key ( currently, it must be 128 bit), represented as a c string |
| tweak    | tweak, represented as a c string         |
| radix    | number of characters in the given alphabet, it must be in [2, 2^16] |
| inlen    | the length of input numeral string (in)  |
| tweaklen | the byte length of the tweak             |
| enc      | can be two value: FPE_ENCRYP for encryp and FPE_DECRYPT for decrypt |

void FPE_ff3_encrypt(unsigned int *in, unsigned int *out, const unsigned char *key, const unsigned char *tweak, unsigned int radix, unsigned int inlen, const int enc)

| name  | description                              |
| ----- | ---------------------------------------- |
| in    | numeral string to be encrypted, represented as an array of integers |
| out   | encrypted numeral string, represented as an array of integers |
| key   | encryption key ( currently, it must be 128 bit), represented as a c string |
| tweak | tweak, its byte length must be 64, represented as a c string |
| radix | number of characters in the given alphabet, it must be in [2, 2^16] |
| inlen | the length of input numeral string (in)  |
| enc   | can be two value: FPE_ENCRYP for encryp and FPE_DECRYPT for decrypt |

The example code is [test.c](https://github.com/0NG/Format-Preserving-Encryption/blob/master/test.c). Also, there are some official [test vectors](http://csrc.nist.gov/groups/ST/toolkit/examples.html) for both FF1 and FF3 provided by NIST. They may help you get started.

After *make*, to compile with the fpe library, you should run:

```bash
gcc test.c -o test -L. -lfpe -lm -lcrypto
```

## Existing Implementations

Based on searching GitHub and the Internet, there are no known reference implementations for either algorithm.

An [existing C++ implementation](https://github.com/randombit/botan/tree/753b4c2d5301574d3c9390b79aa275a49809e6c8/src/lib/misc/fpe_fe1) based on the FFX mode, but the implementation differs from the NIST recommendation. 

Also, another [implementation in Go](https://github.com/capitalone/fpe) is great. I have learned a lot from it.
