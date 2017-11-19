# FPE - Format Preserving Encryption Implementation in C

An implementation of the NIST approved Format Preserving Encryption (FPE) FF1 and FF3 algorithms in C.

[NIST Recommendation SP 800-38G](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)

This follows the FF1 and FF3 schemes for Format Preserving Encryption outlined in the NIST Recommendation, released in March 2016. For FF1, it builds on and formalizes (differing from but remaining mathematically equivalent to) the FFX-A10 scheme by Bellare, Rogaway and Spies as defined [here](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec.pdf) and [here](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec2.pdf). For FF3, it formalizes the BPS scheme.

A note about FF3: There was some [recent cryptanalysis](https://beta.csrc.nist.gov/News/2017/Recent-Cryptanalysis-of-FF3) about the FF3 algorithm that is important to review. NIST has concluded that FF3 is no longer suitable as a general-purpose FPE method.

A note about FF2: FF2 was originally NOT recommended by NIST, but it is under review again as DFF. You can read about it [here](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/dff/dff-ff2-fpe-scheme-update.pdf).

## Example Usage

This implementation is based on openssl's BIGNUM and AES, so you need to install openssl first.

The example code is [test.c](https://github.com/0NG/Format-Preserving-Encryption/blob/master/test.c). Also, I have written a makefile for it. They may help you get started

## Existing Implementations

Based on searching GitHub and the Internet, there are no known reference implementations for either algorithm.

An [existing C++ implementation](https://github.com/randombit/botan/tree/753b4c2d5301574d3c9390b79aa275a49809e6c8/src/lib/misc/fpe_fe1) based on the FFX mode, but the implementation differs from the NIST recommendation. 

Also, another [implementation in Go](https://github.com/capitalone/fpe) is great. I have learned a lot from it.