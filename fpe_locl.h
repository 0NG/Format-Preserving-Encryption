#ifndef HEADER_FPE_LOCL_H
# define HEADER_FPE_LOCL_H

#include <openssl/bn.h>

void pow_uv(BIGNUM *pow_u, BIGNUM *pow_v, unsigned int x, int u, int v, BN_CTX *ctx);

int bits(int x);

#endif
