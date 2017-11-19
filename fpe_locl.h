#ifndef HEADER_FPE_LOCL_H
# define HEADER_FPE_LOCL_H

# include <openssl/bn.h>

// ceil and floor for x / (2 ^ bit)
# define ceil(x, bit) ( ( (x) >> (bit) ) + ( (x) & (( 1 << (bit) ) - 1) ) )
# define floor(x, bit) ( (x) >> (bit) )

void pow_uv(BIGNUM *pow_u, BIGNUM *pow_v, unsigned int x, int u, int v, BN_CTX *ctx);

int bits(int x);

#endif
