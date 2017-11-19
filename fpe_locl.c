#include <assert.h>
#include "fpe_locl.h"

// quick power: result = x ^ e
void pow_uv(BIGNUM *pow_u, BIGNUM *pow_v, unsigned int x, int u, int v, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *base = BN_CTX_get(ctx),
           *e = BN_CTX_get(ctx);

    BN_set_word(base, x);
    if (u > v) {
        BN_set_word(e, v);
        BN_exp(pow_v, base, e, ctx);
        BN_mul(pow_u, pow_v, base, ctx);
    } else {
        BN_set_word(e, u);
        BN_exp(pow_u, base, e, ctx);
        if (u == v)    BN_copy(pow_v, pow_u);
        else    BN_mul(pow_v, pow_u, base, ctx);
    }

    BN_CTX_end(ctx);
    return;

    /*
    // old veresion, classical quick power
    mpz_t temp;
    mpz_init_set_ui(result, 1);
    mpz_init_set_ui(temp, x);
    while (e) {
        if (e & 1)    mpz_mul(result, result, temp);
        mpz_mul(temp, temp, temp);
        e >>= 1;
    }
    mpz_clear(temp);
    return;
    */
}

// ceil( log2(x) )
int bits(int x)
{
    int len = 0;
    if (x >> 16) { len += 16; x >>= 16; }
    if (x >> 8) { len += 8; x >>= 8; }
    if (x >> 4) { len += 4; x >>= 4; }
    if (x >> 2) { len += 2; x >>= 2; }
    if (x >> 1) { len += 1; x >>= 1; }
    len += x & 1;
    assert(len > 0 && len <= 16);
    return len;
}

