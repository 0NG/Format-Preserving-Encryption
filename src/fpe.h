#ifndef HEADER_FPE_H
# define HEADER_FPE_H

# include <openssl/aes.h>

# ifdef __cplusplus
extern "C" {
# endif

# define FPE_ENCRYPT 1
# define FPE_DECRYPT 0

# define FF1_ROUNDS 10
# define FF3_ROUNDS 8
# define FF3_TWEAK_SIZE 8

struct fpe_key_st {
    unsigned int radix;
    unsigned int tweaklen;
    unsigned char *tweak;
    AES_KEY aes_enc_ctx;
};

typedef struct fpe_key_st FPE_KEY;

/*** FF1 ***/
int FPE_set_ff1_key(const unsigned char *userKey, const int bits, const unsigned char *tweak, const unsigned int tweaklen, const int radix, FPE_KEY *key);

void FPE_unset_ff1_key(FPE_KEY *key);

void FPE_ff1_encrypt(unsigned int *in, unsigned int *out, unsigned int inlen, FPE_KEY *key, const int enc);

/*** FF3 ***/
int FPE_set_ff3_key(const unsigned char *userKey, const int bits, const unsigned char *tweak, const unsigned int radix, FPE_KEY *key);

void FPE_unset_ff3_key(FPE_KEY *key);

void FPE_ff3_encrypt(unsigned int *in, unsigned int *out, unsigned int inlen, FPE_KEY *key, const int enc);

# ifdef __cplusplus
}
# endif

#endif
