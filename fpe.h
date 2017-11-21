#ifndef HEADER_FPE_H
# define HEADER_FPE_H

# ifdef __cplusplus
extern "C" {
# endif

# define FPE_ENCRYPT 1
# define FPE_DECRYPT 0

# define FF1_ROUNDS 10
# define FF3_ROUNDS 8
# define FF3_TWEAK_SIZE 8

// void FPE_set_key(const unsigned char *userKey, const int bits);

void FPE_ff1_encrypt(unsigned int *in, unsigned int *out, const unsigned char *key, const unsigned char *tweak, unsigned int radix, unsigned int inlen, unsigned int tweaklen, const int enc);

void FPE_ff3_encrypt(unsigned int *in, unsigned int *out, const unsigned char *key, const unsigned char *tweak, unsigned int radix, unsigned int inlen, const int enc);

# ifdef __cplusplus
}
# endif

#endif
