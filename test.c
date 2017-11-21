#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "fpe.h"

int main(void)
{
    unsigned char K[] = {0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F, 0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94},
                  T[] = {0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73};
    unsigned int X[] = {8, 9, 0, 1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0};
    int Xlen = sizeof(X) / 4,
        Tlen = 8,
        radix = 10;
    unsigned int Y[Xlen];

    /*
    printf("radix: ");
    scanf("%d", &radix);
    */

    for (int i = 0; i < Xlen; ++i)
        assert(X[i] < radix);

    printf("origin: ");
    for (int i = 0; i < Xlen; ++i)    printf("%d ", X[i]);
    printf("\n\n");

    printf("========== FF1 ==========\n");
    FPE_ff1_encrypt(X, Y, K, T, radix, Xlen, Tlen, FPE_ENCRYPT);

    printf("ciphertext: ");
    for (int i = 0; i < Xlen; ++i)    printf("%d ", Y[i]);
    printf("\n\n");

    memset(X, 0, sizeof(X));
    FPE_ff1_encrypt(Y, X, K, T, radix, Xlen, Tlen, FPE_DECRYPT);

    printf("plaintext: ");
    for (int i = 0; i < Xlen; ++i)    printf("%d ", X[i]);
    printf("\n\n");

    printf("========== FF3 ==========\n");
    FPE_ff3_encrypt(X, Y, K, T, radix, Xlen, FPE_ENCRYPT);

    printf("ciphertext: ");
    for (int i = 0; i < Xlen; ++i)    printf("%d ", Y[i]);
    printf("\n\n");

    memset(X, 0, sizeof(X));
    FPE_ff3_encrypt(Y, X, K, T, radix, Xlen, FPE_DECRYPT);

    printf("plaintext: ");
    for (int i = 0; i < Xlen; ++i)    printf("%d ", X[i]);
    printf("\n");

    return 0;
}

