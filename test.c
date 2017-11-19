#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "fpe.h"

int main(void)
{
    unsigned char K[] = "1234567891234567",
                  T[] = "1234567891234567";
    unsigned int X[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 131, 114, 555, 6666, 777, 8988, 59999, 100};
    int Xlen = sizeof(X) / 4,
        Tlen = 16,
        radix = 65535;
    unsigned int Y[Xlen];

    printf("radix: ");
    scanf("%d", &radix);

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
    FPE_ff3_encrypt(X, Y, K, T, radix, Xlen, 16, FPE_ENCRYPT);

    printf("ciphertext: ");
    for (int i = 0; i < Xlen; ++i)    printf("%d ", Y[i]);
    printf("\n\n");

    memset(X, 0, sizeof(X));
    FPE_ff3_encrypt(Y, X, K, T, radix, Xlen, 16, FPE_DECRYPT);

    printf("plaintext: ");
    for (int i = 0; i < Xlen; ++i)    printf("%d ", X[i]);
    printf("\n");

    return 0;
}

