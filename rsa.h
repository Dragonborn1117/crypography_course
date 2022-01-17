#ifndef __RSA_H_
#define __RSA_H_
#include <gmp.h>

typedef struct {
	mpz_t e;
	mpz_t N;
    mpz_t d;
} rsa_key_t;

void rsa_encrypt(char *plain, char *cipher, rsa_key_t *key, int len);
void rsa_decrypt(char *plain, char *cipher, rsa_key_t *key, int len);
void rsa_key_generation(rsa_key_t *key);

#endif