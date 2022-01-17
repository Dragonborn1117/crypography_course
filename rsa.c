#include <stdio.h>
#include <stdlib.h>
#include "rsa.h"
#define PRIME_LENGTH 512

unsigned long GMP_SEED = 233;

void init_random_state(gmp_randstate_t state) {
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, GMP_SEED);
}

void get_prime(mpz_t p, gmp_randstate_t state) {
    mpz_rrandomb(p, state, PRIME_LENGTH);
    while (!(mpz_millerrabin(p, PRIME_LENGTH))) {
        gmp_randclear(state);
        GMP_SEED++;
        init_random_state(state);
        mpz_rrandomb(p, state, PRIME_LENGTH);
    }
    gmp_randclear(state);
    GMP_SEED++;
}

void rsa_key_generation(rsa_key_t *key) {
    mpz_inits(key->d, key->e, key->N, NULL);
    gmp_randstate_t state;
    mpz_set_ui(key->e, 65537);
    mpz_t p, q;
    mpz_inits(p, q, NULL);
    init_random_state(state);
    get_prime(p, state);
    init_random_state(state);
    get_prime(q, state);
    mpz_mul(key->N, p, q);
    mpz_t p_minus1, q_minus1, phi_N;
    mpz_inits(p_minus1, q_minus1, phi_N, NULL);
    mpz_sub_ui(p_minus1, p, 1);
    mpz_sub_ui(q_minus1, q, 1);
    mpz_mul(phi_N, p_minus1, q_minus1);
    mpz_clears(p, q, p_minus1, q_minus1, NULL);
    mpz_invert(key->d, key->e, phi_N);
}

void rsa_encode(mpz_t encode, unsigned char encode_arr[]) {
    mpz_export(encode_arr, NULL, 1, sizeof(encode_arr[0]), 0, 0, encode);
}

void rsa_decode(mpz_t decode, unsigned char decode_arr[]) {
    mpz_import(decode, 128, 1, sizeof(decode_arr[0]), 0, 0, decode_arr);
}

void rsa_encrypt(char *plain, char *cipher, rsa_key_t *key, int len) {
    mpz_t plain_text, cipher_text;
    mpz_inits(plain_text, cipher_text, NULL);
    for (int i = 0; i < len; i += 128) {
        rsa_decode(plain_text, plain + i);
        mpz_powm(cipher_text, plain_text, key->e, key->N);
        rsa_encode(cipher_text, cipher + i);
    }
}

void rsa_decrypt(char *plain, char *cipher, rsa_key_t *key, int len) {
    mpz_t plain_text, cipher_text;
    mpz_inits(plain_text, cipher_text, NULL);
    for (int i = 0; i < len; i += 128) {
        rsa_decode(cipher_text, cipher + i);
        mpz_powm(plain_text, cipher_text, key->d, key->N);
        rsa_encode(plain_text, plain + i);
    }
}