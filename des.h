#ifndef __DES_H__
#define __DES_H__
#define DES_KEY_LEN 8
#define DES_BLOCK_SIZE 8

typedef struct {
    char key[DES_KEY_LEN];
} des_key_t;

void des_key_generation(des_key_t *key);
void des_encrypt(char *plain, char *cipher, des_key_t *key, int len);
void des_decrypt(char *plain, char *cipher, des_key_t *key, int len);

#endif