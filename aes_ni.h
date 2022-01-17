#ifndef __AES_NI_H__
#define __AES_NI_H__

#define AES_KEY_LEN 16
#define AES_BLOCK_SIZE 16
typedef struct {
    char key[AES_KEY_LEN];
} aes_key_t;

void aes_key_generation(aes_key_t *key);
void aes_encrypt(char *plain, char *cipher, aes_key_t *key, int len);
void aes_decrypt(char *plain, char *cipher, aes_key_t *key, int len);

#endif