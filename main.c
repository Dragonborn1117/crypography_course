#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "rsa.h"
#include "aes_ni.h"
#include "des.h"
#include "sha256.h"
#include "color.h"

#define MAX_NAME_LEN 60
const char *default_key_filename = "default.key";
const char *help_msg =
        "Usage: encrypt.exe [options]\n"
        "  -a={rsa|des|sha|aes|sign}\talgorithm: rsa, des, sha, aes, sign\n"
        "  -i\tinput file path\n"
        "  -o\toutput file path\n"
        "  -d\tdecrypt\n"
        "  -k\tkey path\n"
        "  -g\tgenerating key only\n"
        "  -m={ECB|CBC|OFB|CTR|XCBC}\tencryption mode\n"
        ;

#define UNIT_LEN 8
#define UNIT_B   0
#define UNIT_KB  1
#define UNIT_MB  2
const char size_unit[][UNIT_LEN] = {"B", "KB", "MB"};

#define ALGORITHM_NUM 5
#define RSA 0
#define DES 1
#define SHA 2
#define SIGN 3
#define AES 4
#define RSA_BLOCK 128
#define DES_BLOCK 8
#define SHA_BLOCK 32
#define SIGN_BLOCK 128
#define AES_BLOCK 16
const char algorithm_set[ALGORITHM_NUM][MAX_NAME_LEN] = {"rsa", "des", "sha", "sign", "aes"};
const int block_size[] = {RSA_BLOCK, DES_BLOCK, SHA_BLOCK, SIGN_BLOCK, AES_BLOCK};
int algo_num = -1;

int check_algorithm(char *algo) {
    int res = 0;
    for (int i = 0; i < ALGORITHM_NUM; i++) {
        if (strcmp(algo, algorithm_set[i]) == 0) {
            algo_num = i;
            res = 1;
            break;
        }
    }
    return res;
}

int compute_actual_size(int size) {
    if (size % block_size[algo_num])
        return (size / block_size[algo_num] + 1) * block_size[algo_num];
    else
        return size;
}

void rsa_save_key(rsa_key_t *key, char *save_path) {
    char mpz_buffer[1024];
    FILE *fd = fopen(save_path, "wb");
    mpz_out_raw(fd, key->e);
    mpz_out_raw(fd, key->d);
    mpz_out_raw(fd, key->N);
    fclose(fd);
}

void rsa_read_key(rsa_key_t *key, char *save_path) {
    mpz_inits(key->e, key->d, key->N, NULL);
    FILE *fd = fopen(save_path, "rb");
    mpz_inp_raw(key->e, fd);
    mpz_inp_raw(key->d, fd);
    mpz_inp_raw(key->N, fd);
    fclose(fd);
}

void aes_read_key(aes_key_t *key, char *save_path) {
    FILE *fd = fopen(save_path, "rb");
    fread(key->key, 1, AES_KEY_LEN, fd);
    fclose(fd);
}

void aes_save_key(aes_key_t *key, char *save_path) {
    FILE *fd = fopen(save_path, "wb");
    fwrite(key->key, 1, AES_KEY_LEN, fd);
    fclose(fd);
}

void des_read_key(des_key_t *key, char *save_path) {
    FILE *fd = fopen(save_path, "rb");
    fread(key->key, 1, DES_KEY_LEN, fd);
    fclose(fd);
}

void des_save_key(des_key_t *key, char *save_path) {
    FILE *fd = fopen(save_path, "wb");
    fwrite(key->key, 1, DES_KEY_LEN, fd);
    fclose(fd);
}

int main(int argc, char **argv)
{
    char algorithm[MAX_NAME_LEN] = {0};
    char input_file[MAX_NAME_LEN] = {0};
    char output_file[MAX_NAME_LEN] = {0};
    char key_filename[MAX_NAME_LEN] = {0};

    rsa_key_t rsa_key;
    aes_key_t aes_key;
    des_key_t des_key;
    FILE *fd_in, *fd_out;
    int ch;
    int opterr = 0;
    int decrypt = 0;
    int has_key = 0;
    int generate_key = 0;

    while ((ch = getopt(argc, argv, "ha:i:o:dk:g")) != -1) {
        switch (ch)
        {
        case 'h':
            printf(help_msg);
            exit(0);
            break;
        case 'a':
            strcpy(algorithm, optarg);
            if (!check_algorithm(algorithm)) {
                fprintf(stderr, "algo : %s not supported\n", algorithm);
                printf(help_msg);
                exit(0);
            }
            break;
        case 'i':
            strcpy(input_file, optarg);
            break;
        case 'o':
            strcpy(output_file, optarg);
            break;
        case 'd':
            decrypt = 1;
            break;
        case 'k':
            has_key = 1;
            strcpy(key_filename, optarg);
            break;
        case 'g':
            generate_key = 1;
            break;
        default:
            printf(help_msg);
            break;
        }
    }
    if (algorithm[0] == 0) {
        printf("no algorithm selected!\n");
        printf(help_msg);
        exit(0);
    }

    if (input_file[0] == 0 && !generate_key) {
        printf("no input_file!\n");
        printf(help_msg);
        exit(0);
    }

    if (output_file[0] == 0) {
        if (decrypt)
            sprintf(output_file, "%s.dec", input_file);
        else if (algo_num == SIGN)
            sprintf(output_file, "%s.sgn", input_file);
        else if (algo_num == SHA)
            sprintf(output_file, "%s.sha256", input_file);
        else
            sprintf(output_file, "%s.enc", input_file);
    }

    FILE *fd_key;
    if (key_filename[0] == 0) {
        sprintf(key_filename, default_key_filename);
    }
    if (decrypt) {
        if ((fd_key = fopen(key_filename, "rb")) == NULL) {
            printf("key not found!\n");
            fclose(fd_key);
            exit(0);
        }
        fclose(fd_key);
    }

    if (generate_key) {
        switch (algo_num)
        {
        case RSA:
            rsa_key_generation(&rsa_key);
            rsa_save_key(&rsa_key, key_filename);
            break;
        case AES:
            aes_key_generation(&aes_key);
            aes_save_key(&aes_key, key_filename);
            break;
        case DES:
            des_key_generation(&des_key);
            des_save_key(&des_key, key_filename);
            break;
        default:
            break;
        }
        exit(0);
    }

    if ((fd_in = fopen(input_file, "rb")) == NULL) {
        fprintf(stderr, "file not exist: %s", input_file);
        exit(0);
    }

    fd_out = fopen(output_file, "wb");

    fseek(fd_in, 0, SEEK_END);
    int size = ftell(fd_in);
    rewind(fd_in);
    if (algo_num != SHA)
        size = compute_actual_size(size);

    char *text_in = (char *)calloc(size, sizeof(char));
    char *text_out;
    if (algo_num == SHA) {
        text_out = (char *)calloc(SHA_BLOCK, sizeof(char));
    } else {
        text_out = (char *)calloc(size, sizeof(char));
    }

    fread(text_in, 1, size, fd_in);
    clock_t start, end;
    switch (algo_num)
    {
    case RSA:
        if (decrypt) {
            rsa_read_key(&rsa_key, key_filename);
            start = clock(); 
            rsa_decrypt(text_out, text_in, &rsa_key, size);
            end = clock();
        } else {
            if (!has_key) {
                rsa_key_generation(&rsa_key);
                rsa_save_key(&rsa_key, key_filename);
            } else {
                rsa_read_key(&rsa_key, key_filename);
            }
            start = clock(); 
            rsa_encrypt(text_in, text_out, &rsa_key, size);
            end = clock();
        }
        break;
    case DES:
    if (decrypt) {
            des_read_key(&des_key, key_filename);
            start = clock(); 
            des_decrypt(text_out, text_in, &des_key, size);
            end = clock();
        } else {
            if (!has_key) {
                des_key_generation(&des_key);
                des_save_key(&des_key, key_filename);
            } else {
                des_read_key(&des_key, key_filename);
            }
            start = clock(); 
            des_encrypt(text_in, text_out, &des_key, size);
            end = clock();
        }
        break;
    case SHA:
        start = clock(); 
        sha256_hash(text_out, text_in, size);
        end = clock();
        break;
    case SIGN:
        rsa_read_key(&rsa_key, key_filename);
        start = clock(); 
        rsa_decrypt(text_out, text_in, &rsa_key, size);
        end = clock();
        break;
    case AES:
        if (decrypt) {
            aes_read_key(&aes_key, key_filename);
            start = clock(); 
            aes_decrypt(text_out, text_in, &aes_key, size);
            end = clock();
        } else {
            if (!has_key) {
                aes_key_generation(&aes_key);
                aes_save_key(&aes_key, key_filename);
            } else {
                aes_read_key(&aes_key, key_filename);
            }
            start = clock(); 
            aes_encrypt(text_in, text_out, &aes_key, size);
            end = clock();
        }
        break;
    default:
        break;
    }
    clock_t duration = end - start;
    float time_total = (float)duration / CLOCKS_PER_SEC * 1000;
    float speed = size / time_total * 1000 / 1024 / 1024;
    int is_giga = 0;
    if (speed > 1024) {
        is_giga = 1;
        speed /= 1024;
    }
    float filesize = size;
    int file_unit = 0;
    while (filesize > 1024) {
        file_unit++;
        if (file_unit > UNIT_MB) break;
        filesize /= 1024;
    }
    printf(
        RED     "--------------------------\n" NONE
        RED "| " YELLOW  "encryption & signature" RED " |\n" NONE
        RED     "--------------------------\n" NONE
        RED "| " YELLOW  "algo\t"    RED " | " GREEN "%-10s"    YELLOW ""      RED "\t |\n" NONE
        RED "| " YELLOW  "is_dec"    RED " | " GREEN "%-10s"    YELLOW ""      RED "\t |\n" NONE
        RED "| " YELLOW  "input\t"   RED " | " GREEN "%-10s"    YELLOW ""      RED "\t |\n" NONE
        RED "| " YELLOW  "size\t"    RED " | " GREEN "%-10.2f"  YELLOW "%s"     RED "\t |\n" NONE
        RED "| " YELLOW  "output"    RED " | " GREEN "%-10s"    YELLOW ""      RED "\t |\n" NONE
        RED "| " YELLOW  "clocks"    RED " | " GREEN "%-10d"    YELLOW ""      RED "\t |\n" NONE
        RED "| " YELLOW  "time\t"    RED " | " GREEN "%-10.2f"  YELLOW "ms"    RED "\t |\n" NONE
        RED "| " YELLOW  "speed\t"   RED " | " GREEN "%-10.2f"  YELLOW "%s"  RED "|\n" NONE
        RED     "--------------------------\n" NONE
        , algorithm_set[algo_num]
        , decrypt ? "Yes" : "No"
        , input_file
        , filesize
        , size_unit[file_unit]
        , output_file
        , duration
        , time_total
        , speed
        , is_giga ? "GB/s" : "MB/s"
    );

    /* 结果写入文件 */
    if (algo_num == SHA) {
        fwrite(text_out, 1, SHA_BLOCK, fd_out);
    } else {
        if (!decrypt)
        fwrite(text_out, 1, size, fd_out);
        else {
            int pos = 0;
            for (int i = 0; i < size; i++) {
                if (text_out[i] != 0) pos = i;
            }
            fwrite(text_out, 1, pos + 1, fd_out);
        }
    }
    fclose(fd_in);
    fclose(fd_out);
    free(text_in);
    free(text_out);
    return 0;
}