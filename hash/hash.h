#ifndef HASH_H
#define HASH_H

#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <zlib.h>

#include "../log/log.h"

typedef struct {
    char* sha256;
    char* sha1;
    char* md5;
    char* crc32;
} Hash;


Hash* create_hash(char* sha256, char* sha1, char* md5, char* crc32);
void free_hash(Hash* hash);

char* buffer_to_hex(const unsigned char* buffer, const int size);

char* get_buffer_crc32(const unsigned char* buffer, const int size);
char* get_buffer_md5(const unsigned char* buffer, const int size);
char* get_buffer_sha1(const unsigned char* buffer, const int size);
char* get_buffer_sha256(const unsigned char* buffer, const int size);
Hash* get_buffer_hash(const unsigned char* buffer, const int size);

char* get_file_crc32(const char* file);
char* get_file_md5(const char* file);
char* get_file_sha1(const char* file);
char* get_file_sha256(const char* file);
Hash* get_file_hash(const char* file);

#endif
