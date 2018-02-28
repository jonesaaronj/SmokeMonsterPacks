#ifndef HASH_H
#define HASH_H

#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <zlib.h>

#include "../log/log.h"

char* buffer_to_hex(const unsigned char *buffer, const int size);

char* crc32_buffer(const unsigned char *buffer, const int size);
char* md5_buffer(const unsigned char *buffer, const int size);
char* sha1_buffer(const unsigned char *buffer, const int size);
char* sha256_buffer(const unsigned char *buffer, const int size);

char* crc32_file(const char *file);
char* md5_file(const char *file);
char* sha1_file(const char *file);
char* sha256_file(const char *file);

#endif
