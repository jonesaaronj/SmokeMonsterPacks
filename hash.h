#ifndef HASH_H
#define HASH_H

#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

char* buffer_to_hex(const unsigned char *buffer, int size);
char* calculate_md5(const unsigned char *buffer, const int size);
char* calculate_sha1(const unsigned char *buffer, const int size);
char* calculate_sha256(const unsigned char *buffer, const int size);

#endif
