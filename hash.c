#include "hash.h"

char* buffer_to_hex(const unsigned char *buffer, const int size) {
    char *hex = malloc((sizeof(char) * size * 2) + 1);
    int i = 0;
    for (i = 0; i < size; i++) {
        sprintf(hex + (i * 2), "%02x", buffer[i]); 
    }
    hex[(size * 2) + 1] = 0;
    return hex;
}

char* md5_buffer(const unsigned char *buffer, const int size) {
    unsigned char md5[MD5_DIGEST_LENGTH];
    MD5(buffer, size, md5);
    return buffer_to_hex(md5, MD5_DIGEST_LENGTH);
}

char* sha1_buffer(const unsigned char *buffer, const int size) {
    unsigned char sha1[SHA_DIGEST_LENGTH];
    SHA1(buffer, size, sha1);
    return buffer_to_hex(sha1, SHA_DIGEST_LENGTH);
}

char* sha256_buffer(const unsigned char *buffer, const int size) {
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    SHA256(buffer, size, sha256);
    return buffer_to_hex(sha256, SHA256_DIGEST_LENGTH);
}

