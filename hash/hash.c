#include "hash.h"

#define BUFFER_SIZE 4096

char* buffer_to_hex(const unsigned char *buffer, const int size) {
    char *hex = malloc((sizeof(char) * size * 2) + 1);
    int i = 0;
    for (i = 0; i < size; i++) {
        sprintf(hex + (i * 2), "%02x", buffer[i]); 
    }
    hex[(sizeof(char) * size * 2) + 1] = 0;
    return hex;
}

char* ulong_to_hex(ulong buffer) {
    char *hex = malloc((sizeof(ulong) * 2) + 1);
    sprintf(hex, "%08x", buffer);
    hex[(sizeof(ulong) * 2) + 1];
    return hex;
}

char* crc32_buffer(const unsigned char *buffer, const int size) {
    ulong crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, buffer, size);
    crc = crc & 0xffffffff;
    return ulong_to_hex(crc);
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

char* crc32_file(const char *file) {
    FILE* f = fopen(file, "rb");
    if (!f)
        log_error("Could not open %s", file);

    unsigned char buffer[BUFFER_SIZE];
    uLong crc = crc32(0L, Z_NULL, 0);
    int read = 0;
    while ((read = fread(buffer, 1, BUFFER_SIZE, f)) !=  0)
        crc = crc32(crc, buffer, read);
    crc = crc & 0xffffffff;

    fclose(f);
    return ulong_to_hex(crc);
}

char* md5_file(const char *file) {
    FILE* f = fopen(file, "rb");
    if (!f)
        log_error("Could not open %s", file);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char md5[MD5_DIGEST_LENGTH];
    MD5_CTX md;
    MD5_Init(&md);

    int read = 0;
    while ((read = fread(buffer, 1, BUFFER_SIZE, f)) !=  0)
        MD5_Update(&md, buffer, read);
    MD5_Final(md5, &md);

    fclose(f);
    return buffer_to_hex(md5, MD5_DIGEST_LENGTH);
}

char* sha1_file(const char *file) {
    FILE* f = fopen(file, "rb");
    if (!f)
        log_error("Could not open %s", file);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char sha1[SHA_DIGEST_LENGTH];
    SHA_CTX sha;
    SHA1_Init(&sha);
    
    int read = 0;
    while ((read = fread(buffer, 1, BUFFER_SIZE, f)) !=  0)
        SHA1_Update(&sha, buffer, read);
    SHA1_Final(sha1, &sha);
    
    fclose(f);
    return buffer_to_hex(sha1, SHA_DIGEST_LENGTH);
}

char* sha256_file(const char *file) {
    FILE* f = fopen(file, "rb");
    if (!f)
        log_error("Could not open %s", file);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha;
    SHA256_Init(&sha);

    int read = 0;
    while ((read = fread(buffer, 1, BUFFER_SIZE, f)) !=  0)
        SHA256_Update(&sha, buffer, read);
    SHA256_Final(sha256, &sha);
    
    fclose(f);
    return buffer_to_hex(sha256, SHA256_DIGEST_LENGTH);
}
