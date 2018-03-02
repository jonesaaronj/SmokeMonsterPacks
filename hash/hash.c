#include "hash.h"

#define BUFFER_SIZE 4096

Hash* create_hash(char* sha256, char* sha1, char* md5, char* crc32) {
    Hash* hash = (Hash*) malloc(sizeof(Hash));

    if (hash) {
        hash->sha256 = sha256;
        hash->sha1   = sha1;
        hash->md5    = md5;
        hash->crc32  = crc32;
    }
    return hash;
}

void free_hash(Hash* hash) {
    free(hash->sha256);
    free(hash->sha1);
    free(hash->md5);
    free(hash->crc32);
    free(hash);
}

char* buffer_to_hex(const unsigned char* buffer, const int size) {
    char* hex = malloc((sizeof(char) * size * 2) + 1);
    int i = 0;
    for (i = 0; i < size; i++) {
        sprintf(hex + (i * 2), "%02x", buffer[i]); 
    }
    hex[(sizeof(char) * size * 2) + 1] = 0;
    return hex;
}

char* ulong_to_hex(ulong buffer) {
    char* hex = malloc((sizeof(ulong) * 2) + 1);
    sprintf(hex, "%08x", buffer);
    hex[(sizeof(ulong) * 2) + 1];
    return hex;
}

char* get_buffer_crc32(const unsigned char* buffer, const int size) {
    ulong crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, buffer, size);
    crc = crc & 0xffffffff;
    return ulong_to_hex(crc);
}

char* get_buffer_md5(const unsigned char* buffer, const int size) {
    unsigned char md5[MD5_DIGEST_LENGTH];
    MD5(buffer, size, md5);
    return buffer_to_hex(md5, MD5_DIGEST_LENGTH);
}

char* get_buffer_sha1(const unsigned char* buffer, const int size) {
    unsigned char sha1[SHA_DIGEST_LENGTH];
    SHA1(buffer, size, sha1);
    return buffer_to_hex(sha1, SHA_DIGEST_LENGTH);
}

char* get_buffer_sha256(const unsigned char* buffer, const int size) {
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    SHA256(buffer, size, sha256);
    return buffer_to_hex(sha256, SHA256_DIGEST_LENGTH);
}

Hash* get_buffer_hash(const unsigned char* buffer, const int size) {
    char* sha256 = get_buffer_sha256(buffer, size);
    char* sha1   = get_buffer_sha1(buffer, size);
    char* md5    = get_buffer_md5(buffer, size);
    char* crc32  = get_buffer_crc32(buffer, size);
    return create_hash(sha256, sha1, md5, crc32);
}

char* get_file_crc32(const char* file) {
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

char* get_file_md5(const char* file) {
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

char* get_file_sha1(const char* file) {
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

char* get_file_sha256(const char* file) {
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

Hash *get_file_hash(const char* file) {
    FILE* f = fopen(file, "rb");
    if (!f)
        log_error("Could not open %s", file);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    unsigned char sha1[SHA_DIGEST_LENGTH];
    unsigned char md5[MD5_DIGEST_LENGTH];
    uLong crc = crc32(0L, Z_NULL, 0);
    
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA_CTX sha1_ctx;
    SHA1_Init(&sha1_ctx);
    MD5_CTX md5_ctx;
    MD5_Init(&md5_ctx);

    int read = 0;
    while ((read = fread(buffer, 1, BUFFER_SIZE, f)) !=  0) {
        SHA256_Update(&sha256_ctx, buffer, read);
        SHA1_Update(&sha1_ctx, buffer, read);
        MD5_Update(&md5_ctx, buffer, read);
        crc = crc32(crc, buffer, read);
    }

    SHA256_Final(sha256, &sha256_ctx);
    SHA1_Final(sha1, &sha1_ctx);
    MD5_Final(md5, &md5_ctx);
    crc = crc & 0xffffffff;
    
    fclose(f);

    return create_hash(buffer_to_hex(sha256, SHA256_DIGEST_LENGTH), \
        buffer_to_hex(sha1, SHA_DIGEST_LENGTH), \
        buffer_to_hex(md5, MD5_DIGEST_LENGTH), \
        ulong_to_hex(crc));
}
