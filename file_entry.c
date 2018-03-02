
#include "file_entry.h"

File_entry* create_file_entry(const char* path, Hash* hash) {

    File_entry* new_file_entry = (File_entry*) malloc(sizeof(File_entry));

    if (new_file_entry) {
        new_file_entry->path = path;
        new_file_entry->hash = hash;
    }
    return new_file_entry;
}

File_entry* create_file_entry_from_file(const char* path, const char* file) {
    Hash* hash = get_file_hash(file);
    log_trace("sha256: %s", hash->sha256);
    log_trace("sha1: %s", hash->sha1);
    log_trace("md5: %s", hash->md5);
    log_trace("crc32: %s", hash->crc32);
    
    //return create_file_entry(path, hash);
    File_entry* file_entry = create_file_entry(path, hash);
    log_trace("path: %s", file_entry->path);
    log_trace("sha256: %s", file_entry->hash->sha256);
    log_trace("sha1: %s", file_entry->hash->sha1);
    log_trace("md5: %s", file_entry->hash->md5);
    log_trace("crc32: %s", file_entry->hash->crc32);

    return file_entry;
}

void free_file_entry(File_entry* file_entry) {
    free_hash(file_entry->hash);
    free(file_entry);
}

void write_entry_to_file(FILE* file, File_entry* file_entry) {
    fprintf(file, "%s\t%s\t%s\t%s\t%s\n", \
        file_entry->hash->sha256, \
        file_entry->path, \
        file_entry->hash->sha1, \
        file_entry->hash->md5, \
        file_entry->hash->crc32);
}

