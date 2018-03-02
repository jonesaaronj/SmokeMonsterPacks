#ifndef FILE_ENTRY_H
#define FILE_ENTRY_H

#include <stdio.h>
#include <stdlib.h>

#include "hash/hash.h"

typedef struct {
    const char* path;
    Hash* hash;
} File_entry;

File_entry* create_file_entry(const char* path, Hash* hash);
File_entry* create_file_entry_from_file(const char* path, const char* file);

void free_file_entry(File_entry* file_entry);

void write_entry_to_file(FILE* file, File_entry* file_entry);

#endif
