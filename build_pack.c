

#include <ftw.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/sha.h>
#include <archive.h>
#include <archive_entry.h>

#include "vec/vec.h"
#include "map/map.h"
#include "mkdir_p/mkdir_p.h"

const char *kPathSeparator =
#ifdef _WIN32
    "\\";
#else
    "/";
#endif

typedef map_t(vec_str_t) map_vec_str_t;

int copy_to_file(const unsigned char *buffer, const int size, char *file) {
    char *tmp = strdup(file);
    char *out_dir = dirname(tmp);
    mkdir_p(out_dir);
    FILE *f = fopen(file, "w");
    fwrite(buffer, 1, size, f);
    fclose(f);
}

const char *get_file_ext(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if(!dot || dot == filename) return "";
    return dot;
}

void copy_to_archive_old(const unsigned char *buffer, const int size, char *archive, char *archive_path) {
    //const char *file_ext = get_file_ext(archive);
    //printf("Setting output to %s\n", file_ext);
    
    struct archive *a = archive_write_new();
    archive_write_set_format_filter_by_ext(a, archive);
    int status = archive_write_open_filename(a, archive);
    if (status != ARCHIVE_OK) {
        fprintf(stderr, "ERROR: %s\n", archive_error_string(a));
        return;
    }
    
    struct archive_entry *a_entry = archive_entry_new();
    archive_entry_set_pathname(a_entry, archive_path);
    archive_entry_set_size(a_entry, size);
    archive_entry_set_filetype(a_entry, AE_IFREG);
    archive_entry_set_perm(a_entry, 0644);
    status = archive_write_header(a, a_entry);
    if (status != ARCHIVE_OK) {
        fprintf(stderr, "ERROR: %s\n", archive_error_string(a));
    }
    
    archive_write_data(a, buffer, size);
    archive_write_finish_entry(a);
    
    archive_entry_free(a_entry);
    //status = archive_free(a);
    
    status = archive_write_close(a);
    if (status != ARCHIVE_OK)
        fprintf(stderr, "ERROR: %s\n", archive_error_string(a));
    
    status = archive_write_free(a);
    if (status != ARCHIVE_OK)
        fprintf(stderr, "ERROR: %s\n", archive_error_string(a));
}

void open_archive(struct archive *a, char *archive) {
    archive_write_set_format_filter_by_ext(a, archive);
    int status = archive_write_open_filename(a, archive);
    if (status != ARCHIVE_OK)
        fprintf(stderr, "ERROR: %s\n", archive_error_string(a));
}

void copy_to_archive(const unsigned char *buffer, const int size, struct archive *a, char *archive_path) {
    struct archive_entry *a_entry = archive_entry_new();
    archive_entry_set_pathname(a_entry, archive_path);
    archive_entry_set_size(a_entry, size);
    archive_entry_set_filetype(a_entry, AE_IFREG);
    archive_entry_set_perm(a_entry, 0644);
    //archive_entry_set_mtime(ae, 123456789, 0);
    int status = archive_write_header(a, a_entry);
    if (status == ARCHIVE_OK) {
        archive_write_data(a, buffer, size);
    } else {
        fprintf(stderr, "ERROR: %s\n", archive_error_string(a));
    }
    
    //archive_write_finish_entry(a);
    archive_entry_free(a_entry);
}

void close_archive(struct archive *a) {
    int status = archive_write_close(a);
    if (status != ARCHIVE_OK)
        fprintf(stderr, "ERROR: %s\n", archive_error_string(a));
    
    status = archive_write_free(a);
    if (status != ARCHIVE_OK)
        fprintf(stderr, "ERROR: %s\n", archive_error_string(a));
}

void sha256_hash_string(const unsigned char *hash, char *output) {
    int i = 0;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = 0;
}

void calculate_sha256(const unsigned char *buffer, const int size, char output[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, buffer, size);
    SHA256_Final(hash, &sha256);
    sha256_hash_string(hash, output);
}

void handle_to_folder(const unsigned char *buffer, const int size, char *output_folder, char *output_entry) {
    char output_path[PATH_MAX];
    strcpy(output_path, output_folder);
    strcat(output_path, kPathSeparator);
    strcat(output_path, output_entry);
    //printf("Copying to file %s\n\n", output_path);
    copy_to_file(buffer, size, output_path);
}

void handle_to_archive(const unsigned char *buffer, const int size, struct archive *output_archive, char *output_entry) {
    //printf("Copying to entry %s\n\n", output_entry);
    copy_to_archive(buffer, size, output_archive, output_entry);
}

int handle_archive(map_vec_str_t *db, int *found, const char *input_archive, char *output_folder, struct archive *output_archive) {
    
    struct archive *a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);
    int status = archive_read_open_filename(a, input_archive, 4096);
    if (status != ARCHIVE_OK) {
        fprintf(stderr, "ERROR: %s\n", archive_error_string(a));
        return status;
    }
    
    int found_in_archive = 0;
    struct archive_entry *entry;
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char *entry_pathname = archive_entry_pathname(entry);
        int size = archive_entry_size(entry);
             
        unsigned char *buffer = malloc(size);
        archive_read_data(a, buffer, size);

        char *sha256 = malloc(65);
        calculate_sha256(buffer, size, sha256);
         
        //printf("entry: %s\n", entry_pathname);
        //printf("sha256: %s\n", sha256);
        //printf("size: %d\n", size);
        
        vec_str_t *output_entries = map_get(db, sha256);
        if (output_entries != NULL) {
            int i;
            char *output_entry;
            vec_foreach(output_entries, output_entry, i) {
                //printf("Entry:   %s\n", entry_pathname);
                //printf("Of size: %d\n", size);
                //printf("Matches: %s\n", output_entry);
                (*found)++;
                found_in_archive++;
                if (output_folder) {
                    handle_to_folder(buffer, size, output_folder, output_entry);
                }
                if (output_archive) {
                    handle_to_archive(buffer, size, output_archive, output_entry);
                }
            }
            map_remove(db, sha256);
        }
        free(buffer);
        free(sha256);
    }
    //printf("%d entries matched in %s\n", found_in_archive, input_archive);

    if (status != ARCHIVE_EOF)
        fprintf(stderr, "ERROR: %s\n", archive_error_string(a));
    
    status = archive_read_free(a);
    if (status != ARCHIVE_OK)
        fprintf(stderr, "ERROR: %s\n", archive_error_string(a));
    return status;
}

int handle_file(map_vec_str_t *db, int *found, const char *file_in, char *output_folder, struct archive *output_archive) {

    FILE *f = fopen(file_in, "rb");
    fseek(f, 0, SEEK_END);
    int size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *buffer = malloc(size);
    fread(buffer, size, 1, f);
    fclose(f);

    char *sha256 = malloc(65);
    calculate_sha256(buffer, size, sha256);
   
    //printf("Size: %d\n", size);
    //printf("SHA256: %s\n", sha256);

    vec_str_t *output_entries = map_get(db, sha256);
    if (output_entries != NULL) {
        int i;
        char *output_entry;
        vec_foreach(output_entries, output_entry, i) {
            //printf("File:    %s\n", file_in);
            //printf("Of size: %d\n", size);
            //printf("Matches: %s\n", output_entry);
            (*found)++;
            if (output_folder) {
                handle_to_folder(buffer, size, output_folder, output_entry);
            }
            if (output_archive) {
                handle_to_archive(buffer, size, output_archive, output_entry);
            }
        }
        map_remove(db, sha256);
    }

    free(buffer);
    free(sha256);
}

void print_vec_str_map(map_vec_str_t *m, const char *key_label, const char *entry_label){
    int count = 0;
    const char *key;
    map_iter_t iter = map_iter(m);
    while ((key = map_next(m, &iter))) {
        vec_str_t *val = map_get(m, key);
        if (key_label)
            printf("%s: %s\n", key_label, key);
        int i;
        char *entry;
        vec_foreach(val, entry, i) {
            count++;
            if (entry_label)
                printf("%s: %s\n", entry_label, entry);
        }
    }
    printf("Number of entries in database: %d\n", count);
}

int create_db(const char *file, map_vec_str_t *db) {

    int entries = 0;
    FILE *f = fopen(file, "r");
    size_t len = 0;
    ssize_t read;

    if (!f) {
        fprintf(stderr, "Could not open %s\n", file);
        return 1;
    }

    while(1) {
        char *line = NULL;
        read = getline(&line, &len, f);
        if (read <= 0) break;

        entries++;
        char *sha256 = strtok(line, "\t");
        char *entry = strtok(NULL, "\t");
        char *hash1 = strtok(NULL, "\t");
        char *hash2 = strtok(NULL, "\t");
        char *hash3 = strtok(NULL, "\t");
        
        vec_str_t *val = map_get(db, sha256);
        if (val == NULL ) {
            vec_str_t v;
            vec_init(&v);
            vec_push(&v, entry);
            map_set(db, sha256, v);
        } else {
            vec_push(val, entry);
        }
    }
    fclose(f);

    return entries;
}

int main(int argc, char**argv) {
    setlocale(LC_ALL, "");

    vec_str_t input_folders;
    vec_init(&input_folders);
    char *database = NULL;
    char *output_folder = NULL;
    char *output_archive = NULL;
    int missing = 0;
    int verbose = 0;

    int c;
    opterr=0;

    while((c = getopt(argc, argv, "i:d:o:a:mv")) != -1) {
        switch(c) {
            case 'i':
                vec_push(&input_folders, optarg);
                break;
            case 'd':
                database = optarg;
                break;
            case 'o':
                output_folder = optarg;
                break;
            case 'a':
                output_archive = optarg;
                break;
            case 'm':
                missing = 1;
                break;
            case 'v':
                verbose = 1;
                break;
            case '?':
                break;
            default:
                abort();
        }
    }

    //printf("output_folder = %s\n", output_folder);
    //printf("output_archive = %s\n", output_archive);
    //printf("missing = %d\n", missing);
    //printf("verbose = %d\n", verbose);

    map_vec_str_t db;
    map_init(&db);
    
    printf("Using database %s\n", database);
    int entries_in_db = create_db(database, &db);
    //print_vec_str_map(&db, "sha256", "entry");
    printf("Number of entries in database: %d\n", entries_in_db);

    struct archive *output_a = NULL;
    if (output_archive) {
        output_a = archive_write_new();
        open_archive(output_a, output_archive);
    }

    int found = 0;
    int list(const char *file, const struct stat *status, int type) {
        if(type == FTW_F){
            //printf("Processing file: %s\n", file);
            const char *file_ext = get_file_ext(file);
            
            if (0 == strcmp(file_ext, ".zip") ||
                0 == strcmp(file_ext, ".7z")  ||
                0 == strcmp(file_ext, ".rar")) {
                //printf("Handle %s as archive\n", file);
                handle_archive(&db, &found, file, output_folder, output_a);
            } else {
                //printf("Handle %s as file\n", file);
                handle_file(&db, &found, file, output_folder, output_a);
            }
        }
        return 0;
    }

    int i;
    char *input_folder;
    vec_foreach(&input_folders, input_folder, i) {
        //printf("Processing input_folder: %s\n", input_folder);
        ftw(input_folder, list, 1);
    }
    
    if (output_a) {
        close_archive(output_a);
    }

    if (missing) {
        print_vec_str_map(&db, "missing sha256", "missing entry");
    }

    double coverage = 100 * (double) found / entries_in_db;
    printf("Coverage: %d/%d {%.2f\%}\n", found, entries_in_db, coverage);
   
    vec_deinit(&input_folders); 
    map_deinit(&db);
}
