
#include <archive.h>
#include <archive_entry.h>
#include <ctype.h>
#include <ftw.h>
#include <libgen.h>
#include <limits.h>
#include <locale.h>

#include "hash/hash.h"
#include "log/log.h"
#include "map/map.h"
#include "vec/vec.h"

#include "file_entry.h"

#ifdef _WIN32
#else
    #include "mkdir_p/mkdir_p.h"
#endif

const char *kPathSeparator =
#ifdef _WIN32
    "\\";
#else
    "/";
#endif

typedef vec_t(File_entry*) vec_file_entry_t;
typedef map_t(vec_file_entry_t) map_vec_file_entry_t;

char* strlwr(char* str){
  unsigned char* p = (unsigned char*)str;
  while (*p) {
     *p = tolower((unsigned char)*p);
      p++;
  }
  return str;
}

int copy_to_file(const unsigned char* buffer, const int size, char* path) {
    char* tmp = strdup(path);
    char* out_dir = dirname(tmp);
    mkdir_p(out_dir);
    FILE* f = fopen(path, "w");
    fwrite(buffer, 1, size, f);
    fclose(f);
}

const char* get_file_ext(const char* filename) {
    const char* dot = strrchr(filename, '.');
    if(!dot || dot == filename) return "";
    return dot;
}

void open_archive(struct archive* a, char* archive) {
    archive_write_set_format_filter_by_ext(a, archive);
    int status = archive_write_open_filename(a, archive);
    if (status != ARCHIVE_OK)
        log_error("%s", archive_error_string(a));
}

void copy_to_archive(const unsigned char* buffer, const int size, struct archive* a, char* archive_path) {
    struct archive_entry* a_entry = archive_entry_new();
    archive_entry_set_pathname(a_entry, archive_path);
    archive_entry_set_size(a_entry, size);
    archive_entry_set_filetype(a_entry, AE_IFREG);
    archive_entry_set_perm(a_entry, 0644);
    //archive_entry_set_mtime(a_entry, 123456789, 0);
    int status = archive_write_header(a, a_entry);
    if (status == ARCHIVE_OK) {
        archive_write_data(a, buffer, size);
    } else {
        log_error("%s", archive_error_string(a));
    }
    
    //archive_write_finish_entry(a);
    archive_entry_free(a_entry);
}

void close_archive(struct archive* a) {
    int status = archive_write_close(a);
    if (status != ARCHIVE_OK)
        log_error("%s", archive_error_string(a));
    
    status = archive_write_free(a);
    if (status != ARCHIVE_OK)
        log_error("%s", archive_error_string(a));
}

void handle_to_folder(const unsigned char* buffer, const int size, char* output_folder, char* output_entry) {
    char output_path[PATH_MAX];
    strcpy(output_path, output_folder);
    strcat(output_path, kPathSeparator);
    strcat(output_path, output_entry);
    log_debug("Copying to file %s", output_path);
    copy_to_file(buffer, size, output_path);
}

void handle_to_archive(const unsigned char* buffer, const int size, struct archive* output_archive, char* output_path) {
    log_debug("Copying to entry %s", output_path);
    copy_to_archive(buffer, size, output_archive, output_path);
}

int handle_archive(map_vec_file_entry_t* db, int* found, const char* input_archive, char* output_folder, struct archive* output_archive) {
    struct archive* a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);
    int status = archive_read_open_filename(a, input_archive, 4096);
    if (status != ARCHIVE_OK) {
        log_error("%s", archive_error_string(a));
        return status;
    }
    
    int found_in_archive = 0;
    struct archive_entry* entry;
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char* entry_pathname = archive_entry_pathname(entry);
        int size = archive_entry_size(entry);
             
        unsigned char* buffer = malloc(size);
        archive_read_data(a, buffer, size);

        Hash* hash = get_buffer_hash(buffer, size);

        log_trace("entry: %s", entry_pathname);
        log_trace("size: %d", size);
        log_trace("sha256: %s", hash->sha256);
        log_trace("sha1: %s", hash->sha1);
        log_trace("md5:  %s", hash->md5);
        log_trace("crc32: %s", hash->crc32);
        
        vec_file_entry_t* file_entries = map_get(db, hash->sha256);
        if (file_entries != NULL) {
            int i;
            File_entry* file_entry;
            vec_foreach(file_entries, file_entry, i) {
                log_debug("Entry:   %s", entry_pathname);
                log_trace("Of size: %d", size);
                log_debug("Matches: %s", file_entry->path);
                (*found)++;
                found_in_archive++;
                if (output_folder) {
                    handle_to_folder(buffer, size, output_folder, (char*) file_entry->path);
                }
                if (output_archive) {
                    handle_to_archive(buffer, size, output_archive, (char*) file_entry->path);
                }
            }
            free(file_entry);
            map_remove(db, hash->sha256);
        }
        free(buffer);
    }
    log_debug("%d entries matched in %s", found_in_archive, input_archive);

    if (status != ARCHIVE_EOF)
        log_error("%s", archive_error_string(a));
    
    status = archive_read_free(a);
    if (status != ARCHIVE_OK)
        log_error("%s", archive_error_string(a));
    return status;
}

int handle_file(map_vec_file_entry_t* db, int* found, const char* file_in, char* output_folder, struct archive* output_archive) {

    FILE* f = fopen(file_in, "rb");
    fseek(f, 0, SEEK_END);
    int size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char* buffer = malloc(size);
    fread(buffer, size, 1, f);
    fclose(f);

    Hash* hash = get_buffer_hash(buffer, size);
   
    log_trace("size: %d", size);
    log_trace("sha256: %s", hash->sha256);
    log_trace("sha1: %s", hash->sha1);
    log_trace("md5: %s", hash->md5);
    log_trace("crc32: %s", hash->crc32);

    vec_file_entry_t* file_entries = map_get(db, hash->sha256);
    if (file_entries != NULL) {
        int i;
        File_entry* file_entry;
        vec_foreach(file_entries, file_entry, i) {
            log_debug("File:    %s", file_in);
            log_trace("Of size: %d", size);
            log_debug("Matches: %s", file_entry->path);
            (*found)++;
            if (output_folder) {
                handle_to_folder(buffer, size, output_folder, (char*) file_entry->path);
            }
            if (output_archive) {
                handle_to_archive(buffer, size, output_archive, (char*) file_entry->path);
            }
        }
        free(file_entry);
        map_remove(db, hash->sha256);
    }

    free(buffer);
}

void handle_create_db_from_archive(FILE* db_file, const char* archive) {
    struct archive* a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);
    int status = archive_read_open_filename(a, archive, 4096);
    if (status != ARCHIVE_OK) {
        log_error("%s", archive_error_string(a));
    }
    
    struct archive_entry* entry;
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char* entry_pathname = archive_entry_pathname(entry);
        int size = archive_entry_size(entry);
             
        unsigned char* buffer = malloc(size);
        archive_read_data(a, buffer, size);

        Hash* hash = get_buffer_hash(buffer, size);

        log_trace("entry: %s", entry_pathname);
        log_trace("size: %d", size);
        log_trace("sha256: %s", hash->sha256);
        log_trace("sha1: %s", hash->sha1);
        log_trace("md5:  %s", hash->md5);
        log_trace("crc32: %s", hash->crc32);

        File_entry* file_entry = create_file_entry(entry_pathname, hash);
        write_entry_to_file(db_file, file_entry);
        free_file_entry(file_entry);
        free(buffer);
    }

    if (status != ARCHIVE_EOF)
        log_error("%s", archive_error_string(a));
    
    status = archive_read_free(a);
    if (status != ARCHIVE_OK)
        log_error("%s", archive_error_string(a));
}

void handle_create_db_from_folder(FILE* db_file, const char* file, char* folder) {

    log_trace("folder: %s", folder);
    log_trace("file: %s", file);
  
    int i = 0; 
    const char* entry = file; 
    for(; i < strlen(folder); i++)
        if (folder[i] == file[i])
            entry++;
    if (file[i] == '/')
        entry++;
    log_trace("entry: %s", entry);

    File_entry* file_entry = create_file_entry_from_file(entry, file);
    log_trace("%s", file_entry->hash->sha256);
    log_trace("%s", file_entry->hash->sha1);
    log_trace("%s", file_entry->hash->md5);
    log_trace("%s", file_entry->hash->crc32);
    
    write_entry_to_file(db_file, file_entry);

    free_file_entry(file_entry);
}

int create_db(const char* file, map_vec_file_entry_t *db) {

    int entries = 0;
    FILE* f = fopen(file, "r");
    size_t len = 0;
    ssize_t read;

    if (!f) {
        log_error("Could not open %s", file);
        return 1;
    }

    while(1) {
        char* line = NULL;
        read = getline(&line, &len, f);
        if (read <= 0) break;

        entries++;
        char* sha256 = strlwr(strtok(line, "\t"));
        char* path   = strtok(NULL, "\t");
        char* sha1   = strlwr(strtok(NULL, "\t"));
        char* md5    = strlwr(strtok(NULL, "\t"));
        char* crc32  = strlwr(strtok(NULL, "\t"));

        Hash* hash = create_hash(sha256, sha1, md5, crc32);
        File_entry* file_entry = create_file_entry(path, hash);
        
        vec_file_entry_t* val = map_get(db, sha256);
        if (val == NULL ) {
            vec_file_entry_t v;
            vec_init(&v);
            vec_push(&v, file_entry);
            map_set(db, sha256, v);
        } else {
            vec_push(val, file_entry);
        }
    }
    fclose(f);

    return entries;
}

void print_usage() {
    printf("Usage: \n");
    printf("       smp -d database_file -i input_directory [-o output_directory] [-a output_archive]\n\n");
    printf("       smp -D database_file (-P parse_directory | -A parse_archive)\n\n");
    printf("build pack:\n");
    printf("       -d database_file\n");
    printf("            set location of the database file\n\n");
    printf("       -i input_directory\n");
    printf("            set an input directory\n\n");
    printf("       -o output_directory\n");
    printf("            set an output directory\n\n");
    printf("       -a output_archive\n");
    printf("            set an output archive\n\n");
    printf("       -m missing_file\n");
    printf("            set a missing file\n\n");
    printf("build db:\n");
    printf("       -D database_file\n");
    printf("            set location of the database file\n\n");
    printf("       -P parse_directory\n");
    printf("            create a database file from the provided directory\n\n");
    printf("       -A parse_archive\n");
    printf("            create a database file from the provided archive\n\n");
    printf("logging:\n");
    printf("       -l log_file\n");
    printf("            set log file\n\n");
    printf("flags:\n");
    printf("       -v  verbose output\n");
    printf("       -vv very verbose output\n");
    printf("       -q  quite output\n");
}

int main(int argc, char** argv) {

    setlocale(LC_ALL, "");
    log_set_level(LOG_INFO);

    vec_str_t input_folders;
    vec_init(&input_folders);
    char* database = NULL;
    char* parse_folder = NULL;
    char* parse_archive = NULL;
    char* output_folder = NULL;
    char* output_archive = NULL;
    char* log = NULL;
    char* missing = NULL;

    int c;
    opterr = 0;

    while((c = getopt(argc, argv, "i:d:D:P:A:o:a:l:m:vqh")) != -1) {
        switch(c) {
            case 'i':
                vec_push(&input_folders, optarg);
                break;
            case 'd':
            case 'D':
                database = optarg;
                break;
            case 'P':
                parse_folder = optarg;
                break;
            case 'A':
                parse_archive = optarg;
                break;
            case 'o':
                output_folder = optarg;
                break;
            case 'a':
                output_archive = optarg;
                break;
            case 'l':
                log = optarg;
                break;
            case 'm':
                missing = optarg;
                break;
            case 'v':
                if (log_level_is(LOG_DEBUG))
                    log_set_level(LOG_TRACE);
                else
                    log_set_level(LOG_DEBUG);
                break;
            case 'q':
                log_set_quiet(1);
                break;
            case 'h':
                print_usage();
                exit(1);
                break;
            case '?':
                break;
            default:
                break;
        }
    }
    if (database == NULL || (parse_archive == NULL && parse_folder == NULL && input_folders.length == 0)) {
        print_usage();
        exit(1);
    }

    FILE* log_file = NULL;
    if (log) {
        log_file = fopen(log, "w");
        log_set_fp(log_file);
    }

    log_trace("parse_folder = %s", parse_folder);
    log_trace("parse_archive = %s", parse_archive);
    log_trace("output_folder = %s", output_folder);
    log_trace("output_archive = %s", output_archive);

    FILE* db_file;
    map_vec_file_entry_t db;
    map_init(&db); 
    int entries_in_db = 0;

    if (database != NULL && (parse_folder != NULL || parse_archive != NULL)) {
        log_info("Creating database file %s", database);
        db_file = fopen(database, "w");

    } else if (database != NULL && input_folders.length > 0) {
        log_info("Using database %s", database);
        entries_in_db = create_db(database, &db);
        log_info("Number of entries in database: %d", entries_in_db);
    }

    struct archive* output_a = NULL;
    if (output_archive) {
        output_a = archive_write_new();
        open_archive(output_a, output_archive);
    }

    int found = 0;
    int list(const char* file, const struct stat* status, int type) {
        if(type == FTW_F){
            log_trace("Processing file: %s", file);
            const char *file_ext = get_file_ext(file);
   
            if (parse_folder != NULL) {
                //log_debug("Process %s as archive.", file);
                handle_create_db_from_folder(db_file, file, parse_folder);
            } else if (strcasecmp(file_ext, ".zip") == 0 ||
                strcasecmp(file_ext, ".7z")  == 0 ||
                strcasecmp(file_ext, ".rar") == 0) {
                log_debug("Process %s as archive.", file);
                handle_archive(&db, &found, file, output_folder, output_a);
            } else {
                log_debug("Process %s as file.", file);
                handle_file(&db, &found, file, output_folder, output_a);
            }
        }
        return 0;
    }

    if (parse_archive != NULL) {
        handle_create_db_from_archive(db_file, parse_archive);
    } else if (parse_folder != NULL) {
        ftw(parse_folder, list, 1);
    } else if (input_folders.length > 0) {
        int i = 0;
        char* input_folder;
        vec_foreach(&input_folders, input_folder, i) {
            log_debug("Processing input_folder: %s", input_folder);
            ftw(input_folder, list, 1);
        }
    }

    if (output_a) {
        close_archive(output_a);
    }

    if (input_folders.length > 0) {
        int missed = entries_in_db - found;
        double coverage = 100 * (double) found / entries_in_db;
        log_info("Coverage: %d/%d {%.2f\%}", found, entries_in_db, coverage);
        if (missed > 0) {
            log_info("Missing: %d", missed);
        }

        FILE* missing_file = NULL;
        if (missing) {
            log_trace("missing = %s", missing);
            missing_file = fopen(missing, "w");
            
            int i = 0;
            const char* key;
            map_iter_t iter = map_iter(&db);
            while ((key = map_next(&db, &iter))) {
                vec_file_entry_t* val = map_get(&db, key);
                File_entry* file_entry;
                vec_foreach(val, file_entry, i) {
                     write_entry_to_file(missing_file, file_entry);
                }
            }
            fclose(missing_file);
        }
        vec_deinit(&input_folders);
    }

    map_deinit(&db);

    if (log_file) {
        fclose(log_file);
    }
    if (db_file) {
        fclose(db_file);
    }
}
