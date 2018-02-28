
#include <archive.h>
#include <archive_entry.h>
#include <ftw.h>
#include <libgen.h>
#include <limits.h>
#include <locale.h>

#include "hash.h"
#include "log/log.h"
#include "map/map.h"
#include "vec/vec.h"

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

void open_archive(struct archive *a, char *archive) {
    archive_write_set_format_filter_by_ext(a, archive);
    int status = archive_write_open_filename(a, archive);
    if (status != ARCHIVE_OK)
        log_error("%s", archive_error_string(a));
}

void copy_to_archive(const unsigned char *buffer, const int size, struct archive *a, char *archive_path) {
    struct archive_entry *a_entry = archive_entry_new();
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

void close_archive(struct archive *a) {
    int status = archive_write_close(a);
    if (status != ARCHIVE_OK)
        log_error("%s", archive_error_string(a));
    
    status = archive_write_free(a);
    if (status != ARCHIVE_OK)
        log_error("%s", archive_error_string(a));
}

void handle_to_folder(const unsigned char *buffer, const int size, char *output_folder, char *output_entry) {
    char output_path[PATH_MAX];
    strcpy(output_path, output_folder);
    strcat(output_path, kPathSeparator);
    strcat(output_path, output_entry);
    log_debug("Copying to file %s", output_path);
    copy_to_file(buffer, size, output_path);
}

void handle_to_archive(const unsigned char *buffer, const int size, struct archive *output_archive, char *output_entry) {
    log_debug("Copying to entry %s", output_entry);
    copy_to_archive(buffer, size, output_archive, output_entry);
}

int handle_archive(map_vec_str_t *db, int *found, const char *input_archive, char *output_folder, struct archive *output_archive) {
    
    struct archive *a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);
    int status = archive_read_open_filename(a, input_archive, 4096);
    if (status != ARCHIVE_OK) {
        log_error("%s", archive_error_string(a));
        return status;
    }
    
    int found_in_archive = 0;
    struct archive_entry *entry;
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char *entry_pathname = archive_entry_pathname(entry);
        int size = archive_entry_size(entry);
             
        unsigned char *buffer = malloc(size);
        archive_read_data(a, buffer, size);

        char *sha256 = calculate_sha256(buffer, size);
        char *sha1 = calculate_sha1(buffer, size);
        char *md5 = calculate_md5(buffer, size);
         
        log_trace("entry: %s", entry_pathname);
        log_trace("sha256: %s", sha256);
        log_trace("sha1: %s", sha1);
        log_trace("md5:  %s", md5);
        log_trace("size: %d", size);
        
        vec_str_t *output_entries = map_get(db, sha256);
        if (output_entries != NULL) {
            int i;
            char *output_entry;
            vec_foreach(output_entries, output_entry, i) {
                log_debug("Entry:   %s", entry_pathname);
                log_trace("Of size: %d", size);
                log_debug("Matches: %s", output_entry);
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
        free(sha1);
        free(md5);
    }
    log_debug("%d entries matched in %s", found_in_archive, input_archive);

    if (status != ARCHIVE_EOF)
        log_error("%s", archive_error_string(a));
    
    status = archive_read_free(a);
    if (status != ARCHIVE_OK)
        log_error("%s", archive_error_string(a));
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

    char *sha256 = calculate_sha256(buffer, size);
    char *sha1 = calculate_sha1(buffer, size);
    char *md5 = calculate_md5(buffer, size);
   
    log_trace("Size: %d", size);
    log_trace("sha256: %s", sha256);
    log_trace("sha1: %s", sha1);
    log_trace("md5: %s", md5);

    vec_str_t *output_entries = map_get(db, sha256);
    if (output_entries != NULL) {
        int i;
        char *output_entry;
        vec_foreach(output_entries, output_entry, i) {
            log_debug("File:    %s", file_in);
            log_trace("Of size: %d", size);
            log_debug("Matches: %s", output_entry);
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
    free(sha1);
    free(md5);
}

void print_vec_str_map(map_vec_str_t *m, const char *key_label, const char *entry_label, int level){
    int count = 0;
    const char *key;
    map_iter_t iter = map_iter(m);
    while ((key = map_next(m, &iter))) {
        vec_str_t *val = map_get(m, key);
        if (key_label)
            log(level, "%s: %s", key_label, key);
        int i;
        char *entry;
        vec_foreach(val, entry, i) {
            count++;
            if (entry_label)
                log(level, "%s: %s", entry_label, entry);
        }
    }
    log(level, "Number of entries in database: %d", count);
}

int create_db(const char *file, map_vec_str_t *db) {

    int entries = 0;
    FILE *f = fopen(file, "r");
    size_t len = 0;
    ssize_t read;

    if (!f) {
        log_error("Could not open %s", file);
        return 1;
    }

    while(1) {
        char *line = NULL;
        read = getline(&line, &len, f);
        if (read <= 0) break;

        entries++;
        char *sha256 = strtok(line, "\t");
        char *entry  = strtok(NULL, "\t");
        char *sha1   = strtok(NULL, "\t");
        char *md5    = strtok(NULL, "\t");
        char *crc    = strtok(NULL, "\t");
        
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

void print_usage() {
    printf("Usage: build_pack -d database_file -i input_directory [-o output_directory] [-a output_archive]\n");
    printf("flags:\n");
    printf("       -v  verbose output\n");
    printf("       -vv very verbose output\n");
    printf("       -q  quite output\n");
    printf("       -m  show missing\n");
}

int main(int argc, char**argv) {
    setlocale(LC_ALL, "");
    log_set_level(LOG_INFO);

    vec_str_t input_folders;
    vec_init(&input_folders);
    char *database = NULL;
    char *output_folder = NULL;
    char *output_archive = NULL;
    int missing = 0;

    int c;
    opterr = 0;

    while((c = getopt(argc, argv, "i:d:o:a:mvqh")) != -1) {
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
    if (database == NULL || input_folders.length == 0) {
        print_usage();
        exit(1);
    }

    log_trace("output_folder = %s", output_folder);
    log_trace("output_archive = %s", output_archive);

    map_vec_str_t db;
    map_init(&db);
    
    log_info("Using database %s", database);
    int entries_in_db = create_db(database, &db);
    if (log_level_is(LOG_TRACE))
        print_vec_str_map(&db, "sha256", "entry", LOG_TRACE);
    log_info("Number of entries in database: %d", entries_in_db);

    struct archive *output_a = NULL;
    if (output_archive) {
        output_a = archive_write_new();
        open_archive(output_a, output_archive);
    }

    int found = 0;
    int list(const char *file, const struct stat *status, int type) {
        if(type == FTW_F){
            log_trace("Processing file: %s", file);
            const char *file_ext = get_file_ext(file);
            
            if (strcmp(file_ext, ".zip") == 0 ||
                strcmp(file_ext, ".7z")  == 0 ||
                strcmp(file_ext, ".rar") == 0) {
                log_debug("Process %s as archive.", file);
                handle_archive(&db, &found, file, output_folder, output_a);
            } else {
                log_debug("Process %s as file.", file);
                handle_file(&db, &found, file, output_folder, output_a);
            }
        }
        return 0;
    }

    int i;
    char *input_folder;
    vec_foreach(&input_folders, input_folder, i) {
        log_debug("Processing input_folder: %s", input_folder);
        ftw(input_folder, list, 1);
    }
    
    if (output_a) {
        close_archive(output_a);
    }

    if (missing && log_level_is(LOG_INFO)) {
        print_vec_str_map(&db, "missing sha256", "missing entry", LOG_INFO);
    }

    int missed = entries_in_db - found;
    double coverage = 100 * (double) found / entries_in_db;
    log_info("Coverage: %d/%d {%.2f\%}", found, entries_in_db, coverage);
    if (missed > 0) {
        log_info("Missing: %d", missed);
    }

    vec_deinit(&input_folders); 
    map_deinit(&db);
}
