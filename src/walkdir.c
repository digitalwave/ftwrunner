#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>

int walkcmp(const void *p1, const void *p2) {
    return strcmp(*(const char **) p1, *(const char **) p2);
}

void walkdir(char *rootdir, char ***files, unsigned *files_count) {
    DIR *dir;
    const struct dirent *entry;
    size_t rootlen = strlen(rootdir);

    if (!(dir = opendir(rootdir))) {
        fprintf(stderr, "Directory not found: %s\n", rootdir);
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        char *name = entry->d_name;
        if (entry->d_type == DT_DIR) {
            if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
                if (rootlen + strlen(name) + 2 > 1024) {
                    fprintf(stderr, "Path too long: %s/%s\n", rootdir, name);
                    exit(EXIT_FAILURE);
                } else {
                    rootdir[rootlen] = '/';
                    strcpy(rootdir + rootlen + 1, name);
                    walkdir(rootdir, files, files_count);
                    rootdir[rootlen] = '\0';
                }
            }
        } else {
            if (strlen(name) > 6 && strcmp(name + strlen(name) - 5, ".yaml") == 0) {
                (*files) = realloc((*files), sizeof(char *) * ((*files_count) + 1));
                if ((*files) == NULL) {
                    fprintf(stderr, "Out of memory\n");
                    exit(EXIT_FAILURE);
                }
                else {
                    char * tname = malloc(strlen(name) + rootlen + 2);
                    if (tname == NULL) {
                        fprintf(stderr, "Out of memory\n");
                        exit(EXIT_FAILURE);
                    }
                    sprintf(tname, "%s/%s", rootdir, name);
                    (*files)[(*files_count)] = strdup(tname);
                    free(tname);
                    (*files_count)++;
                }
            }
        }
    }
    closedir(dir);
}
