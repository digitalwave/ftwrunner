/*
 * This file is part of the ftwrunner distribution (https://github.com/digitalwave/ftwrunner).
 * Copyright (c) 2022 digitalwave and Ervin Hegedüs.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

//
// yamtest.c
// a test file for yamlapi.h
//

#include <stdio.h>
#include <string.h>

#include "yamlapi.h"

int main(int argc, char** argv) {
    yaml_item *yroot = NULL, *ymeta = NULL;
    yaml_item *yenabled = NULL;


    if (argc < 2) {
        printf("Usage: %s file1.yaml ...\n", argv[0]);
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        yroot = parse_yaml(argv[1]);

        if (yroot == NULL) {
            printf("Error parsing file %s\n", argv[1]);
            return 1;
        }
        else {
            if (yaml_item_get_value_by_key(yroot, (const char *)"meta", &ymeta) != YAML_KEYSEARCH_FOUND) {
                printf("Key not exists: meta\n");
            }
            else {
                if (yaml_item_get_value_by_key(ymeta, (const char *)"enabled", &yenabled) != YAML_KEYSEARCH_FOUND) {
                    printf("Key not exists: enabled\n");
                }
                else {
                    printf("enabled: %s, %d\n", yenabled->value.sval, yaml_item_value_as_bool(yenabled));
                }
            }
            yaml_item_print(yroot);
            yaml_item_free(yroot);
        }
    }

    return 0;
}
