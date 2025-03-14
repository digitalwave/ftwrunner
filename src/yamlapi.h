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
// yamlapi.h
// structures and functions for parsing yaml files
//


#ifndef YAMLAPI_H
#define YAMLAPI_H

#include <yaml.h>

#define MAXDEPTH 32

#define INDENT(d)                   \
    for (int i = 0; i < (d); i++) { \
        printf("  ");               \
    }

#ifndef ybool
typedef enum {
    FALSE = 0,
    TRUE  = 1
} ybool;
#endif

typedef unsigned int yaml_valtype_t;
typedef unsigned int yaml_listtype_t;

enum {
    YAML_VALTYPE_NOT_SET = 0,
    YAML_VALTYPE_INT     = 1,
    YAML_VALTYPE_STRING  = 2,
    YAML_VALTYPE_LIST    = 3,
    YAML_VALTYPE_DICT    = 4,
    YAML_VALTYPE_KEYVAL  = 5
};

enum {
    YAML_LISTTYPE_LIST = 1,
    YAML_LISTTYPE_DICT = 2,
};

enum {
    YAML_KEYSEARCH_FOUND     = 0,
    YAML_KEYSEARCH_NOT_DICT  = 1,
    YAML_KEYSEARCH_NOT_FOUND = 2
};

typedef struct yaml_item_list_t yaml_item_list;

typedef struct {
    char               *name;
    union {
        char           *sval;
        yaml_item_list *list;
    } value;
    yaml_valtype_t      type;
    yaml_scalar_style_t style;
} yaml_item;

typedef struct yaml_item_list_t {
    size_t            length;
    yaml_item       **list;
    yaml_listtype_t   type;
} yaml_item_list;

void       yaml_item_free (yaml_item * yval);
void       yaml_item_list_free (yaml_item_list * ylist);
yaml_item *parse_yaml (const char *file_name);
void       yaml_item_print (yaml_item * yval);
void       yaml_item_list_print (yaml_item_list * ylist);
int        yaml_item_has_key (const yaml_item * yval, const char *key);
int        yaml_item_get_value_by_key (yaml_item * yval, const char *key, yaml_item ** item);
ybool      yaml_item_value_as_bool (const yaml_item * yval);

extern char yaml_item_types[][50];
extern char yaml_list_types[][50];
extern char yaml_node_types[][50];

#endif
