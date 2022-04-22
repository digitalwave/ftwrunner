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
// yamlapi.c
// functions for parsing yaml files
//

#include "yamlapi.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char yaml_item_types[][50] = {
    "YAML_VALTYPE_NOT_SET",
    "YAML_VALTYPE_INT",
    "YAML_VALTYPE_STRING",
    "YAML_VALTYPE_LIST",
    "YAML_VALTYPE_DICT",
    "YAML_VALTYPE_KEYVAL"
};


char yaml_list_types[][50] = {
    "YAML_LISTTYPE_NONE",
    "YAML_LISTTYPE_LIST",
    "YAML_LISTTYPE_DICT"
};

char yaml_node_types[][50] = {
    "",
    "YAML_NO_NODE",
    "YAML_SCALAR_NODE",
    "YAML_SEQUENCE_NODE",
    "YAML_MAPPING_NODE"
};

static yaml_item *itemstack[MAXDEPTH];
static unsigned int itemstackptr = 0;
static yaml_item *curritem = NULL;

static int print_level = 0;

// CREATE FUNCTIONS
//
// Create item
yaml_item * yaml_item_create (yaml_valtype_t type) {

    if (itemstackptr >= MAXDEPTH) {
        return NULL;
    }
    yaml_item *item = calloc (sizeof (yaml_item), 1);
    item->type = type;
    item->style = -1;
    itemstack[itemstackptr++] = item;
    return item;
}

// Create list
yaml_item_list * yaml_item_list_init (yaml_listtype_t type) {
    yaml_item_list *ylist = calloc (sizeof (yaml_item_list), 1);
    ylist->list = calloc (sizeof (yaml_item *), 1);
    ylist->type = type;
    ylist->length = 0;
    return ylist;
}

// UTIL FUNCTIONS
//
// Add item to list
void yaml_item_list_add_item (yaml_item * yval, yaml_item * value) {
    yaml_item **tlist;
    tlist = realloc (yval->value.list->list, (yval->value.list->length + 1) * sizeof (yaml_item *));
    tlist[yval->value.list->length++] = value;
    unsigned int length = yval->value.list->length;
    yval->value.list->list = tlist;
    yval->value.list->length = length;
}

// FREE FUNCTIONS
//
// Free item
void yaml_item_free (yaml_item * yval) {
    if (yval->name != NULL) {
        free (yval->name);
    }
    switch (yval->type) {
        case YAML_VALTYPE_STRING:
            free (yval->value.sval);
            break;
        case YAML_VALTYPE_LIST:
        case YAML_VALTYPE_DICT:
            yaml_item_list_free (yval->value.list);
            break;
        default:
            break;
    }
    free (yval);
}

// Free list
void yaml_item_list_free (yaml_item_list * ylist) {
    if (ylist != NULL) {
        if (ylist->type == YAML_LISTTYPE_LIST){
            for (int i = 0; i < ylist->length; i++){
                yaml_item_free (ylist->list[i]);
            }
        }
        else if (ylist->type == YAML_LISTTYPE_DICT) {
            for (int i = 0; i < ylist->length; i++) {
                yaml_item_free (ylist->list[i]);
            }
        }
        free (ylist->list);
        free (ylist);
    }
}

// DUMP FUNCTIONS
//
// Print item
void yaml_item_print (yaml_item * yval) {
    if (yval->name != NULL) {
        INDENT (print_level);
        printf ("key: '%s', ", yval->name);
    }
    switch (yval->type) {
        case YAML_VALTYPE_STRING:
            INDENT (print_level);
            printf ("value: '%s'\n", yval->value.sval);
            break;
        case YAML_VALTYPE_LIST:
        case YAML_VALTYPE_DICT:
            yaml_item_list_print (yval->value.list);
            break;
        default:
            INDENT (print_level);
            printf ("type: %d\n", yval->type);
            printf ("value: EMPTY\n");
    }
}

// Print item list
void yaml_item_list_print (yaml_item_list * ylist) {
    if (ylist != NULL) {
        if (ylist->type == YAML_LISTTYPE_LIST) {
            INDENT (print_level);
            printf ("[\n");
            print_level++;
            for (int i = 0; i < ylist->length; i++) {
                yaml_item_print (ylist->list[i]);
            }
            print_level--;
            INDENT (print_level);
            printf ("]\n");
        }
        else if (ylist->type == YAML_LISTTYPE_DICT) {
            INDENT (print_level);
            printf ("{\n");
            print_level++;
            for (int i = 0; i < ylist->length; i++) {
                yaml_item_print (ylist->list[i]);
            }
            print_level--;
            INDENT (print_level);
            printf ("}\n");
        }
    }
}

// KEY FUNCTIONS
//
// Check key exists
int yaml_item_has_key (yaml_item * yval, char *key) {
    if (yval->type != YAML_VALTYPE_DICT) {
        return YAML_KEYSEARCH_NOT_DICT;
    }
    for (int i = 0; i < yval->value.list->length; i++) {
        if (strcmp (yval->value.list->list[i]->name, key) == 0) {
            return YAML_KEYSEARCH_FOUND;
        }
    }
    return YAML_KEYSEARCH_NOT_FOUND;
}

// Get item by key
int yaml_item_get_value_by_key (yaml_item * yval, const char *key, yaml_item ** item) {
    if (yval->type != YAML_VALTYPE_DICT) {
        return YAML_KEYSEARCH_NOT_DICT;
    }
    for (int i = 0; i < yval->value.list->length; i++) {
        if (strcmp (yval->value.list->list[i]->name, key) == 0) {
            *item = yval->value.list->list[i];
            return YAML_KEYSEARCH_FOUND;
        }
    }
    return YAML_KEYSEARCH_NOT_FOUND;
}

// OTHER FUNCTIONS
//
// Cast value as bool if possible
ybool yaml_item_value_as_bool (yaml_item * yval) {

    char *t[] = {"y", "Y", "yes", "Yes", "YES", "true", "True", "TRUE", "on", "On", "ON", NULL};
    char *f[] = {"n", "N", "no", "No", "NO", "false", "False", "FALSE", "off", "Off", "OFF", NULL};
    char **ptr;

    if (yval->type != YAML_VALTYPE_STRING) {
        return -1;
    }
    if (yval->style == YAML_PLAIN_SCALAR_STYLE) {
        for (ptr = t; *ptr; ptr++) {
            if (strcmp(yval->value.sval, *ptr) == 0) {
                return TRUE;
            }
        }
        for (ptr = f; *ptr; ptr++) {
            if (strcmp(yval->value.sval, *ptr) == 0) {
                return FALSE;
            }
        }
    }
    return -1;
}

// main loop, called recursively
void parse_yaml_node (yaml_document_t * document, yaml_node_t * node) {
    yaml_node_t *next_node;

    switch (node->type) {
        case YAML_NO_NODE:
            break;
        case YAML_SCALAR_NODE:
            curritem = yaml_item_create (YAML_VALTYPE_STRING);
            curritem->value.sval = strdup ((const char *) node->data.scalar.value);
            curritem->style = node->data.scalar.style;
            break;
        case YAML_SEQUENCE_NODE:
            // if the list is a value of a parent item (dict or other list)
            if (curritem != NULL && curritem->type == YAML_VALTYPE_NOT_SET) {
                curritem->type = YAML_VALTYPE_LIST;
            }
            else {
                curritem = yaml_item_create (YAML_VALTYPE_LIST);
            }
            curritem->value.list = yaml_item_list_init (YAML_LISTTYPE_LIST);
            {
                yaml_node_item_t *i_node;
                for (i_node = node->data.sequence.items.start;
                    i_node < node->data.sequence.items.top; i_node++) {
                    next_node = yaml_document_get_node (document, *i_node);
                    if (next_node) {
                        parse_yaml_node (document, next_node);
                    }
                }
            }
            break;
        case YAML_MAPPING_NODE:
            // if the map is a value of a parent item (dict or other list)
            if (curritem != NULL && curritem->type == YAML_VALTYPE_NOT_SET) {
                curritem->type = YAML_VALTYPE_DICT;
            }
            else {
                curritem = yaml_item_create (YAML_VALTYPE_DICT);
            }
            curritem->value.list = yaml_item_list_init (YAML_LISTTYPE_DICT);
            {
                yaml_node_pair_t *i_node_p;
                for (i_node_p = node->data.mapping.pairs.start;
                    i_node_p < node->data.mapping.pairs.top; i_node_p++) {
                    next_node = yaml_document_get_node (document, i_node_p->key);
                    curritem = yaml_item_create (YAML_VALTYPE_NOT_SET);
                    if (next_node) {
                        // set the key here
                        switch (next_node->type) {
                            case YAML_SCALAR_NODE:
                                curritem->name = strdup ((const char *) next_node->data.scalar.value);
                                break;
                            case YAML_SEQUENCE_NODE:
                            case YAML_MAPPING_NODE:
                                printf ("Unsupported key type: %s\n", yaml_item_types[next_node->type]);
                                break;
                            default:
                                curritem->name = strdup ("");
                        }
                    }
                    else {
                        fputs ("Couldn't find next node\n", stderr);
                        exit (1);
                    }
                    next_node = yaml_document_get_node (document, i_node_p->value);
                    if (next_node) {
                        // set the value here
                        switch (next_node->type) {
                            case YAML_SCALAR_NODE:
                                curritem->type = YAML_VALTYPE_STRING;
                                curritem->value.sval = strdup ((const char *) next_node->data.scalar.value);
                                curritem->style = next_node->data.scalar.style;
                                if (itemstackptr > 1) {
                                    yaml_item *parent = itemstack[itemstackptr - 2];
                                    switch (parent->type) {
                                        case YAML_VALTYPE_LIST:
                                        case YAML_VALTYPE_DICT:
                                            yaml_item_list_add_item (parent, curritem);
                                            break;
                                        default:
                                            printf ("Error: syntax error\n");
                                            break;
                                    }
                                    curritem = parent;
                                    itemstackptr--;
                                }
                                break;
                            case YAML_SEQUENCE_NODE:
                            case YAML_MAPPING_NODE:
                                parse_yaml_node (document, next_node);
                                break;
                            default:
                                curritem->name = strdup ("");
                                break;
                        }
                    }
                    else {
                        exit (1);
                    }
                }
            }
            break;
        default:
            fputs ("Unknown node type\n", stderr);
            exit (1);
    }

    // implicit END NODE
    // push current item to parent item
    if (itemstackptr > 1) {
        yaml_item *parent = itemstack[itemstackptr - 2];
        if (parent->type == YAML_VALTYPE_LIST || parent->type == YAML_VALTYPE_DICT) {
            yaml_item_list_add_item (parent, curritem);
        }
        else {
            printf("Error: syntax error\n");
        }
        curritem = parent;
        itemstackptr--;
    }
}

void parse_yaml_document (yaml_document_t * document) {
    parse_yaml_node (document, yaml_document_get_root_node (document));
}

yaml_item * parse_yaml (const char *file_name) {

    FILE *fh = fopen (file_name, "r");
    yaml_parser_t parser;
    yaml_document_t document;

    // Parser init, file open
    if (!yaml_parser_initialize (&parser)) {
        fputs ("Failed to initialize parser!\n", stderr);
    }

    itemstackptr = 0;
    curritem = NULL;

    // Handle the file
    if (fh == NULL) {
        fprintf(stderr, "Failed to open file: %s\n", file_name);
        return NULL;
    }

    yaml_parser_set_input_file (&parser, fh);

    int yaml_done = 0;
    while (!yaml_done) {
        if (!yaml_parser_load (&parser, &document)) {
            fprintf (stderr, "Failed to load document in %s\n", file_name);
            break;
        }

        yaml_done = (!yaml_document_get_root_node (&document));

        if (!yaml_done) {
            parse_yaml_document (&document);
        }

        yaml_document_delete (&document);
    }

    // Cleanup resources
    yaml_parser_delete (&parser);
    fclose (fh);

    return curritem;
}
