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
// ftwtest.h
// structures and functions for ftw tests
//

#ifndef _FTWTEST_H
#define _FTWTEST_H

#include "yamlapi.h"

enum ftw_stage_data_type {
    FTW_STAGE_TYPE_STRING = 1,
    FTW_STAGE_TYPE_LIST   = 2
};

typedef struct ftw_header_t {
    char *name;
    char *value;
} ftw_header;

typedef struct ftw_input_t {
    char           *dest_addr;
    unsigned int    port;
    char           *method;
    ftw_header    **headers;
    unsigned int    headers_len;
    char           *protocol;
    char           *uri;
    char           *version;
    char           *data;
    int             save_cookie;
    int             stop_magic;
    char           *encoded_request;
    char           *raw_request;
    int             is_sent_header_content_type;
    char           *content_type;
    int             is_sent_header_content_length;
    //int             is_sent_header_accept;
} ftw_input;

typedef struct ftw_output_t {
    char  *status;
    char  *response_contains;
    char  *log_contains;
    char  *no_log_contains;
    char  *expect_error;
    char  *response;
    size_t response_len;
    int    response_code;
    char  *response_date;
} ftw_output;

typedef struct ftw_stage_item_t {
    ftw_input  *input;
    ftw_output *output;
} ftw_stage;

typedef struct {
    char          *test_title;
    char          *rule_id;
    char          *test_id;
    char          *desc;
    ftw_stage    **stages;
    unsigned int   stages_count;
} ftwtest;

typedef struct {
    ybool        enabled;
    ftwtest    **tests;
    unsigned int test_count;
} ftwtestcollection;

ftwtestcollection *ftwtestcollection_new(yaml_item * yroot, char * rule_id, char * test_id);
void               ftwtestcollection_free(ftwtestcollection * collection);

#endif