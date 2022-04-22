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
// engines.h
// structures and functions for the wrapper for WAF engines

#ifndef FTW_ENGINES_H
#define FTW_ENGINES_H

#include "../ftwtest.h"
#include "../../config.h"

enum {
    FTW_ENGINE_TYPE_DUMMY = 0,
    FTW_ENGINE_TYPE_MODSECURITY = 1,
    FTW_ENGINE_TYPE_CORAZA = 2
};

#define FTW_TEST_PASS 0
#define FTW_TEST_FAIL 1
#define FTW_TEST_DISA 2
#define FTW_TEST_SKIP 4

#define GREEN 0
#define RED 1
#define END 2

typedef struct ftw_engine_t ftw_engine;

typedef struct ftw_runtest_t {
    
} ftw_runtest;

typedef void * (*ftw_engine_init_fn)();
typedef void * (*ftw_engine_create_rules_set_fn)(void * engine_instance, char * main_rule_uri, const char ** error);
typedef void * (*ftw_engine_cleanup_fn)(void * engine_instance);
typedef int    (*ftw_engine_runtest_fn)(ftw_engine * engine, char * title, ftw_stage *stage, int debug);

typedef struct ftw_engine_t {
    int                            engine_type;
    ftw_engine_init_fn             engine_init;
    void                         * engine_instance;
    void                         * rules;
    ftw_engine_create_rules_set_fn engine_create_rules_set;
    ftw_engine_cleanup_fn          engine_cleanup;
    ftw_engine_runtest_fn          runtest;
    int                            cnt_passed;
    int                            cnt_passedwl;
    int                            cnt_failed;
    int                            cnt_failedwl;
    int                            cnt_skipped;
    int                            cnt_disabled;
    int                            cnt_total;
    char                        ** failed_test_list;
    char                        ** failed_wl_test_list;
    char                        ** passed_wl_test_list;
} ftw_engine;

ftw_engine * ftw_engine_init(int enginetype, char * main_rule_uri, const char ** error);
void         ftw_engine_free(ftw_engine * engine);
void         ftw_engine_show_result(ftw_engine * engine);

void         fancy_print(char * test_title, int code, const char * msg, int modifier);

int          qsearch(char **array, int size, char *key);
int          engine_runtest(ftw_engine * engine, int enabled, int listed, char * title, ftw_stage *stage, int debug);

void         logCbInit();
void         logCbCleanup();
void         logCbText(void *data, const void *msg);
void         logCbDump();
void         logCbClearLog();
char       * logContains(char * pattern, int negate);

#endif