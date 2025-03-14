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
// engines.c
// structures and functions for the wrapper for WAF engines

#include "engines.h"
#include <string.h>
#include <pthread.h>
#include <ctype.h>
#include <stdlib.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#ifdef HAVE_MODSECURITY
#include <modsecurity/modsecurity.h>
#ifdef MSC_USE_RULES_SET
#include <modsecurity/rules_set.h>
#else
#include <modsecurity/rules.h>
#endif
#endif

#ifdef HAVE_LIBCORAZA
#include <coraza/core.h>
#include <coraza/utils.h>
#endif

#include "ftwcoraza/ftwcoraza.h"
#include "ftwmodsecurity/ftwmodsecurity.h"
#include "ftwdummy/ftwdummy.h"


char **loglines = NULL;
static int loglines_count = 0;
static int loglines_count_allocated = 0;
static pthread_mutex_t lock;

/*
 * Logger
 */

// init the log structure
void logCbInit() {
    loglines_count = 0;
}

// clear the logs
void logCbClearLog() {
    for (int i = 0; i < loglines_count; i++) {
        free(loglines[i]);
        loglines[i] = NULL;
    }
    loglines_count = 0;
}

// cleanup the whole log structure
void logCbCleanup() {
    if (loglines != NULL) {
        for (int i = 0; i < loglines_count; i++) {
            free(loglines[i]);
        }
        free(loglines);
    }
}

// add a line to the log
// this can be added to the engine as callback
void logCbText(void *data, const void *msgorig) {
    if (msgorig == NULL) {
        return;
    }
    char * msg = strdup(msgorig);
    if (msg == NULL) {
        perror("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }
    pthread_mutex_lock(&lock);
    if (loglines_count == loglines_count_allocated) {
        loglines_count_allocated++;

        char ** loglines_tmp = realloc(loglines, sizeof(char*) * (loglines_count_allocated));
        if (loglines_tmp == NULL) {
            perror("Failed to allocate memory");
            for (size_t j = 0; j < loglines_count_allocated; j++) free(loglines[j]);
            free(loglines);
            exit(EXIT_FAILURE);
        }
        loglines = loglines_tmp;
        for(size_t j = loglines_count; j < loglines_count_allocated; j++) {

            loglines[j] = NULL;
        }
    }

    size_t msglen = strlen(msg);
    loglines[loglines_count] = calloc(1, msglen+1);
    strncpy(loglines[loglines_count], msg, msglen);
    free(msg);
    loglines_count++;
    pthread_mutex_unlock(&lock);

    return;
}

// dump the log to stdout
void logCbDump() {
    for (int i = 0; i < loglines_count; i++) {
        printf("LOG: %s\n", loglines[i]);
    }
}

// search a patternin a log line
// negate reverse the result and colorize with red the result
// elsewhise colorize with green
char * logContains(char * pattern, int negate) {

    pcre2_code          * re           = NULL;
    pcre2_match_data    * match_data;
    pcre2_match_context * mcontext;
    pcre2_jit_stack     * jit_stack    = NULL;
    int                   errornumber;
    PCRE2_SIZE            erroroffset;
    char                * tstr         = NULL;
    const PCRE2_SIZE    * ovector;
    int                   rc;

    const char  * format_reset  = "\033[0m";
    const char  * format_bgreen = "\033[1m\033[32m";
    const char  * format_bred   = "\033[1m\033[31m";

    const char  * format = (negate) ? format_bred : format_bgreen;

    re = pcre2_compile(
        (unsigned char*)pattern,
        PCRE2_ZERO_TERMINATED, //PCRE2_DOTALL | PCRE2_DOLLAR_ENDONLY,
        0,
        &errornumber,
        &erroroffset,
        NULL
    );
    if (re == NULL) {
        return NULL;
    }

    rc = pcre2_jit_compile(re, PCRE2_JIT_COMPLETE);
    if (rc != 0) {
        puts("JIT compilation failed");
    }
    int jit_enabled;
    pcre2_config(PCRE2_CONFIG_JIT, &jit_enabled);
    if (jit_enabled == 1) {
        int rcj = pcre2_jit_compile(re, PCRE2_JIT_COMPLETE);

        if (rcj == 0) {
            jit_stack = pcre2_jit_stack_create(1, 1024 * 1024, NULL);
            if (jit_stack != NULL) {
                mcontext = pcre2_match_context_create(NULL);
                if (mcontext != NULL) {
                    pcre2_jit_stack_assign(mcontext, NULL, jit_stack);
                }
                else {
                    puts("Couldn't allocate PCRE2 match context");
                }
            }
            else {
                puts("Couldn't allocate PCRE2 JIT stack");
            }
        }
        else {
            if (rcj == PCRE2_ERROR_JIT_BADOPTION) {
                puts("Regex does not support JIT");
            }
            else if (rcj == PCRE2_ERROR_NOMEMORY) {
                puts("Not enough memory to create JIT stack");
            }
            else {
                puts("An error occurred while JIT stack created");
            }
        }
    }

    match_data = pcre2_match_data_create_from_pattern(re, NULL);
    if (match_data == NULL) {
        if (re != NULL) {
            pcre2_code_free(re);
        }
        re = NULL;
    }

    for (int i = 0; i < loglines_count; i++) {
        size_t subject_len  = strlen(loglines[i]);
        // this hack needs because of the pcre2_match()
        // contains an "invalid read of size 16" Valgrind error
        char * subject = calloc(sizeof(char *), subject_len + 16);
        if (subject == NULL) {
            perror("Failed to allocate memory");
            exit(EXIT_FAILURE);
        }
        strncpy(subject, loglines[i], subject_len);
        rc = pcre2_match(
            re,
            (unsigned char *)subject,
            subject_len,
            0,
            0,
            match_data,
            mcontext
        );

        if (rc > 0) {
            ovector = pcre2_get_ovector_pointer(match_data);
            tstr = calloc(1, sizeof(char) * strlen(subject) + strlen(format_bgreen) + strlen(format_reset) + 1);
            if (tstr == NULL) {
                perror("Failed to allocate memory");
                exit(EXIT_FAILURE);
            }
            if (ovector[0] > 0) {
                strncat(tstr, subject, ovector[0]);
                strcat(tstr, format);
            }
            else {
                strcat(tstr, format);
            }
            // colorized substring
            strcat(tstr, pattern);
            strcat(tstr, format_reset);
            if (ovector[1] < strlen(subject)) {
                strncat(tstr, subject + ovector[1], strlen(subject) - ovector[1]);
            }
            i = loglines_count;
        }
        free(subject);
    }

    if (re != NULL) {
        pcre2_code_free(re);
    }
    if (match_data != NULL) {
        pcre2_match_data_free(match_data);
    }
    if (mcontext != NULL) {
        pcre2_match_context_free(mcontext);
    }
    if (jit_stack != NULL) {
        pcre2_jit_stack_free(jit_stack);
    }

    return tstr;
}

/*
 * End Logger
 */

// init the engine
// this is a wrapper for the engine init function
ftw_engine * ftw_engine_init(int enginetype, char * main_rule_uri, const char ** error) {
    ftw_engine * engine = malloc(sizeof(ftw_engine));

    if (engine == NULL) {
        perror("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }

    engine->engine_type  = enginetype;
    engine->cnt_passed   = 0;
    engine->cnt_passedwl = 0;
    engine->cnt_failed   = 0;
    engine->cnt_failedwl = 0;
    engine->cnt_skipped  = 0;
    engine->cnt_total    = 0;
    engine->cnt_disabled = 0;

    logCbInit();

    engine->failed_test_list = malloc(sizeof(char*));
    engine->failed_wl_test_list = malloc(sizeof(char*));
    engine->passed_wl_test_list = malloc(sizeof(char*));

    switch(enginetype) {
        case FTW_ENGINE_TYPE_DUMMY:
            engine->engine_instance = (void*)1;
            engine->rules           = (void*)1;
            engine->runtest         = ftw_engine_runtest_dummy;
            break;

#ifdef HAVE_MODSECURITY
        case FTW_ENGINE_TYPE_MODSECURITY:
            engine->engine_instance = (void*)ftw_engine_init_msc();
            engine->rules           = (void*)ftw_engine_create_rules_set_msc(engine->engine_instance, main_rule_uri, error);
            engine->runtest         = ftw_engine_runtest_msc;
            break;
#endif

#ifdef HAVE_LIBCORAZA
        case FTW_ENGINE_TYPE_CORAZA:
            engine->engine_instance = (void*)ftw_engine_init_coraza();
            engine->rules           = (void*)ftw_engine_create_rules_set_coraza(engine->engine_instance, main_rule_uri, error);
            engine->runtest         = ftw_engine_runtest_coraza;
            break;
#endif

    }
    return engine;
}

// cleanup the engine
void ftw_engine_free(ftw_engine * engine) {
    if (engine != NULL) {

        if (engine->failed_test_list != NULL) {
            for (int i = 0; i < engine->cnt_failed; i++) {
                free(engine->failed_test_list[i]);
            }
            free(engine->failed_test_list);
        }
        if (engine->failed_wl_test_list != NULL) {
            for (int i = 0; i < engine->cnt_failedwl; i++) {
                free(engine->failed_wl_test_list[i]);
            }
            free(engine->failed_wl_test_list);
        }
        if (engine->passed_wl_test_list != NULL) {
            for (int i = 0; i < engine->cnt_passedwl; i++) {
                free(engine->passed_wl_test_list[i]);
            }
            free(engine->passed_wl_test_list);
        }

        switch(engine->engine_type) {
            case FTW_ENGINE_TYPE_DUMMY:
                free(engine);
                break;
#ifdef HAVE_MODSECURITY
            case FTW_ENGINE_TYPE_MODSECURITY:
                if (engine->rules != NULL) {
#ifdef MSC_USE_RULES_SET
                    msc_rules_cleanup((RulesSet *)engine->rules);
#else
                    msc_rules_cleanup((Rules *)engine->rules);
#endif
                }
                if (engine->engine_instance != NULL) {
                    msc_cleanup((ModSecurity *)engine->engine_instance);
                }
                free(engine);
                break;
#endif
#ifdef HAVE_LIBCORAZA
            case FTW_ENGINE_TYPE_CORAZA:
                if (engine->engine_instance != NULL) {
                    coraza_free_waf((coraza_waf_t *)engine->engine_instance);
                }
                free(engine);
                break;
#endif
            default:
                free(engine);
                break;
        }
    }
    logCbCleanup();
}

// show the cummulated test results
void ftw_engine_show_result(const ftw_engine * engine) {
    printf("\n");
    printf("SUMMARY\n");
    printf("===============================\n");
    printf("ENGINE:                 %s\n", engine->engine_type == FTW_ENGINE_TYPE_DUMMY ? "Dummy" : "ModSecurity");
    printf("PASSED:                 %d\n", engine->cnt_passed);
    printf("FAILED:                 %d\n", engine->cnt_failed);
    printf("FAILED (whitelisted):   %d\n", engine->cnt_failedwl);
    printf("SKIPPED:                %d\n", engine->cnt_skipped);
    printf("DISABLED:               %d\n", engine->cnt_disabled);
    printf("===============================\n");
    printf("TOTAL:                  %d\n", engine->cnt_total);
    printf("===============================\n");
    if (engine->cnt_failed > 0) {
        printf("FAILED TESTS:\n");
        for (int i = 0; i < engine->cnt_failed; i++) {
            printf("%s", engine->failed_test_list[i]);
            if (i < engine->cnt_failed - 1) {
                printf(", ");
            }
        }
        printf("\n===============================\n");
    }
    if (engine->cnt_failedwl > 0) {
        printf("FAILED WHITELISTED TESTS:\n");
        for (int i = 0; i < engine->cnt_failedwl; i++) {
            printf("%s", engine->failed_wl_test_list[i]);
            if (i < engine->cnt_failedwl - 1) {
                printf(", ");
            }
        }
        printf("\n===============================\n");
    }
    if (engine->cnt_passedwl > 0) {
        printf("PASSED WHITELISTED TESTS:\n");
        for (int i = 0; i < engine->cnt_passedwl; i++) {
            printf("%s", engine->passed_wl_test_list[i]);
            if (i < engine->cnt_passedwl - 1) {
                printf(", ");
            }
        }
        printf("\n===============================\n");
    }
}

// make a fancy output for any tests
static void fancy_print(const char * test_title, int code, const char * msg, int modifier) {
    printf("%s: ", test_title);
    switch(code) {
        case FTW_TEST_PASS:
            if (modifier == 0) {
                printf("\033[92mPASSED\033[0m");
            }
            else {
                printf("\033[92mPASSED\033[32m - WHITELISTED\033[0m");
            }
            break;
        case FTW_TEST_FAIL:
            if (modifier == 0) {
                printf("\033[91mFAILED\033[0m");
            }
            else {
                printf("\033[31mFAILED - WHITELISTED\033[0m");
            }
            break;
        case FTW_TEST_DISA:
            printf("\033[90mDISABLED\033[0m");
            break;
        case FTW_TEST_SKIP:
            printf("\033[94mSKIPPED\033[0m");
            break;
    }
    if (strlen(msg) > 0) {
        printf(" %s", msg);
    }
    printf("\n");
}

// a quick search function
// returns the index of the first occurence of needle in haystack
int qsearch(char **array, int size, const char *key) {
    int first = 0;
    int last = size - 1;

    while (first <= last) {
        int middle = (first + last) / 2;
        int cmp = strcmp(array[middle], key);
        if (cmp < 0) {
            first = middle + 1;
        } else if (cmp > 0) {
            last = middle - 1;
        } else {
            return middle;
        }
    }
    return -1;
}

// run a test with an engine
int engine_runtest(ftw_engine * engine, int enabled, int listed, char * title, ftw_stage *stage, int debug, int verbose) {

    const ftw_input  * input  = stage->input;
    const ftw_output * output = stage->output;

    if (enabled == 0) {
        fancy_print(title, FTW_TEST_DISA, "", 0);
        engine->cnt_disabled++;
    }
    else {
        if (input->encoded_request != NULL && strlen(input->encoded_request) > 0) {
            fancy_print(title, FTW_TEST_SKIP, "'encoded_request' not implemented yet", listed);
            engine->cnt_skipped++;
        }
        else if (input->raw_request != NULL && (input->raw_request) > 0) {
            fancy_print(title, FTW_TEST_SKIP, "'raw_request' not implemented yet", listed);
            engine->cnt_skipped++;
        }
        else if (output->expect_error != 0) {
            fancy_print(title, FTW_TEST_SKIP, "'expect_error' is HTTP server specific - test skipped", listed);
            engine->cnt_skipped++;
        }
        else if (output->status != 0) {
            fancy_print(title, FTW_TEST_SKIP, "'status' is HTTP server specific - test skipped", listed);
            engine->cnt_skipped++;
        }
        else if (input->version != NULL &&
                (strlen(input->version) == 0 ||
                strncmp(input->version, "HTTP", 4) != 0)) {
            fancy_print(title, FTW_TEST_SKIP, "Only HTTP protocol allowed", listed);
            engine->cnt_skipped++;
        }
        else if (
                    (output->log_contains == NULL          || strlen(output->log_contains) == 0) &&
                    (output->no_log_contains == NULL       || strlen(output->no_log_contains) == 0) &&
                    ((output->log->expect_ids_len == 0)    && (output->log->no_expect_ids_len == 0)) &&
                    ((output->log->match_regex == NULL)    || (strlen(output->log->match_regex) == 0)) &&
                    ((output->log->no_match_regex == NULL) || (strlen(output->log->no_match_regex) == 0))
                ) {
            fancy_print(title, FTW_TEST_SKIP, "No valid test output", listed);
            engine->cnt_skipped++;
        }
        else {
            // if test (collection) is not disabled and shouldn't be skipped
            int res = engine->runtest(engine, title, stage, debug, verbose);
            fancy_print(title, res, "", listed);
            if (res == FTW_TEST_PASS) {
                engine->cnt_passed++;
                if (listed == 1) {
                    engine->cnt_passedwl++;
                    engine->passed_wl_test_list = realloc(engine->passed_wl_test_list, sizeof(char *) * engine->cnt_passedwl);
                    engine->passed_wl_test_list[engine->cnt_passedwl - 1] = strdup(title);
                }
            }
            else if (res == FTW_TEST_FAIL && listed == 0) {
                engine->failed_test_list = realloc(engine->failed_test_list, sizeof(char *) * (engine->cnt_failed + 1));
                engine->failed_test_list[engine->cnt_failed] = strdup(title);
                engine->cnt_failed++;
            }
            else if (res == FTW_TEST_FAIL && listed == 1) {
                engine->failed_wl_test_list = realloc(engine->failed_wl_test_list, sizeof(char *) * (engine->cnt_failedwl + 1));
                engine->failed_wl_test_list[engine->cnt_failedwl] = strdup(title);
                engine->cnt_failedwl++;
            }
        }
    }
    engine->cnt_total++;
    return 0;
}
