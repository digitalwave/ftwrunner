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
#include <pcre.h>

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


static char **loglines = NULL;
static int loglines_count = 0;
static pthread_mutex_t lock;

/*
 * Logger
 */

// init the log structure
void logCbInit() {
    loglines = malloc(sizeof(char*));
}

// clear the logs
void logCbClearLog() {
    for (int i = 0; i < loglines_count; i++) {
        free(loglines[i]);
    }
    loglines_count = 0;
}

// cleanup the whole log structure
void logCbCleanup() {
    int i;
    if (loglines != NULL) {
        for (i = 0; i < loglines_count; i++) {
            free(loglines[i]);
        }
        free(loglines);
    }
}

// add a line to the log
// this can be added to the engine as callback
void logCbText(void *data, const void *msg) {
    if (msg == NULL) {
        printf("I was called but the message was null ;(\n");
        return;
    }

    pthread_mutex_lock(&lock);
    loglines = realloc(loglines, sizeof(char*) * (loglines_count + 1));
    loglines[loglines_count] = malloc(strlen(msg) + 1);
    strcpy(loglines[loglines_count], msg);
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

    const char * error        = NULL;
    int          erroffset    = 0;
    pcre       * re           = NULL;
    pcre_extra * pce          = NULL;
    char       * tstr         = NULL;

    int          ovector[30];
    int          rc;

    const char  * format_reset  = "\033[0m";
    const char  * format_bgreen = "\033[1m\033[32m";
    const char  * format_bred   = "\033[1m\033[31m";

    const char  * format = (negate) ? format_bred : format_bgreen;

#if PCRE_HAVE_JIT
    int          pcre_study_opt = PCRE_STUDY_JIT_COMPILE;
#else
    int          pcre_study_opt = 0;
#endif

    re = pcre_compile(
        pattern,                           /* the pattern */
        PCRE_DOTALL | PCRE_DOLLAR_ENDONLY, /* options from re_operators */
        &error,                            /* for error message */
        &erroffset,                        /* for error offset */
        NULL                               /* use default character tables */
    );
    if (re == NULL) {
        return NULL;
    }
    pce = pcre_study(re, pcre_study_opt, &error);
    if (pce == NULL) {
        pce = calloc(1, sizeof(pcre_extra));
        if (pce == NULL) {
            return NULL;
        }
    }

    for (int i = 0; i < loglines_count; i++) {
        char * subject = loglines[i];
        size_t subject_len  = strlen(subject);

        rc = pcre_exec(
            re,                   /* the compiled pattern */
            pce,                  /* no extra data - we didn't study the pattern */
            subject,              /* the subject string */
            subject_len,          /* the length of the subject */
            0,                    /* start at offset 0 in the subject */
            0,                    /* default options */
            ovector,              /* output vector for substring information */
            30                    /* number of elements in the output vector */
        );

        if (rc > 0) {
            tstr = calloc(1, sizeof(char) * strlen(subject) + strlen(format_bgreen) + strlen(format_reset) + 1);

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
    }

    if (re != NULL) {
        pcre_free(re);
    }

    if (pce != NULL) {
#if PCRE_HAVE_JIT
        pcre_free_study(pce);
#else
        pcre_free(pce);
#endif
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
void ftw_engine_show_result(ftw_engine * engine) {
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
void fancy_print(char * test_title, int code, const char * msg, int modifier) {
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
int qsearch(char **array, int size, char *key) {
    int first = 0;
    int last = size - 1;
    int middle = 0;
    int cmp = 0;

    while (first <= last) {
        middle = (first + last) / 2;
        cmp = strcmp(array[middle], key);
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
int engine_runtest(ftw_engine * engine, int enabled, int listed, char * title, ftw_stage *stage, int debug) {

    ftw_input  * input  = stage->input;
    ftw_output * output = stage->output;

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
        else if (output->expect_error != NULL && strlen(output->expect_error) > 0) {
            fancy_print(title, FTW_TEST_SKIP, "'expect_error' is HTTP server specific - test skipped", listed);
            engine->cnt_skipped++;
        }
        else if (output->status != NULL && strlen(output->status) > 0) {
            fancy_print(title, FTW_TEST_SKIP, "'status' is HTTP server specific - test skipped", listed);
            engine->cnt_skipped++;
        }
        else if (input->version != NULL &&
                (strlen(input->version) == 0 ||
                strncmp(input->version, "HTTP", 4) != 0)) {
            fancy_print(title, FTW_TEST_SKIP, "Only HTTP protocol allowed", listed);
            engine->cnt_skipped++;
        }
        else if ((output->log_contains == NULL || strlen(output->log_contains) == 0) &&
                (output->no_log_contains == NULL || strlen(output->no_log_contains) == 0)) {
            fancy_print(title, FTW_TEST_SKIP, "No valid test output", listed);
            engine->cnt_skipped++;
        }
        else {
            // if test (collection) is not disabled and shouldn't be skipped
            int res = engine->runtest(engine, title, stage, debug);
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
