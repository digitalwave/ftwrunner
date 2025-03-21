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
// main.c
// main program of ftwrunner

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "ftwrunner.h"
#include "yamlapi.h"
#include "walkdir.h"
#include "ftwtest.h"
#include "engines/engines.h"
#include "config.h"


static char available_engines[3][20] = {"dummy", "", ""};
static int engine_count = 1;

void showhelp(void) {
    printf("Use: %s [OPTIONS]\n\n", PRGNAME);
    printf("OPTIONS:\n");
    printf("\t-h\tThis help\n");
    printf("\t-c\tUse alternative config instead of ftwrunner.yaml in same directory\n");
    printf("\t-f\tUse alternative ftw test collection instead of in default config\n");
    printf("\t-m\tUse alternative ModSecurity config instead of in default config\n");
    printf("\t-r\tUse only this rule test, eg. '-r 911100'\n");
    printf("\t-t\tUse only this test of all, eg. '-t 1'\n");
    printf("\t-o\tUse overrides from file\n");
    printf("\t-e\tUse WAF engine\n");
    printf("\t  \tavailable engines:\n");
    for(int i = 0; i < engine_count; i++) {
        printf("\t  \t- %s\n", available_engines[i]);
    }
    printf("\t-d  \tShow detailed information.\n");
    printf("\t-v  \tVerbose output.\n");
    printf("\n");
}


int main(int argc, char **argv) {

    int  debug                = 0;
    int  verbose              = 0;
    char c;
    char *ftwconfig           = NULL;
    char *modsecurity_config  = NULL;
    char *ftwtest_root        = NULL;
    unsigned int rule_test    = 0;
    unsigned int rule_test_id = 0;
    char **test_whitelist     = NULL;
    int test_whitelist_count  = 0;
    char *ftwengine           = NULL;
    char *overrides           = NULL;

    char     **tests          = NULL;
    unsigned   test_count     = 0;
    unsigned   failed_count   = 0;

    yaml_item *yroot = NULL;
    const char * errormsg = NULL;

#ifdef HAVE_MODSECURITY
strcpy(available_engines[engine_count++], "modsecurity");
#endif
#ifdef HAVE_LIBCORAZA
strcpy(available_engines[engine_count++], "coraza");
#endif

    // parse arguments
    while ((c = getopt (argc, argv, "hdvc:m:r:t:f:e:o:")) != -1) {
        switch (c) {
            case 'h':
                showhelp();
                return EXIT_SUCCESS;
            case 'c':
                ftwconfig    = strdup(optarg);
                break;
            case 'm':
                modsecurity_config = strdup(optarg);
                break;
            case 'r':
                rule_test    = atoi(optarg);
                break;
            case 't':
                rule_test_id = atoi(optarg);
                break;
            case 'f':
                ftwtest_root = strdup(optarg);
                break;
            case 'e':
                ftwengine    = strdup(optarg);
                break;
            case 'd':
                debug = 1;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'o':
                overrides    = strdup(optarg); // cppcheck-suppress unreadVariable
            case '?':
                if (optopt == 'n' || optopt == 'm' || optopt == 'r' || optopt == 't' || optopt == 'f' || optopt == 'e') {
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                }
                else if (isprint (optopt)) {
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                }
                else {
                    fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                }
                return EXIT_FAILURE;
            default:
                abort ();
        }
    }

    if (ftwengine == NULL) {
        ftwengine = strdup(available_engines[0]);
    }
    // read config, config options
    if (ftwconfig == NULL) {
        ftwconfig = strdup(FTWRUNNER_YAML);
    }
    if(access(ftwconfig, F_OK) != 0) {
        fprintf(stderr, "Error: config file %s not found!\n", ftwconfig);
        return EXIT_FAILURE;
    }
    if (overrides != NULL) {
        if(access(overrides, F_OK) != 0) {
            fprintf(stderr, "Error: overriders file %s not found!\n", overrides);
            return EXIT_FAILURE;
        }
        else {

            yroot = parse_yaml(overrides);
            if (yroot == NULL) {
                fprintf(stderr, "Error parsing file %s!\n", overrides);
                return EXIT_FAILURE;
            }
            else {
                yaml_item *titem;
                if (yaml_item_get_value_by_key(yroot, (const char *)"test_whitelist", &titem) == YAML_KEYSEARCH_FOUND && titem->type == YAML_VALTYPE_LIST) {
                    int i;
                    test_whitelist = calloc(titem->value.list->length+1, sizeof(char *));
                    if (test_whitelist == NULL) {
                        fprintf(stderr, "Error: out of memory!\n");
                        return EXIT_FAILURE;
                    }
                    for (i = 0; i < titem->value.list->length; i++) {
                        test_whitelist[i] = strdup(titem->value.list->list[i]->value.sval);
                    }
                    qsort(test_whitelist, titem->value.list->length, sizeof(char *), walkcmp);
                    test_whitelist_count = titem->value.list->length;
                    test_whitelist[i] = NULL;
                }
                yaml_item_free(yroot);
            }

        }
    }

    if (engine_count == 0) {
        fprintf(stderr, "Error: no engine available!\n");
        return EXIT_FAILURE;
    }
    else {
        int i = 0;
        for(i = 0; i < engine_count; i++) {
            if (ftwengine != NULL && strcmp(ftwengine, available_engines[i]) == 0) {
                break;
            }
        }
        if (i == engine_count) {
            fprintf(stderr, "Error: engine %s not available!\n", ftwengine);
            return EXIT_FAILURE;
        }
    }
    yroot = parse_yaml(ftwconfig);
    if (yroot == NULL) {
        fprintf(stderr, "Error parsing file %s!\n", ftwconfig);
        return EXIT_FAILURE;
    }
    else {
        yaml_item *titem;
        if (ftwtest_root == NULL) {
            if (yaml_item_get_value_by_key(yroot, (const char *)"ftwtest_root", &titem) == YAML_KEYSEARCH_FOUND && titem->type == YAML_VALTYPE_STRING) {
                ftwtest_root = strdup(titem->value.sval);
            }
        }
        if (modsecurity_config == NULL) {
            if (yaml_item_get_value_by_key(yroot, (const char *)"modsecurity_config", &titem) == YAML_KEYSEARCH_FOUND && titem->type == YAML_VALTYPE_STRING) {
                modsecurity_config = strdup(titem->value.sval);
            }
        }
        if (yaml_item_get_value_by_key(yroot, (const char *)"test_whitelist", &titem) == YAML_KEYSEARCH_FOUND && titem->type == YAML_VALTYPE_LIST) {
            int i;
            test_whitelist = calloc(titem->value.list->length+1, sizeof(char *));
            if (test_whitelist == NULL) {
                fprintf(stderr, "Error: out of memory!\n");
                return EXIT_FAILURE;
            }
            for (i = 0; i < titem->value.list->length; i++) {
                test_whitelist[i] = strdup(titem->value.list->list[i]->value.sval);
            }
            qsort(test_whitelist, titem->value.list->length, sizeof(char *), walkcmp);
            test_whitelist_count = titem->value.list->length;
            test_whitelist[i] = NULL;
        }
        yaml_item_free(yroot);
    }
    if (modsecurity_config == NULL) {
        fprintf(stderr, "Error: modsecurity_config not set!\n");
        return EXIT_FAILURE;
    }
    if (ftwtest_root == NULL) {
        fprintf(stderr, "Error: ftwtest_root not set!\n");
        return EXIT_FAILURE;
    }
    // END read config, config options

    char rootdir[1024];
    strcpy(rootdir, ftwtest_root);
    walkdir(rootdir, &tests, &test_count);

    if (tests != NULL) {

        ftw_engine *engine = NULL;

        if (strcmp(ftwengine, "dummy") == 0) {
            engine = ftw_engine_init(FTW_ENGINE_TYPE_DUMMY, modsecurity_config, &errormsg);
        }
        else if (strcmp(ftwengine, "modsecurity") == 0) {
            engine = ftw_engine_init(FTW_ENGINE_TYPE_MODSECURITY, modsecurity_config, &errormsg);
        }
        else if (strcmp(ftwengine, "coraza") == 0) {
            engine = ftw_engine_init(FTW_ENGINE_TYPE_CORAZA, modsecurity_config, &errormsg);
        }
        if (errormsg != NULL) {
            fprintf(stderr, "ftwrunner init error: %s\n", errormsg);
            for(int i = 0; i < test_count; i++) {
                free(tests[i]);
            }
        }
        else {
            qsort(tests, test_count, sizeof(char *), walkcmp);
            for(int i = 0; i < test_count; i++) {
                yaml_item *yrootsub = parse_yaml(tests[i]);
                ftwtestcollection * collection = ftwtestcollection_new(yrootsub, rule_test, rule_test_id);
                if (collection == NULL) {
                    fprintf(stderr, "Error parsing file %s! (Memory allocation error)\n", tests[i]);
                    exit(EXIT_FAILURE);
                }
                if (collection->meta.enabled) {
                    for(int t = 0; t < collection->test_count; t++) {
                        ftwtest *test = collection->tests[t];
                        if (rule_test == 0 || rule_test == collection->rule_id) {
                            if (rule_test_id == 0 || rule_test_id == test->test_id) {
                                for(int si = 0; si < test->stages_count; si++) {
                                    ftw_stage *stage = test->stages[si];
                                    char test_full_id[50];
                                    sprintf(test_full_id, "%u-%u", collection->rule_id, test->test_id);
                                    int wl = qsearch(test_whitelist, test_whitelist_count, test_full_id);
                                    engine_runtest(engine, collection->meta.enabled, ((wl >= 0) ? 1 : 0), test_full_id, stage, debug, verbose);
                                }
                            }
                        }
                    }
                }
                ftwtestcollection_free(collection);
                yaml_item_free(yrootsub);
                free(tests[i]);
            }
            ftw_engine_show_result(engine);
            logCbClearLog();
        }
        if (engine != NULL) {
            failed_count = engine->cnt_failed;
            ftw_engine_free(engine);
        }
        free(tests);
    }
    else {
        printf("No tests found!\n");
    }

    FTW_FREE_STRING(ftwconfig);
    FTW_FREE_STRING(modsecurity_config);
    FTW_FREE_STRING(ftwtest_root);
    FTW_FREE_STRING(ftwengine);
    FTW_FREE_STRINGLIST(test_whitelist);
    return failed_count;
}
