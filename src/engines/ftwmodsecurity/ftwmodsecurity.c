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
// ftwmodsecurity.c
// ModSecurity WAF engine for testing

#include "ftwmodsecurity.h"

#ifdef HAVE_MODSECURITY

// init modsecurity waf
void * ftw_engine_init_msc() {
    ModSecurity *modsec = msc_init();
    msc_set_log_cb(modsec, logCbText);
    return (void*)modsec;
}

// set the rules
void * ftw_engine_create_rules_set_msc(void * engine_instance, char * main_rule_uri, const char ** error) {
#ifdef MSC_USE_RULES_SET
    RulesSet *rules = msc_create_rules_set();
#else
    Rules * rules = msc_create_rules_set();
#endif
    if (msc_rules_add_file(rules, main_rule_uri, error) < 0) {
        if (rules != NULL) {
            msc_rules_cleanup(rules);
        }
        return NULL;
    }
    return (void*)rules;
}

// cleanup the WAF engine
void ftw_engine_cleanup_msc(void * modsec) {
    msc_cleanup((ModSecurity *)modsec);
}

#define VERBOSE(format, ...) if (verbose == 1) { \
  fprintf(stdout, "\033[35;46mVERBOSE\033[0m " format, __VA_ARGS__); }

// run a transaction
// a stage contains a transaction
int ftw_engine_runtest_msc(ftw_engine * engine, char * title, ftw_stage *stage, int debug, int verbose) {

    int ret = FTW_TEST_FAIL;

    ModSecurityIntervention it;
    Transaction * transaction = msc_new_transaction(
        (ModSecurity *)engine->engine_instance,
#ifdef MSC_USE_RULES_SET
        (RulesSet *)engine->rules,
#else
        (Rules *)engine->rules,
#endif
        NULL);

    it.status = N_INTERVENTION_STATUS;
    it.url = NULL;
    it.log = NULL;
    it.disruptive = 0;

    //logCbClearLog();

    // phase 0
    msc_process_connection(transaction, "127.0.0.1", 33333, stage->input->dest_addr, stage->input->port);
    if (verbose == 1) {
        printf("\033[35;46mVERBOSE\033[0m Connection data: source addr: 127.0.0.1, source port: 33333, dest addr: %s, dest port: %u\n", stage->input->dest_addr, stage->input->port);
    }
    char version[10] = "1.1";
    if (stage->input->version != NULL) {
        if (strlen(stage->input->version) > 5 && strncmp(stage->input->version, "HTTP/", 5) == 0) {
            memset(version, 0, 10);
            strncpy(version, stage->input->version + 5, strlen(stage->input->version) - 5);
        }
    }
    msc_process_uri(transaction, stage->input->uri, stage->input->method, version);
    if (verbose == 1) {
        printf("\033[35;46mVERBOSE\033[0m URI: %s %s %s\n", stage->input->uri, stage->input->method, version);
    }
    msc_intervention(transaction, &it);
    if (verbose == 1) {
        printf("\033[35;46mVERBOSE\033[0m intervention: status: %d, disruptive: %d\n", it.status, it.disruptive);
    }

    // phase 1
    for(int hi = 0; hi < stage->input->headers_len; hi++) {
        msc_add_request_header(transaction, (const unsigned char *)stage->input->headers[hi]->name, (const unsigned char *)stage->input->headers[hi]->value);
        if (verbose == 1) {
            printf("\033[35;46mVERBOSE\033[0m Add req header: %s: %s\n", (const unsigned char *)stage->input->headers[hi]->name, (const unsigned char *)stage->input->headers[hi]->value);
        }
    }
    msc_add_request_header(transaction, (const unsigned char *)"X-CRS-Test", (const unsigned char *)title);
    if (verbose == 1) {
        printf("\033[35;46mVERBOSE\033[0m Add req header: %s: %s\n", (const unsigned char *)"X-CRS-Test", (const unsigned char *)title);
    }
    msc_process_request_headers(transaction);
    msc_intervention(transaction, &it);
    if (verbose == 1) {
        printf("\033[35;46mVERBOSE\033[0m intervention: status phase 1: %d, disruptive: %d\n", it.status, it.disruptive);
    }

    // phase 2
    if (stage->input->data != NULL) {
        msc_append_request_body(transaction, (const unsigned char *)stage->input->data, strlen(stage->input->data));
        if (verbose == 1) {
            printf("\033[35;46mVERBOSE\033[0m Add req body: %s\n", (const unsigned char *)stage->input->data);
        }
    }
    msc_process_request_body(transaction);
    msc_intervention(transaction, &it);
    if (verbose == 1) {
        printf("\033[35;46mVERBOSE\033[0m intervention: status, phase 2: %d, disruptive: %d\n", it.status, it.disruptive);
        //printf("\033[35;46mVERBOSE\033[0m intervention: log: '%s'\n", it.log);
    }

    // phase 3
    char response_len[10];
    sprintf(response_len, "%lu", stage->response->response_len); 
    msc_add_response_header(transaction, (const unsigned char *)"Date", (const unsigned char *)stage->response->response_date);
    VERBOSE("Add resp header: %s: %s\n", (const unsigned char *)"Date", (const unsigned char *)stage->response->response_date);
    msc_add_response_header(transaction, (const unsigned char *)"Server", (const unsigned char *)"Ftwrunner");
    VERBOSE("Add resp header: %s: %s\n", (const unsigned char *)"Server", (const unsigned char *)"Ftwrunner");
    if (stage->response->response_body == NULL) {
        msc_add_response_header(transaction, (const unsigned char *)"Content-Type", (const unsigned char *)"text/html; charset=UTF-8");
        VERBOSE("Add resp header: %s: %s\n", (const unsigned char *)"Content-Type", (const unsigned char *)"text/html; charset=UTF-8");
        msc_add_response_header(transaction, (const unsigned char *)"Content-Length", (const unsigned char *)response_len);
        VERBOSE("Add resp header: %s: %s\n", (const unsigned char *)"Content-Length", (const unsigned char *)response_len);
    }
    else {
        msc_add_response_header(transaction, (const unsigned char *)"Content-Type", stage->response->response_content_type);
        VERBOSE("Add resp header: %s: %s\n", (const unsigned char *)"Content-Type", stage->response->response_content_type);
        msc_add_response_header(transaction, (const unsigned char *)"Content-Length", (const unsigned char *)response_len);
        VERBOSE("Add resp header: %s: %s\n", (const unsigned char *)"Content-Length", (const unsigned char *)response_len);
    }
    msc_process_response_headers(transaction, stage->response->response_code, (const char *)"HTTP/1.1");
    msc_intervention(transaction, &it);
    VERBOSE("intervention: status, phase 3: %d, disruptive: %d\n", it.status, it.disruptive);

    // phase 4
    if (stage->response->response_body != NULL) {
        msc_append_response_body(transaction, (const unsigned char *)stage->response->response_body, stage->response->response_len);
        VERBOSE("Add resp body: %s\n", (const unsigned char *)stage->response->response_body);
    }
    msc_process_response_body(transaction);
    msc_intervention(transaction, &it);
    VERBOSE("intervention: status, phase 4: %d, disruptive: %d\n", it.status, it.disruptive);

    // phase 5
    msc_process_logging(transaction);
    msc_intervention(transaction, &it);
    VERBOSE("intervention: status, phase 5: %d, disruptive: %d\n", it.status, it.disruptive);

    //logCbDump();
    char * log = NULL;
    if (stage->output->log_contains != NULL) {
        log = logContains(stage->output->log_contains, 0);
        if (log != NULL) {
            ret = FTW_TEST_PASS;
            if (debug == 1) {
                printf("%s\n", log);
            }
            free(log);
        }
        else {
            ret = FTW_TEST_FAIL;
            if (debug == 1) {
                printf("Log no contains required pattern: '%s'\n", stage->output->log_contains);
            }
        }
    }
    if (stage->output->no_log_contains != NULL) {
        log = logContains(stage->output->no_log_contains, 1);
        if (log == NULL) {
            ret = FTW_TEST_PASS;
        }
        else {
            ret = FTW_TEST_FAIL;
            if (debug == 1) {
                printf("%s\n", log);
            }
            free(log);
        }
    }
    if (stage->output->log->expect_ids_len > 0) {
        for(int i = 0; i < stage->output->log->expect_ids_len; i++) {

            char idsubj[50];
            sprintf(idsubj, "id \"%u\"", stage->output->log->expect_ids[i]);
            log = logContains(idsubj, 0);
            if (log != NULL) {
                ret = FTW_TEST_PASS;
                if (debug == 1) {
                    printf("%s\n", log);
                }
                free(log);
            }
            else {
                ret = FTW_TEST_FAIL;
                if (debug == 1) {
                    printf("Log no contains required pattern: '%s'\n", idsubj);
                }
            }
        }
    }
    if (stage->output->log->no_expect_ids_len > 0) {
        for(int i = 0; i < stage->output->log->no_expect_ids_len; i++) {

            char idsubj[50];
            sprintf(idsubj, "id \"%u\"", stage->output->log->no_expect_ids[i]);
            log = logContains(idsubj, 1);
            if (log == NULL) {
                ret = FTW_TEST_PASS;
            }
            else {
                ret = FTW_TEST_FAIL;
                if (debug == 1) {
                    printf("%s\n", log);
                }
                free(log);
            }
        }
    }


    if (it.url != NULL) {
        free(it.url);
    }
    if (it.log != NULL) {
        free(it.log);
    }
    msc_transaction_cleanup(transaction);

    //logCbDump();
    logCbClearLog();

    return ret;
}

#endif

