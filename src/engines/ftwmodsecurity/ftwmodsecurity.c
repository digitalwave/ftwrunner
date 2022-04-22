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

// run a transaction
// a stage contains a transaction
int ftw_engine_runtest_msc(ftw_engine * engine, char * title, ftw_stage *stage, int debug) {

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

    logCbClearLog();

    // phase 0
    msc_process_connection(transaction, "127.0.0.1", 33333, stage->input->dest_addr, stage->input->port);
    char version[10] = "1.1";
    if (stage->input->version != NULL) {
        if (strlen(stage->input->version) > 5 && strncmp(stage->input->version, "HTTP/", 5) == 0) {
            memset(version, 0, 10);
            strncpy(version, stage->input->version + 5, strlen(stage->input->version) - 5);
        }
    }
    msc_process_uri(transaction, stage->input->uri, stage->input->method, version);
    msc_intervention(transaction, &it);

    // phase 1
    for(int hi = 0; hi < stage->input->headers_len; hi++) {
        msc_add_request_header(transaction, (const unsigned char *)stage->input->headers[hi]->name, (const unsigned char *)stage->input->headers[hi]->value);
    }
    msc_add_request_header(transaction, (const unsigned char *)"X-CRS-Test", (const unsigned char *)title);
    msc_process_request_headers(transaction);
    msc_intervention(transaction, &it);

    // phase 2
    if (stage->input->data != NULL) {
        msc_append_request_body(transaction, (const unsigned char *)stage->input->data, strlen(stage->input->data));
    }
    msc_process_request_body(transaction);
    msc_intervention(transaction, &it);

    // phase 3
    char response_len[10];
    sprintf(response_len, "%ld", stage->output->response_len); 
    msc_add_response_header(transaction, (const unsigned char *)"Date", (const unsigned char *)stage->output->response_date);
    msc_add_response_header(transaction, (const unsigned char *)"Server", (const unsigned char *)"Ftwrunner");
    msc_add_response_header(transaction, (const unsigned char *)"Content-Type", (const unsigned char *)"text/html; charset=UTF-8");
    msc_add_response_header(transaction, (const unsigned char *)"Content-Length", (const unsigned char *)response_len);
    msc_process_response_headers(transaction, stage->output->response_code, (const char *)"HTTP/1.1");
    msc_intervention(transaction, &it);

    // phase 4
    if (stage->output->response != NULL) {
        msc_append_response_body(transaction, (const unsigned char *)stage->output->response, stage->output->response_len);
    }
    msc_process_response_body(transaction);
    msc_intervention(transaction, &it);

    // phase 5
    msc_process_logging(transaction);
    msc_intervention(transaction, &it);

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
    else if (stage->output->no_log_contains != NULL) {
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

    if (it.url != NULL) {
        free(it.url);
    }
    if (it.log != NULL) {
        free(it.log);
    }
    msc_transaction_cleanup(transaction);

    //logCbDump();

    return ret;
}

#endif

