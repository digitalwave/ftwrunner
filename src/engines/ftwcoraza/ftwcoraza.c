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
// ftwcoraza.c
// Coraza WAF engine for testing

#include "ftwcoraza.h"

#ifdef HAVE_LIBCORAZA

// init coraza WAF
void * ftw_engine_init_coraza() {
    coraza_waf_t *coraza = coraza_new_waf();
    return (void*)coraza;
}

// set the rules
void * ftw_engine_create_rules_set_coraza(void * engine_instance, char * main_rule_uri, const char ** error) {
    coraza_rules_add_file((coraza_waf_t *) engine_instance, main_rule_uri, (char **)error);
    return NULL;
}

// cleanup the resources
void ftw_engine_cleanup_coraza(void * waf) {
    coraza_free_waf((coraza_waf_t *)waf);
}

// run a transaction
// a stage contains a transaction
int ftw_engine_runtest_coraza(ftw_engine * engine, char * title, ftw_stage *stage, int debug) {

    int ret = FTW_TEST_FAIL;

    coraza_intervention_t *it;
    coraza_transaction_t *transaction = NULL;

    logCbClearLog();
    transaction = coraza_new_transaction((coraza_waf_t*) engine->engine_instance, logCbText);

    // phase 0
    coraza_process_connection(transaction, "127.0.0.1", 33333, stage->input->dest_addr, stage->input->port);
    char version[10] = "1.1";
    if (stage->input->version != NULL) {
        if (strlen(stage->input->version) > 5 && strncmp(stage->input->version, "HTTP/", 5) == 0) {
            memset(version, 0, 10);
            strncpy(version, stage->input->version + 5, strlen(stage->input->version) - 5);
        }
    }
    coraza_process_uri(transaction, stage->input->uri, stage->input->method, version);
    it = coraza_intervention(transaction);

    // phase 1
    for(int hi = 0; hi < stage->input->headers_len; hi++) {
        coraza_add_request_header(
            transaction,
            stage->input->headers[hi]->name,
            (int)strlen(stage->input->headers[hi]->name),
            stage->input->headers[hi]->value,
            (int)strlen(stage->input->headers[hi]->value)
        );
    }
    coraza_add_request_header(transaction, "X-CRS-Test", 10, title, (int)strlen(title));
    coraza_process_request_headers(transaction);
    it = coraza_intervention(transaction);

    // phase 2
    if (stage->input->data != NULL) {
        coraza_append_request_body(transaction, (unsigned char *)stage->input->data, strlen(stage->input->data));
    }
    coraza_process_request_body(transaction);
    it = coraza_intervention(transaction);

    // phase 3
    char response_len[10];
    sprintf(response_len, "%ld", stage->output->response_len); 
    coraza_add_response_header(transaction, "Date",            4, stage->output->response_date, (int)strlen(stage->output->response_date));
    coraza_add_response_header(transaction, "Server",          6, "Ftwrunner", 9);
    coraza_add_response_header(transaction, "Content-Type",   12, "text/html; charset=UTF-8", 24);
    coraza_add_response_header(transaction, "Content-Length", 14, response_len, (int)strlen(response_len));
    coraza_process_response_headers(transaction, stage->output->response_code, (char *)"HTTP/1.1");
    it = coraza_intervention(transaction);

    // phase 4
    if (stage->output->response != NULL) {
        coraza_append_response_body(transaction, (unsigned char *)stage->output->response, stage->output->response_len);
    }
    coraza_process_response_body(transaction);
    it = coraza_intervention(transaction);

    // phase 5
    coraza_process_logging(transaction);
    it = coraza_intervention(transaction);
    if (it != NULL) {
        if (it->log != NULL) {
            free(it->log);
        }
    }

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

    /*if (it->url != NULL) {
        free(it->url);
    }
    if (it->log != NULL) {
        free(it->log);
    }*/
    coraza_free_transaction(transaction);

    logCbDump();

    return ret;
}

#endif

