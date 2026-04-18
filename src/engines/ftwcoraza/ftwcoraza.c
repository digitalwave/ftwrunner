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

// error callback for coraza - captures matched rule error logs
static void coraza_error_log_cb(void *ctx, coraza_matched_rule_t rule) {
    (void)ctx;
    char *error_log = coraza_matched_rule_get_error_log(rule);
    if (error_log != NULL) {
        logCbText(NULL, error_log);
        free(error_log);
    }
}

// init coraza WAF config
void * ftw_engine_init_coraza() {
    coraza_waf_config_t config = coraza_new_waf_config();
    coraza_add_error_callback(config, coraza_error_log_cb, NULL);
    return (void*)config;
}

// set the rules and create WAF
void * ftw_engine_create_rules_set_coraza(void * engine_instance, char * main_rule_uri, const char ** error) {
    coraza_waf_config_t config = (coraza_waf_config_t)engine_instance;

    if (coraza_rules_add_file(config, main_rule_uri) < 0) {
        *error = "failed to add rules file";
        coraza_free_waf_config(config);
        return NULL;
    }

    char *waf_error = NULL;
    coraza_waf_t waf = coraza_new_waf(config, &waf_error);
    coraza_free_waf_config(config);

    if (waf == 0) {
        *error = waf_error ? waf_error : "failed to create WAF";
        return NULL;
    }

    return (void*)waf;
}

// cleanup the resources
void ftw_engine_cleanup_coraza(void * waf) {
    coraza_free_waf((coraza_waf_t)waf);
}

// run a transaction
// a stage contains a transaction
int ftw_engine_runtest_coraza(ftw_engine * engine, char * title, ftw_stage *stage, int debug, int verbose) {

    int ret = FTW_TEST_FAIL;

    coraza_intervention_t *it;
    coraza_transaction_t transaction = 0;
    coraza_waf_t waf = (coraza_waf_t)engine->rules;

    logCbClearLog();
    transaction = coraza_new_transaction(waf);

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
    if (it != NULL) { coraza_free_intervention(it); }

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
    if (it != NULL) { coraza_free_intervention(it); }

    // phase 2
    if (stage->input->data != NULL) {
        coraza_append_request_body(transaction, (unsigned char *)stage->input->data, strlen(stage->input->data));
    }
    coraza_process_request_body(transaction);
    it = coraza_intervention(transaction);
    if (it != NULL) { coraza_free_intervention(it); }

    // phase 3
    char response_len[10];
    sprintf(response_len, "%ld", stage->response->response_len);
    if (stage->response->response_date != NULL) {
        coraza_add_response_header(transaction, "Date", 4, stage->response->response_date, (int)strlen(stage->response->response_date));
    }
    coraza_add_response_header(transaction, "Server",          6, "Ftwrunner", 9);
    coraza_add_response_header(transaction, "Content-Type",   12, "text/html; charset=UTF-8", 24);
    coraza_add_response_header(transaction, "Content-Length", 14, response_len, (int)strlen(response_len));
    coraza_process_response_headers(transaction, stage->response->response_code, (char *)"HTTP/1.1");
    it = coraza_intervention(transaction);
    if (it != NULL) { coraza_free_intervention(it); }

    // phase 4
    if (stage->response->response_body != NULL) {
        coraza_append_response_body(transaction, stage->response->response_body, stage->response->response_len);
    }
    coraza_process_response_body(transaction);
    it = coraza_intervention(transaction);
    if (it != NULL) { coraza_free_intervention(it); }

    // phase 5
    coraza_process_logging(transaction);
    it = coraza_intervention(transaction);
    if (it != NULL) { coraza_free_intervention(it); }

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

    coraza_free_transaction(transaction);

    logCbDump();
    logCbClearLog();

    return ret;
}

#endif

