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
// ftwtest.c
// functions for building tests
//
// this functions builds a data structure which equals the yaml structure:
// ---
// meta:
//   author: "AUTHOR"
//   enabled: true
//   name: "NAME.yaml"
//   description: "DESC"
// tests:
//   - test_title: NAME-1
//     stages:
//       - stage:
//           input:
//             dest_addr: "127.0.0.1"
//             port: 80
//             headers:
//               User-Agent: "OWASP ModSecurity Core Rule Set"
//               Host: "localhost"
//               Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
//           output:
//             no_log_contains: "id \"RULEID\""
//

#include <time.h>
#include "ftwtest.h"
#include "yamlapi.h"
#include "ftwrunner.h"
#include "ftwtestutils.h"

#define STR(X) #X

// normal respond body
static const char response_ok[] = ""
    "<doctype>\n"
    "<html>\n"
    "  <heade>\n"
    "    <title>FTWRunner test</title>\n"
    "  </head>\n"
    "  <body>This is the body</body>\n"
    "</html>\n"
    "\n";

// 404 respond body
static const char response_404[] = ""
    "<doctype>\n"
    "<html>\n"
    "  <heade>\n"
    "    <title>FTWRunner test</title>\n"
    "  </head>\n"
    "  <body>File not found</body>\n"
    "</html>\n"
    "\n";

// free the input section of a stage
void ftwinput_free(ftw_input *input) {
    // free the headers
    if (input->headers != NULL) {
        for (int i = 0; i < input->headers_len; i++) {
            FTW_FREE_STRING(input->headers[i]->name);
            FTW_FREE_STRING(input->headers[i]->value);
            free(input->headers[i]);
        }
        free(input->headers);
    }
    FTW_FREE_STRING(input->dest_addr);
    FTW_FREE_STRING(input->method);
    FTW_FREE_STRING(input->protocol);
    FTW_FREE_STRING(input->uri);
    FTW_FREE_STRING(input->version);
    FTW_FREE_STRING(input->data);
    FTW_FREE_STRING(input->encoded_request);
    FTW_FREE_STRING(input->raw_request);

    free(input);
}

// free the output section of a stage
void ftwoutput_free(ftw_output *output) {
    FTW_FREE_STRING(output->status);
    FTW_FREE_STRING(output->response_contains);
    FTW_FREE_STRING(output->log_contains);
    FTW_FREE_STRING(output->no_log_contains);
    FTW_FREE_STRING(output->expect_error);
    FTW_FREE_STRING(output->response);
    FTW_FREE_STRING(output->response_date);
    free(output);
}

// free a stage, contains input and output sections
void ftwstage_free(ftw_stage * stage) {
    if (stage != NULL) {
        if (stage->input != NULL) {
            ftwinput_free(stage->input);
        }
        if (stage->output != NULL) {
            ftwoutput_free(stage->output);
        }
        free(stage);
    }
}

// free a test, contains stages
void ftwtest_free(ftwtest *test) {
    if (test != NULL) {
        FTW_FREE_STRING(test->test_title);
        FTW_FREE_STRING(test->desc);
        FTW_FREE_STRING(test->rule_id);
        FTW_FREE_STRING(test->test_id);
        // free stages
        for(int i=0; i<test->stages_count; i++) {
            ftwstage_free(test->stages[i]);
        }
        if (test->stages != NULL) {
            free(test->stages);
        }
        // Finally, free the test itself
        free(test);
    }
}

// free a collection of tests, contains tests
void ftwtestcollection_free(ftwtestcollection * collection) {
    for(int t = 0; t < collection->test_count; t++) {
        ftwtest_free(collection->tests[t]);
    }
    free(collection->tests);
    free(collection);
}

#define FTWOUTPUT_VAR(v) { \
    if (yaml_item_get_value_by_key(youtput, (const char *)#v, &ytitem) == YAML_KEYSEARCH_FOUND) { \
        output->v = strdup(ytitem->value.sval); \
        ytitem = NULL; \
    } \
    }

// create a new output section for a stage
ftw_output * ftwoutput_new(yaml_item * youtput) {

    yaml_item * ytitem;

    ftw_output *output         = malloc(sizeof(ftw_output));
    output->status            = NULL;
    output->response_contains = NULL;
    output->log_contains      = NULL;
    output->no_log_contains   = NULL;
    output->expect_error      = NULL;
    output->response          = NULL;
    output->response_len      = 0;
    output->response_code     = 200;
    output->response_date     = NULL;

    FTWOUTPUT_VAR(status);
    FTWOUTPUT_VAR(response_contains);
    FTWOUTPUT_VAR(log_contains);
    FTWOUTPUT_VAR(no_log_contains);
    FTWOUTPUT_VAR(expect_error);

    return output;
}

// create a header list for input section of a stage
void ftwinput_headers_new(ftw_input * input, yaml_item * yheaders) {

    input->headers = calloc(1, sizeof(ftw_header *));
    input->headers_len = 0;
    for(int i = 0; i < yheaders->value.list->length; i++) {

        yaml_item * yheader = yheaders->value.list->list[i];
        ftw_header *header = calloc(1, sizeof(ftw_header));

        header->name = strdup(yheader->name);
        header->value = strdup(yheader->value.sval);

        // collect some headers; these are necessary to run the tests,
        // if the stop_magic is TRUE
        if (strcmp(header->name, "Content-Type") == 0) {
            input->is_sent_header_content_type = 1;
            input->content_type = header->value;
        }
        if (strcmp(header->name, "Content-Length") == 0) {
            input->is_sent_header_content_length = 1;
        }

        input->headers_len++;
        input->headers = realloc(input->headers, input->headers_len * sizeof(ftw_header *));
        input->headers[i] = header;
    }
}

#define FTWINPUT_VAR(v) { \
    if (yaml_item_get_value_by_key(yinput, (const char *)#v, &ytitem) == YAML_KEYSEARCH_FOUND) { \
        input->v = strdup(ytitem->value.sval); \
        ytitem = NULL; \
    } \
    }

// create a new input section for a stage
// sets the default values: method, uri
ftw_input * ftwinput_new(yaml_item * yinput) {

    yaml_item * ytitem;

    ftw_input *input       = malloc(sizeof(ftw_input));
    input->dest_addr       = NULL;
    input->port            = 0;
    input->method          = NULL;
    input->headers         = NULL;
    input->headers_len     = 0;
    input->protocol        = NULL;
    input->uri             = NULL;
    input->version         = NULL;
    input->data            = NULL;
    input->save_cookie     = 0;
    input->stop_magic      = 0;
    input->encoded_request = NULL;
    input->raw_request     = NULL;

    input->is_sent_header_content_type   = 0;
    input->is_sent_header_content_length = 0;

    input->content_type    = NULL;

    FTWINPUT_VAR(dest_addr);
    if (yaml_item_get_value_by_key(yinput, (const char *)"port", &ytitem) == YAML_KEYSEARCH_FOUND) {
        input->port = atoi(ytitem->value.sval);
        ytitem = NULL;
    }
    FTWINPUT_VAR(method);
    FTWINPUT_VAR(protocol);
    FTWINPUT_VAR(uri);
    FTWINPUT_VAR(version);
    FTWINPUT_VAR(data);
    if (yaml_item_get_value_by_key(yinput, (const char *)"save_cookie", &ytitem) == YAML_KEYSEARCH_FOUND) {
        input->save_cookie = yaml_item_value_as_bool(ytitem);
        ytitem = NULL;
    }
    if (yaml_item_get_value_by_key(yinput, (const char *)"stop_magic", &ytitem) == YAML_KEYSEARCH_FOUND) {
        input->stop_magic = yaml_item_value_as_bool(ytitem);
        ytitem = NULL;
    }
    FTWINPUT_VAR(encoded_request);
    FTWINPUT_VAR(raw_request);

    if (yaml_item_get_value_by_key(yinput, (const char *)"headers", &ytitem) == YAML_KEYSEARCH_FOUND) {
        ftwinput_headers_new(input, ytitem);
        ytitem = NULL;
    }

    if (input->method == NULL) {
        input->method = strdup("GET");
    }

    if (input->uri == NULL) {
        input->uri = strdup("/");
    }

    if (input->stop_magic == 0) {

        size_t data_len = 0;
        if (input->data != NULL) {
            data_len = strlen(input->data);
        }

        if (data_len > 0 && input->is_sent_header_content_type == 0) {

            ftw_header *header = calloc(1, sizeof(ftw_header));

            header->name = strdup("Content-Type");
            header->value = strdup("application/x-www-form-urlencoded");
            input->content_type = header->value;

            input->headers = realloc(input->headers, (input->headers_len+1) * sizeof(ftw_header *));
            input->headers[input->headers_len++] = header;
        }

        // check whether the data is in encoded form or not
        // only need if:
        // - data_len > 0
        // - method is not GET
        // - content-type is set and it is application/x-www-form-urlencoded
        if (data_len > 0 &&
           ((strcmp(input->method, "GET") == 0) ||
            (input->content_type != NULL && strcmp(input->content_type, "application/x-www-form-urlencoded") == 0))) {
            // check the given 'data' is quoted or not
            // try to produce the unquoted form, if it's equal to the given 'data'
            // then it's not quoted; in this case, we should parse the query string
            // and produce the encoded form
            char * unquoted_data = unquote(input->data);
            if (strcmp(unquoted_data, input->data) == 0) {
                char *** parsed = malloc(sizeof(char**));
                int parsed_len = 0;
                // parse_qs produces a list of key-value pairs
                // pair[0] is the key, pair[1] is the value
                // in some cases, one of them is NULL, eg 'foo=',
                // '=foo' or '===='
                parse_qs(input->data, &parsed, &parsed_len);
                if (parsed_len > 0) {
                    char * qs = calloc((data_len*4)+1, sizeof(char));
                    for(int i = 0; i < parsed_len; i++) {
                        char ** pair = parsed[i];
                        if (pair[0] != NULL && pair[1] != NULL) {
                            strcat(qs, pair[0]);
                            strcat(qs, "=");
                            strcat(qs, pair[1]);
                            strcat(qs, "&");
                            free(pair[0]);
                            free(pair[1]);
                        }
                        else if (pair[0] != NULL && pair[1] == NULL) {
                            strcat(qs, pair[0]);
                            strcat(qs, "=");
                            strcat(qs, "&");
                            free(pair[0]);
                        }
                        else if (pair[0] == NULL && pair[1] != NULL) {
                            strcat(qs, "=");
                            strcat(qs, pair[1]);
                            strcat(qs, "&");
                            free(pair[1]);
                        }
                        free(pair);
                    }
                    free(input->data);
                    input->data = qs;
                    input->data[strlen(qs)-1] = '\0';
                    data_len = strlen(input->data);
                }
                if (parsed != NULL) {
                    free(parsed);
                }
            }
            free(unquoted_data);
        }

        if (data_len > 0 && input->is_sent_header_content_length == 0) {
            ftw_header *header = calloc(1, sizeof(ftw_header));

            header->name = strdup("Content-Length");
            header->value = calloc(data_len+1, sizeof(char));
            sprintf(header->value, "%ld", data_len);

            input->headers = realloc(input->headers, (input->headers_len+1) * sizeof(ftw_header *));
            input->headers[input->headers_len++] = header;
        }
           
    }
    return input;
}

// create a new collection of tests
// a collection contains the 'meta' and the 'test' sections
// input arguments:
// * yroot: the root ptr of a yaml tree
// * rule_id: string of the rule id what we want to run only, eg "920100"
// * test_id: string of the test id what we want to run only, eg "1"
ftwtestcollection *ftwtestcollection_new(yaml_item * yroot, char * rule_id, char * test_id) {

    yaml_item * ytitem1 = NULL, * ytitem2 = NULL, * ytests = NULL;
    ftwtestcollection *collection = malloc(sizeof(ftwtestcollection));
    collection->tests = calloc(1, sizeof(ftwtest *));
    collection->test_count = 0;

    // meta needs only to read the meta.enabled value
    if (yaml_item_get_value_by_key(yroot, (const char *)"meta", &ytitem1) != YAML_KEYSEARCH_FOUND) {
        printf("Key not exists: meta\n");
        ftwtestcollection_free(collection);
        return NULL;
    }
    else {
        if (yaml_item_get_value_by_key(ytitem1, (const char *)"enabled", &ytitem2) != YAML_KEYSEARCH_FOUND) {
            printf("Key not exists: enabled\n");
            ftwtestcollection_free(collection);
            return NULL;
        }
        else {
            collection->enabled = yaml_item_value_as_bool(ytitem2);
        }
    }

    // parse the list of tests only if the meta.enabled is true
    if (collection->enabled == TRUE) {
        if (yaml_item_get_value_by_key(yroot, (const char *)"tests", &ytests) != YAML_KEYSEARCH_FOUND) {
            printf("Key not exists: tests\n");
            ftwtestcollection_free(collection);
            return NULL;
        }
        else {
            if (ytests->type != YAML_VALTYPE_LIST) {
                printf("Test is not a list\n");
                ftwtestcollection_free(collection);
                return NULL;
            }
            else {

                // iterate the tests
                for(int t = 0; t < ytests->value.list->length; t++) {
                    yaml_item *ytest = ytests->value.list->list[t];
                    ftwtest *test = malloc(sizeof(ftwtest));
                    test->test_title = NULL;
                    test->desc = NULL;
                    test->rule_id = NULL;
                    test->test_id = NULL;
                    test->stages  = NULL;
                    test->stages_count = 0;
                    int test_need = 0;
                    if (yaml_item_get_value_by_key(ytest, (const char *)"test_title", &ytitem1) == YAML_KEYSEARCH_FOUND) {
                        test->test_title = strdup(ytitem1->value.sval);
                        char* token = strtok(ytitem1->value.sval, "-");
                        if (token != NULL) {
                            test->rule_id = strdup(token);
                            token = strtok(NULL, "-");
                            if (token != NULL) {
                                test->test_id = strdup(token);
                            }
                            else {
                                test->test_id = strdup("");
                            }
                        }
                        else {
                            test->rule_id = strdup(test->test_title);
                            test->test_id = strdup("");
                        }
                        ytitem1 = NULL;
                        if (rule_id == NULL || strcmp(rule_id, test->rule_id) == 0) {
                            if (test_id == NULL || strcmp(test_id, test->test_id) == 0) {
                                test_need = 1;
                                if (yaml_item_get_value_by_key(ytest, (const char *)"desc", &ytitem1) == YAML_KEYSEARCH_FOUND) {
                                    test->desc = strdup(ytitem1->value.sval);
                                    ytitem1 = NULL;
                                }
                                if (yaml_item_get_value_by_key(ytest, (const char *)"stages", &ytitem1) == YAML_KEYSEARCH_FOUND) {
                                    if (ytitem1->type != YAML_VALTYPE_LIST) {
                                        printf("Stages is not a list\n");
                                        return NULL;
                                    }
                                    else {
                                        test->stages       = calloc(1, sizeof(ftw_stage *));
                                        test->stages_count = 0;
                                        for(int si = 0; si < ytitem1->value.list->length; si++) {
                                            yaml_item *ystage = ytitem1->value.list->list[si];
                                            if (yaml_item_get_value_by_key(ystage, (const char *)"stage", &ytitem2) == YAML_KEYSEARCH_FOUND) {
                                                ystage       = ytitem2;
                                                ytitem2      = NULL;
                                            }
                                            ftw_stage *stage  = malloc(sizeof(ftw_stage));
                                            stage->input      = NULL;
                                            stage->output     = NULL;
                                            if (yaml_item_get_value_by_key(ystage, (const char *)"input", &ytitem2) == YAML_KEYSEARCH_FOUND) {
                                                stage->input = ftwinput_new(ytitem2);
                                                ytitem2      = NULL;
                                            }
                                            else {
                                                printf("input not found\n");
                                            }
                                            if (yaml_item_get_value_by_key(ystage, (const char *)"output", &ytitem2) == YAML_KEYSEARCH_FOUND) {
                                                stage->output = ftwoutput_new(ytitem2);
                                                ytitem2       = NULL;
                                            }
                                            test->stages_count++;
                                            test->stages = realloc(test->stages, test->stages_count * sizeof(ftw_stage *));
                                            test->stages[test->stages_count-1] = stage;

                                            // prepare the response based on the input
                                            if (stage->input->uri != NULL) {
                                                if (strlen(stage->input->uri) == 0) {
                                                    stage->output->response = calloc(strlen(response_ok)+1, sizeof(char));
                                                    stage->output->response_len = strlen(response_ok);
                                                    stage->output->response_code = 200;
                                                }
                                                else if (strcmp(stage->input->uri, "/anything") != 0 && strncmp(stage->input->uri, "/base64/", 8) != 0) {
                                                    stage->output->response = calloc(strlen(response_404)+1, sizeof(char));
                                                    strcpy(stage->output->response, response_404);
                                                    stage->output->response_len = strlen(response_404);
                                                    stage->output->response_code = 404;
                                                }
                                                else {
                                                    if (stage->input->data != NULL && strcmp(stage->input->uri, "/anything") == 0) {
                                                        stage->output->response = calloc(strlen(stage->input->data)+1, sizeof(char));
                                                        strcpy(stage->output->response, stage->input->data);
                                                        stage->output->response_len = strlen(stage->input->data);
                                                        stage->output->response_code = 200;
                                                    }
                                                    else if (strncmp(stage->input->uri, "/base64/", 8) == 0) {
                                                        size_t b64len = 0;
                                                        unsigned char *base64 = base64_decode(((const unsigned char *)stage->input->uri)+8, strlen(stage->input->uri)-7, &b64len);
                                                        stage->output->response = calloc(b64len+1, sizeof(char));
                                                        strcpy(stage->output->response, (const char *)base64);
                                                        stage->output->response_len = strlen((const char *)base64);
                                                        stage->output->response_code = 200;
                                                        free(base64);
                                                    }
                                                    else {
                                                        stage->output->response = calloc(strlen(response_ok)+1, sizeof(char));
                                                        strcpy(stage->output->response, response_ok);
                                                        stage->output->response_len = strlen(response_ok);
                                                        stage->output->response_code = 200;
                                                    }
                                                }
                                                {
                                                    time_t timeraw;
                                                    struct tm * timeinfo;
                                                    time(&timeraw);
                                                    timeinfo = gmtime(&timeraw);
                                                    stage->output->response_date = calloc(40, sizeof(char));
                                                    strftime(stage->output->response_date, 40, "%a, %d %b %Y %H:%M:%S GMT", timeinfo);
                                                }
                                            }
                                        }
                                    }
                                    ytitem1 = NULL;
                                }
                                else {
                                    printf("Key not exists: stages\n");
                                    return NULL;
                                }
                                // FIXME: Add stages
                                collection->tests = realloc(collection->tests, sizeof(ftwtest *) * (collection->test_count + 1));
                                collection->tests[collection->test_count++] = test;                                                               
                            }
                        }
                        if (test_need == 0) {
                            ftwtest_free(test);
                        }
                    }
                }
            }
        }
    }

    return collection;
}

