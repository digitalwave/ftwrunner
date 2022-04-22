/*
 * This file is part of the ftwrunner distribution (https://github.com/digitalwave/ftwrunner).
 * Copyright (c) 2022 digitalwave and Ervin Hegedüs.
 *
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
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
// ftwtestutils.c
// helper functions for tests

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "ftwtestutils.h"

/*
 * Tools
 */

// https://gist.github.com/litefeel/1197e5c24eb9ec93d771
// arguments:
// * c: input character
// * hex1: first hex digit
// * hex2: second hex digit
void hexchar(unsigned char c, unsigned char *hex1, unsigned char *hex2) {
    *hex1 = c / 16;
    *hex2 = c % 16;
    *hex1 += *hex1 <= 9 ? '0' : 'A' - 10;
    *hex2 += *hex2 <= 9 ? '0' : 'A' - 10;
}

// urlencode the string
char * urlencode(const char * s) {
    char * v = calloc(sizeof(char), (strlen(s)+1)*3);
    // *3: assume we need 3 bytes for each char
    size_t j = 0;
    for (size_t i = 0; i < strlen(s); i++) {
        char c = s[i];
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            c == '-' || c == '_' || c == '.' || c == '!' || c == '~' ||
            c == '*' || c == '\'' || c == '(' || c == ')') {
                v[j++] = c;
        } else if (c == ' ') {
            v[j++] = '+';
        } else {
            v[j++] = '%';
            unsigned char d1, d2;
            hexchar(c, &d1, &d2);
            v[j++] = d1;
            v[j++] = d2;
        }
    }
    return v;
}

// unquote the string
char * unquote(char * src) {
    char * ret = calloc(sizeof(char), strlen(src) + 1);
    // assume there is no char to unquote in source
    char ch;
    size_t i;
    unsigned int ii;
    int j = 0;
    for (i=0; i< strlen(src); i++) {
        if (src[i] == '%') {
            char substr[3];
            if (i < strlen(src) - 2) {
                if (isxdigit(src[i+1]) && isxdigit(src[i+2])) {
                    substr[0] = src[i+1];
                    substr[1] = src[i+2];
                    substr[2] = '\0';
                    sscanf(substr, "%x", &ii);
                    ch = (char) ii;
                    ret[j++] = ch;
                    i += 2;
                } else {
                    ret[j++] = src[i];
                }
            } else {
                ret[j++] = src[i];
            }
        }
        else {
            ret[j++] = src[i];
        }
    }
    return ret;
}

// parse query string
// arguments:
// * q: input string
// * parsed: output array
// * parsed_count: output count
//
// example:
// char * q = "a=1&b=2&c=3";
// ***parsed: {{a, 1}, {b, 2}, {c, 3}}
// ***parsed_count: 3

void parse_qs(char * q, char **** parsed, int * parsed_count) {

    char *token         = NULL;

    while ((token = strtok_r(q, "&", &q))) {
        if (token != NULL) {
            int c = 0;
            size_t tlen = strlen(token);
            // find the first '='
            for (c = 0; c < tlen && token[c] != '='; c++);

            (*parsed) = realloc((*parsed), sizeof(char**) * ((*parsed_count) + 1));
            (*parsed)[*parsed_count] = malloc(sizeof(char*) * 2);
            // set key and val if there is a '=' in the middle of the token
            if (c > 0 && c < tlen) {
                (*parsed)[*parsed_count][0] = calloc(c+1, sizeof(char));
                strncpy((*parsed)[*parsed_count][0], token, c);
                (*parsed)[*parsed_count][1] = strdup(token + c + 1);
            } else {
                // otherwise handle the spec cases
                if (c == 0) {
                    // eg. query string part is '=foo'
                    (*parsed)[*parsed_count][0] = NULL;
                    (*parsed)[*parsed_count][1] = strdup(token);
                }
                else {
                    // or query string part is 'foo=' or '===='
                    (*parsed)[*parsed_count][0] = strdup(token);
                    (*parsed)[*parsed_count][1] = NULL;
                }
            }
            (*parsed_count)++;
        }
    }

    return;
}

/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

/*
 * replaced os_* functions with plain C
 */

static const unsigned char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
unsigned char * base64_decode(const unsigned char *src, size_t len,
			      size_t *out_len)
{
	unsigned char dtable[256], *out, *pos, block[4], tmp;
	size_t i, count, olen;
	int pad = 0;

	memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[base64_table[i]] = (unsigned char) i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return NULL;

	olen = count / 4 * 3;
	pos = out = calloc(olen+1, sizeof(unsigned char));
	if (out == NULL)
		return NULL;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
					/* Invalid padding */
					free(out);
					return NULL;
				}
				break;
			}
		}
	}

	*out_len = pos - out;
	return out;
}

/*
 * End Tools
 */