/*
 * This file is part of the ftwrunner distribution (https://github.com/digitalwave/ftwrunner).
 * Copyright (c) 2022 digitalwave and Ervin Hegedüs.
 *
 * Except base64_decode
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
// ftwtestutils.h
// helper functions for tests

#ifndef FTWTE_UTILS_H
#define FTWTE_UTILS_H

void            hexchar(unsigned char c, unsigned char *hex1, unsigned char *hex2);
char          * urlencode(const char * s);
char          * unquote(char * src);
void            parse_qs(char * q, char **** parsed, int * parsed_count);
unsigned char * base64_decode(const unsigned char *src, size_t len, size_t *out_len);

#endif