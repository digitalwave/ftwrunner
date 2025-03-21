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
// ftwrunner.h
// macros for ftwrunner
//

#ifndef _FTWRUNNER_H_
#define _FTWRUNNER_H_

#define PRGNAME "ftwrunner"
#define FTWRUNNER_YAML "ftwrunner.yaml"

#define FTW_FREE_STRING(p) { \
        if(p != NULL) { \
            free(p); \
            p = NULL; \
        } \
    }
#define FTW_FREE_STRINGLIST(p) { \
        if (p != NULL) { \
            int i = 0; \
            while(p[i] != NULL) { \
                free(p[i++]); \
            } \
            free(p); \
        } \
    }

#endif