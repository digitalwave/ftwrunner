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
// ftwcoraza.h
// Coraza WAF engine for testing

#include "../engines.h"

#ifndef FTW_ENGINE_CORAZA
#define FTW_ENGINE_CORAZA
#ifdef HAVE_LIBCORAZA

#include <coraza/core.h>
#include <coraza/utils.h>

#define N_INTERVENTION_STATUS 200

void * ftw_engine_init_coraza();
void * ftw_engine_create_rules_set_coraza(void * engine_instance, char * main_rule_uri, const char ** error);
int    ftw_engine_runtest_coraza(ftw_engine * engine, char * title, ftw_stage *stage, int debug);

void   ftw_engine_cleanup_coraza(void * waf);

#endif
#endif
