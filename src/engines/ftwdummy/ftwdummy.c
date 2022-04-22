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
// ftwdummy.v
// dummy WAF engine for testing

#include <string.h>
#include "ftwdummy.h"

// run a transaction
// a stage contains a transaction
int ftw_engine_runtest_dummy(ftw_engine * engine, char * title, ftw_stage *stage, int debug) {

    logCbText(NULL, "This is just a test log entry from dummy engine.");
    return FTW_TEST_PASS;
}