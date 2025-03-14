#include "../engines.h"

#ifndef FTW_ENGINE_MODSECURITY
#define FTW_ENGINE_MODSECURITY
#ifdef HAVE_MODSECURITY

#include <modsecurity/modsecurity.h>
#include <modsecurity/intervention.h>

#define N_INTERVENTION_STATUS 200

#ifdef MODSECURITY_CHECK_VERSION
#if MODSECURITY_VERSION_NUM >= 304010
#define MSC_USE_RULES_SET 1
#endif
#endif

#ifdef MSC_USE_RULES_SET
#include <modsecurity/rules_set.h>
#else
#include <modsecurity/rules.h>
#endif

void * ftw_engine_init_msc();
void * ftw_engine_create_rules_set_msc(void * engine_instance, char * main_rule_uri, const char ** error);
int    ftw_engine_runtest_msc(ftw_engine * engine, char * title, ftw_stage *stage, int debug, int verbose);

void   ftw_engine_cleanup_msc(void * modsec);

#endif
#endif
