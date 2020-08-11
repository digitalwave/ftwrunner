#ifndef FTWRUNNER_H
#define FTWRUNNER_H

#include <iostream>
#include <mutex>
#include <yaml-cpp/yaml.h>

#include <modsecurity/modsecurity.h>

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

#include <modsecurity/rule_message.h>
#include <modsecurity/transaction.h>

#define PRGNAME "ftwrunner"
#define FTWRUNNER_YAML "ftwrunner.yaml"

#define FTW_TEST_PASS 0
#define FTW_TEST_FAIL 1
#define FTW_TEST_DISA 2
#define FTW_TEST_SKIP 4

#define READSTRING(src, name) if (src[#name]) { name = src[#name].as<std::string>(); }
#define READINT(src, name)    if (src[#name]) { name = src[#name].as<int>(); }
#define READBOOL(src, name)   if (src[#name]) { name = src[#name].as<bool>(); }

#endif

