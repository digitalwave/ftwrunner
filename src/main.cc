/*
 * This file is part of the ftwrunner distribution (https://github.com/digitalwave/ftwrunner).
 * Copyright (c) 2019 digitalwave and Ervin Hegedüs.
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

#include <string>
#include "ftwrunner.h"
#include "ftree.h"
#include "runner.h"

#define READYAMLCONF(config)         try { \
            YAML::Node runnerconf = YAML::LoadFile(config); \
            READSTRING(runnerconf, modsecurity_config); \
            READSTRING(runnerconf, ftwtest_root); \
            if (runnerconf["test_whitelist"].IsSequence()) { \
                std::vector<std::string> _whitelist = runnerconf["test_whitelist"].as<std::vector<std::string>>(); \
                for(auto w: _whitelist) { \
                    test_whitelist.insert(w); \
                } \
            } \
        } \
        catch (YAML::BadFile &) { \
            std::cout << "Can't open file: " << config << std::endl; \
            showhelp(); \
            return -1; \
        }

#define CHECKARG(arg, sw, st)  if(std::string(arg) == #sw) { state = #st; }

std::vector<std::string> loglines;
std::mutex loggerlock;

// need for modsecurity::ModSecurity instance
static void logCbText(void *data, const void *msg) {
    if (msg == NULL) {
        std::cout << "I was called but the message was null ;(";
        std::cout << std::endl;
        return;
    }

    //std::cout << "--->" << reinterpret_cast<const char *>(msg) << std::endl;
    loggerlock.lock();
    loglines.push_back(reinterpret_cast<const char *>(msg));
    loggerlock.unlock();
    return;
}

void showhelp() {
    std::cout << " -h This help" << std::endl;
    std::cout << " -c Use alternative config instead of ftwrunner.yaml in same directory" << std::endl;
    std::cout << " -m Use alternative ModSecurity config instead of in default config" << std::endl;
    std::cout << " -f Use alternative ftw test collection instead of in default config" << std::endl;
    std::cout << " -r Use only this ruleset, eg. '-r 911100'" << std::endl;
    std::cout << " -t Use only this test of all, eg. '-t 1'" << std::endl;
    std::cout << " -d Debug mode - in case of FAILED test the error log lines showed" << std::endl;
}

int main(int argc, char **argv) {

    modsecurity::ModSecurity *modsec;
    modsecurity::Rules *rules;
    int rc;
    std::string modsecurity_config = "";
    std::string ftwtest_root = "";
    std::string modsecurity_config_cli = "";
    std::string ftwtest_root_cli = "";
    std::set<std::string> test_whitelist;
    std::string test_to_run_cli = "";
    std::string ruleset_to_run_cli = "";
    std::string state = "";
    bool debug = false;

    READYAMLCONF(FTWRUNNER_YAML);
    if (argc > 1) {
        // if cli arguments...
        for(int a=1; a < argc; a++) {

            if(std::string(argv[a]) == "-h") {
                std::cout << "This is " << PRGNAME << std::endl;
                std::cout << "Avaliable arguments:" << std::endl;
                showhelp();
                return 0;
            }

            if (state == "rconf") { READYAMLCONF(argv[a]); state = ""; }
            if (state == "msconf") { modsecurity_config_cli = std::string(argv[a]); state = ""; }
            if (state == "ftconf") { ftwtest_root_cli = std::string(argv[a]); state = ""; }
            if (state == "test") { test_to_run_cli = std::string(argv[a]); state = ""; }
            if (state == "ruleset") { ruleset_to_run_cli = std::string(argv[a]); state = ""; }

            CHECKARG(argv[a], -c, rconf);
            CHECKARG(argv[a], -m, msconf);
            CHECKARG(argv[a], -f, ftconf);
            CHECKARG(argv[a], -r, ruleset);
            CHECKARG(argv[a], -t, test);

            if(std::string(argv[a]) == "-d") {
                debug = true;
            }

        }
        if (state != "") {
            std::cout << "Error while parsing command line argument!" << std::endl;
            return -1;
        }
    }
    // overwrite variables with given arguments
    if (modsecurity_config_cli != "") {
        modsecurity_config = modsecurity_config_cli;
    }
    if (ftwtest_root_cli != "") {
        ftwtest_root = ftwtest_root_cli;
    }

    if (modsecurity_config == "" || ftwtest_root == "") {
        std::cout << "Modsecurity config path or ftw test root path is missing!" << std::endl;
        return -1;
    }

    if (test_to_run_cli != "" && ruleset_to_run_cli == "") {
        std::cout << "Test number could pass only when ruleset passed!" << std::endl;
        return -1;
    }

    // create ModSec instance
    modsec = new modsecurity::ModSecurity();
    // set the callback function for logging - see the possible arguments behind the comment
    modsec->setServerLogCb(logCbText); //, modsecurity::RuleMessageLogProperty); // | modsecurity::IncludeFullHighlightLogProperty);
    // create a Rule instance
    rules = new modsecurity::Rules();
    // load config
    rc = rules->loadFromUri(modsecurity_config.c_str());
    if (rc < 0) {
        std::cout << "Can't load rules: " << rules->m_parserError.str() << std::endl;
        return rc;
    }

    // get the list of yaml test files, run the tests
    Ftree ftree(ftwtest_root, ruleset_to_run_cli);
    ftree.walk();
    // create a Runner instance, iterate the tests
    Runner runner(modsec, rules, test_whitelist);
    for(auto f: ftree.filelist) {
        runner.runtests(f, test_to_run_cli, debug);
    }

    std::cout << std::endl << "SUMMARY:" << std::endl;
    std::cout << "===============================" << std::endl;
    std::cout << "PASSED:                   " << runner.cnt_passed << std::endl;
    std::cout << "FAILED:                   " << runner.cnt_failed << std::endl;
    std::cout << "FAILED (whitelisted):     " << runner.cnt_failedwl << std::endl;
    std::cout << "SKIPPED:                  " << runner.cnt_skipped << std::endl;
    std::cout << "===============================" << std::endl;
    std::cout << "TOTAL:                    " << runner.cnt_all << std::endl;
    std::cout << "===============================" << std::endl;
    if (runner.failed_list.size() > 0) {
        std::cout << "FAILED TESTS:             ";
        for(size_t i = 0; i < runner.failed_list.size(); i++) {
            std::cout << runner.failed_list[i];
            if (i < runner.failed_list.size()-1) {
                std::cout << ", ";
            }
            else {
                std::cout << std::endl;
            }
        }
        std::cout << "===============================" << std::endl;
    }
    if (runner.whitelisted_passed_list.size() > 0) {
        std::cout << "PASSED WHITELISTED TESTS: ";
        for(size_t i = 0; i < runner.whitelisted_passed_list.size(); i++) {
            std::cout << runner.whitelisted_passed_list[i];
            if (i < runner.whitelisted_passed_list.size()-1) {
                std::cout << ", ";
            }
            else {
                std::cout << std::endl;
            }
        }
    }

    delete rules;
    delete modsec;

    return runner.cnt_failed;

}
    