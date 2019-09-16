/*
 * This file is part of the ftwrunner distribution (https://github.com/digitalwave/ftwrunner).
 * Copyright (c) 2019 digitalwave and Ervin Hegedüs
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

#include "ftwrunner.h"

#include <time.h>
#include <pcre.h>
#include <sstream>
#include <string>
#include <vector>
#include <set>

#if PCRE_HAVE_JIT
#define pcre_study_opt PCRE_STUDY_JIT_COMPILE
#else
#define pcre_study_opt 0
#endif

#define OVECSIZE 100

#define FANCY(code, msg, modifier) fancy_print(test_title, code, #msg, modifier)

class Runner {
    public:
        Runner(modsecurity::ModSecurity * modsec, modsecurity::Rules * rule, std::set<std::string> whitelist);
        int runtests(std::string, std::string, bool);
        unsigned int cnt_passed = 0;
        unsigned int cnt_failed = 0;
        unsigned int cnt_skipped = 0;
        unsigned int cnt_disabled = 0;
        unsigned int cnt_failedwl = 0;
        unsigned int cnt_all = 0;
        std::vector<std::string> failed_list;
        std::vector<std::string> whitelisted_passed_list;
    private:
        modsecurity::ModSecurity *modsec;
        modsecurity::Rules * rules;
        void hexchar(unsigned char, unsigned char &, unsigned char &);
        void fancy_print(std::string, int, const char *, int);
        std::string urlencode(std::string);
        std::string unquote(std::string &);
        std::vector<std::string> split(std::string, char);
        std::vector<std::vector<std::string>> parse_qsl(std::string);
        std::string response_body;
        std::set<std::string> whitelist;
};

Runner::Runner(modsecurity::ModSecurity *arg_modsec, modsecurity::Rules * arg_rules, std::set<std::string> arg_whitelist) {
    modsec = arg_modsec;
    rules = arg_rules;
    whitelist = arg_whitelist;
    response_body = "";
    response_body += "<doctype>\n";
    response_body += "<html>\n";
    response_body += "  <heade>\n";
    response_body += "    <title>MSC test</title>\n";
    response_body += "  </head>\n";
    response_body += "  <body>This is the body</body>\n";
    response_body += "</html>\n";
    response_body += "\n";
}

void Runner::fancy_print(std::string test_title, int code, const char * msg, int modifier = 0) {
    std::cout << test_title << ": ";
    switch(code) {
        case FTW_TEST_PASS:
            if (modifier == 0) {
                std::cout<<"\033[92mPASSED\033[0m";
            }
            else {
                std::cout<<"\033[92mPASSED\033[32m - WHITELISTED\033[0m";
            }
            break;
        case FTW_TEST_FAIL:
            if (modifier == 0) {
                std::cout<<"\033[91mFAILED\033[0m";
            }
            else {
                std::cout<<"\033[31mFAILED - WHITELISTED\033[0m";
            }
            break;
        case FTW_TEST_DISA:
            std::cout<<"\033[90mDISABLED\033[0m";
            break;
        case FTW_TEST_SKIP:
            std::cout<<"\033[94mSKIPPED\033[0m";
            break;
    }
    if (strlen(msg) > 0) {
        std::cout << " " << msg;
    }
    std::cout << std::endl;
}

// https://gist.github.com/litefeel/1197e5c24eb9ec93d771
void Runner::hexchar(unsigned char c, unsigned char &hex1, unsigned char &hex2) {
    hex1 = c / 16;
    hex2 = c % 16;
    hex1 += hex1 <= 9 ? '0' : 'a' - 10;
    hex2 += hex2 <= 9 ? '0' : 'a' - 10;
}

std::string Runner::urlencode(std::string s) {
    const char *str = s.c_str();
    std::vector<char> v(s.size());
    v.clear();
    for (size_t i = 0, l = s.size(); i < l; i++) {
        char c = str[i];
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            c == '-' || c == '_' || c == '.' || c == '!' || c == '~' ||
            c == '*' || c == '\'' || c == '(' || c == ')') {
                v.push_back(c);
        } else if (c == ' ') {
            v.push_back('+');
        } else {
            v.push_back('%');
            unsigned char d1, d2;
            hexchar(c, d1, d2);
            v.push_back(d1);
            v.push_back(d2);
        }
    }

    return std::string(v.cbegin(), v.cend());
}
// / gist.github.com

// unquote string
std::string Runner::unquote(std::string &src) {
    std::string ret;
    char ch;
    unsigned int i, ii;
    for (i=0; i< (unsigned int)src.length(); i++) {
        if (src[i] == '%') {
            sscanf(src.substr(i+1, 2).c_str(), "%x", &ii);
            ch = static_cast<char>(ii);
            ret += ch;
            i += 2;
        }
        else {
            ret += src[i];
        }
    }
    return (ret);
}

// split string by delimiter
std::vector<std::string> Runner::split(std::string str, char delimiter) {
    std::vector<std::string> vstring;
    std::stringstream sstr(str);
    std::string token;
    ssize_t n = str.length();
    int i = 0;

    while (getline(sstr, token, delimiter)) {
        n -= token.length();
        if (i > 0) {
            n--;
        }
        vstring.push_back(n == 1 ? token + delimiter : token);
        i++;
    }

    return vstring;
}

// parse quoted string
std::vector<std::vector<std::string>> Runner::parse_qsl(std::string q) {
    std::vector<std::string> arguments = split(q, '&');
    std::vector<std::vector<std::string>> parsed;
    for(auto &arg: split(q, '&')) {
        std::vector<std::string> a = split(arg, '=');
        if (a.size() == 1) {
            a.push_back("");
        }
        if (a.size() == 2) {
            parsed.push_back(a);
        }
    }
    return parsed;
}

// run the tests collection, eg. a yaml file
int Runner::runtests(std::string infile, std::string testid, bool debug) {
    YAML::Node ftwtest = YAML::LoadFile(infile.c_str());

    extern std::vector<std::string> loglines;
    extern std::mutex loggerlock;

    const char *re_err_ptr = NULL;
    int re_err_offset;
    int rrc, pcre_found;
    int checkmod = 0;
    bool whitelisted = false;

    int status = FTW_TEST_FAIL;

    // test is enabled by default
    bool enabled = true;
    if (ftwtest["meta"]["enabled"]) {
        enabled = ftwtest["meta"]["enabled"].as<bool>();
    }
    if (enabled == false) {
        std::string basename = (infile.size() > 0) ? infile.substr(infile.find_last_of("/\\")+1, infile.size()-1) : "";
        std::cout << basename << ": tests not enabled in file, skipping...\n";
        return FTW_TEST_DISA;
    }
    // iterate tests
    for (std::size_t i=0; i<ftwtest["tests"].size(); i++) {
        const std::string test_title = ftwtest["tests"][i]["test_title"].as<std::string>();
        if (testid != "") {
            unsigned int _pos = test_title.find_last_of("-");
            if (_pos != std::string::npos) {
                if (test_title.substr(_pos+1, test_title.size()-1) != testid) {
                    continue;
                }
            }
        }
        whitelisted = false;
        if (whitelist.find(test_title) != whitelist.end()) {
            whitelisted = true;
        }

        // iterate stages
        for (std::size_t j=0; j < ftwtest["tests"][i]["stages"].size(); j++) {
            YAML::Node input  = ftwtest["tests"][i]["stages"][j]["stage"]["input"];
            YAML::Node output = ftwtest["tests"][i]["stages"][j]["stage"]["output"];

            if (input["encoded_request"]) {
                FANCY(FTW_TEST_SKIP, 'encoded_request' not implemented yet, 0);
                status = FTW_TEST_SKIP;
                cnt_skipped++;
                cnt_all++;
                continue;
            }
            else if (input["raw_request"]) {
                FANCY(FTW_TEST_SKIP, 'raw_request' not implemented yet, 0);
                status = FTW_TEST_SKIP;
                cnt_skipped++;
                cnt_all++;
                continue;
            }
            else if (output["status"]) {
                FANCY(FTW_TEST_SKIP, 'status' is HTTP server specific - test skipped, 0);
                status = FTW_TEST_SKIP;
                cnt_skipped++;
                cnt_all++;
                continue;
            }
            else if (output["expect_error"]) {
                FANCY(FTW_TEST_SKIP, 'expect_error' is HTTP server specific - test skipped, 0);
                status = FTW_TEST_SKIP;
                cnt_skipped++;
                cnt_all++;
                continue;
            }
            // default values
            std::string dest_addr = "127.0.0.1";
            int port = 80;
            std::string method = "GET";
            // std::string protocol = "http"; // not needed
            std::string uri = "/";
            std::string version = "HTTP/1.1";
            std::string data = "";
            bool stop_magic = false;

            std::string log_contains = "";
            std::string no_log_contains = "";

            // read values - see the macros above
            READSTRING(input, dest_addr);
            READINT(input, port);
            READSTRING(input, method);
            READSTRING(input, uri);
            READSTRING(input, version);
            READBOOL(input, stop_magic);

            READSTRING(output, log_contains);
            READSTRING(output, no_log_contains);

            if (log_contains == "" && no_log_contains == "") {
                FANCY(FTW_TEST_SKIP, No valid test output, 0);
                status = FTW_TEST_SKIP;
                cnt_skipped++;
                cnt_all++;
                continue;
            }

            std::size_t pos = version.find("/");
            std::string _proto = version.substr(0, pos);
            std::string _vers = version.substr(pos+1, version.length()-1);
            if (_proto != "HTTP") {
                FANCY(FTW_TEST_SKIP, Only HTTP protocol allowed (given: '" << _proto << "' - full: '" << version << "'), 0);
                status = FTW_TEST_SKIP;
                cnt_skipped++;
                cnt_all++;
                continue;
            }

            // read data - check it's string or list of strings
            if (input["data"]) {
                if (input["data"].IsScalar()) {
                    READSTRING(input, data);
                }
                else if (input["data"].IsSequence()) {
                    std::vector<std::string> vdata = input["data"].as<std::vector<std::string>>();
                    for (std::size_t s=0; s < vdata.size(); s++) {
                        data += vdata[s];
                        if (s < vdata.size()-1) {
                            data += "\r\n";
                        }
                    }
                }
            }

            // clear log lines
            loggerlock.lock();
            loglines.clear();
            loggerlock.unlock();

            // Transaction and Interveniation instances
            modsecurity::Transaction *trans = new modsecurity::Transaction(modsec, rules, NULL);
            modsecurity::ModSecurityIntervention *it = new modsecurity::ModSecurityIntervention();

            // phase 0
            trans->processConnection("127.0.0.1", 33333, dest_addr.c_str(), port);
            trans->processURI(uri.c_str(), method.c_str(), _vers.c_str());
            trans->intervention(it);

            bool ct_sent = false; // Content-Type sent?
            bool cl_sent = false; // Content-Length sent?
            bool ah_sent = false; // Accept header sent? - this is plus against the ftw
            std::string ct = "";  // Content-Type value

            if (input["headers"]) {
                YAML::Node headerType = input["headers"];
                for(YAML::const_iterator it=headerType.begin(); it != headerType.end(); ++it) {
                    const std::string key = it->first.as<std::string>();      // key
                    const std::string val = it->second.as<std::string>();     // val
                    //std::cout << key << " ==> " << val << "\n";
                    trans->addRequestHeader(key, val);
                    if (key == "Content-Type") {
                        ct_sent = true;
                        ct = val;
                    }
                }
            }
            if (data != "") {
                if (ct_sent == false && stop_magic == false) {
                    trans->addRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                }
                if (ct == "application/x-www-form-urlencoded" && stop_magic == false) {
                    if (unquote(data) == data) {
                        std::string qs = "";
                        for(auto &p: parse_qsl(data)) {
                            if (p[1] != "") {
                                qs += urlencode(p[0]) + "=" + urlencode(p[1]) + "&";
                            }
                            else {
                                qs += p[0] + "&";
                            }
                        }
                        data = qs.substr(0, qs.size()-1);
                    }
                }
                if (cl_sent == false && stop_magic == false) {
                    trans->addRequestHeader("Content-Length", std::to_string(data.length()));
                }
                if (ah_sent == false && stop_magic == false) {
                    trans->addRequestHeader("Accept", "*/*");
                }
                trans->appendRequestBody((const unsigned char *)data.c_str(), data.length());
            }
            // phase 1
            trans->processRequestHeaders();
            trans->intervention(it);

            // phase 2
            trans->processRequestBody();
            trans->intervention(it);

            // prepare add response headers, eg. date and time
            time_t timeraw;
            struct tm * timeinfo;
            char timebuff [40];

            time(&timeraw);
            timeinfo = gmtime(&timeraw);
            strftime(timebuff, 40, "%a, %d %b %Y %H:%M:%S GMT", timeinfo);

            trans->addResponseHeader("Date", timebuff);
            trans->addResponseHeader("Server", "Ftwrunner");
            trans->addResponseHeader("Content-Type", "text/html; charset=UTF-8");
            trans->addResponseHeader("Content-Length", std::to_string(response_body.size()));

            trans->appendResponseBody((const unsigned char *)response_body.c_str(), response_body.size());

            // phase 4
            trans->processResponseHeaders(200, "HTTP/1.1");
            trans->intervention(it);

            // phase 5
            trans->processResponseBody();
            trans->intervention(it);
    
            delete trans;

            loggerlock.lock();
            // check logs

            pcre *re = NULL;
            pcre_extra *ree = NULL;
            int ovector[OVECSIZE];
    
            if (log_contains != "") {
                re = pcre_compile(log_contains.c_str(), PCRE_DOTALL|PCRE_MULTILINE, &re_err_ptr, &re_err_offset, NULL);
                checkmod = 1;
            }
            else if (no_log_contains != "") {
                re = pcre_compile(no_log_contains.c_str(), PCRE_DOTALL|PCRE_MULTILINE, &re_err_ptr, &re_err_offset, NULL);
                checkmod = -1;
            }
            ree = pcre_study(re, pcre_study_opt, &re_err_ptr);
            rrc = 0;
            pcre_found = 0;
            for(auto &l: loglines) {
                pcre_found = pcre_exec(re, ree, l.c_str(), l.length(), 0, 0, ovector, OVECSIZE);
                if (pcre_found > 0) {
                    rrc++;
                }
                if (rrc > 0) {
                    if (checkmod == 1) {
                        status = FTW_TEST_PASS;
                    }
                    else {
                        status = FTW_TEST_FAIL;
                    }
                    break;
                }
            }
            if (rrc <= 0) {
                if (checkmod == 1) {
                    status = FTW_TEST_FAIL;
                }
                else {
                    status = FTW_TEST_PASS;
                }
            }
            if (status == FTW_TEST_FAIL && debug == true) {
                for(auto &l: loglines) {
                    std::cout << l << std::endl;
                }
            }

            pcre_free(re);
#if PCRE_HAVE_JIT
            pcre_free_study(ree);
#else
            pcre_free(ree);
#endif
            if (status == FTW_TEST_PASS) {
                //std::cout << "PASSED\n";
                cnt_passed++;
                cnt_all++;
                if(whitelisted == true) {
                    whitelisted_passed_list.push_back(test_title);
                    FANCY(FTW_TEST_PASS, , 1);
                }
                else {
                    FANCY(FTW_TEST_PASS, , 0);
                }
            }
            if (status == FTW_TEST_FAIL) {
                if (whitelisted == true) {
                    FANCY(FTW_TEST_FAIL, , 1);
                    cnt_failedwl++;
                    cnt_all++;
                }
                else {
                    FANCY(FTW_TEST_FAIL, , 0);
                    cnt_failed++;
                    cnt_all++;
                    failed_list.push_back(test_title);
                }
            }
            loglines.clear();
            loggerlock.unlock();
        }

    }
    return status;
}


