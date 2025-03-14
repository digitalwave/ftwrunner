ftwrunner
=========

Welcome to the `ftwrunner` documentation. I'ld try to show this tool to every ModSecurity users, who's interesting about the rules and its tests.

Motivation
==========

I help to maintain the code of [ModSecurity](https://modsecurity.org) (especially the [libmodsecurity3](https://github.com/owasp-modsecurity/ModSecurity)). A most important goal that get the state that the [CRS](https://coreruleset.org) can work together with libmodsecurity3, without errors: false positives and not working rules.

[CRS](https://github.com/coreruleset/coreruleset) has a very good tool to test all of the rules, it's called [go-ftw](https://github.com/coreruleset/go-ftw), but it works only with a supported webserver - consequently a HTTP server is required. Go-ftw uses [sets of tests](https://github.com/coreruleset/coreruleset/tree/main/tests/regression/tests), which are divided to different sections, represented the attack type. Each section has a multiple test files, which represented the rules: every file named by the rule id. And finally, all ruleset has one or more test.

These tests were written in [YAML](https://yaml.org/) format. The used schema is well documented on [ftw-tests-schema](https://github.com/coreruleset/ftw-tests-schema)


Libmodsecurity3 has written in C++, and - therefore as a library - has an [API](https://github.com/owasp-modsecurity/ModSecurity#simple-example-using-c). The library has an own regression test framework, but mostly it's useful to tests the different functions one by one.

As I wrote, my main goal is to adjusting the libmodsecurity3 code to use those rules, so I needed a tool, which I can test with the whole ruleset without any other external distractions, eg. webserver responses, other behaviors, etc...

At first time, I've made a very ugly HTTP server, but it just generated more problems rather than taken away them.

Then the idea came - use the API, but not through the HTTP: inject the existing YAML tests to API directly.

That is why this tool was created.

In version v1.0 I added [Coraza](https://github.com/corazawaf/coraza) support too, through [libcoraza](https://github.com/corazawaf/libcoraza), and I completely rewrited the whole tool in pure C.

Prerequisites
=============

`ftwrunner` was designed to run on Linux, but I think it runs on most Unix systems.

To build the `ftwrunner`, you need:

+ a **C compiler**, I used **gcc**
+ **autotools**, **make**
+ of course, need the compiled and installed **libmodsecurity3**
+ and/or **coraza** and **librcoraza**
+ **pcre2** - the **new** version
+ **libyaml**

You have to install them on Debian with this command:

```
sudo apt install gcc make autotools libpcre2-dev libpcre2-8-0 libyaml-dev
```
and - as I wrote above - an installed libmodsecurity3 and/or libcoraza.

(Note: unfortunately libcoraza is a very beta state at the moment, and it does not work.)

*Note: Debian 10 and Debian 11 contains the libmodsecurity3 package, but since it released, there are so much modification in the code, so I **strongly suggest** that you get a clone with git, and compile it for yourself. Optionally, you can use our Debian repository: [https://modsecurity.digitalwave.hu](https://modsecurity.digitalwave.hu)*

Compile the code
================

It's simple, grab the code, and type this commands:

```
$ autoreconf --install
$ ./configure
```

At the and of `./configure`, you will get a report:

```
----------------------------------------------------------------------

 ftwrunner Version 1.0 configuration:

 OS Type        Linux
 Prefix         /usr/local
 Preprocessor   gcc -E 
 C Compiler     gcc -g -O2
 CPPCHECK       cppcheck
 Engines:
    modsecurity  yes
    coraza       yes

-----------------------------------------------------------------------
```

Then type

```
$ make
```

and if you want to install it to your system, type

```
$ sudo make install
```

This will be installed to /usr/local/bin directory.

If everything was right, a new file created until `src/` in your project directory with name `ftwrunner`. Copy it to where you want to use, eg. to your project dir:
```
$ cp src/ftwrunner .
```

How does it work
================

Prepare the configuration file
------------------------------

In the source directory, there is a configuration file, called `ftwrunner.yaml.example`. `ftwrunner` doesn't need that, but I think it helps your work. If you want to use that, make a copy from that:
```
$ cp ftwrunner.yaml.example ftwrunner.yaml
```
and edit the options what you found there. Here is the content:
```
modsecurity_config: /etc/nginx/modsecurity_includes.conf
ftwtest_root: /path/to/owasp-modsecurity-crs/util/regression-tests/tests
test_whitelist:
- 941190-3 # known MSC bug - PR #2023 (Cookie without value)
- 941330-1 # know MSC bug - #2148 (double escape)
```

If you run `ftwrunner`, it's also try to open this file first, and if it done, uses the variables. There are two mandatory variable: `modsecurity_config` and `ftwtest_root`. Both of them can be overwritten with the command line arguments. As I wrote, you don't need this file with this name, but you can pass to `ftwrunner` another one with cli argument `-c /path/to/config.yaml`.

Content of config file
----------------------

I suppose you use separated config files, at least your WAF config. When `ftwrunner` runs, it reads the whole config as your web server, so if your debug.log/audit.log is turned on, `ftwrunner` also wants to write it.

The best what you can do is make a single config file what you pass to `ftwrun`, and through that file the runner includes the other ones. This config file can be `modsecurity_includes.conf`.

Make a copy of your `modsecurity.conf` or `coraza.conf`. Make any modifications what you want (turn on/off the logs, change the log paths, and so on.)

Put the name of this file into `modsecurity_includes.conf`:

```
include modsecurity.conf
# or
include coraza.conf
```

Then find the file which loads your CRS setup file, before and after loaders, and the rules. Put that file too into the `modsecurity_includes.conf`. Now your file looks like this:

```
$ cat modsecurity_includes.conf 
include modsecurity.conf
include /path/to/coreruleset/owasp-crs.load
```

and my `owasp-crs.load` contains:

```
include /path/to/coreruleset/crs-setup.conf
include /path/to/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
include /path/to/coreruleset/rules/*.conf
include /path/to/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
```

**AGAIN: if you set up the debug in that config (`SecDebugLog /var/log/nginx/modsec_debug.log`), libmodsecurity3 wants to open it when it starts, so you have to give the permissions to the user what you run, or use a copy and change this variable, or turn off debug log. No, you don't want to run it as root.**

**Also please make sure if you copy your `modsecurity.conf`, that you copy the `unicode.mapping` file too.**

You can overwrite the `modsecurity_config: modsecurity_include.conf` variable with cli argument `-m /path/to/config`.

`ftwtest_root` - path to your regression tests root directory. It's depend on your config, version, etc... and also can be overwriten with a cli argument `-f /path/to/coreruleset/tests/regression/tests`.

Note, that it's generally useful if you don't want to run all tests in that directory, just a subset. Here is an example:
```
$ ./ftwrunner -f /path/to/coreruleset/tests/regression/tests/REQUEST-920-PROTOCOL-ENFORCEMENT/
```

`test_whitelist` - this is **not** a mandatory option, but can be useful to lists the tests titles, what you know that will FAILED. You can place a comment after the test title with a `#`, see example:

```
test_whitelist:
- 941190-3 # known MSC bug - PR #2023 (Cookie without value)
- 941330-1 # know MSC bug - #2148 (double escape)
- 942480-2 # known MSC bug - PR #2023 (Cookie without value)
- 944100-11 # known MSC bug - PR #2045, ISSUE #2146
- 944100-12
- 944100-15
- 944100-16
```

Command line options
--------------------

With the command line options you can overwrite the two mandatory options above, and can extend the functions. See them:

`-h` - gives a short help

`-c /path/to/alternative.yaml` - you can choose another config file, than the default

`-m /path/to/another/modsecurity.conf` - as described above, you can change the default ModSecurity config file

`-f /path/to/another/ftw/test/root` - as you can see above, it could be a 'root' directory (`ftwrunner` will walk the tree), or for a rule, or just one file.

`-r ruleid` - if you don't want to pass the `-f /path/to/ftwtest/root/group-of-rules/rule.yaml`, then just pass this option with a rule id, eg:

```
$ ./ftwrunner -r 942210
```

Note, that these argument lists are equals:

`$ ./ftwrunner -f /path/to/942210.yaml` and `$ ./ftwrunner -f /path/to -r 942210`, so if you passed a regular file, `ftwrunner` set it up as ruleid.

`-t test_title` - if you want to run only one test case for a rule, not the whole set, just pass this argument. Note, that you can use this only with `-r`. Example:

```
$ ./ftwrunner -r 942380 -t 20
```

this command will run the test only for rule id `942380` with test title `942380-20`. The value of this argument need to match exactly as the title after `-` sign. If the title ends with `...-1FP`, you have to pass `-t 1FP`. Note, that this argument can be used only **with** the `-r ruleid`. Without `-r` it makes no sense.

`-e engine` - sets the engine. Available engines are `dummy` (default), `modsecurity` and `coraza`. The `modsecurity` and `coraza` engines are options only if the build flow finds the libraries.

`-d` - turn on the debug mode. This means, if a test FAILED, `ftwrunner` shows the error log immediately below the test line, what you would see in your webserver's error.log.

Output
------

The tests runs one after one. The rules are sorted, the first test is the lower. A set of test will skipped, if the yaml file `meta` section contains `enabled: false`. In this case, you will see just this line:

```
920250.yaml: tests not enabled in file, skipping...
```

Otherwise, the tests will runs.

*Note, that this tests will not counts anywhere at final summary.*

`ftwrunner` can evaulates only those tests, which checks the error log. If the original `ftw` expects the HTTP status code or any HTTP error, then it can't catch it, so if the test output expects `status` or `expects_error`, then it will be SKIPPED. There is an another criteria to run the test: if the test input section gives `raw_request` or `encoded_request`, then test also will SKIPPED - these keywords are not implemented yet. If a test SKIPPED, then the the reason will showed.

The runned tests can generate three main types of output:

* SKIPPED - see criterias above; note, that the reason will showed, why test skipped
* PASSED - if the output of request with given data matched the result(s) (eg. `log_contains` pattern found in the generated log lines, or `no_log_contains` pattern not found in that), then the test passed
* FAILED - if none of them above

There are two mutations of the results PASSED and FAILED: if a test PASSED, but you listed it in your `test_whitelist`, then the output will `PASSED - WHITELISTED`. This is important, because you will informed that the bug eliminated. You will also noticed if the test FAILED, but that's expected by a know reason, eg: `FAILED - WHITELISTED`.

When the all tests finished, `ftwrunner` will inform you with a summary:

```
SUMMARY:
===============================
PASSED:                   14
FAILED:                   0
FAILED (whitelisted):     4
SKIPPED:                  0
===============================
TOTAL:                    18
===============================
```

From this table, you can see how many test was PASSED, FAILED, SKIPPED. The whitelisted failed tests will showed separately.

If there are one or more failed test, the summary will extended with the list of those:

```
SUMMARY:
===============================
PASSED:                   14
FAILED:                   2
FAILED (whitelisted):     2
SKIPPED:                  0
DISABLED:                 0
===============================
TOTAL:                    18
===============================
FAILED TESTS:             944110-15, 944110-16
```

It can helps you if you run a whole set of tests (actually it's more, that 2000), and then you can check them one by one.

Return value
------------

When `ftwrunner` terminates, the return value will be 0 if there isn't any error or failed test. If the error occurred until the run (eg. your config file not found, can't open the debug.log, ...), the return value vill be less than 0 (usually -1). If there were one or more failed test, the return value will be greather than 0, it will the number of failed test. See the example above:

```
$ ./ftwrunner -r 944110
944110-1: PASSED
...
SUMMARY:
===============================
PASSED:                   14
FAILED:                   2
FAILED (whitelisted):     2
SKIPPED:                  0
DISABLED:                 0
===============================
TOTAL:                    18
===============================
FAILED TESTS:             944110-15, 944110-16
===============================
$ echo $?
2
```

Use `ftwrunner` with Valgrind
=============================

`ftwunner` can help to discover memory leaks in the library. It's highly recommended to make a minimal configuration (eg. only 1 rule) and make a test for that rule. Then you will see only the specific place where the memleak occurrs.

Here is how do I do that.

Create a new `ftwrunner` config:
```
$ cat ftwrunner-valgrind.yaml
modsecurity_config: modsecurity_valgrind.conf
#modsecurity_config: modsecurity_temp.conf
ftwtest_root: /home/airween/src/coreruleset/tests/regression/tests/
```
Create a `new modsecurity_valgrind.conf` file in same directory:
```
include modsecurity.conf

SecRule REQUEST_METHOD "!strEq GET" \
    "id:911100,\
    phase:1,\
    block,\
    msg:'Method is not allowed by policy',\
    logdata:'%{MATCHED_VAR}',\
    severity:'CRITICAL'"
```
Copy your original `modsecurity.conf` and `unicode.mapping` files into the same directory:
```
$ cp /path/to/your/modsecurity.conf .
$ cp /path/to/your/unicode.mapping .
```
Try your setup first:
```
$ src/ftwrunner -e modsecurity -c ftwrunner-valgrind.yaml -r 911100 -t 6
911100-6: PASSED

SUMMARY
===============================
ENGINE:                 ModSecurity
PASSED:                 1
FAILED:                 0
FAILED (whitelisted):   0
SKIPPED:                0
DISABLED:               0
===============================
TOTAL:                  1
===============================
```
Note, that you only run test case 911100-6 with command arguments `-r 911100 -t 6`.

Now you can check this again with **DUMMY** engine:
```
$ src/ftwrunner -e dummy -c ftwrunner-valgrind.yaml -r 911100 -t 6
911100-6: PASSED

SUMMARY
===============================
ENGINE:                 Dummy
PASSED:                 1
FAILED:                 0
FAILED (whitelisted):   0
SKIPPED:                0
DISABLED:               0
===============================
TOTAL:                  1
===============================
```
Note, that with **DUMMY** engine all tests will be passed.

If your test is passed, then you can run the same command with valgrind:
```
$ valgrind -s --track-origins=yes src/ftwrunner -e modsecurity -c ftwrunner-valgrind.yaml -r 911100 -t 6 
==359703== Memcheck, a memory error detector
==359703== Copyright (C) 2002-2024, and GNU GPL'd, by Julian Seward et al.
==359703== Using Valgrind-3.24.0 and LibVEX; rerun with -h for copyright info
==359703== Command: src/ftwrunner -e modsecurity -c ftwrunner-valgrind.yaml -r 911100 -t 6
==359703== 
==359703== Conditional jump or move depends on uninitialised value(s)
==359703==    at 0x8C2831E: ???
==359703==    by 0x8A9CE2F: ???
==359703==  Uninitialised value was created by a heap allocation
...
```

Now you can try the same command except the engine: use **DUMMY** again:
```
$ valgrind -s --track-origins=yes src/ftwrunner -e dummy -c ftwrunner-valgrind.yaml -r 911100 -t 6
==359704== Memcheck, a memory error detector
==359704== Copyright (C) 2002-2024, and GNU GPL'd, by Julian Seward et al.
==359704== Using Valgrind-3.24.0 and LibVEX; rerun with -h for copyright info
==359704== Command: src/ftwrunner -e dummy -c ftwrunner-valgrind.yaml -r 911100 -t 6
==359704== 
...
```

Theoretically you must get a `no leaks are possible` answer from Valgrind:
```
...
==359704== 
==359704== HEAP SUMMARY:
==359704==     in use at exit: 0 bytes in 0 blocks
==359704==   total heap usage: 1,079,372 allocs, 1,079,372 frees, 92,166,262 bytes allocated
==359704== 
==359704== All heap blocks were freed -- no leaks are possible
==359704== 
==359704== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```




Reporting issues
================

If you ran an unexpected behavior, found a bug, or have a feature request, just open an issue here, or drop an e-mail to us: modsecurity at digitalwave dot hu.

Todo
====

See the TODO.txt file.
