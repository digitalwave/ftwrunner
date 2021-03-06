ftwrunner
=========

Welcome to the `ftwrunner` documentation. I'ld try to show this tool to every ModSecurity users, who's interesting about the rules and its tests.

Motivation
==========

I help to maintain the code of [ModSecurity](https://www.modsecurity.org) (especially the [libmodsecurity3](https://github.com/SpiderLabs/ModSecurity)). A most important goal that get the state that the [CRS](https://coreruleset.org) can work together with libmodsecurity3, without errors: false positives and not working rules.

[CRS](https://github.com/SpiderLabs/owasp-modsecurity-crs) has a very good tool to test all of the rules, it's called [ftw](https://github.com/CRS-support/ftw), but it works only with the Apache webserver - consequently a HTTP server is required. Ftw uses [sets of tests](https://github.com/SpiderLabs/owasp-modsecurity-crs/tree/v3.2/dev/util/regression-tests/tests), which are divided to different sections, represented the attack type. Each section has a multiple test files, which represented the rules: every file named by the rule id. And finally, all ruleset has one or more test.

These tests had written in [YAML](https://yaml.org/) format.


Libmodsecurity3 has written in C++, and - therefore as a library - has an [API](https://github.com/SpiderLabs/ModSecurity#simple-example-using-c). The library has an own regression test framework, but mostly it's useful to tests the different functions one by one.

As I wrote, my main goal is to adjusting the libmodsecurity3 code to use those rules, so I needed a tool, which I can test with the whole ruleset without any other external distractions, eg. webserver responses, other behaviors, etc...

At first time, I've made a very ugly HTTP server, but it just generated more problems rather than taken away them.

Then the idea came - use the API, but not through the HTTP: inject the existing YAML tests to API directly.

That is why this tool was created.

Prerequisites
=============

`ftwrunner` was designed to run on Linux, but I think it runs on most Unix systems.

To build the `ftwrunner`, you need:

+ a **C++ compiler**, I used **g++**
+ **autotools**, **make**
+ of course, need the compiled and installed **libmodsecurity3**
+ **pcre** - the old version
+ **yaml-cpp**

You have to install them on Debian with this command:

```
sudo apt install g++ make autotools libpcre3-dev libyaml-cpp-dev
```
and - as I wrote above - an installed libmodsecurity3.

*Note: Debian 10 contains the libmodsecurity3 package, but since it released, there are so much modification in the code, so I **strongly suggest** that you get a clone with git, and compile it for yourself.*

Compile the code
================

It's simple, grab the code, and type this commands:

```
$ autoreconf    # optional
$ ./autogen.sh  # optional, but necessary if you run autoreconf
$ ./configure
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
modsecurity_config: /etc/apache2/modsecurity_includes.conf
ftwtest_root: /path/to/owasp-modsecurity-crs/util/regression-tests/tests
test_whitelist:
- 941190-3 # known MSC bug - PR #2023 (Cookie without value)
- 941330-1 # know MSC bug - #2148 (double escape)
```

If you run `ftwrunner`, it's also try to open this file first, and if it done, uses the variables. There are two mandatory variable: `modsecurity_config` and `ftwtest_root`. Both of them can be overwritten with the command line arguments. As I wrote, you don't need this file with this name, but you can pass to `ftwrunner` another one with cli argument `-c /path/to/config.yaml`.

Content of config file
----------------------

`modsecurity_config` - path to your modsecurity.conf, what you use for your webserver. You can make a copy from that file, and can make some modification. Here is the part of mine:
```
$ cat /etc/apache2/modsecurity_includes.conf 
Include modsecurity.conf
Include /etc/modsecurity/crs/crs-setup.conf
Include /etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
Include /usr/share/modsecurity-crs/rules/REQUEST-901-INITIALIZATION.conf
Include /usr/share/modsecurity-crs/rules/REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf
...
```
**IMPORTANT: if you set up the debug in that config (`SecDebugLog /var/log/apache2/modsec_debug.log`), libmodsecurity3 wants to open it when it starts, so you have to give the permissions to the user what you run, or use a copy and change this variable, or turn off debug log. No, you don't want to run it as root.**

You can overwrite this variable with cli argument `-m /path/to/config`.

`ftwtest_root` - path to your regression tests root directory. It's depend on your config, version, etc... and also can be overwriten with a cli argument `-f /path/to/owasp-modsecurity-crs/util/regression-tests/tests`.

Note, that it's generally useful if you don't want to run all tests in that directory, just a subset. Here is an example:
```
$ ./ftwrunner -f /path/to/owasp-modsecurity-crs/util/regression-tests/tests/REQUEST-920-PROTOCOL-ENFORCEMENT/
```
or you can pass only one rule:
```
$ ./ftwrunner -f /path/to/owasp-modsecurity-crs/util/regression-tests/tests/REQUEST-920-PROTOCOL-ENFORCEMENT/920210.yaml
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

Reporting issues
================

If you ran an unexpected behavior, found a bug, or have a feature request, just open an issue here, or drop an e-mail to us: modsecurity at digitalwave dot hu.

Todo
====

See the TODO.txt file.
