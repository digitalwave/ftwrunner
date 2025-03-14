#AM_CFLAGS = -Wall -fsanitize=address -g -O0
AM_CFLAGS = -Wall -g -O0

bin_PROGRAMS = ftwrunner yamltest
ftwrunner_SOURCES = main.c yamlapi.c walkdir.c ftwtest.c ftwtestutils.c \
                    engines/engines.c \
                    engines/ftwdummy/ftwdummy.c \
                    engines/ftwmodsecurity/ftwmodsecurity.c \
                    engines/ftwcoraza/ftwcoraza.c
ftwrunner_CFLAGS = $(AM_CFLAGS)
ftwrunner_LDADD = @LIBMODSECURITY_LIB@ @LIBCORAZA_LIB@ @LIBPCRE2_LIB@

yamltest_SOURCES = yamltest.c yamlapi.c
yamltest_CFLAGS = $(AM_CFLAGS)

LDADD =  -lyaml


