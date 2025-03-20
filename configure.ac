#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([ftwrunner], [1.1], [airween@digitalwave.hu])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for header files.

AC_CHECK_HEADERS([modsecurity/modsecurity.h], [], [AC_MSG_NOTICE([unable to find header modsecurity/modsecurity.h])])
AC_CHECK_HEADERS([coraza/core.h], [], [AC_MSG_NOTICE([unable to find header coraza/core.h])])
AC_DEFINE([PCRE2_CODE_UNIT_WIDTH], [8], [Define the PCRE2 code unit width])
AC_CHECK_HEADERS([pcre2.h], [], [AC_MSG_ERROR([unable to find header pcre2.h], 1)])
AC_CHECK_HEADERS([yaml.h], [], [AC_MSG_ERROR([unable to find header yaml.h], 1)])

#AX_CHECK_PCRE2([8])

has_modsecurity=no
has_coraza=no

# Checks for libraries.
#AC_CHECK_LIB([pcre2-8], [pcre2_compile], [AC_SUBST([LIBPCRE2_LIB], [-lpcre2-8])], AC_MSG_ERROR([libpcre2 is not installed.], 1))
PKG_CHECK_MODULES([PCRE2], [libpcre2-8], [AC_SUBST([LIBPCRE2_LIB], [-lpcre2-8])],
    [AC_MSG_ERROR([PCRE2 library is missing])])
AC_CHECK_LIB([modsecurity],
             [msc_init],
             [
                 AC_DEFINE([HAVE_MODSECURITY],
                           [1],
                           [Define to 1 if you have the `modsecurity' library (-lmodsecurity).])
                 AC_SUBST([LIBMODSECURITY_LIB], [-lmodsecurity])
                 has_modsecurity=yes
             ],
             AC_MSG_NOTICE([libmodsecurity is not installed.])
)
AC_CHECK_LIB([corazacore],
             [coraza_new_waf],
             [
                 AC_DEFINE([HAVE_LIBCORAZA],
                           [1],
                           [Define to 1 if you have the `libcorazacore' library (-lcorazacore).])
                 AC_SUBST([LIBCORAZA_LIB], [-lcorazacore])
                 has_coraza=yes
             ],
             AC_MSG_NOTICE([libcorazacore is not installed.])
)

AS_IF([test "x$has_modsecurity" = xno], 
    AS_IF([test "x$has_coraza" = xno],
        [AC_MSG_ERROR([neither libmodsecurity nor libcorazacore is installed.], 1)]
    )
)

AC_CHECK_LIB([yaml], [yaml_parser_initialize], [], AC_MSG_ERROR([libyaml is not installed.], 1))


# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# check host os
AC_CANONICAL_HOST

build_linux=no
build_mac=no
os_type=unknown

case "${host_os}" in
    linux*)
        build_linux=yes
        os_type=Linux
        ;;
    darwin*)
        build_mac=yes
        os_type=Darwin
        ;;
    *)
        AC_MSG_ERROR(["OS $host_os is not supported"])
        ;;
esac

# Checks for library functions.

AC_CONFIG_FILES([Makefile src/Makefile])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_OUTPUT

AC_CHECK_PROG([CPPCHECK], [cppcheck], [cppcheck], [no])
if test "x$CPPCHECK" = "xno"; then
   AC_MSG_WARN([Cppcheck is not available, skipping static analysis.])
fi

echo \
"----------------------------------------------------------------------

 ${PACKAGE_NAME} Version ${PACKAGE_VERSION} configuration:

 OS Type        ${os_type}
 Prefix         ${prefix}
 Preprocessor   ${CPP} ${CPPFLAGS}
 C Compiler     ${CC} ${CFLAGS}
 CPPCHECK       ${CPPCHECK}
 Engines:
    modsecurity  ${has_modsecurity}
    coraza       ${has_coraza}

-----------------------------------------------------------------------"
