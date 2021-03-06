dnl ##
dnl ##  OSSP uuid - Universally Unique Identifier
dnl ##  Copyright (c) 2004-2021 Dr. Ralf S. Engelschall <rse@engelschall.com>
dnl ##  Copyright (c) 2004-2021 The OSSP Project <http://www.ossp.org/>
dnl ##
dnl ##  This file is part of OSSP uuid, a library for the generation
dnl ##  of UUIDs which can found at https://github.com/rse/uuid
dnl ##
dnl ##  Permission to use, copy, modify, and distribute this software for
dnl ##  any purpose with or without fee is hereby granted, provided that
dnl ##  the above copyright notice and this permission notice appear in all
dnl ##  copies.
dnl ##
dnl ##  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
dnl ##  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
dnl ##  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
dnl ##  IN NO EVENT SHALL THE AUTHORS AND COPYRIGHT HOLDERS AND THEIR
dnl ##  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
dnl ##  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
dnl ##  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
dnl ##  USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
dnl ##  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
dnl ##  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
dnl ##  OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
dnl ##  SUCH DAMAGE.
dnl ##
dnl ##  uuid.ac: UUID specific Autoconf checks
dnl ##

dnl #   Check for anything OSSP uuid wants to know
dnl #   configure.ac:
dnl #     UUID_CHECK_ALL

AC_DEFUN([UUID_CHECK_ALL],[
    dnl #   make sure libnsl and libsocket are linked in if they exist
    AC_CHECK_LIB(nsl, gethostname)
    if test ".`echo $LIBS | grep nsl`" = .; then
        AC_CHECK_LIB(nsl, gethostbyname)
    fi
    AC_CHECK_LIB(socket, accept)

    dnl #  check for portable va_copy()
    AC_CHECK_VA_COPY()

    dnl #   check for system headers
    AC_CHECK_HEADERS(sys/types.h sys/param.h sys/time.h sys/socket.h sys/sockio.h sys/ioctl.h sys/select.h)
    AC_CHECK_HEADERS(netdb.h ifaddrs.h net/if.h net/if_dl.h net/if_arp.h netinet/in.h arpa/inet.h,,,
[[
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
]])

    dnl #   check for existence of particular C structures
    AC_MSG_CHECKING(for struct timeval)
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <time.h>
    ]],[[ struct timeval tv; ]])],
    [ msg="yes" ], [ msg="no" ])
    if test ".$msg" = .yes; then
        AC_DEFINE(HAVE_STRUCT_TIMEVAL, 1, [define if exists "struct timeval"])
    fi
    AC_MSG_RESULT([$msg])

    dnl #   check for functions
    AC_CHECK_FUNCS(getifaddrs nanosleep Sleep gettimeofday clock_gettime)

    dnl #   check size of built-in types
    AC_CHECK_TYPES([long long, long double])
    AC_CHECK_SIZEOF(char, 1)
    AC_CHECK_SIZEOF(unsigned char, 1)
    AC_CHECK_SIZEOF(short, 2)
    AC_CHECK_SIZEOF(unsigned short, 2)
    AC_CHECK_SIZEOF(int, 4)
    AC_CHECK_SIZEOF(unsigned int, 4)
    AC_CHECK_SIZEOF(long, 4)
    AC_CHECK_SIZEOF(unsigned long, 4)
    AC_CHECK_SIZEOF(long long, 8)
    AC_CHECK_SIZEOF(unsigned long long, 8)

    dnl #   configure option --with-dce
    AC_ARG_WITH([dce],
        AS_HELP_STRING([--with-dce], [build DCE 1.1 backward compatibility API]),
        [ac_cv_with_dce=$withval], [ac_cv_with_dce=no])
    AC_CACHE_CHECK([whether to build DCE 1.1 backward compatibility API], [ac_cv_with_dce], [ac_cv_with_dce=no])
    if test ".$ac_cv_with_dce" = ".yes"; then
        AC_DEFINE(WITH_DCE, 1, [whether to build DCE 1.1 backward compatibility API])
        WITH_DCE='yes'
        DCE_NAME='$(DCE_NAME)'
    else
        WITH_DCE='no'
        DCE_NAME=''
    fi
    AC_SUBST(WITH_DCE)
    AC_SUBST(DCE_NAME)

    dnl #   configure option --with-cxx
    AC_ARG_WITH([cxx],
        AS_HELP_STRING([--with-cxx], [build C++ bindings to C API]),
        [ac_cv_with_cxx=$withval], [ac_cv_with_cxx=no])
    AC_CACHE_CHECK([whether to build C++ bindings to C API], [ac_cv_with_cxx], [ac_cv_with_cxx=no])
    if test ".$ac_cv_with_cxx" = ".yes"; then
        AC_DEFINE(WITH_CXX, 1, [whether to build C++ bindings to C API])
        WITH_CXX='yes'
        CXX_NAME='$(CXX_NAME)'
        AC_REQUIRE([AC_PROG_CXX])
    else
        WITH_CXX='no'
        CXX_NAME=''
    fi
    AC_SUBST(CXX_NAME)
    AC_SUBST(WITH_CXX)

    dnl #   configure option --with-perl
    AC_ARG_WITH([perl],
        AS_HELP_STRING([--with-perl], [build Perl bindings to C API]),
        [ac_cv_with_perl=$withval], [ac_cv_with_perl=no])
    AC_CACHE_CHECK([whether to build Perl bindings to C API], [ac_cv_with_perl], [ac_cv_with_perl=no])
    AC_ARG_WITH([perl-compat],
        AS_HELP_STRING([--with-perl-compat], [build Perl compatibility API]),
        [ac_cv_with_perl_compat=$withval], [ac_cv_with_perl_compat=no])
    AC_CACHE_CHECK([whether to build Perl compatibility API], [ac_cv_with_perl_compat], [ac_cv_with_perl_compat=no])
    if test ".$ac_cv_with_perl" = ".yes"; then
        AC_DEFINE(WITH_PERL, 1, [whether to build Perl bindings to C API])
        WITH_PERL='yes'
        PERL_NAME='$(PERL_NAME)'
    else
        WITH_PERL='no'
        PERL_NAME=''
    fi
    if test ".$ac_cv_with_perl_compat" = ".yes"; then
        AC_DEFINE(WITH_PERL_COMPAT, 1, [whether to build Perl compatibility API])
        WITH_PERL_COMPAT=1
    else
        WITH_PERL_COMPAT=0
    fi
    AC_SUBST(PERL_NAME)
    AC_SUBST(WITH_PERL)
    AC_SUBST(WITH_PERL_COMPAT)
    AC_PATH_PROG(PERL, perl, NA)
    if test ".$ac_cv_with_perl" = ".yes" -a ".$PERL" = ".NA"; then
        AC_MSG_ERROR([required Perl interpreter not found in \$PATH])
    fi
    
    dnl #   configure option --with-php
    AC_ARG_WITH([php],
        AS_HELP_STRING([--with-php], [build PHP bindings to C API]),
        [ac_cv_with_php=$withval], [ac_cv_with_php=no])
    AC_CACHE_CHECK([whether to build PHP bindings to C API], [ac_cv_with_php], [ac_cv_with_php=no])
    if test ".$ac_cv_with_php" = ".yes"; then
        AC_DEFINE(WITH_PHP, 1, [whether to build PHP bindings to C API])
        WITH_PHP='yes'
        PHP_NAME='$(PHP_NAME)'
    else
        WITH_PHP='no'
        PHP_NAME=''
    fi
    AC_SUBST(PHP_NAME)
    AC_SUBST(WITH_PHP)
    AC_PATH_PROGS(PHP, php5 php, NA)
    if test ".$ac_cv_with_php" = ".yes" -a ".$PHP" = ".NA"; then
        AC_MSG_ERROR([required PHP interpreter not found in \$PATH])
    fi
    if test ".$ac_cv_with_php" = ".yes"; then
        (cd php && make -f Makefile.local config PHP=$PHP)
    fi

    dnl #   configure option --with-pgsql
    AC_ARG_WITH([pgsql],
        AS_HELP_STRING([--with-pgsql], [build PostgreSQL bindings to C API]),
        [ac_cv_with_pgsql=$withval], [ac_cv_with_pgsql=no])
    AC_CACHE_CHECK([whether to build PostgreSQL bindings to C API], [ac_cv_with_pgsql], [ac_cv_with_pgsql=no])
    if test ".$ac_cv_with_pgsql" = ".yes"; then
        AC_DEFINE(WITH_PGSQL, 1, [whether to build PostgreSQL bindings to C API])
        WITH_PGSQL='yes'
        PGSQL_NAME='$(PGSQL_NAME)'
    else
        WITH_PGSQL='no'
        PGSQL_NAME=''
    fi
    AC_SUBST(PGSQL_NAME)
    AC_SUBST(WITH_PGSQL)
    AC_PATH_PROGS(PG_CONFIG, pg_config, NA)
    if test ".$ac_cv_with_pgsql" = ".yes" -a ".$PG_CONFIG" = ".NA"; then
        AC_MSG_ERROR([required PostgreSQL pg_config utility not found in \$PATH])
    fi
    if test ".$ac_cv_with_pgsql" = ".yes" -a ".`${MAKE-make} -v 2>/dev/null | grep GNU`" = .; then
        AC_MSG_ERROR([PostgreSQL bindings require GNU make to build])
    fi
])

