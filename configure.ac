dnl $Id$
dnl Process this file with autoconf to produce a configure script.

AC_INIT([ike-scan],[1.6.4],[ike-scan@nta-monitor.com])
AC_PREREQ(2.59)
AC_REVISION($Revision$)
AC_CONFIG_SRCDIR([ike-scan.c])
AM_INIT_AUTOMAKE(1.8)	dnl Require Automake 1.8 or later

AM_CONFIG_HEADER([config.h])

dnl Check for programs.
AC_PROG_CC
 if test -n "$GCC"; then
      CFLAGS="$CFLAGS -Wall "
dnl Uncomment the line below for testing with stricter warnings.
dnl      CFLAGS="$CFLAGS -pedantic -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings -Wconversion -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wnested-externs "
 fi
AC_PROG_INSTALL
AC_PROG_LN_S
dnl Check endian-ness. MD5 and SHA1 hash functions need to know this.
AC_C_BIGENDIAN

dnl Check for libraries.
dnl Solaris 8 needs nsl and socket.  Linux and {Free,Open}BSD do not.
dnl We should only include these libraries if they are actually needed.
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([socket], [socket])

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([inttypes.h stdint.h arpa/inet.h netdb.h netinet/in.h netinet/tcp.h sys/socket.h sys/time.h syslog.h unistd.h getopt.h signal.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

dnl Check for the uint{8,16,32,64}_t types and, if we don't have them, define
dnl them using types which will work on most systems.
AC_NTA_CHECK_TYPE(uint8_t, unsigned char)
AC_NTA_CHECK_TYPE(uint16_t, unsigned short)
AC_NTA_CHECK_TYPE(uint32_t, unsigned int)
AC_NTA_CHECK_TYPE(uint64_t, unsigned long long)

dnl Check to see if we have a working 64-bit integer type.
dnl This breaks down into two steps:
dnl (1) figure out if the compiler has a 64-bit int type with working
dnl arithmetic, and if so
dnl (2) see whether snprintf() can format the type correctly.  (Currently,
dnl snprintf is the only library routine we really need for int8 support.)
dnl It's entirely possible to have a compiler that handles a 64-bit type
dnl when the C library doesn't; this is fairly likely when using gcc on
dnl an older platform, for example.
dnl If there is no native snprintf() or it does not handle the 64-bit type,
dnl we force our own version of snprintf() to be used instead.
dnl Note this test must be run after our initial check for snprintf/vsnprintf.

PGAC_TYPE_64BIT_INT([long int])

if test x"$HAVE_LONG_INT_64" = x"yes" ; then
  INT64_TYPE="long int"
  UINT64_TYPE="unsigned long int"
else
  PGAC_TYPE_64BIT_INT([long long int])
    if test x"$HAVE_LONG_LONG_INT_64" = x"yes" ; then
      INT64_TYPE="long long int"
      UINT64_TYPE="unsigned long long int"
    else
      AC_MSG_ERROR([cannot determine 64-bit integer type])
    fi
fi

AC_DEFINE_UNQUOTED(INT64, $INT64_TYPE,
                   [Define to the appropriate type for 64-bit ints.])
AC_DEFINE_UNQUOTED(UINT64, $UINT64_TYPE,
                   [Define to the appropriate type for unsigned 64-bit ints.])

dnl If we found "long int" is 64 bits, assume snprintf handles it.  If
dnl we found we need to use "long long int", better check.  We cope with
dnl snprintfs that use %lld, %qd, or %I64d as the format.
dnl
if test "$HAVE_LONG_LONG_INT_64" = yes ; then
  PGAC_FUNC_SNPRINTF_LONG_LONG_INT_FORMAT
  if test "$LONG_LONG_INT_FORMAT" = ""; then
    AC_MSG_ERROR([cannot determine snprintf format string for long long int])
  fi
  LONG_LONG_UINT_FORMAT=`echo "$LONG_LONG_INT_FORMAT" | sed 's/d$/u/'`
  INT64_FORMAT="\"$LONG_LONG_INT_FORMAT\""
  UINT64_FORMAT="\"$LONG_LONG_UINT_FORMAT\""
else
  # Here if we are not using 'long long int' at all
  INT64_FORMAT='"%ld"'
  UINT64_FORMAT='"%lu"'
fi

AC_DEFINE_UNQUOTED(INT64_FORMAT, $INT64_FORMAT,
                   [Define to the appropriate snprintf format for 64-bit ints.])

AC_DEFINE_UNQUOTED(UINT64_FORMAT, $UINT64_FORMAT,
                   [Define to the appropriate snprintf format for unsigned 64-bit ints.])

dnl Checks for library functions.
AC_CHECK_FUNCS([malloc gethostbyname gettimeofday inet_ntoa memset select socket strerror])

dnl Determine type for 3rd arg to accept()
dnl This is normally socklen_t, but can sometimes be size_t or int.
AC_NTA_NET_SIZE_T

dnl Check if the Posix regular expression functions "regcomp" and "regexec"
dnl and the header file "regex.h" are present.
AC_MSG_CHECKING([for posix regular expression support])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <regex.h>]],
[[regcomp(0, 0, 0);
regexec(0, 0, 0, 0, 0)]])],
[ac_nta_posix_regex=yes],
[ac_nta_posic_regex=no])
AC_MSG_RESULT([$ac_nta_posix_regex])
if test $ac_nta_posix_regex = no; then
   AC_MSG_WARN([You don't seem to have posix regular expression support])
else
   AC_DEFINE(HAVE_REGEX_H, 1, [Define to 1 if you have posix regex support])
fi

dnl GNU systems e.g. Linux have getopt_long_only, but many other systems
dnl e.g. FreeBSD 4.3 and Solaris 8 do not.  For systems that don't have it,
dnl use the GNU getopt sources (obtained from glibc).
AC_CHECK_FUNC([getopt_long_only], ,
  [ AC_LIBOBJ(getopt)
    AC_LIBOBJ(getopt1)
    AC_LIBSOURCE(getopt.h) ])

dnl Do we have inet_aton?  Most systems do, but some e.g. Solaris don't
dnl If we don't have it, then use Russ Allbery's implementation as a
dnl replacement function.
AC_CHECK_FUNC(inet_aton, , [ AC_LIBOBJ(inet_aton) ])

dnl Check for OpenSSL headers and libraries if the --with-openssl=PATH
dnl option was specified
have_openssl="no"
AC_ARG_WITH(openssl,
	AC_HELP_STRING([--with-openssl=PATH],
                       [Specify path to OpenSSL installation]),
	[
		if test "x$withval" != "xno" ; then
			if test -d "$withval/lib"; then
				LDFLAGS="-L${withval}/lib ${LDFLAGS}"
			else
				LDFLAGS="-L${withval} ${LDFLAGS}"
			fi
			if test -d "$withval/include"; then
				CPPFLAGS="-I${withval}/include ${CPPFLAGS}"
			else
				CPPFLAGS="-I${withval} ${CPPFLAGS}"
			fi
                        LIBS="-lcrypto $LIBS"
                        AC_MSG_CHECKING([for OpenSSL in $withval])
                        AC_LINK_IFELSE([AC_LANG_PROGRAM(
[[
#include <openssl/md5.h>
#include <openssl/sha.h>
]],
[[
MD5(0, 0, 0);
SHA1(0, 0, 0);
]] ) ],
[
AC_MSG_RESULT(yes)
AC_DEFINE(HAVE_OPENSSL, 1, [Define to 1 if you have the OpenSSL libraries and header files])
have_openssl="yes"
],
[
AC_MSG_RESULT(no)
AC_MSG_ERROR([cannot find OpenSSL headers & libraries in $withval])
] )

		fi
	]
)

dnl If we're not using OpenSSL, then use the replacement functions instead.
if test "x$have_openssl" = "xyes"; then
   AC_MSG_NOTICE([Using OpenSSL hash and HMAC functions.])
else
   AC_MSG_NOTICE([Using built in hash and HMAC functions.])
   AC_MSG_NOTICE([Specify --with-openssl=PATH to use the OpenSSL functions instead.])
   AC_LIBOBJ(md5)
   AC_LIBSOURCE(md5.h)
   AC_LIBOBJ(sha1)
   AC_LIBSOURCE(sha1.h)
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
