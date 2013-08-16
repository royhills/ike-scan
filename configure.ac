dnl $Id$
dnl Process this file with autoconf to produce a configure script.

AC_INIT([ike-scan],[1.9.4],[ike-scan@nta-monitor.com])
AC_PREREQ(2.61)
AC_REVISION($Revision$)
AC_CONFIG_SRCDIR([ike-scan.c])
AM_INIT_AUTOMAKE

AC_CONFIG_HEADERS([config.h])

dnl Check for programs.
AC_PROG_CC
if test -n "$GCC"; then
   AC_DEFINE([ATTRIBUTE_UNUSED], [__attribute__ ((__unused__))],
             [Define to the compiler's unused pragma])
   CFLAGS="$CFLAGS -Wall -Wshadow -Wwrite-strings"
   GCC_WEXTRA
   GCC_STACK_PROTECT_CC
   GCC_FORTIFY_SOURCE
   GCC_FORMAT_SECURITY
dnl Uncomment the lines below for testing with stricter warnings.
dnl CFLAGS="$CFLAGS -pedantic -Wpointer-arith -Wcast-qual -Wcast-align -Wconversion -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wnested-externs -Winline "
dnl Uncomment the line below to check malloc/free with electric fence
dnl LIBS="-lefence $LIBS"
else
   AC_DEFINE([ATTRIBUTE_UNUSED], [],
             [Define to the compiler's unused pragma])
fi
AC_PROG_INSTALL
AC_PROG_LN_S
dnl Check endian-ness. MD5 and SHA1 hash functions need to know this.
AC_C_BIGENDIAN
dnl Check for inline support.  This is used in psk-crack.c
AC_C_INLINE

dnl Check for libraries.
dnl Solaris 8 needs nsl and socket.  Linux and {Free,Open}BSD do not.
dnl We should only include these libraries if they are actually needed.
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([socket], [socket])

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([inttypes.h stdint.h arpa/inet.h netdb.h netinet/in.h netinet/tcp.h sys/socket.h sys/time.h unistd.h getopt.h signal.h sys/stat.h fcntl.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

dnl Check for the uint{8,16,32}_t types and, if we don't have them, define
dnl them using types which will work on most systems.
dnl We use these fixed-width types for constructing the IKE packet payloads.
AC_NTA_CHECK_TYPE(uint8_t, unsigned char)
AC_NTA_CHECK_TYPE(uint16_t, unsigned short)
AC_NTA_CHECK_TYPE(uint32_t, unsigned int)

dnl Checks for 64-bit integer types.  These checks are from postgresql.
dnl Check to see if we have a working 64-bit integer type.
dnl This breaks down into two steps:
dnl (1) figure out if the compiler has a 64-bit int type with working
dnl arithmetic, and if so
dnl (2) see whether snprintf() can format the type correctly.

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

AC_DEFINE_UNQUOTED(IKE_INT64, $INT64_TYPE,
                   [Define to the appropriate type for 64-bit ints.])
AC_DEFINE_UNQUOTED(IKE_UINT64, $UINT64_TYPE,
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

AC_DEFINE_UNQUOTED(IKE_INT64_FORMAT, $INT64_FORMAT,
                   [Define to the appropriate snprintf format for 64-bit ints.])

AC_DEFINE_UNQUOTED(IKE_UINT64_FORMAT, $UINT64_FORMAT,
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
   AC_MSG_ERROR([You don't seem to have posix regular expression support])
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

dnl Do we want to disable the initial gethostbyname() call?
dnl The default is for it to be enabled.
AC_ARG_ENABLE(lookup,
   AS_HELP_STRING([--enable-lookup],[Legacy option, present for compatibility]),
   AC_MSG_NOTICE([The --enable-lookup option is depreciated])
)

dnl The big OpenSSL hunt.
dnl
dnl Check for OpenSSL headers and libraries if the --with-openssl[=PATH]
dnl option was specified.
dnl
dnl We search for "include/openssl/ssl.h" and "openssl/ssl.h" in the
dnl given path (if specified) plus a number of standard locations.
dnl When we find it, we use the directory we found it in to add the
dnl required -I option to CPPFLAGS (so we can find the include files),
dnl the -L option to LDFLAGS (so we can find the libraries), and add
dnl "-lcrypto" to LIBS (so we link against the OpenSSL libraries).
dnl
have_openssl="no"
AC_MSG_CHECKING([if OpenSSL libraries are required])
AC_ARG_WITH(openssl,
   AS_HELP_STRING([--with-openssl],[Use the OpenSSL MD5 and SHA1 hash functions]),
   [
      if test "x$withval" != "xno" ; then
         AC_MSG_RESULT(yes)
         for ssldir in $withval /usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/local /usr; do
            if test -f "${ssldir}/include/openssl/ssl.h"; then
               found_openssl="yes"
               openssl_header_dir="${ssldir}/include"
               AC_MSG_NOTICE([Found ${ssldir}/include/openssl/ssl.h])
               break
            fi
            if test -f "${ssldir}/openssl/ssl.h"; then
               found_openssl="yes"
               openssl_header_dir="${ssldir}"
               AC_MSG_NOTICE([Found ${ssldir}/openssl/ssl.h])
               break
            fi
         done
         if test x$found_openssl != xyes; then
            AC_MSG_ERROR([Cannot find OpenSSL header files])
         else
            AC_MSG_NOTICE([OpenSSL header files found in $openssl_header_dir])
            CPPFLAGS="-I${openssl_header_dir} ${CPPFLAGS}"
         fi
         if test -f "${ssldir}/lib/libcrypto.so"; then
            openssl_lib_dir="${ssldir}/lib"
            AC_MSG_NOTICE([Found ${ssldir}/lib/libcrypto.so])
         elif test -f "${ssldir}/libcrypto.so"; then
            openssl_lib_dir="${ssldir}"
            AC_MSG_NOTICE([Found ${ssldir}/libcrypto.so])
         elif test -f "${ssldir}/lib/libcrypto.dylib"; then
            openssl_lib_dir="${ssldir}/lib"
            AC_MSG_NOTICE([Found ${ssldir}/lib/libcrypto.dylib])
         elif test -f "${ssldir}/libcrypto.dylib"; then
            openssl_lib_dir="${ssldir}"
            AC_MSG_NOTICE([Found ${ssldir}/libcrypto.dylib])
         elif test -f "${ssldir}/lib/libcrypto.a"; then
            openssl_lib_dir="${ssldir}/lib"
            AC_MSG_NOTICE([Found ${ssldir}/lib/libcrypto.a])
         elif test -f "${ssldir}/libcrypto.a"; then
            openssl_lib_dir="${ssldir}"
            AC_MSG_NOTICE([Found ${ssldir}/libcrypto.a])
         else
            openssl_lib_dir="${ssldir}/lib"
            AC_MSG_NOTICE([Cannot find libcrypto under $ssldir - assuming its in the standard search path])
         fi
         AC_MSG_NOTICE([OpenSSL libraries found in $openssl_lib_dir])
         LDFLAGS="-L${openssl_lib_dir} ${LDFLAGS}"
         LIBS="-lcrypto ${LIBS}"

         AC_MSG_CHECKING([that OpenSSL headers and libraries in ${ssldir} work])
         AC_LINK_IFELSE([AC_LANG_PROGRAM(
[[
#ifdef STDC_HEADERS
#include <stdlib.h>
#endif
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
AC_MSG_ERROR([OpenSSL libraries in ${ssldir} do not appear to work])
] )

      else
         AC_MSG_RESULT(no)
      fi
   ],
   [
      AC_MSG_RESULT(no)
   ]
)

dnl If we're not using OpenSSL, then use the replacement functions instead.
if test "x$have_openssl" = "xyes"; then
   AC_MSG_NOTICE([Using OpenSSL MD5 and SHA1 hash functions.])
else
   AC_MSG_NOTICE([Using ike-scan built in MD5 and SHA1 hash functions.])
   AC_MSG_NOTICE([])
   AC_MSG_NOTICE([If you plan to perform aggressive mode pre-shared key cracking, then])
   AC_MSG_NOTICE([you probably want to use the OpenSSL hash functions instead because])
   AC_MSG_NOTICE([they are generally faster than the built-in hash functions.])
   AC_MSG_NOTICE([])
   AC_MSG_NOTICE([You will need to have the OpenSSL libraries and headers installed])
   AC_MSG_NOTICE([to configure ike-scan with the OpenSSL hash functions.])
   AC_MSG_NOTICE([])
   AC_MSG_NOTICE([To use the OpenSSL hash functions, specify the following option])
   AC_MSG_NOTICE([to configure:])
   AC_MSG_NOTICE([   --with-openssl])
   AC_MSG_NOTICE([If the OpenSSL libraries are in a non-standard location, you can])
   AC_MSG_NOTICE([specify the base directory as an argument to --with-openssl.])
   AC_MSG_NOTICE([])
   AC_LIBOBJ(md5)
   AC_LIBSOURCE(md5.h)
   AC_LIBOBJ(sha1)
   AC_LIBSOURCE(sha1.h)
fi

dnl Check for strlcat and strlcpy.  If we don't have them, use the replacement
dnl functions from OpenBSD.  Most modern C libraries have these functions,
dnl but some such as as glibc don't.
AC_CHECK_FUNC([strlcat],
              [AC_DEFINE(HAVE_STRLCAT, 1, [Define to 1 if the C library includes the strlcat function])],
              [AC_LIBOBJ(strlcat)])
AC_CHECK_FUNC([strlcpy],
              [AC_DEFINE(HAVE_STRLCPY, 1, [Define to 1 if the C library includes the strlcpy function])],
              [AC_LIBOBJ(strlcpy)])

dnl	XXXX
dnl	Include "ip.h" and "udp.h" for raw packet support
dnl	This should be changed to only include raw packet support if the host
dnl	OS supports it.
dnl	XXXX
AC_LIBSOURCES([ip.h, udp.h])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
