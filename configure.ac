dnl $Id$
dnl Process this file with autoconf to produce a configure script.

AC_INIT([ike-scan], [1.6.1], [ike-scan@nta-monitor.com])
AC_PREREQ(2.59)
AC_REVISION($Revision$)
AC_CONFIG_SRCDIR([ike-scan.c])
AM_INIT_AUTOMAKE(1.8)	dnl Require Automake 1.8 or later

AM_CONFIG_HEADER([config.h])

dnl Check for programs.
AC_PROG_CC
 if test -n "$GCC"; then
      CFLAGS="$CFLAGS -Wall "
dnl Uncomment the line below for testing
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
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h sys/socket.h sys/time.h syslog.h unistd.h getopt.h])

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
    AC_LIBOBJ(getopt1) ])

dnl Do we have inet_aton?  Most systems do, but some e.g. Solaris don't
dnl If we don't have it, then use Russ Allbery's implementation as a
dnl replacement function.
AC_CHECK_FUNC(inet_aton, , [ AC_LIBOBJ(inet_aton) ])

dnl --- OpenSSL START ---
# Search for OpenSSL
# From openssh-3.8.1p1/configure.ac
saved_CPPFLAGS="$CPPFLAGS"
saved_LDFLAGS="$LDFLAGS"
AC_ARG_WITH(ssl-dir,
	[  --with-ssl-dir=PATH     Specify path to OpenSSL installation ],
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
		fi
	]
)
LIBS="-lcrypto $LIBS"
AC_TRY_LINK_FUNC(RAND_add, AC_DEFINE(HAVE_OPENSSL, 1, [Define to 1 if you have the OpenSSL libraries and header files]),
	[
		dnl Check default openssl install dir
		LDFLAGS="-L/usr/local/ssl/lib ${saved_LDFLAGS}"
		CPPFLAGS="-I/usr/local/ssl/include ${saved_CPPFLAGS}"
		AC_TRY_LINK_FUNC(RAND_add, AC_DEFINE(HAVE_OPENSSL),
			[
				AC_MSG_ERROR([*** Can't find recent OpenSSL libcrypto (see config.log for details) ***])
			]
		)
	]
)

# Determine OpenSSL header version
AC_MSG_CHECKING([OpenSSL header version])
AC_TRY_RUN(
	[
#include <stdio.h>
#include <string.h>
#include <openssl/opensslv.h>
#define DATA "conftest.sslincver"
int main(void) {
	FILE *fd;
	int rc;

	fd = fopen(DATA,"w");
	if(fd == NULL)
		exit(1);

	if ((rc = fprintf(fd ,"%x (%s)\n", OPENSSL_VERSION_NUMBER, OPENSSL_VERSION_TEXT)) <0)
		exit(1);

	exit(0);
}
	],
	[
		ssl_header_ver=`cat conftest.sslincver`
		AC_MSG_RESULT($ssl_header_ver)
	],
	[
		AC_MSG_RESULT(not found)
		AC_MSG_ERROR(OpenSSL version header not found.)
	]
)

# Determine OpenSSL library version
AC_MSG_CHECKING([OpenSSL library version])
AC_TRY_RUN(
	[
#include <stdio.h>
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#define DATA "conftest.ssllibver"
int main(void) {
	FILE *fd;
	int rc;

	fd = fopen(DATA,"w");
	if(fd == NULL)
		exit(1);

	if ((rc = fprintf(fd ,"%x (%s)\n", SSLeay(), SSLeay_version(SSLEAY_VERSION))) <0)
		exit(1);

	exit(0);
}
	],
	[
		ssl_library_ver=`cat conftest.ssllibver`
		AC_MSG_RESULT($ssl_library_ver)
	],
	[
		AC_MSG_RESULT(not found)
		AC_MSG_ERROR(OpenSSL library not found.)
	]
)

# Sanity check OpenSSL headers
AC_MSG_CHECKING([whether OpenSSL's headers match the library])
AC_TRY_RUN(
	[
#include <string.h>
#include <openssl/opensslv.h>
int main(void) { exit(SSLeay() == OPENSSL_VERSION_NUMBER ? 0 : 1); }
	],
	[
		AC_MSG_RESULT(yes)
	],
	[
		AC_MSG_RESULT(no)
		AC_MSG_ERROR([Your OpenSSL headers do not match your library.
Check config.log for details.
Also see contrib/findssl.sh for help identifying header/library mismatches.])
	]
)
dnl --- OpenSSL END ---

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
