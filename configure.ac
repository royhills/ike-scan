dnl $Id$
dnl Process this file with autoconf to produce a configure script.

AC_INIT(ike-scan.c)
AM_INIT_AUTOMAKE(ike-scan, 1.0, nodefine)

AM_CONFIG_HEADER(config.h)

dnl Checks for programs.
AC_PROG_CC
 if test -n "$GCC"; then
      CFLAGS="$CFLAGS -Wall "
 fi
AC_PROG_INSTALL
AC_PROG_LN_S

dnl Checks for libraries.
dnl Solaris 8 needs nsl and socket.  Linux and {Free,Open}BSD do not.
AC_CHECK_LIB(nsl, t_open)
AC_CHECK_LIB(socket, socket)

AC_SUBST(COMPAT_OBJS)
AC_SUBST(COMPAT_SRCS)

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h getopt.h libgen.h stdarg.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

dnl Checks for library functions.
AC_CHECK_FUNCS([malloc gethostbyname gettimeofday inet_ntoa memset select socket strerror])

dnl GNU systems e.g. Linux have getopt_long_only, but many other systems
dnl e.g. FreeBSD 4.3 and Solaris 8 do not.  For systems that don't have it,
dnl we compile the GNU getopt sources (obtained from glibc) and link with the
dnl resultant objects.
AC_CHECK_FUNC(getopt_long_only, ,
  [ COMPAT_SRCS="$COMPAT_SRCS getopt.c getopt1.c"
    COMPAT_OBJS="$COMPAT_OBJS getopt.o getopt1.o" ])

AC_OUTPUT(Makefile)
