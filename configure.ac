dnl $Id$
dnl Process this file with autoconf to produce a configure script.

AC_INIT(ike-scan, 1.5, [ike-scan@nta-monitor.com])
AC_CONFIG_SRCDIR(ike-scan.c)
dnl If I don't pass $PACKAGE_NAME and $PACKAGE_VERSION to AM_INIT_AUTOMAKE,
dnl then PACKAGE and VERSION are not defined and these are required for
dnl make dist.  The documentation implies that I shouldn't need to
dnl supply these arguments, but I find that I do need to with autoconf 2.53 and
dnl automake 1.4.
AM_INIT_AUTOMAKE($PACKAGE_NAME, $PACKAGE_VERSION)

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

dnl GNU systems e.g. Linux have getopt_long_only, but many other systems
dnl e.g. FreeBSD 4.3 and Solaris 8 do not.  For systems that don't have it,
dnl we compile the GNU getopt sources (obtained from glibc) and link with the
dnl resultant objects.
dnl
dnl We should be able to use AC_LIBOBJ here, but I've not been able to get
dnl that to work with automake 1.4 and autoconf 2.53.
AC_CHECK_FUNC(getopt_long_only, ,
  [ COMPAT_SRCS="$COMPAT_SRCS getopt.c getopt1.c"
    COMPAT_OBJS="$COMPAT_OBJS getopt.o getopt1.o" ])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
