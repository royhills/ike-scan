dnl $Id$
dnl ike-scan autoconf macros

dnl	AC_NTA_CHECK_TYPE -- See if a type exists using reasonable includes
dnl
dnl	Although there is a standard macro AC_CHECK_TYPE, we can't always
dnl	use this because it doesn't include enough header files.
dnl
AC_DEFUN(AC_NTA_CHECK_TYPE,
   [AC_MSG_CHECKING(for $1 using $CC)
   AC_CACHE_VAL(ac_cv_nta_have_$1,
	AC_TRY_COMPILE([
#	include "confdefs.h"
#	include <sys/types.h>
#	if HAVE_ARPA_INET_H
#	include <arpa/inet.h>
#	endif
#	if HAVE_NETDB_H
#	include <netdb.h>
#	endif
#	if HAVE_NETINET_IN_H
#	include <netinet/in.h>
#	endif
#	if SYS_SOCKET_H
#	include <sys/socket.h>
#	endif
#	if STDC_HEADERS
#	include <stdlib.h>
#	include <stddef.h>
#	endif],
	[$1 i],
	ac_cv_nta_have_$1=yes,
	ac_cv_nta_have_$1=no))
   AC_MSG_RESULT($ac_cv_nta_have_$1)
   if test $ac_cv_nta_have_$1 = no ; then
	   AC_DEFINE($1, $2, [Define to required type if we don't have $1])
   fi])

