dnl $Id$
dnl ike-scan autoconf macros

dnl	AC_NTA_CHECK_TYPE -- See if a type exists using reasonable includes
dnl
dnl	Although there is a standard macro AC_CHECK_TYPE, we can't always
dnl	use this because it doesn't include enough header files.
dnl
AC_DEFUN(AC_NTA_CHECK_TYPE,
   [AC_MSG_CHECKING([for $1 using $CC])
   AC_CACHE_VAL(ac_cv_nta_have_$1,
	AC_TRY_COMPILE([
#	include "confdefs.h"
#	include <sys/types.h>
#	ifdef HAVE_ARPA_INET_H
#	include <arpa/inet.h>
#	endif
#	ifdef HAVE_NETDB_H
#	include <netdb.h>
#	endif
#	ifdef HAVE_NETINET_IN_H
#	include <netinet/in.h>
#	endif
#	ifdef SYS_SOCKET_H
#	include <sys/socket.h>
#	endif
#	ifdef STDC_HEADERS
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

dnl	AC_NTA_NET_SIZE_T -- Determine type of 3rd argument to accept
dnl
dnl	This type is normally socklen_t but is sometimes size_t or int instead.
dnl
AC_DEFUN(AC_NTA_NET_SIZE_T,
   [AC_MSG_CHECKING([for socklen_t or equivalent using $CC])
   ac_nta_net_size_t=no
   AC_TRY_COMPILE([
#	include "confdefs.h"
#	include <sys/types.h>
#	ifdef HAVE_SYS_SOCKET_H
#	include <sys/socket.h>
#	endif],
	[int s;
	struct sockaddr addr;
	socklen_t addrlen;
	int result;
	result=accept(s, &addr, &addrlen)],
	   ac_nta_net_size_t=socklen_t,ac_nta_net_size_t=no)
   if test ac_nta_net_size_t = no; then
   AC_TRY_COMPILE([
#	include "confdefs.h"
#	include <sys/types.h>
#	ifdef HAVE_SYS_SOCKET_H
#	include <sys/socket.h>
#	endif],
	[int s;
	struct sockaddr addr;
	size_t addrlen;
	int result;
	result=accept(s, &addr, &addrlen)],
	ac_nta_net_size_t=size_t,ac_nta_net_size_t=no)
   fi
   if test ac_nta_net_size_t = no; then
   AC_TRY_COMPILE([
#	include "confdefs.h"
#	include <sys/types.h>
#	ifdef HAVE_SYS_SOCKET_H
#	include <sys/socket.h>
#	endif],
	[int s;
	struct sockaddr addr;
	int addrlen;
	int result;
	result=accept(s, &addr, &addrlen)],
	ac_nta_net_size_t=int,ac_nta_net_size_t=no)
   fi
   if test ac_nta_net_size_t = no; then
      AC_MSG_ERROR([Cannot find acceptable type for 3rd arg to accept()])
   else
      AC_MSG_RESULT($ac_nta_net_size_t)
      AC_DEFINE_UNQUOTED(NET_SIZE_T, $ac_nta_net_size_t, [Define required type for 3rd arg to accept()])
   fi
   ])

