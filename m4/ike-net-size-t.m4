dnl	IKE_NET_SIZE_T -- Determine type of 3rd argument to accept
dnl
dnl	This type is normally socklen_t but is sometimes size_t or int instead.
dnl	We try, in order: socklen_t, int, size_t until we find one that compiles
dnl
AC_DEFUN([IKE_NET_SIZE_T],
   [AC_MSG_CHECKING([for socklen_t or equivalent using $CC])
   ac_nta_net_size_t=no
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#	include "confdefs.h"
#	include <sys/types.h>
#	ifdef HAVE_SYS_SOCKET_H
#	include <sys/socket.h>
#	endif]], [[int s;
	struct sockaddr addr;
	socklen_t addrlen;
	int result;
	result=accept(s, &addr, &addrlen)]])],[ac_nta_net_size_t=socklen_t],[ac_nta_net_size_t=no])
   if test $ac_nta_net_size_t = no; then
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#	include "confdefs.h"
#	include <sys/types.h>
#	ifdef HAVE_SYS_SOCKET_H
#	include <sys/socket.h>
#	endif]], [[int s;
	struct sockaddr addr;
	int addrlen;
	int result;
	result=accept(s, &addr, &addrlen)]])],[ac_nta_net_size_t=int],[ac_nta_net_size_t=no])
   fi
   if test $ac_nta_net_size_t = no; then
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#	include "confdefs.h"
#	include <sys/types.h>
#	ifdef HAVE_SYS_SOCKET_H
#	include <sys/socket.h>
#	endif]], [[int s;
	struct sockaddr addr;
	size_t addrlen;
	int result;
	result=accept(s, &addr, &addrlen)]])],[ac_nta_net_size_t=size_t],[ac_nta_net_size_t=no])
   fi
   if test $ac_nta_net_size_t = no; then
      AC_MSG_ERROR([Cannot find acceptable type for 3rd arg to accept()])
   else
      AC_MSG_RESULT($ac_nta_net_size_t)
      AC_DEFINE_UNQUOTED(NET_SIZE_T, $ac_nta_net_size_t, [Define required type for 3rd arg to accept()])
   fi
   ])
