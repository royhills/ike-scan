/*
 * $Id$
 *
 * error.c -- error routines
 *
 * Author: Roy Hills
 * Date: 1 December 2001
 *
 * Revision History:
 *
 * $Log$
 * Revision 1.1  2002/09/12 17:58:11  rsh
 * Initial revision
 *
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>

#include "ike-scan.h"

int daemon_proc;	/* Non-zero if process is a daemon */

/*
 *	Function to handle fatal system call errors.
 */
void err_sys(const char *fmt,...) {
   va_list ap;

   va_start(ap, fmt);
   err_print(1, 0, fmt, ap);
   va_end(ap);
   exit(1);
}

/*
 *	Function to handle non-fatal system call errors.
 */
void warn_sys(const char *fmt,...) {
   va_list ap;

   va_start(ap, fmt);
   err_print(1, 0, fmt, ap);
   va_end(ap);
}

/*
 *	Function to handle fatal errors not from system calls.
 */
void err_msg(const char *fmt,...) {
   va_list ap;

   va_start(ap, fmt);
   err_print(0, 0, fmt, ap);
   va_end(ap);
   exit(1);
}

/*
 *	Function to handle non-fatal errors not from system calls.
 */
void warn_msg(const char *fmt,...) {
   va_list ap;

   va_start(ap, fmt);
   err_print(0, 0, fmt, ap);
   va_end(ap);
}

/*
 *	Function to handle infomational syslog messages
 */
void info_syslog(const char *fmt,...) {
   va_list ap;

   va_start(ap, fmt);
   err_print(0, LOG_INFO, fmt, ap);
   va_end(ap);
}

/*
 *	General error printing function used by all the above
 *	functions.
 */
void err_print (int errnoflag, int level, const char *fmt, va_list ap) {
   int errno_save;
   int n;
   char buf[MAXLINE];

   errno_save=errno;

   vsnprintf(buf, MAXLINE, fmt, ap);
   n=strlen(buf);
   if (errnoflag)
     snprintf(buf+n, MAXLINE-n, ": %s", strerror(errno_save));
   strcat(buf, "\n");

   if (level != 0) {
      syslog(level, buf);
   } else {
      fflush(stdout);	/* In case stdout and stderr are the same */
      fputs(buf, stderr);
      fflush(stderr);
   }
}
