/*
 *  The IKE security scanner is copyright (C) Roy Hills, NTA Monitor Ltd.
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation; Version 2.  This guarantees your
 *  right to use, modify, and redistribute this software under certain
 *  conditions.  If this license is unacceptable to you, I may be
 *  willing to negotiate alternative licenses (contact
 *  Roy.Hills@nta-monitor.com).
 *
 *  You are encouraged to send comments, improvements or suggestions to
 *  me at Roy.Hills@nta-monitor.com.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details:
 *  http://www.gnu.org/copyleft/gpl.html
 *
 * $Id$
 *
 * error.c -- error routines for IKE scanner
 *
 * Author: Roy Hills
 * Date: 1 December 2001
 *
 * Revision History:
 *
 * $Log$
 * Revision 1.5  2002/12/31 21:09:01  rsh
 * Add autoconf config.h
 *
 * Revision 1.4  2002/12/31 15:10:04  rsh
 * Changed function definitions so return type is on a line by itself.
 *
 * Revision 1.3  2002/11/26 16:54:24  rsh
 * Minor comment change.
 *
 * Revision 1.2  2002/11/21 13:51:38  rsh
 * Added GPL
 *
 * Revision 1.1  2002/09/12 17:58:11  rsh
 * Initial revision
 *
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
void
err_sys(const char *fmt,...) {
   va_list ap;

   va_start(ap, fmt);
   err_print(1, 0, fmt, ap);
   va_end(ap);
   exit(1);
}

/*
 *	Function to handle non-fatal system call errors.
 */
void
warn_sys(const char *fmt,...) {
   va_list ap;

   va_start(ap, fmt);
   err_print(1, 0, fmt, ap);
   va_end(ap);
}

/*
 *	Function to handle fatal errors not from system calls.
 */
void
err_msg(const char *fmt,...) {
   va_list ap;

   va_start(ap, fmt);
   err_print(0, 0, fmt, ap);
   va_end(ap);
   exit(1);
}

/*
 *	Function to handle non-fatal errors not from system calls.
 */
void
warn_msg(const char *fmt,...) {
   va_list ap;

   va_start(ap, fmt);
   err_print(0, 0, fmt, ap);
   va_end(ap);
}

/*
 *	Function to handle infomational syslog messages
 */
void
info_syslog(const char *fmt,...) {
   va_list ap;

   va_start(ap, fmt);
   err_print(0, LOG_INFO, fmt, ap);
   va_end(ap);
}

/*
 *	General error printing function used by all the above
 *	functions.
 */
void
err_print (int errnoflag, int level, const char *fmt, va_list ap) {
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
