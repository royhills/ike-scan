/*
 * The IKE Scanner (ike-scan) is Copyright (C) 2003 Roy Hills, NTA Monitor Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * If this license is unacceptable to you, I may be willing to negotiate
 * alternative licenses (contact ike-scan@nta-monitor.com).
 *
 * You are encouraged to send comments, improvements or suggestions to
 * me at ike-scan@nta-monitor.com.
 *
 * $Id$
 *
 * ike-scan.h -- Header file for IKE Scanner (ike-scan)
 *
 * Author:	Roy Hills
 * Date:	12 September 2002
 */

/* Includes */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef STDC_HEADERS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <math.h>
#else
#error This program requires the ANSI C Headers
#endif

#include <sys/types.h>  /* FreeBSD needs explicit include for sys/types.h */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
/* Include getopt.h for the sake of getopt_long.
   We don't need the declaration of getopt, and it could conflict
   with something from a system header file, so effectively nullify that.  */
#define getopt getopt_loser
#include "getopt.h"
#undef getopt
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>	/* For struct sockaddr */
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "global.h"
#include "md5.h"
#include "isakmp.h"

/* Defines */

#define MAXLINE 255			/* Max line length for input files */
#define MAXUDP 65507			/* Max UDP data size = 64k - 20 - 8 */
#define DEFAULT_SELECT_TIMEOUT 10	/* Default select timeout in ms */
#define DEFAULT_BACKOFF_FACTOR 1.5	/* Default timeout backoff factor */
#define DEFAULT_RETRY 3			/* Default number of retries */
#define DEFAULT_TIMEOUT 500		/* Default per-host timeout in ms */
#define DEFAULT_INTERVAL 75		/* Default delay between packets (ms) */
#define DEFAULT_SOURCE_PORT 500		/* Default UDP source port */
#define DEFAULT_DEST_PORT 500		/* Default UDP destination port */
#define DEFAULT_LIFETIME 28800		/* Default lifetime in seconds */
#define DEFAULT_AUTH_METHOD 1		/* Default authentication method */
#define DEFAULT_END_WAIT 60		/* Default time to wait at end in sec */
#define DEFAULT_PATTERN_FUZZ 100	/* Default pattern fuzz in ms */
#define SYSLOG 1			/* Use syslog if defined */
#define SYSLOG_FACILITY LOG_USER	/* Syslog facility to use */
#define PATTERNS_FILE "ike-backoff-patterns" /* Backoff patterns filename */

/* Structures */
struct host_entry {
   struct host_entry *prev;	/* Previous pointer */
   struct host_entry *next;	/* Next pointer */
   unsigned n;			/* Ordinal number for this entry */
   struct in_addr addr;		/* Host IP address */
   u_char live;			/* Set when awaiting response */
   struct timeval last_send_time; /* Time when last packet sent to this addr */
   struct time_list *recv_times; /* List of receive times */
   unsigned timeout;		/* Timeout for this host */
   unsigned num_sent;		/* Number of packets sent */
   unsigned num_recv;		/* Number of packets received */
   uint32_t icookie[COOKIE_SIZE];	/* IKE Initiator cookie */
};

struct time_list {
   struct timeval time;
   struct time_list *next;
};

struct pattern_list {
   char *name;
   int num_times;
   struct time_list *recv_times;
   struct pattern_list *next;
};

/* Functions */

void err_sys(const char *, ...);
void warn_sys(const char *, ...);
void err_msg(const char *, ...);
void warn_msg(const char *, ...);
void info_syslog(const char *, ...);
void err_print(int, int, const char *, va_list);
char *cpystr(char *string);
void usage(void);
void add_host(char *);
void send_packet(int, struct host_entry *);
int recvfrom_wto(int, char *, int, struct sockaddr *, int);
void remove_host(struct host_entry *);
void timeval_diff(struct timeval *, struct timeval *, struct timeval *);
void initialise_ike_packet(void);
struct host_entry *find_host_by_cookie(struct host_entry *, char *, int);
void display_packet(int, char *, struct host_entry *, struct in_addr *);
void advance_cursor(void);
void decode_transform(char *, int, int);
void dump_list(void);
void dump_times(void);
void add_recv_time(struct host_entry *);
void add_pattern(char *);
char *match_pattern(struct host_entry *);
int times_close_enough(struct timeval *, struct timeval *);
void dump_backoff(void);
