/*
 * The IKE Scanner (ike-scan) is Copyright (C) 2003-2004 Roy Hills,
 * NTA Monitor Ltd.
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

#ifndef IKE_SCAN_H
#define IKE_SCAN_H 1

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
#include <limits.h>
#else
#error This program requires the ANSI C Headers
#endif

#include <sys/types.h>  /* FreeBSD needs explicit include for sys/types.h */

#ifdef __CYGWIN__
#include <windows.h>	/* Include windows.h if compiling under Cygwin */
#endif

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

#ifdef HAVE_REGEX_H
#include <regex.h>	/* Posix regular expression support */
#endif

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
#define DEFAULT_LIFESIZE 0		/* Default lifesize in KB */
#define DEFAULT_AUTH_METHOD 1		/* Default authentication method */
#define DEFAULT_END_WAIT 60		/* Default time to wait at end in sec */
#define DEFAULT_PATTERN_FUZZ 100	/* Default pattern fuzz in ms */
#define DEFAULT_DH_GROUP 2		/* Default DH group for agg. mode */
#define DEFAULT_IDTYPE ID_USER_FQDN	/* Default ID Type for agg. mode */
#define DEFAULT_EXCHANGE_TYPE ISAKMP_XCHG_IDPROT	/* Main Mode */
#define SYSLOG 1			/* Use syslog if defined */
#define SYSLOG_FACILITY LOG_USER	/* Syslog facility to use */
#define PATTERNS_FILE "ike-backoff-patterns" /* Backoff patterns filename */
#define VID_FILE "ike-vendor-ids"	/* Vendor ID patterns filename */
#define EXPECTED_TOTAL 72		/* Expected ISAKMP header size total */

#define STR_OR_ID(x, tab) \
        (((x) < sizeof(tab)/sizeof(tab[0]) && tab[(x)]) ? tab[(x)] : numstr(x))

/* Structures */
struct host_entry {
   struct host_entry *prev;	/* Previous pointer */
   struct host_entry *next;	/* Next pointer */
   unsigned n;			/* Ordinal number for this entry */
   struct in_addr addr;		/* Host IP address */
   unsigned char live;		/* Set when awaiting response */
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

struct pattern_entry_list {
   struct timeval time;
   unsigned fuzz;
   struct pattern_entry_list *next;
};

struct pattern_list {
   char *name;			/* Name of this backoff pattern */
   unsigned num_times;		/* Number of time entries in this pattern */
   struct pattern_entry_list *recv_times;	/* Pointer to list of times */
   struct pattern_list *next;
};

#ifdef HAVE_REGEX_H
struct vid_pattern_list {
   char *name;
   char *pattern;	/* Text regular expression */
   regex_t *regex;	/* Compiled regular expression */
   struct vid_pattern_list *next;
};
#endif

/* Functions */

void err_sys(const char *, ...);
void warn_sys(const char *, ...);
void err_msg(const char *, ...);
void warn_msg(const char *, ...);
void info_syslog(const char *, ...);
void err_print(int, int, const char *, va_list);
void usage(int);
void add_host_pattern(const char *, unsigned, unsigned *);
void add_host(const char *, unsigned, unsigned *);
void send_packet(int, unsigned char *, size_t, struct host_entry *, unsigned,
                 struct timeval *);
int recvfrom_wto(int, unsigned char *, size_t, struct sockaddr *, int);
void remove_host(struct host_entry *, unsigned *);
void timeval_diff(struct timeval *, struct timeval *, struct timeval *);
unsigned char *initialise_ike_packet(size_t *, unsigned, unsigned, unsigned, unsigned,
                                     unsigned, unsigned char *, size_t, int, int,
                                     unsigned, int, unsigned char *, size_t);
struct host_entry *find_host_by_cookie(struct host_entry *, unsigned char *,
                                       int);
void display_packet(int, unsigned char *, struct host_entry *,
                    struct in_addr *, unsigned *, unsigned *, int, int);
void advance_cursor(unsigned);
void dump_list(unsigned);
void dump_times(void);
void add_recv_time(struct host_entry *, struct timeval *);
void load_backoff_patterns(const char *, unsigned);
void add_pattern(char *, unsigned);
void load_vid_patterns(const char *);
void add_vid_pattern(char *);
char *match_pattern(struct host_entry *);
int times_close_enough(struct timeval *, struct timeval *, unsigned);
void dump_backoff(unsigned);
void dump_vid(void);
unsigned int hstr_i(const char *);
unsigned char* hex2data(const char *, size_t *);
struct isakmp_hdr* make_isakmp_hdr(unsigned, unsigned, unsigned);
struct isakmp_sa* make_sa_hdr(unsigned, unsigned);
struct isakmp_proposal* make_prop(unsigned, unsigned);
unsigned char* make_trans(size_t *, unsigned, unsigned, unsigned,
                          unsigned, unsigned, unsigned, unsigned,
                          unsigned, unsigned, int, unsigned char *, size_t);
unsigned char* add_trans(int, size_t *, unsigned, unsigned, unsigned, unsigned,
                         unsigned, unsigned, unsigned, int, unsigned char *,
                         size_t);
unsigned char* make_attr(size_t *, int, unsigned, size_t, unsigned, void *);
unsigned char* add_attr(int, size_t *, int, unsigned, size_t, unsigned,
                        void *);
unsigned char* make_vid(size_t *, unsigned, unsigned char *, size_t);
unsigned char* add_vid(int, size_t *, unsigned char *, size_t);
unsigned char* make_ke(size_t *, unsigned, size_t);
unsigned char* make_nonce(size_t *, unsigned, size_t);
unsigned char* make_id(size_t *, unsigned, unsigned, unsigned char *, size_t);
int Gettimeofday(struct timeval *);
void *Malloc(size_t);
void *Realloc(void *, size_t);
void decode_trans(char *, unsigned *, unsigned *, unsigned *, unsigned *,
                  unsigned *);
unsigned char *skip_payload(unsigned char *, size_t *, unsigned *);
unsigned char *process_isakmp_hdr(unsigned char *, size_t *, unsigned *,
                                  unsigned *);
char *process_sa(unsigned char *, size_t, unsigned, int, int);
char *process_attr(unsigned char **, size_t *);
char *process_vid(unsigned char *, size_t, struct vid_pattern_list *);
char *process_notify(unsigned char *, size_t);
char *process_id(unsigned char *, size_t);
char *make_message(const char *, ...);
char *numstr(unsigned);
char *printable(unsigned char*, size_t);
char *hexstring(unsigned char*, size_t);
/* The following functions are just to prevent rcsid being optimised away */
void error_use_rcsid(void);
void isakmp_use_rcsid(void);
void wrappers_use_rcsid(void);

#endif	/* IKE_SCAN_H */
