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
 */

/* Includes */
#include <sys/types.h>  /* FreeBSD needs explicit include for sys/types.h */
#include <stdarg.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/socket.h>	/* For struct sockaddr */
#include <arpa/inet.h>
#include "isakmp.h"

/* Defines */

#define MAXLINE 255			/* Max line length for input files */
#define MAXUDP 65507			/* Max UDP data size = 64k - 20 - 8 */
#define DEFAULT_SELECT_TIMEOUT 10	/* Default select timeout in ms */
#define DEFAULT_BACKOFF_FACTOR 1.5	/* Default timout backoff factor */
#define DEFAULT_RETRY 3			/* Default number of retries */
#define DEFAULT_TIMEOUT 500		/* Default per-host timeout in ms */
#define DEFAULT_INTERVAL 75		/* Default delay between packets (ms) */
#define DEFAULT_SOURCE_PORT 500		/* Default UDP source port */
#define DEFAULT_DEST_PORT 500		/* Default UDP destination port */
#define DEFAULT_LIFETIME 28800		/* Default lifetime in seconds */
#define DEFAULT_AUTH_METHOD 1		/* Default authentication method */
#define DEFAULT_END_WAIT 60000		/* Default time to wait at end in ms */
#define DEFAULT_PATTERN_FUZZ 100	/* Default pattern fuzz in ms */
#define SYSLOG 1			/* Use syslog if defined */
#define SYSLOG_FACILITY LOG_USER	/* Syslog facility to use */
#define PATTERNS_FILE "/usr/local/bin/backoff-patterns" /* Backoff patterns file */

/* Structures */
struct host_entry {
   struct host_entry *prev;	/* Previous pointer */
   struct host_entry *next;	/* Next pointer */
   int n;			/* Ordinal number for this entry */
   struct in_addr addr;		/* Host IP address */
   u_char live;			/* Set when awaiting response */
   struct timeval last_send_time; /* Time when last packet sent to this addr */
   struct time_list *recv_times; /* List of receive times */
   unsigned timeout;		/* Timeout for this host */
   unsigned num_sent;		/* Number of packets sent */
   unsigned num_recv;		/* Number of packets received */
   u_int32_t icookie[COOKIE_SIZE];	/* IKE Initiator cookie */
};

struct time_list {
   struct timeval time;
   struct time_list *next;
};

struct pattern_list {
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
