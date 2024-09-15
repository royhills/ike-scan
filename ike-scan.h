/*
 * The IKE Scanner (ike-scan) is Copyright (C) 2003-2009 Roy Hills,
 * NTA Monitor Ltd.
 *
 * This file is part of ike-scan.
 *
 * ike-scan is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ike-scan is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ike-scan.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library, and distribute linked combinations including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.
 *
 * If this license is unacceptable to you, I may be willing to negotiate
 * alternative licenses (contact ike-scan@nta-monitor.com).
 *
 * You are encouraged to submit comments, improvements or suggestions
 * at the github repository https://github.com/royhills/ike-scan
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

/* C89 standard headers */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <signal.h>	/* For TCP connect() timeout using alarm */

/* C99 standard headers */
#include <stdint.h>

#include <sys/types.h>  /* FreeBSD needs explicit include for sys/types.h */

#ifdef __CYGWIN__
#include <windows.h>	/* Include windows.h if compiling under Cygwin */
#endif

/* headers first defined in POSIX-1 issue 1 */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

/* headers first defined in POSIX.1 issue 4 */

#ifdef HAVE_REGEX_H
#include <regex.h>	/* Posix regular expression support */
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

/* headers first defined in POSIX.1 issue 6 */

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>	/* For struct sockaddr */
#endif

/* Other system headers */

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

#ifdef HAVE_OPENSSL
#include <openssl/md5.h>
#include <openssl/sha.h>
#else
#include "md5.h"
#include "sha1.h"
#endif

#include "isakmp.h"

#include "ip.h"
#include "udp.h"

/* Defines */

#define MAXLINE 255			/* Max line length for input files */
#define MAXUDP 65507			/* Max UDP data size = 64k - 20 - 8 */
#define DEFAULT_SELECT_TIMEOUT 10	/* Default select timeout in ms */
#define DEFAULT_BACKOFF_FACTOR 1.5	/* Default timeout backoff factor */
#define DEFAULT_RETRY 3			/* Default number of retries */
#define DEFAULT_TIMEOUT 500		/* Default per-host timeout in ms */
#define DEFAULT_BANDWIDTH 56000		/* Default bandwidth in bits/sec */
#define DEFAULT_SOURCE_PORT 500		/* Default UDP source port */
#define DEFAULT_DEST_PORT 500		/* Default UDP destination port */
#define DEFAULT_NAT_T_SOURCE_PORT 4500	/* Default UDP src port with NAT-T */
#define DEFAULT_NAT_T_DEST_PORT 4500	/* Default UDP dest port with NAT-T */
#define DEFAULT_LIFETIME 28800		/* Default lifetime in seconds */
#define DEFAULT_LIFESIZE 0		/* Default lifesize in KB */
#define DEFAULT_AUTH_METHOD 1		/* Default authentication method */
#define DEFAULT_END_WAIT 60		/* Default time to wait at end in sec */
#define DEFAULT_PATTERN_FUZZ 500	/* Default pattern fuzz in ms */
#define DEFAULT_DH_GROUP 2		/* Default DH group for agg. mode */
#define DEFAULT_IDTYPE ID_USER_FQDN	/* Default ID Type for agg. mode */
#define DEFAULT_EXCHANGE_TYPE ISAKMP_XCHG_IDPROT	/* Main Mode */
#define DEFAULT_NONCE_LEN 20		/* Default Nonce length in bytes */
#define DEFAULT_HEADER_VERSION 0x10	/* Default ISAKMP header version */
#define DEFAULT_DOI ISAKMP_DOI_IPSEC	/* Default SA DOI */
#define DEFAULT_SITUATION SIT_IDENTITY_ONLY /* Default SA Situation */
#define DEFAULT_PROTOCOL PROTO_ISAKMP	/* Default Proposal Protocol */
#define DEFAULT_TRANS_ID KEY_IKE	/* Default Transform ID */
#define DEFAULT_IKE_VERSION 1		/* Default IKE version */
#define PATTERNS_FILE "ike-backoff-patterns" /* Backoff patterns filename */
#define VID_FILE "ike-vendor-ids"	/* Vendor ID patterns filename */
#define REALLOC_COUNT	1000		/* Entries to realloc at once */
#define DEFAULT_TCP_CONNECT_TIMEOUT 10	/* TCP connect timeout in seconds */
#define TCP_PROTO_RAW 1			/* Raw IKE over TCP (Checkpoint) */
#define TCP_PROTO_ENCAP 2		/* Encapsulated IKE over TCP (cisco) */
#define PACKET_OVERHEAD 28		/* 20 bytes for IP hdr + 8 for UDP */
#define OPT_SPISIZE 256
#define OPT_HDRFLAGS 257
#define OPT_HDRMSGID 258
#define OPT_COOKIE 259
#define OPT_EXCHANGE 260
#define OPT_NEXTPAYLOAD 261
#define OPT_WRITEPKTTOFILE 262
#define OPT_RANDOMSEED 263
#define OPT_TIMESTAMP 264
#define OPT_SOURCEIP 265
#define OPT_SHOWNUM 266
#define OPT_NAT_T 267
#define OPT_RCOOKIE 268
#define OPT_READPKTFROMFILE 269
#define OPT_BINDIP 270
#undef DEBUG_TIMINGS			/* Define to 1 to debug timing code */
/* #define WRITE_RECEIVED_IKE_PACKET "received-ike-packet.dat" */

/* Structures */
typedef struct time_list_ {
   struct timeval time;
   struct time_list_ *next;
} time_list;

typedef struct {
   int id;
   union {
      void *ptr;
      int val;
   } un;
} misc_data;

typedef struct {
   time_list *recv_times; 	/* List of receive times */
   misc_data *extra;		/* Extra data for this entry */
   unsigned n;			/* Ordinal number for this entry */
   unsigned timeout;		/* Timeout for this host */
   uint32_t icookie[COOKIE_SIZE];	/* IKE Initiator cookie */
   struct in_addr addr;		/* Host IP address */
   struct timeval last_send_time; /* Time when last packet sent to this addr */
   unsigned short num_sent;	/* Number of packets sent */
   unsigned short num_recv;	/* Number of packets received */
   unsigned char live;		/* Set when awaiting response */
} host_entry;

typedef struct pattern_entry_list_ {
   struct timeval time;
   unsigned fuzz;
   struct pattern_entry_list_ *next;
} pattern_entry_list;

typedef struct pattern_list_ {
   char *name;			/* Name of this backoff pattern */
   unsigned num_times;		/* Number of time entries in this pattern */
   pattern_entry_list *recv_times;	/* Pointer to list of times */
   struct pattern_list_ *next;
} pattern_list;

typedef struct vid_pattern_list_ {
   char *name;
   char *pattern;	/* Text regular expression */
   regex_t *regex;	/* Compiled regular expression */
   struct vid_pattern_list_ *next;
} vid_pattern_list;

typedef struct {
   unsigned char *g_xr;		/* Responder DH public value */
   unsigned char *g_xi;		/* Initiator DH public value */
   unsigned char *cky_r;	/* Responder cookie */
   unsigned char *cky_i;	/* Initiator cookie */
   unsigned char *sai_b;	/* Initiator SA payload */
   unsigned char *idir_b;	/* Responder ID payload */
   unsigned char *ni_b;		/* Initiator nonce */
   unsigned char *nr_b;		/* Responder nonce */
   unsigned char *hash_r;	/* Responder hash */
   size_t g_xr_len;
   size_t g_xi_len;
   size_t cky_r_len;
   size_t cky_i_len;
   size_t sai_b_len;
   size_t idir_b_len;
   size_t ni_b_len;
   size_t nr_b_len;
   size_t hash_r_len;
} psk_crack;

typedef struct {
   int id;			/* IKE IDs are generally 8 or 16-bits */
   const char *name;
} id_name_map;

typedef struct {		/* Used for encapsulated IKE */
  uint16_t     source;
  uint16_t     dest;
  uint16_t     len;
  uint16_t     check;
} ike_udphdr;

/*
 * If you change the ordering of the members in this struct, then you must
 * also change the initialisation of ike_params in main() in ike-scan.c to
 * conform to the new order.
 */
typedef struct {	/* IKE Packet Parameters */
   unsigned char *lifetime_data;
   size_t lifetime_data_len;
   unsigned char *lifesize_data;
   size_t lifesize_data_len;
   unsigned auth_method;
   unsigned dhgroup;
   unsigned idtype;
   unsigned char *id_data;
   size_t id_data_len;
   int vendor_id_flag;
   int trans_flag;
   unsigned exchange_type;
   int gss_id_flag;
   unsigned char *gss_data;
   size_t gss_data_len;
   size_t nonce_data_len;
   char *header_length;
   unsigned char *cr_data;
   size_t cr_data_len;	
   int header_version;	/* ISAKMP Header Version */
   unsigned doi;	/* SA DOI */
   unsigned situation;	/* SA Situation */
   unsigned protocol;	/* Proposal protocol */
   unsigned trans_id;	/* Transform ID */
   unsigned spi_size;	/* Proposal SPI Size */
   int hdr_flags;	/* ISAKMP Header flags */
   unsigned hdr_msgid;	/* ISAKMP Header message id */
   unsigned hdr_next_payload;	/* Next payload in ISAKMP header */
   int advanced_trans_flag;
   int ike_version;	/* IKE version */
   unsigned char *rcookie_data;	/* Responder cookie */
   size_t rcookie_data_len;
} ike_packet_params;

/* Functions */

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

void err_sys(const char *, ...);
void warn_sys(const char *, ...);
void err_msg(const char *, ...);
void warn_msg(const char *, ...);
void err_print(int, const char *, va_list);
void usage(int, int);
void add_host_pattern(const char *, unsigned, unsigned *, unsigned char *,
                      size_t);
void add_host(const char *, unsigned, unsigned *, unsigned char *,
              size_t, int);
void send_packet(int, unsigned char *, size_t, host_entry *, unsigned, unsigned,
                 struct timeval *);
int recvfrom_wto(int, unsigned char *, size_t, struct sockaddr *, int);
void remove_host(host_entry **, unsigned *, unsigned);
void timeval_diff(const struct timeval *, const struct timeval *,
                  struct timeval *);
unsigned char *initialise_ike_packet(size_t *, ike_packet_params *);
host_entry *find_host_by_cookie(host_entry **, unsigned char *,
                                       int, unsigned);
void display_packet(int, unsigned char *, host_entry *,
                    struct in_addr *, unsigned *, unsigned *, int, int);
void advance_cursor(unsigned, unsigned);
void dump_list(unsigned);
void dump_times(unsigned);
void add_recv_time(host_entry *, struct timeval *);
void load_backoff_patterns(const char *, unsigned);
void add_pattern(char *, unsigned);
void load_vid_patterns(const char *);
void add_vid_pattern(char *);
char **load_id_strings(char *);
char *match_pattern(host_entry *);
int times_close_enough(struct timeval *, struct timeval *, unsigned);
void dump_backoff(unsigned);
void dump_vid(void);
unsigned int hstr_i(const char *);
unsigned char* hex2data(const char *, size_t *);
unsigned char* hex_or_str(const char *, size_t *);
unsigned char* hex_or_num(const char *, size_t *);
unsigned char* make_isakmp_hdr(unsigned, unsigned, unsigned, int, int,
                               unsigned, unsigned char*, size_t);
unsigned char* make_sa(size_t *, unsigned, unsigned, unsigned, unsigned char *,
                       size_t);
unsigned char* make_sa2(size_t *, unsigned, unsigned char *, size_t);
unsigned char* make_prop(size_t *, unsigned, unsigned, unsigned, unsigned,
                         unsigned, unsigned char *, size_t);
unsigned char* add_prop(int, size_t *, unsigned, unsigned,
                        unsigned, unsigned char *, size_t);
unsigned char* make_trans_simple(size_t *, unsigned, unsigned, unsigned,
                                 unsigned, unsigned, unsigned, unsigned,
                                 unsigned char *, size_t, unsigned char *,
                                 size_t, int, unsigned char *, size_t,
                                 unsigned);
unsigned char* add_trans_simple(int, size_t *, unsigned, unsigned, unsigned,
                                unsigned, unsigned, unsigned char *, size_t,
                                unsigned char *, size_t, int, unsigned char *,
                                size_t, unsigned);
unsigned char* make_attr(size_t *, int, unsigned, size_t, unsigned, void *);
unsigned char* add_attr(int, size_t *, int, unsigned, size_t, unsigned,
                        void *);
unsigned char* make_vid(size_t *, unsigned, unsigned char *, size_t);
unsigned char* add_vid(int, size_t *, unsigned char *, size_t, int, unsigned);
unsigned char* make_ke(size_t *, unsigned, size_t);
unsigned char* make_ke2(size_t *, unsigned, unsigned, size_t);
unsigned char* make_nonce(size_t *, unsigned, size_t);
unsigned char* make_id(size_t *, unsigned, unsigned, unsigned char *, size_t);
unsigned char* make_cr(size_t *, unsigned, unsigned char *, size_t);
unsigned char* make_udphdr(size_t *, unsigned, unsigned, unsigned);
int Gettimeofday(struct timeval *);
void *Malloc(size_t);
void *Realloc(void *, size_t);
unsigned long int Strtoul(const char *, int);
long int Strtol(const char *, int);
void decode_trans_simple(const char *, unsigned *, unsigned *, unsigned *,
                         unsigned *, unsigned *);
unsigned char *decode_transform(const char *, size_t *);
unsigned char *skip_payload(unsigned char *, size_t *, unsigned *);
unsigned char *process_isakmp_hdr(unsigned char *, size_t *, unsigned *,
                                  unsigned *, char **);
char *process_sa(unsigned char *, size_t, unsigned, int, int, char *);
char *process_sa2(unsigned char *, size_t, unsigned, int, int, char *);
char *process_attr(unsigned char **, size_t *);
char *process_transform2(unsigned char **, size_t *);
char *process_vid(unsigned char *, size_t, vid_pattern_list *);
char *process_notify(unsigned char *, size_t, int, int, char *);
char *process_notify2(unsigned char *, size_t, int, int, char *);
char *process_id(unsigned char *, size_t);
char *process_cert(unsigned char *, size_t, unsigned);
char *process_delete(unsigned char *, size_t);
char *process_notification(unsigned char *, size_t);
char *process_generic(unsigned char *, size_t, unsigned);
unsigned char *make_transform(size_t *, unsigned, unsigned, unsigned,
                              unsigned char *, size_t);
unsigned char* add_transform(int, size_t *, unsigned, unsigned char *, size_t);
unsigned char* make_transform2(size_t *, unsigned, unsigned, unsigned,
                               unsigned char *, size_t);
unsigned char* add_transform2(int, size_t *, unsigned, unsigned,
                              unsigned char *, size_t);
unsigned char *add_isakmp_payload(unsigned char *, size_t, unsigned char **);
void print_payload(unsigned char *cp, unsigned payload, int);
void add_psk_crack_payload(unsigned char *cp, unsigned, int);
void print_psk_crack_values(const char *);
unsigned char *clone_payload(const unsigned char *, size_t);
char *make_message(const char *, ...);
char *numstr(unsigned);
char *printable(const unsigned char*, size_t);
char *hexstring(const unsigned char*, size_t);
void print_times(void);
void sig_alarm(int);
const char *id_to_name(unsigned, const id_name_map[]);
int name_to_id(const char *, const id_name_map[]);
uint16_t in_cksum(uint16_t *, size_t);
uint8_t random_byte(void);
uint32_t random_ip(void);
int str_ccmp(const char *, const char *);
unsigned name_or_number(const char *, const id_name_map[]);
unsigned str_to_bandwidth(const char *);
unsigned str_to_interval(const char *);
char *dupstr(const char *);
/* MT19937 prototypes */
void init_genrand(unsigned long);
void init_by_array(unsigned long[], int);
unsigned long genrand_int32(void);
long genrand_int31(void);
double genrand_real1(void);
double genrand_real2(void);
double genrand_real3(void);
double genrand_res53(void);

#endif	/* IKE_SCAN_H */
