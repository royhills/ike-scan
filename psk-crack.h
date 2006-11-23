/*
 * The IKE Scanner (ike-scan) is Copyright (C) 2003-2005 Roy Hills,
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
 * You are encouraged to send comments, improvements or suggestions to
 * me at ike-scan@nta-monitor.com.
 *
 * $Id$
 *
 * psk-crack.h -- Header file for psk-crack
 *
 * Author:	Roy Hills
 * Date:	21 November 2006
 */

#ifndef PSK_CRACK_H
#define PSK_CRACK_H 1

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
#else
#error This program requires the ANSI C Headers
#endif

/* Integer types */
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#else
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#endif

#ifdef __CYGWIN__
#include <windows.h>	/* Include windows.h if compiling under Cygwin */
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

#ifdef HAVE_OPENSSL
#include <openssl/md5.h>
#include <openssl/sha.h>
#else
#include "md5.h"
#include "sha1.h"
unsigned char *MD5(const unsigned char *, size_t, unsigned char *);
unsigned char *SHA1(const unsigned char *, size_t, unsigned char *);
#endif

/* Defines */

#define MAXLINE 255			/* Max line length for input files */
#define DICT_FILE "psk-crack-dictionary" /* psk-crack dictionary filename */
#define MAXLEN 4096
#define HASH_TYPE_MD5 1
#define HASH_TYPE_SHA1 2
#define MD5_HASH_LEN 16
#define SHA1_HASH_LEN 20
#define PSK_REALLOC_COUNT 10		/* Number of PSK entries to allocate */

/* Structures */

/* PSK parameter entry */
typedef struct {
   unsigned char *skeyid_data;	/* Data for SKEYID calculation */
   unsigned char *hash_r_data;	/* Data for HASH_R calculation */
   unsigned char *hash_r;	/* HASH_R received from server */
   char *hash_r_hex;		/* Server HASH_R as hex for display */
   char *hash_name;		/* Hash algo. name for display */
   size_t skeyid_data_len;	/* Length of skeyid_data field */
   size_t hash_r_data_len;	/* Length of hash_r_data field */
   size_t hash_r_len;		/* Length of hash_r field */
   int hash_type;		/* Hash algorithm used for hmac */
} psk_entry;


/* Functions */

static unsigned load_psk_params(const char *);
void err_sys(const char *, ...);
void warn_sys(const char *, ...);
void err_msg(const char *, ...);
void warn_msg(const char *, ...);
void info_syslog(const char *, ...);
void err_print(int, int, const char *, va_list);
static void psk_crack_usage(int);
void timeval_diff(const struct timeval *, const struct timeval *,
                  struct timeval *);
unsigned int hstr_i(const char *);
unsigned char* hex2data(const char *, size_t *);
unsigned char* hex_or_str(const char *, size_t *);
unsigned char* hex_or_num(const char *, size_t *);
int Gettimeofday(struct timeval *);
void *Malloc(size_t);
void *Realloc(void *, size_t);
unsigned long int Strtoul(const char *, int);
char *make_message(const char *, ...);
char *numstr(unsigned);
char *printable(const unsigned char*, size_t);
char *hexstring(const unsigned char*, size_t);
unsigned char *hmac_md5(const unsigned char *, size_t,
                        const unsigned char *, size_t, unsigned char *);
unsigned char *hmac_sha1(const unsigned char *, size_t,
                         const unsigned char *, size_t, unsigned char *);
/* The following functions are just to prevent rcsid being optimised away */
void error_use_rcsid(void);
void wrappers_use_rcsid(void);
void utils_use_rcsid(void);

#endif	/* PSK_CRACK_H */
