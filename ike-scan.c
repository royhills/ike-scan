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
 * ike-scan -- Scan for IKE hosts
 *
 * Copyright (C) Roy Hills, NTA Monitor Ltd
 *
 * Author: Roy Hills
 * Date: 11 September 2002
 *
 * Usage:
 *    ike-scan [options] [host...]
 *
 * Description:
 *
 * ike-scan - The IKE security scanner
 * 
 * ike-scan sends IKE main mode requests to the specified hosts and displays
 * any responses that are received.  It handles retry and retransmission with
 * backoff to cope with packet loss.
 * 
 * Use ike-scan --help to display information on the usage and options.
 * 
 * The hosts to scan can be specified on the command line or read from an
 * input file using the --file=<fn> option.  The program can cope with
 * large numbers of hosts limited only by the amount of memory needed to store
 * the list of host_entry structures.  Each host_entry structure requires 52
 * bytes on a 32-bit system, so a class B network (65534 hosts) would require
 * about 3.25 MB for the list.
 * 
 * The program limits the rate at which it sends IKE packets to ensure that
 * it does not overload the network connection.  By default the rate limit
 * is one packet every 80ms which equates to a data rate of 36400 bits per
 * second given the default packet size of 364 bytes.  For faster links, the
 * packet rate can be raised by lowering the minimum packet interval using
 * --interval=<n> which sets the minimum packet interval to n ms.
 * 
 * By default, the main mode packets sent contain one proposal which contains
 * 8 transforms.  These 8 transforms represent all possible combinations of:
 * a) Encryption Algorithm: DES-CBC and 3DES-CBC;
 * b) Hash Algorithm: MD5 and SHA; and
 * c) DH Group: 1 (MODP 768) and 2 (MODP 1024).
 * 
 * It is also possible to specify the Authentication Method with --auth
 * (default is 1 - pre-shared key) and the IKE lifetime in seconds with
 * --lifetime (default is 28800 seconds or 8 hours as recommended by RFC 2407).
 * 
 * This default transform set is designed to be acceptable to most IKE
 * implementations - most will accept at least one of the offered transforms.
 * However, it is often necessary to use a different authentication method
 * (pre-shared key is the most common, but is not always supported) and
 * more rarely it may be necessary to reduce the lifetime.
 * 
 * The default transform set results in a packet data length of 336 bytes which
 * when IP and UDP headers are added gives a total packet size of 364 bytes.
 * 
 * It is also possible to specify a single custom transform with
 * --trans=e,h,a,g where e is the Encryption Algorithm, h the Hash Algorithm,
 * a the Authentication Method and g is the DH Group.  These are specified as
 * values; see RFC 2409 Appendix A for details of which values to use.  For
 * example, --trans=2,3,1,5 would specify Enc=IDEA-CBC, Hash=Tiger, DH Group=5
 * (MODP 1536), Auth=1 (pre-shared key).
 * 
 * If a custom transform is specified, then only a single transform is used,
 * and the packet data length is 84 bytes for a total packet length of 112
 * bytes.  Specifying a custom transform also overrides authentication method
 * (either the default of pre-shared key or as specified with --auth).
 * However, it is still possible to change the IKE lifetime of the custom
 * transform with --lifetime.
 * 
 * A custom transform can be useful in the following situations:
 * a) If none of the transforms in the default transform set is acceptable to
 *    the remote IKE implementation;
 * b) If you know that a particular transform will be acceptable, and you want
 *    to minimise bandwidth use or allow faster scanning rates; or
 * c) If you want to determine exactly which transforms a remote IKE
 *    implementation supports for fingerprinting.
 * 
 * For those hosts that respond, ike-scan records the times of the received
 * IKE responses.  The backoff between IKE responses varies between different
 * IKE implementations and can therefore be used as a fingerprint.  The
 * --showbackoff option is used to display the backoff times for each host
 * which responded.  Note that using the --showbackoff option will cause
 * ike-scan to wait for 60 seconds after the last received packet to ensure
 * that it has seen all of the responses.  This 60 second wait can be
 * altered by specifying a different value to the --showbackoff option.
 *
 * Change History:
 *
 * $Log$
 * Revision 1.32  2003/01/04 17:49:05  rsh
 * Added support for matching backoff patterns against patterns file.
 *
 * Revision 1.31  2003/01/04 12:59:27  rsh
 * Wrote body of add_pattern function.
 *
 * Revision 1.30  2003/01/03 15:35:54  rsh
 * Changed DEFAULT_END_WAIT from ms to seconds.
 * Added more details to the usage text.
 *
 * Revision 1.29  2003/01/02 13:28:29  rsh
 * Wrapped libgen.h include in #ifdef HAVE_LIBGEN_H / #endif.
 *
 * Revision 1.28  2002/12/31 21:09:47  rsh
 * Changes to allow compilation on FreeBSD and OpenBSD as well as Linux.
 *
 * Revision 1.27  2002/12/31 15:14:38  rsh
 * Changed function definitions so return type is on a line by itself.
 * Added contents of README file as initial program comments.
 *
 * Revision 1.26  2002/12/31 09:29:42  rsh
 * Added initial support for backoff pattern matching.  This is not working yet.
 *
 * Revision 1.25  2002/11/21 17:59:28  rsh
 * Changed --endwait to --showbackoff.
 *
 * Revision 1.24  2002/11/21 13:49:56  rsh
 * Added GPL and gethostbyname() call.
 *
 * Revision 1.23  2002/11/18 16:20:30  rsh
 * Added endwait option and associated code.
 *
 * Revision 1.22  2002/11/18 12:20:25  rsh
 * Changed timeval_diff() definition to return difference as timeval not int.
 *
 * Revision 1.21  2002/11/18 11:02:45  rsh
 * Added initial backoff fingerprinting support.
 *
 * Revision 1.20  2002/11/15 17:47:37  rsh
 * Added initial syslog support.
 * Minor comment changes.
 *
 * Revision 1.19  2002/10/31 14:45:50  rsh
 * Only display "unknown cookie" message if verbose >= 1
 * Check for he == NULL in find_host_by_cookie to avoid SIGSEGV if it is.
 *
 * Revision 1.18  2002/10/29 09:02:04  rsh
 * Added printing of cookie data in "unknown cookie" message.
 *
 * Revision 1.17  2002/10/28 16:55:32  rsh
 * Added support for --trans option to specify single custom transform.
 *
 * Revision 1.16  2002/10/28 16:24:35  rsh
 * Only use cookie to find host in list.
 * Removed find_host_by_ip() - not needed now.
 *
 * Revision 1.15  2002/10/28 16:05:26  rsh
 * icookie is now md5 hash rather than random no to ensure unique.
 * added dump_list() function.
 *
 * Revision 1.14  2002/10/25 08:55:51  rsh
 * Added vendor id support.  Not fully tested yet.
 *
 * Revision 1.13  2002/10/24 15:19:04  rsh
 * Added "---\t" to wanr messages.
 * Added placeholder function to decode transforms.
 *
 * Revision 1.12  2002/09/20 17:10:01  rsh
 * Added find_host_by_cookie() function and related code to find the host
 * entry if the received IP doesn't match.  Modified display_packet to display
 * both host entry IP and received IP in these cases.
 * Added advance_cursor() function to tidy up main loop.
 *
 * Revision 1.11  2002/09/17 09:00:00  rsh
 * Minor change to usage() display.
 * Removed trans_in from display_packet().
 *
 * Revision 1.10  2002/09/16 14:26:30  rsh
 * Changed timeval_diff computation method from floating point to integer.
 * Modified main loop so that timing is more exact.
 *
 * Revision 1.9  2002/09/16 12:15:39  rsh
 * Don't remove host entries from the list, mark them as not live instead.
 * This allows us to identify responses that come in after the host has been
 * marked as not live.
 * Treat connection refused as timeout because we can't determine which host
 * connection refused relates to.
 * Moved recvfrom_wto to end of main loop so it always gets run once per loop.
 *
 * Revision 1.8  2002/09/16 08:41:27  rsh
 * Changed non-printable characters to spaces for Firewall-1 4.x notify messages.
 *
 * Revision 1.7  2002/09/15 14:08:13  rsh
 * removed exchange_type array as this was not used.
 * Don't set name member of host entry - this is not used as has been removed.
 * Update cursor in remove_host to avoid having to do it before calling the
 * function.
 *
 * Revision 1.6  2002/09/13 15:01:51  rsh
 * Added support for changing authentication method.
 *
 * Revision 1.5  2002/09/13 12:30:59  rsh
 * Added checks that returned packet is long enough before copying.
 * Added lifetime argument.
 *
 * Revision 1.4  2002/09/13 10:04:46  rsh
 * Tidied up VERSION string.
 *
 * Revision 1.3  2002/09/13 10:03:38  rsh
 * Added VERSION (moved from ike-scan.h).
 *
 * Revision 1.2  2002/09/13 09:58:22  rsh
 * Added names for ISAKMP codes.
 * Added --selectwait option.
 * Added dh group 1 which increased number of transforms from 4 to 8
 * Added rcsid[]
 * Improved display for notification message types.
 *
 * Revision 1.1  2002/09/12 17:57:53  rsh
 * Initial revision
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <math.h>
#include <netdb.h>
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
#include <errno.h>
#include <syslog.h>
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif

#include "global.h"
#include "md5.h"
#include "ike-scan.h"

#define VERSION "ike-scan $Revision$ $Date$ <Roy.Hills@nta-monitor.com>"
#define MAX_PAYLOAD 13	/* Maximum defined payload number */
static char rcsid[] = "$Id$";   /* RCS ID for ident(1) */

/* Global variables */
struct host_entry *rrlist = NULL;	/* Round-robin linked list "the list" */
struct host_entry *cursor;		/* Pointer to current list entry */
struct pattern_list *patlist = NULL;	/* Backoff pattern list */
unsigned num_hosts = 0;			/* Number of entries in the list */
unsigned live_count;			/* Number of entries awaiting reply */
unsigned retry = DEFAULT_RETRY;		/* Number of retries */
unsigned timeout = DEFAULT_TIMEOUT;	/* Per-host timeout */
unsigned interval = DEFAULT_INTERVAL;	/* Interval between packets */
unsigned select_timeout = DEFAULT_SELECT_TIMEOUT;	/* Select timeout */
float backoff = DEFAULT_BACKOFF_FACTOR;	/* Backoff factor */
int source_port = DEFAULT_SOURCE_PORT;	/* UDP source port */
int dest_port = DEFAULT_DEST_PORT;	/* UDP destination port */
unsigned lifetime = DEFAULT_LIFETIME;	/* Lifetime in seconds */
int auth_method = DEFAULT_AUTH_METHOD;	/* Authentication method */
unsigned end_wait = DEFAULT_END_WAIT;	/* Time to wait after all done */
unsigned pattern_fuzz = DEFAULT_PATTERN_FUZZ; /* Pattern matching fuzz in ms */
int verbose=0;
char vendor_id[MAXLINE];		/* Vendor ID string */
int vendor_id_flag = 0;			/* Indicates if VID to be used */
char trans_str[MAXLINE];		/* Custom transform string */
int trans_flag = 0;			/* Indicates custom transform */
int showbackoff_flag = 0;		/* Display backoff table? */
int trans_enc;				/* Custom transform encrypt */
int trans_hash;				/* Custom transform hash */
int trans_auth;				/* Custom transform auth */
int trans_group;			/* Custom transform group */
struct timeval last_packet_time;	/* Time last packet was sent */
struct timeval last_recv_time;		/* Time last packet was received */
struct isakmp_hdr hdr;			/* ISAKMP Header */
struct isakmp_sa sa_hdr;		/* SA Header */
struct isakmp_proposal sa_prop;		/* Proposal payload */
struct transform
{
   struct isakmp_transform trans_hdr;
   struct isakmp_attribute attr[5];
   struct isakmp_attribute_l32 attr2;
};
struct transform trans[8];		/* Transform payload */
struct isakmp_vid vid_hdr;		/* Vendor ID header */
unsigned char vid_md5[16];		/* Vendor ID data - md5 digest */

char *auth_methods[] = { /* Authentication methods from RFC 2409 Appendix A */
   "UNSPECIFIED",		/* 0 */
   "pre-shared key",		/* 1 */
   "DSS signatures",		/* 2 */
   "RSA signatures",		/* 3 */
   "Encryption with RSA",	/* 4 */
   "Revised encryption with RSA" /* 5 */
};

char *notification_msg[] = { /* Notify Message Types from RFC 2408 3.14.1 */
   "UNSPECIFIED",                    /* 0 */
   "INVALID-PAYLOAD-TYPE",           /* 1 */
   "DOI-NOT-SUPPORTED",              /* 2 */
   "SITUATION-NOT-SUPPORTED",        /* 3 */
   "INVALID-COOKIE",                 /* 4 */
   "INVALID-MAJOR-VERSION",          /* 5 */
   "INVALID-MINOR-VERSION",          /* 6 */
   "INVALID-EXCHANGE-TYPE",          /* 7 */
   "INVALID-FLAGS",                  /* 8 */
   "INVALID-MESSAGE-ID",             /* 9 */
   "INVALID-PROTOCOL-ID",            /* 10 */
   "INVALID-SPI",                    /* 11 */
   "INVALID-TRANSFORM-ID",           /* 12 */
   "ATTRIBUTES-NOT-SUPPORTED",       /* 13 */
   "NO-PROPOSAL-CHOSEN",             /* 14 */
   "BAD-PROPOSAL-SYNTAX",            /* 15 */
   "PAYLOAD-MALFORMED",              /* 16 */
   "INVALID-KEY-INFORMATION",        /* 17 */
   "INVALID-ID-INFORMATION",         /* 18 */
   "INVALID-CERT-ENCODING",          /* 19 */
   "INVALID-CERTIFICATE",            /* 20 */
   "CERT-TYPE-UNSUPPORTED",          /* 21 */
   "INVALID-CERT-AUTHORITY",         /* 22 */
   "INVALID-HASH-INFORMATION",       /* 23 */
   "AUTHENTICATION-FAILED",          /* 24 */
   "INVALID-SIGNATURE",              /* 25 */
   "ADDRESS-NOTIFICATION",           /* 26 */
   "NOTIFY-SA-LIFETIME",             /* 27 */
   "CERTIFICATE-UNAVAILABLE",        /* 28 */
   "UNSUPPORTED-EXCHANGE-TYPE",      /* 29 */
   "UNEQUAL-PAYLOAD-LENGTHS"         /* 30 */
};

char *payload_name[] = {     /* Payload types from RFC 2408 3.1 */
   "NONE",                           /* 0 */
   "Security Association",           /* 1 */
   "Proposal",                       /* 2 */
   "Transform",                      /* 3 */
   "Key Exchange",                   /* 4 */
   "Identification",                 /* 5 */
   "Certificate",                    /* 6 */
   "Certificate Request",            /* 7 */
   "Hash",                           /* 8 */
   "Signature",                      /* 9 */
   "Nonce",                          /* 10 */
   "Notification",                   /* 11 */
   "Delete",                         /* 12 */
   "Vendor ID"                       /* 13 */
};

int
main(int argc, char *argv[]) {
   struct option long_options[] = {
      {"file", required_argument, 0, 'f'},
      {"help", no_argument, 0, 'h'},
      {"sport", required_argument, 0, 's'},
      {"dport", required_argument, 0, 'd'},
      {"retry", required_argument, 0, 'r'},
      {"timeout", required_argument, 0, 't'},
      {"interval", required_argument, 0, 'i'},
      {"backoff", required_argument, 0, 'b'},
      {"selectwait", required_argument, 0, 'w'},
      {"verbose", no_argument, 0, 'v'},
      {"lifetime", required_argument, 0, 'l'},
      {"auth", required_argument, 0, 'm'},
      {"version", no_argument, 0, 'V'},
      {"vendor", required_argument, 0, 'e'},
      {"trans", required_argument, 0, 'a'},
      {"showbackoff", optional_argument, 0, 'o'},
      {"fuzz", required_argument, 0, 'u'},
      {0, 0, 0, 0}
   };
   char *short_options = "f:hs:d:r:t:i:b:w:vl:m:Ve:a:o::u:";
   int arg;
   char arg_str[MAXLINE];	/* Args as string for syslog */
   int options_index=0;
   char filename[MAXLINE];
   int filename_flag=0;
   int sockfd;			/* UDP socket file descriptor */
   struct sockaddr_in sa_local;
   struct sockaddr_in sa_peer;
   struct timeval now;
   char packet_in[MAXUDP];	/* Received packet */
   int n;
   struct host_entry *temp_cursor;
   struct hostent *hp;
   struct timeval diff;		/* Difference between two timevals */
   unsigned long loop_timediff;
   unsigned long host_timediff;
   unsigned long end_timediff=0;
/*
 *	Open syslog channel and log arguments if required
 */
#ifdef SYSLOG
   openlog(basename(argv[0]), LOG_PID, SYSLOG_FACILITY);
   arg_str[0] = '\0';
   for (arg=0; arg<argc; arg++) {
      strcat(arg_str, argv[arg]);
      if (arg < (argc-1)) {
         strcat(arg_str, " ");
      }
   }
   info_syslog("Starting: %s", arg_str);
#endif
/*
 *	Process options and arguments.
 */
   while ((arg=getopt_long_only(argc, argv, short_options, long_options, &options_index)) != -1) {
      switch (arg) {
         MD5_CTX context;
         int i;
         case 'f':
            strncpy(filename, optarg, MAXLINE);
            filename_flag=1;
            break;
         case 'h':
            usage();
            break;
         case 's':
            source_port=atoi(optarg);
            break;
         case 'd':
            dest_port=atoi(optarg);
            break;
         case 'r':
            retry=atoi(optarg);
            break;
         case 't':
            timeout=atoi(optarg);
            break;
         case 'i':
            interval=atoi(optarg);
            break;
         case 'b':
            backoff=atof(optarg);
            break;
         case 'w':
            select_timeout=atoi(optarg);
            break;
         case 'v':
            verbose++;
            break;
         case 'l':
            lifetime=atoi(optarg);
            break;
         case 'm':
            auth_method=atoi(optarg);
            break;
         case 'V':
            fprintf(stderr, "%s\n", VERSION);
            exit(0);
            break;
         case 'e':
            strncpy(vendor_id, optarg, MAXLINE);
            vendor_id_flag=1;
            MD5Init(&context);
            MD5Update(&context, vendor_id, strlen(vendor_id));
            MD5Final(&vid_md5,&context);
            printf("vid_md5: ");
            for (i=0; i<16; i++)
               printf("%.2x",vid_md5[i]);
            printf("\n");
            break;
         case 'a':
            strncpy(trans_str, optarg, MAXLINE);
            trans_flag=1;
            sscanf(trans_str, "%d,%d,%d,%d", &trans_enc, &trans_hash, &trans_auth, &trans_group);
            break;
         case 'o':
            showbackoff_flag=1;
            if (optarg == NULL) {
               end_wait=1000 * DEFAULT_END_WAIT;
            } else {
               end_wait=1000 * atoi(optarg);
            }
            break;
         case 'u':
            pattern_fuzz=atoi(optarg);
            break;
         default:
            usage();
            break;
      }
   }
/*
 *	If we're not reading from a file, then we must have some hosts
 *	given as command line arguments.
 */
   hp = gethostbyname("ike-scan-target.test.nta-monitor.com");
   if (!filename_flag) 
      if ((argc - optind) < 1)
         usage();
/*
 *	Populate the list from the specified file if --file was specified, or
 *	otherwise from the remaining command line arguments.
 */
   if (filename_flag) {	/* Populate list from file */
      FILE *fp;
      char line[MAXLINE];
      char host[MAXLINE];

      if ((strcmp(filename, "-")) == 0) {	/* Filename "-" means stdin */
         if ((fp = fdopen(0, "r")) == NULL) {
            err_sys("fdopen");
         }
      } else {
         if ((fp = fopen(filename, "r")) == NULL) {
            err_sys("fopen");
         }
      }

      while (fgets(line, MAXLINE, fp)) {
         if ((sscanf(line, "%s", host)) == 1) {
            add_host(host);
         }
      }
      fclose(fp);
   } else {		/* Populate list from command line arguments */
      argv=&argv[optind];
      while (*argv) {
         add_host(*argv);
         argv++;
      }
   }
/*
 *	If we are displaying the backoff table, load known backoff
 *	patterns from the backoff patterns file.
 */
   if (showbackoff_flag) {
      FILE *fp;
      char line[MAXLINE];
      char patfile[MAXLINE];
      int line_no;

      sprintf(patfile, "%s/%s", DATADIR, PATTERNS_FILE);
      if ((fp = fopen(patfile, "r")) == NULL) {
         warn_sys("fopen: %s", patfile);
         warn_msg("Cannot open IKE backoff patterns file.  Will not be able to identify fingerprints.");
      } else {
         line_no=0;
         while (fgets(line, MAXLINE, fp)) {
            line_no++;
            if (line[0] != '#')
               add_pattern(line);
         }
         fclose(fp);
      }
   }
/*
 *	Check that we have at least one entry in the list.
 */
   if (!num_hosts)
      err_msg("No hosts to process.");
#ifdef SYSLOG
   info_syslog("%d hosts in list", num_hosts);
#endif
/*
 *	Create UDP socket and bind to local source port.
 */
   if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
      err_sys("socket");

   memset(&sa_local, '\0', sizeof(sa_local));
   sa_local.sin_family = AF_INET;
   sa_local.sin_addr.s_addr = htonl(INADDR_ANY);
   sa_local.sin_port = htons(source_port);

   if ((bind(sockfd, (struct sockaddr *)&sa_local, sizeof(sa_local))) < 0) {
      perror("bind");
      exit(1);
   }
/*
 *	Set current host pointer (cursor) to start of list, zero
 *	last packet sent time, set last receive time to now and
 *	initialise static IKE header fields.
 */
   live_count = num_hosts;
   cursor = rrlist;
   last_packet_time.tv_sec=0;
   last_packet_time.tv_usec=0;
   if ((gettimeofday(&last_recv_time, NULL)) != 0) {
      err_sys("gettimeofday");
   }
   initialise_ike_packet();
/*
 *	Display the list if verbose setting is 3 or more.
 */
   if (verbose > 2)
      dump_list();
/*
 *	Main loop: send packets to all hosts in order until a response
 *	has been received or the host has exhausted it's retry limit.
 *
 *	The loop exits when all hosts have either responded or timed out
 *	and, if showbackoff_flag is set, at least end_wait ms have elapsed
 *	since the last packet was received.
 */
   while (live_count || (showbackoff_flag && end_timediff < end_wait)) {
/*
 *	Obtain current time and calculate deltas since last packet and
 *	last packet to this host.
 */
      if ((gettimeofday(&now, NULL)) != 0) {
         err_sys("gettimeofday");
      }
      timeval_diff(&now, &last_recv_time, &diff);
      end_timediff = 1000*diff.tv_sec + diff.tv_usec/1000;
/*
 *	If the last packet was sent more than interval ms ago, then we can
 *	potentially send a packet to the current host.
 */
      timeval_diff(&now, &last_packet_time, &diff);
      loop_timediff = 1000*diff.tv_sec + diff.tv_usec/1000;
      if (loop_timediff > interval) {
/*
 *	If the last packet to this host was sent more than the current
 *	timeout for this host ms ago, then we can potentially send a packet
 *	to it.
 */
         timeval_diff(&now, &(cursor->last_send_time), &diff);
         host_timediff = 1000*diff.tv_sec + diff.tv_usec/1000;
         if (host_timediff > cursor->timeout && cursor->live) {
/*
 *	If we've exceeded our retry limit, then this host has timed out so
 *	remove it from the list.  Otherwise, increase the timeout by the
 *	backoff factor if this is not the first packet sent to this host
 *	and send a packet.
 */
            if (cursor->num_sent >= retry) {
               if (verbose)
                  warn_msg("---\tRemoving host entry %d (%s) - Timeout", cursor->n, inet_ntoa(cursor->addr));
               remove_host(cursor);
            } else {	/* Retry limit not reached for this host */
               if (cursor->num_sent) {
                  cursor->timeout *= backoff;
               }
               send_packet(sockfd, cursor);
               advance_cursor();
            }
         } else {	/* We can't send a packet to this host yet */
            advance_cursor();
         } /* End If */
      } /* End If */
      n=recvfrom_wto(sockfd, packet_in, MAXUDP, (struct sockaddr *)&sa_peer, select_timeout);
      if (n > 0) {
/*
 *	We've received a response try to match up the packet by cookie
 */
         temp_cursor=find_host_by_cookie(cursor, packet_in, n);
         if (temp_cursor) {
/*
 *	We found a cookie match for the returned packet.
 */
            add_recv_time(temp_cursor);
            if (verbose > 1)
               warn_msg("---\tReceived packet #%d from %s",temp_cursor->num_recv ,inet_ntoa(sa_peer.sin_addr));
            if (temp_cursor->live) {
               display_packet(n, packet_in, temp_cursor, &(sa_peer.sin_addr));
               if (verbose)
                  warn_msg("---\tRemoving host entry %d (%s) - Received %d bytes", temp_cursor->n, inet_ntoa(sa_peer.sin_addr), n);
               remove_host(temp_cursor);
            }
         } else {
            struct isakmp_hdr hdr_in;
/*
 *	The received cookie doesn't match any entry in the list
 *	so just issue a message to that effect and ignore the packet.
 */
            if (verbose && n >= sizeof(hdr_in)) {
               memcpy(&hdr_in, packet_in, sizeof(hdr_in));
               warn_msg("---\tIgnoring %d bytes from %s with unknown cookie %0x%0x", n, inet_ntoa(sa_peer.sin_addr),hdr_in.isa_icookie[0], hdr_in.isa_icookie[1]);
            }
         }
      } /* End If */
   } /* End While */
/*
 *	Display the backoff times if --showbackoff option was specified.
 */
   if (showbackoff_flag)
      dump_times();

   close(sockfd);
#ifdef SYSLOG
   info_syslog("Ending");
#endif
   return(0);
}

/*
 *	add_host -- Add a host name and associated address to the list
 */
void
add_host(char *name) {
   struct hostent *hp;
   struct host_entry *he;
   char str[MAXLINE];
   struct timeval now;
   MD5_CTX context;
   unsigned char cookie_md5[16];	/* Cookie data - md5 digest */

   if ((hp = gethostbyname(name)) == NULL)
      err_sys("gethostbyname");

   if ((he = malloc(sizeof(struct host_entry))) == NULL)
      err_sys("malloc");

   num_hosts++;

   if ((gettimeofday(&now,NULL)) != 0) {
      err_sys("gettimeofday");
   }

   he->n = num_hosts;
   memcpy(&(he->addr), hp->h_addr_list[0], sizeof(struct in_addr));
   he->live = 1;
   he->timeout = timeout;
   he->num_sent = 0;
   he->num_recv = 0;
   he->last_send_time.tv_sec=0;
   he->last_send_time.tv_usec=0;
   he->recv_times = NULL;
   sprintf(str, "%lu %lu %d %s", now.tv_sec, now.tv_usec, num_hosts, inet_ntoa(he->addr));
   MD5Init(&context);
   MD5Update(&context, str, strlen(str));
   MD5Final(&cookie_md5,&context);
   memcpy(he->icookie, cookie_md5, sizeof(he->icookie));

   if (rrlist) {	/* List is not empty so add entry */
      he->next = rrlist;
      he->prev = rrlist->prev;
      he->prev->next = he;
      he->next->prev = he;
   } else {		/* List is empty so initialise with entry */
      rrlist = he;
      he->next = he;
      he->prev = he;
   }
}

/*
 * 	remove_host -- Remove the specified host from the list
 *
 *	If the host being removed is the one pointed to by the cursor, this
 *	function updates cursor so that it points to the next entry.
 */
void
remove_host(struct host_entry *he) {
   he->live = 0;
   live_count--;
   if (he == cursor)
      advance_cursor();
}

/*
 *	advance_cursor -- Advance the cursor to point at next live entry
 *
 *	Does nothing if there are no live entries in the list.
 */
void
advance_cursor(void) {
   if (live_count) {
      do {
         cursor = cursor->next;
      } while (!cursor->live);
   } /* End If */
}

/*
 *	find_host_by_cookie	-- Find a host in the list by cookie
 *
 *	he points to current position in list.  Search runs backwards
 *	starting from this point.
 *
 *	packet points to the received packet containing the cookie.
 *
 *	Returns a pointer to the host entry associated with the specified IP
 *	or NULL if no match found.
 */
struct host_entry *
find_host_by_cookie(struct host_entry *he, char *packet_in, int n) {
   struct host_entry *p;
   int found;
   struct isakmp_hdr hdr_in;
/*
 *	Check that the current list position is not null.  Return NULL if it
 *	is.  It's possible for "he" to be NULL if a packet is received just
 *	after the last entry in the list is removed.
 */
   if (he == NULL) {
      return NULL;
   }
/*
 *	Check that the received packet is at least as big as the ISAKMP
 *	header.  Return NULL if not.
 */
   if (n < sizeof(hdr_in)) {
      return NULL;
   }
/*
 *	Copy packet into ISAKMP header structure.
 */
   memcpy(&hdr_in, packet_in, sizeof(hdr_in));

   p = he;
   found = 0;

   do {
      if (p->icookie[0] == hdr_in.isa_icookie[0] &&
          p->icookie[1] == hdr_in.isa_icookie[1]) {
         found = 1;
      } else {
         p = p->prev;
      }
   } while (!found && p != he);

   if (found) {
      return p;
   } else {
      return NULL;
   }
}

/*
 *	display_packet -- Display received IKE packet
 */
void
display_packet(int n, char *packet_in, struct host_entry *he, struct in_addr *recv_addr) {
   struct isakmp_hdr hdr_in;
   struct isakmp_sa sa_hdr_in;
   struct isakmp_proposal sa_prop_in;
   struct isakmp_notification notification_in;
   int msg_len;                 /* Size of notification message in bytes */
   int msg_type;                /* Notification message type */
   char msg_in[MAXLINE];        /* Notification message */
   char ip_str[MAXLINE];	/* IP address(es) to display at start */
   char *cp;
/*
 *	Write the IP addresses to the output string.
 */
   cp = ip_str;
   cp += sprintf(cp, "%s\t", inet_ntoa(he->addr));
   if ((he->addr).s_addr != recv_addr->s_addr)
      cp += sprintf(cp, "(%s) ", inet_ntoa(*recv_addr));
   *cp = '\0';
/*
 *	Check that the received packet is at least as big as the ISAKMP
 *	header.
 */
   if (n < sizeof(hdr_in)) {
      printf("%sShort packet returned (len < ISAKMP header length)\n", ip_str);
      return;
   }
/*
 *	Copy packet into ISAKMP header structure.
 */
   memcpy(&hdr_in, packet_in, sizeof(hdr_in));
/*
 *	Check that the initiator cookie in the packet matches what's in the
 *	host entry.
 */
   if (hdr_in.isa_icookie[0] != he->icookie[0] || hdr_in.isa_icookie[1] != he->icookie[1]) {
      printf("%sReturned icookie doesn't match (received %.8x%.8x; expected %.8x%.8x)\n",
         ip_str, htonl(hdr_in.isa_icookie[0]), htonl(hdr_in.isa_icookie[1]),
         htonl(he->icookie[0]), htonl(he->icookie[1]));
      return;
   }

   if (hdr_in.isa_np == ISAKMP_NEXT_SA) {
/*
 *	1st payload is SA -- IKE handshake
 */
      if (n >= sizeof(hdr_in) + sizeof(sa_hdr_in) + sizeof(sa_prop_in)) {
         packet_in += sizeof(hdr_in);
         memcpy(&sa_hdr_in, packet_in, sizeof(sa_hdr_in));
         packet_in += sizeof(sa_hdr_in);
         memcpy(&sa_prop_in, packet_in, sizeof(sa_prop_in));
         packet_in += sizeof(sa_prop_in);
         decode_transform(packet_in, n, sa_prop_in.isap_notrans);
         printf("%sIKE Handshake returned (%d transforms)\n", ip_str, sa_prop_in.isap_notrans);
      } else {
         printf("%sIKE Handshake returned (%d byte packet too short to decode)\n", ip_str, n);
      }
   } else if (hdr_in.isa_np == ISAKMP_NEXT_N) {
/*
 *	1st payload is notification -- Informational message
 */
      if (n >= sizeof(hdr_in) + sizeof(notification_in)) {
         packet_in += sizeof(hdr_in);
         memcpy(&notification_in, packet_in, sizeof(notification_in));
         msg_type = ntohs(notification_in.isan_type);
         if (msg_type < 31) {                /* RFC Defined message types */
            printf("%sNotify message %d (%s)\n", ip_str, msg_type, notification_msg[msg_type]);
         } else if (msg_type == 9101) {      /* Firewall-1 4.x message */
            char *p;
            msg_len = ntohs(notification_in.isan_length) - sizeof(notification_in);
            packet_in += sizeof(notification_in);
            memcpy(msg_in, packet_in, msg_len);
            packet_in += msg_len;
            *packet_in = '\0';      /* Ensure string is null terminated */
/*
 *	Replace any non-printable characters with "."
 */
            for (p=msg_in; *p != '\0'; p++) {
               if (!isprint(*p))
                  *p='.';
            }
            printf("%sNotify message %d (%s)\n", ip_str, msg_type, msg_in);
         } else {                            /* Unknown message type */
            printf("%sNotify message %d (UNKNOWN MESSAGE TYPE)\n", ip_str, msg_type);
         }
      } else {
         printf("%sNotify message (%d byte packet too short to decode)\n", ip_str, n);
      }
   } else {
/*
 *	Some other payload that we don't understand.  Display the payload
 *	number, and also the payload name if defined.
 */
      if (hdr_in.isa_np <= MAX_PAYLOAD) {
         printf("%sUnknown IKE packet returned payload %d (%s)\n", ip_str, hdr_in.isa_np, payload_name[hdr_in.isa_np]);
      } else {
         printf("%sUnknown IKE packet returned payload %d (UNDEFINED)\n", ip_str, hdr_in.isa_np);
      }
   }
}

/*
 *	decode-transform -- Decode an IKE transform payload
 */
void
decode_transform(char *packet_in, int n, int ntrans) {
   if (ntrans <=0)
      return;	/* Nothing to do if no transforms */
/*
 *	Body of function has not been written yet.
 */
}

/*
 *	send_packet -- Construct and send a packet to the specified host
 */
void
send_packet(int s, struct host_entry *he) {
   struct sockaddr_in sa_peer;
   char buf[MAXUDP];
   int buflen;
   int sa_peer_len;
   char *cp;
/*
 *	Set up the sockaddr_in structure for the host.
 */
   memset(&sa_peer, '\0', sizeof(sa_peer));
   sa_peer.sin_family = AF_INET;
   sa_peer.sin_addr.s_addr = he->addr.s_addr;
   sa_peer.sin_port = htons(dest_port);
   sa_peer_len = sizeof(sa_peer);
/*
 *	Copy the initiator cookie from the host entry into the ISAKMP header.
 */
   hdr.isa_icookie[0] = he->icookie[0];
   hdr.isa_icookie[1] = he->icookie[1];
/*
 *	Copy the IKE structures into the output buffer
 */
   cp = buf;
   memcpy(cp,&hdr,sizeof(hdr));
   cp += sizeof(hdr);
   memcpy(cp,&sa_hdr,sizeof(sa_hdr));
   cp += sizeof(sa_hdr);
   memcpy(cp,&sa_prop,sizeof(sa_prop));
   cp += sizeof(sa_prop);
   buflen = sizeof(hdr)+sizeof(sa_hdr)+sizeof(sa_prop);
   if (trans_flag) {
      memcpy(cp,&trans[0],sizeof(trans[0]));
      cp += sizeof(trans[0]);
      buflen += sizeof(trans[0]);
   } else {
      memcpy(cp,&trans,sizeof(trans));
      cp += sizeof(trans);
      buflen += sizeof(trans);
   }
   if (vendor_id_flag) {
      memcpy(cp, &vid_hdr, sizeof(vid_hdr));
      cp += sizeof(vid_hdr);
      memcpy(cp, &vid_md5, sizeof(vid_md5));
      cp += sizeof(vid_md5);
      buflen += sizeof(vid_hdr)+sizeof(vid_md5);
   } 
/*
 *	Update the last send times for this host.
 */
   if ((gettimeofday(&last_packet_time, NULL)) != 0) {
      err_sys("gettimeofday");
   }
   he->last_send_time.tv_sec  = last_packet_time.tv_sec;
   he->last_send_time.tv_usec = last_packet_time.tv_usec;
   he->num_sent++;
/*
 *	Send the packet.
 */
   if (verbose > 1)
      warn_msg("---\tSending packet #%d to host entry %d (%s) tmo %d", he->num_sent, he->n, inet_ntoa(he->addr), he->timeout);
   if ((sendto(s, buf, buflen, 0, (struct sockaddr *) &sa_peer, sa_peer_len)) < 0) {
      err_sys("sendto");
   }
}

/*
 *	recvfrom_wto -- Receive packet with timeout
 *
 *	Returns number of characters received, or -1 for timeout.
 */
int
recvfrom_wto(int s, char *buf, int len, struct sockaddr *saddr, int tmo) {
   fd_set readset;
   struct timeval to;
   int n;
   int saddr_len;

   FD_ZERO(&readset);
   FD_SET(s, &readset);
   to.tv_sec  = tmo/1000;
   to.tv_usec = (tmo - 1000*to.tv_sec) * 1000;
   n = select(s+1, &readset, NULL, NULL, &to);
   if (n < 0) {
      err_sys("select");
   } else if (n == 0) {
      return -1;	/* Timeout */
   }
   saddr_len = sizeof(struct sockaddr);
   if ((n = recvfrom(s, buf, len, 0, saddr, &saddr_len)) < 0) {
      if (errno == ECONNREFUSED) {
/*
 *	Treat connection refused as timeout.
 *	It would be nice to remove the associated host, but we can't because
 *	we cannot tell which host the connection refused relates to.
 */
         return -1;
      } else {
         err_sys("recvfrom");
      }
   }
   return n;
}

/*
 *	Calculates the difference between two timevals and returns this
 *	difference in a third timeval.
 *	diff = a - b.
 */
void
timeval_diff(struct timeval *a, struct timeval *b, struct timeval *diff) {

   /* Perform the carry for the later subtraction by updating y. */
   if (a->tv_usec < b->tv_usec) {
     int nsec = (b->tv_usec - a->tv_usec) / 1000000 + 1;
     b->tv_usec -= 1000000 * nsec;
     b->tv_sec += nsec;
   }
   if (a->tv_usec - b->tv_usec > 1000000) {
     int nsec = (a->tv_usec - b->tv_usec) / 1000000;
     b->tv_usec += 1000000 * nsec;
     b->tv_sec -= nsec;
   }
 
   /* Compute the time difference
      tv_usec is certainly positive. */
   diff->tv_sec = a->tv_sec - b->tv_sec;
   diff->tv_usec = a->tv_usec - b->tv_usec;
}

/*
 *	initialise_ike_packet	-- Initialise IKE packet structures
 */
void
initialise_ike_packet(void) {
   int len;
/*
 *	Zero all header fields to start with.
 */
   memset(&hdr, '\0', sizeof(hdr));
   memset(&sa_hdr, '\0', sizeof(sa_hdr));
   memset(&sa_prop, '\0', sizeof(sa_prop));
   memset(&trans, '\0', sizeof(trans));
/*
 *	Fill in static values...
 */

/*
 *	ISAKMP Header
 */
   hdr.isa_rcookie[0] = 0;              /* Set responder cookie to 0 */
   hdr.isa_rcookie[1] = 0;
   hdr.isa_np = ISAKMP_NEXT_SA;         /* Next payload is SA */
   hdr.isa_version = 0x10;              /* v1.0 */
   hdr.isa_xchg = ISAKMP_XCHG_IDPROT;   /* Identity Protection (main mode) */
   hdr.isa_flags = 0;                   /* No flags */
   hdr.isa_msgid = 0;                   /* MBZ for phase-1 */
   len=sizeof(hdr)+sizeof(sa_hdr)+sizeof(sa_prop);
   if (vendor_id_flag) {
      len += (sizeof(vid_hdr) + sizeof(vid_md5));
   }
   if (trans_flag) {
      len += sizeof(trans[0]);
   } else {
      len += sizeof(trans);
   }
   hdr.isa_length = htonl(len);
/*
 *	SA Header
 */
   if (vendor_id_flag) {
      sa_hdr.isasa_np = ISAKMP_NEXT_VID;  /* Next payload is Vendor ID */
   } else {
      sa_hdr.isasa_np = ISAKMP_NEXT_NONE;  /* No Next payload */
   }
   if (trans_flag) {
      sa_hdr.isasa_length = htons(sizeof(sa_hdr)+sizeof(sa_prop)+sizeof(trans[0]));
   } else {
      sa_hdr.isasa_length = htons(sizeof(sa_hdr)+sizeof(sa_prop)+sizeof(trans));
   }
   sa_hdr.isasa_doi = htonl(ISAKMP_DOI_IPSEC);  /* IPsec DOI */
   sa_hdr.isasa_situation = htonl(SIT_IDENTITY_ONLY);
/*
 *	Proposal payload
 */
   sa_prop.isap_np = 0;                 /* No more proposals */
   if (trans_flag) {
      sa_prop.isap_length = htons(sizeof(sa_prop)+sizeof(trans[0]));
   } else {
      sa_prop.isap_length = htons(sizeof(sa_prop)+sizeof(trans));
   }
   sa_prop.isap_proposal = 1;           /* Proposal #1 (should this start at 0)*/
   sa_prop.isap_protoid = PROTO_ISAKMP;
   sa_prop.isap_spisize = 0;            /* No SPI */
   if (trans_flag) {
      sa_prop.isap_notrans = 1;            /* One Transforms */
   } else {
      sa_prop.isap_notrans = 8;            /* Eight Transforms */
   }
/*
 *	Transform payload
 */
   if (trans_flag) {
      trans[0].trans_hdr.isat_np = 0;                  /* No More transforms */
   } else {
      trans[0].trans_hdr.isat_np = 3;                  /* More transforms */
   }
   trans[0].trans_hdr.isat_length = htons(sizeof(trans[0]));
   trans[0].trans_hdr.isat_transnum = 1;                /* Transform #1 */
   trans[0].trans_hdr.isat_transid = KEY_IKE;
   trans[0].attr[0].isaat_af_type = htons(0x8001);      /* Encrypt */
   if (trans_flag) {
      trans[0].attr[0].isaat_lv = htons(trans_enc);
   } else {
      trans[0].attr[0].isaat_lv = htons(OAKLEY_3DES_CBC);
   }
   trans[0].attr[1].isaat_af_type = htons(0x8002);      /* Hash */
   if (trans_flag) {
      trans[0].attr[1].isaat_lv = htons(trans_hash);
   } else {
      trans[0].attr[1].isaat_lv = htons(OAKLEY_SHA);
   }
   trans[0].attr[2].isaat_af_type = htons(0x8003);      /* Auth */
   if (trans_flag) {
      trans[0].attr[2].isaat_lv = htons(trans_auth);
   } else {
      trans[0].attr[2].isaat_lv = htons(auth_method);
   }
   trans[0].attr[3].isaat_af_type = htons(0x8004);      /* Group */
   if (trans_flag) {
      trans[0].attr[3].isaat_lv = htons(trans_group);   /* custom group */
   } else {
      trans[0].attr[3].isaat_lv = htons(2);             /* group 2 */
   }
   trans[0].attr[4].isaat_af_type = htons(0x800b);      /* Life Type */
   trans[0].attr[4].isaat_lv = htons(1);                /* Seconds */
   trans[0].attr2.isaat_af_type = htons(0x000c);        /* Life Duration */
   trans[0].attr2.isaat_l = htons(4);                   /* 4 Bytes- CANT CHANGE*/
   trans[0].attr2.isaat_v = htonl(lifetime);            /* Lifetime */

   trans[1].trans_hdr.isat_np = 3;                      /* More transforms */
   trans[1].trans_hdr.isat_length = htons(sizeof(trans[1]));
   trans[1].trans_hdr.isat_transnum = 2;                /* Transform #2 */
   trans[1].trans_hdr.isat_transid = KEY_IKE;
   trans[1].attr[0].isaat_af_type = htons(0x8001);      /* Encrypt */
   trans[1].attr[0].isaat_lv = htons(OAKLEY_3DES_CBC);
   trans[1].attr[1].isaat_af_type = htons(0x8002);      /* Hash */
   trans[1].attr[1].isaat_lv = htons(OAKLEY_MD5);
   trans[1].attr[2].isaat_af_type = htons(0x8003);      /* Auth */
   trans[1].attr[2].isaat_lv = htons(auth_method);
   trans[1].attr[3].isaat_af_type = htons(0x8004);      /* Group */
   trans[1].attr[3].isaat_lv = htons(2);                /* group 2 */
   trans[1].attr[4].isaat_af_type = htons(0x800b);      /* Life Type */
   trans[1].attr[4].isaat_lv = htons(1);                /* Seconds */
   trans[1].attr2.isaat_af_type = htons(0x000c);        /* Life Duration */
   trans[1].attr2.isaat_l = htons(4);                   /* 4 Bytes- CANT CHANGE*/
   trans[1].attr2.isaat_v = htonl(lifetime);            /* Lifetime */

   trans[2].trans_hdr.isat_np = 3;                      /* More transforms */
   trans[2].trans_hdr.isat_length = htons(sizeof(trans[2]));
   trans[2].trans_hdr.isat_transnum = 3;                /* Transform #3 */
   trans[2].trans_hdr.isat_transid = KEY_IKE;
   trans[2].attr[0].isaat_af_type = htons(0x8001);      /* Encrypt */
   trans[2].attr[0].isaat_lv = htons(OAKLEY_DES_CBC);
   trans[2].attr[1].isaat_af_type = htons(0x8002);      /* Hash */
   trans[2].attr[1].isaat_lv = htons(OAKLEY_SHA);
   trans[2].attr[2].isaat_af_type = htons(0x8003);      /* Auth */
   trans[2].attr[2].isaat_lv = htons(auth_method);
   trans[2].attr[3].isaat_af_type = htons(0x8004);      /* Group */
   trans[2].attr[3].isaat_lv = htons(2);                /* group 2 */
   trans[2].attr[4].isaat_af_type = htons(0x800b);      /* Life Type */
   trans[2].attr[4].isaat_lv = htons(1);                /* Seconds */
   trans[2].attr2.isaat_af_type = htons(0x000c);        /* Life Duration */
   trans[2].attr2.isaat_l = htons(4);                   /* 4 Bytes- CANT CHANGE*/
   trans[2].attr2.isaat_v = htonl(lifetime);            /* Lifetime */

   trans[3].trans_hdr.isat_np = 3;                      /* More transforms */
   trans[3].trans_hdr.isat_length = htons(sizeof(trans[3]));
   trans[3].trans_hdr.isat_transnum = 4;                /* Transform #4 */
   trans[3].trans_hdr.isat_transid = KEY_IKE;
   trans[3].attr[0].isaat_af_type = htons(0x8001);      /* Encrypt */
   trans[3].attr[0].isaat_lv = htons(OAKLEY_DES_CBC);
   trans[3].attr[1].isaat_af_type = htons(0x8002);      /* Hash */
   trans[3].attr[1].isaat_lv = htons(OAKLEY_MD5);
   trans[3].attr[2].isaat_af_type = htons(0x8003);      /* Auth */
   trans[3].attr[2].isaat_lv = htons(auth_method);
   trans[3].attr[3].isaat_af_type = htons(0x8004);      /* Group */
   trans[3].attr[3].isaat_lv = htons(2);                /* group 2 */
   trans[3].attr[4].isaat_af_type = htons(0x800b);      /* Life Type */
   trans[3].attr[4].isaat_lv = htons(1);                /* Seconds */
   trans[3].attr2.isaat_af_type = htons(0x000c);        /* Life Duration */
   trans[3].attr2.isaat_l = htons(4);                   /* 4 Bytes- CANT CHANGE*/
   trans[3].attr2.isaat_v = htonl(lifetime);            /* Lifetime */

   trans[4].trans_hdr.isat_np = 3;                      /* More transforms */
   trans[4].trans_hdr.isat_length = htons(sizeof(trans[0]));
   trans[4].trans_hdr.isat_transnum = 5;                /* Transform #5 */
   trans[4].trans_hdr.isat_transid = KEY_IKE;
   trans[4].attr[0].isaat_af_type = htons(0x8001);      /* Encrypt */
   trans[4].attr[0].isaat_lv = htons(OAKLEY_3DES_CBC);
   trans[4].attr[1].isaat_af_type = htons(0x8002);      /* Hash */
   trans[4].attr[1].isaat_lv = htons(OAKLEY_SHA);
   trans[4].attr[2].isaat_af_type = htons(0x8003);      /* Auth */
   trans[4].attr[2].isaat_lv = htons(auth_method);
   trans[4].attr[3].isaat_af_type = htons(0x8004);      /* Group */
   trans[4].attr[3].isaat_lv = htons(1);                /* group 1 */
   trans[4].attr[4].isaat_af_type = htons(0x800b);      /* Life Type */
   trans[4].attr[4].isaat_lv = htons(1);                /* Seconds */
   trans[4].attr2.isaat_af_type = htons(0x000c);        /* Life Duration */
   trans[4].attr2.isaat_l = htons(4);                   /* 4 Bytes- CANT CHANGE*/
   trans[4].attr2.isaat_v = htonl(lifetime);            /* Lifetime */

   trans[5].trans_hdr.isat_np = 3;                      /* More transforms */
   trans[5].trans_hdr.isat_length = htons(sizeof(trans[1]));
   trans[5].trans_hdr.isat_transnum = 6;                /* Transform #6 */
   trans[5].trans_hdr.isat_transid = KEY_IKE;
   trans[5].attr[0].isaat_af_type = htons(0x8001);      /* Encrypt */
   trans[5].attr[0].isaat_lv = htons(OAKLEY_3DES_CBC);
   trans[5].attr[1].isaat_af_type = htons(0x8002);      /* Hash */
   trans[5].attr[1].isaat_lv = htons(OAKLEY_MD5);
   trans[5].attr[2].isaat_af_type = htons(0x8003);      /* Auth */
   trans[5].attr[2].isaat_lv = htons(auth_method);
   trans[5].attr[3].isaat_af_type = htons(0x8004);      /* Group */
   trans[5].attr[3].isaat_lv = htons(1);                /* group 1 */
   trans[5].attr[4].isaat_af_type = htons(0x800b);      /* Life Type */
   trans[5].attr[4].isaat_lv = htons(1);                /* Seconds */
   trans[5].attr2.isaat_af_type = htons(0x000c);        /* Life Duration */
   trans[5].attr2.isaat_l = htons(4);                   /* 4 Bytes- CANT CHANGE*/
   trans[5].attr2.isaat_v = htonl(lifetime);            /* Lifetime */

   trans[6].trans_hdr.isat_np = 3;                      /* More transforms */
   trans[6].trans_hdr.isat_length = htons(sizeof(trans[2]));
   trans[6].trans_hdr.isat_transnum = 7;                /* Transform #7 */
   trans[6].trans_hdr.isat_transid = KEY_IKE;
   trans[6].attr[0].isaat_af_type = htons(0x8001);      /* Encrypt */
   trans[6].attr[0].isaat_lv = htons(OAKLEY_DES_CBC);
   trans[6].attr[1].isaat_af_type = htons(0x8002);      /* Hash */
   trans[6].attr[1].isaat_lv = htons(OAKLEY_SHA);
   trans[6].attr[2].isaat_af_type = htons(0x8003);      /* Auth */
   trans[6].attr[2].isaat_lv = htons(auth_method);
   trans[6].attr[3].isaat_af_type = htons(0x8004);      /* Group */
   trans[6].attr[3].isaat_lv = htons(1);                /* group 1 */
   trans[6].attr[4].isaat_af_type = htons(0x800b);      /* Life Type */
   trans[6].attr[4].isaat_lv = htons(1);                /* Seconds */
   trans[6].attr2.isaat_af_type = htons(0x000c);        /* Life Duration */
   trans[6].attr2.isaat_l = htons(4);                   /* 4 Bytes- CANT CHANGE*/
   trans[6].attr2.isaat_v = htonl(lifetime);            /* Lifetime */

   trans[7].trans_hdr.isat_np = 0;                      /* No more transforms */
   trans[7].trans_hdr.isat_length = htons(sizeof(trans[3]));
   trans[7].trans_hdr.isat_transnum = 8;                /* Transform #8 */
   trans[7].trans_hdr.isat_transid = KEY_IKE;
   trans[7].attr[0].isaat_af_type = htons(0x8001);      /* Encrypt */
   trans[7].attr[0].isaat_lv = htons(OAKLEY_DES_CBC);
   trans[7].attr[1].isaat_af_type = htons(0x8002);      /* Hash */
   trans[7].attr[1].isaat_lv = htons(OAKLEY_MD5);
   trans[7].attr[2].isaat_af_type = htons(0x8003);      /* Auth */
   trans[7].attr[2].isaat_lv = htons(auth_method);
   trans[7].attr[3].isaat_af_type = htons(0x8004);      /* Group */
   trans[7].attr[3].isaat_lv = htons(1);                /* group 1 */
   trans[7].attr[4].isaat_af_type = htons(0x800b);      /* Life Type */
   trans[7].attr[4].isaat_lv = htons(1);                /* Seconds */
   trans[7].attr2.isaat_af_type = htons(0x000c);        /* Life Duration */
   trans[7].attr2.isaat_l = htons(4);                   /* 4 Bytes- CANT CHANGE*/
   trans[7].attr2.isaat_v = htonl(lifetime);            /* Lifetime */
/*
 *	Vendor ID Payload (Optional)
 */
   vid_hdr.isavid_np = ISAKMP_NEXT_NONE;	/* No Next payload */
   vid_hdr.isavid_length = htons(sizeof(vid_hdr) + sizeof(vid_md5));	/* Length of MD5 digest */
}

/*
 *	dump_list -- Display contents of list for debugging
 */
void
dump_list(void) {
   struct host_entry *p;

   p = rrlist;

   printf("Entry\tIP Address\tCookie\n");
   do {
      printf("%d\t%s\t%0x%0x\n", p->n, inet_ntoa(p->addr), htonl(p->icookie[0]), htonl(p->icookie[1]));
      p = p->next;
   } while (p != rrlist);
   printf("\nTotal of %d entries\n\n", num_hosts);
}

/*
 *	dump_times -- Display packet times for backoff fingerprinting
 */
void
dump_times(void) {
   struct host_entry *p;
   struct time_list *te;
   int i;
   struct timeval prev_time;
   struct timeval diff;
   char *patname;

   p = rrlist;

   printf("\nIP Address\tNo.\tRecv time\t\tDelta Time\n");
   do {
      if (p->recv_times != NULL && p->num_recv > 1) {
         te = p->recv_times;
         i = 1;
         diff.tv_sec = 0;
         diff.tv_usec = 0;
         while (te != NULL) {
            if (i > 1)
               timeval_diff(&(te->time), &prev_time, &diff);
            printf("%s\t%d\t\%ld.%.6ld\t%ld.%.6ld\n", inet_ntoa(p->addr), i, (long)te->time.tv_sec, (long)te->time.tv_usec, (long)diff.tv_sec, (long)diff.tv_usec);
            prev_time = te->time;
            te = te->next;
            i++;
         } /* End While te != NULL */
         if ((patname=match_pattern(p)) != NULL) {
            printf("%s\tPattern: %s\n", inet_ntoa(p->addr), patname);
         } else {
            printf("%s\tPattern: %s\n", inet_ntoa(p->addr), "UNKNOWN");
         }
         printf("\n");
      } /* End If */
      p = p->next;
   } while (p != rrlist);
}

/*
 *	match_pattern -- Find backoff pattern match
 *
 *	Finds the first match for the backoff pattern of the host entry *he.
 *	If a match is found, returns a pointer to the implementation name,
 *	otherwise returns NULL.
 */
char *
match_pattern(struct host_entry *he) {
   struct pattern_list *pl;
/*
 *	Return NULL immediately if there is no chance of matching.
 */
   if (he == NULL || patlist == NULL)
      return NULL;
   if (he->recv_times == NULL || he->num_recv < 2)
      return NULL;
/*
 *	Try to find a match in the pattern list.
 */
   pl = patlist;
   while (pl != NULL) {
      if (he->num_recv == pl->num_times && pl->recv_times != NULL) {
         struct time_list *hp;
         struct time_list *pp;
         struct timeval diff;
         struct timeval prev_time;
         int match;
         int i;

         hp = he->recv_times;
         pp = pl->recv_times;
         match = 1;
         i = 1;
         diff.tv_sec = 0;
         diff.tv_usec = 0;
         while (pp != NULL && hp != NULL) {
            if (i > 1)
               timeval_diff(&(hp->time), &prev_time, &diff);
            if (!times_close_enough(&(pp->time), &diff)) {
               match = 0;
               break;
            }
            prev_time = hp->time;
            pp = pp->next;
            hp = hp->next;
            i++;
         } /* End While */
         if (match)
            return pl->name;
      } /* End If */
      pl = pl->next;
   } /* End While */
/*
 *	If we reach here, then we havn't mached the pattern so return NULL.
 */
   return NULL;
}

/*
 *	times_close_enough -- return 1 if t1 and t2 are within pattern_fuzz ms
 *	                      of each other.  Otherwise return 0.
 */
int
times_close_enough(struct timeval *t1, struct timeval *t2) {
struct timeval diff;
int diff_ms;

   timeval_diff(t1, t2, &diff);	/* diff = t1 - t2 */
   diff_ms = abs(1000*diff.tv_sec + diff.tv_usec/1000);
   if (diff_ms <= pattern_fuzz) {
      return 1;
   } else {
      return 0;
   }
}

/*
 *	add_recv_time -- Add current time to the recv_times list
 */
void
add_recv_time(struct host_entry *he) {
   struct time_list *p;		/* Temp pointer */
   struct time_list *te;	/* New timeentry pointer */
/*
 *	Allocate and initialise new time structure
 */   
   if ((te = malloc(sizeof(struct time_list))) == NULL)
      err_sys("malloc");
   if ((gettimeofday(&(te->time), NULL)) != 0) {
      err_sys("gettimeofday");
   }
   last_recv_time.tv_sec = te->time.tv_sec;
   last_recv_time.tv_usec = te->time.tv_usec;
   te->next = NULL;
/*
 *	Insert new time structure on the tail of the recv_times list.
 */
   p = he->recv_times;
   if (p == NULL) {
      he->recv_times = te;
   } else {
      while (p->next != NULL)
         p = p->next;
      p->next = te;
   }
/*
 *	Increment num_received for this host
 */
   he->num_recv++;
}

/*
 *	add_pattern -- add a backoff pattern to the list.
 */
void
add_pattern(char *line) {
   char *cp;
   char *np;
   char *pp;
   char name[MAXLINE];
   char pat[MAXLINE];
   int tabseen;
   struct pattern_list *pe;	/* Pattern entry */
   struct pattern_list *p;	/* Temp pointer */
   struct time_list *te;
   struct time_list *tp;
   char *endp;
   int i;
   double back;
/*
 *	Allocate new pattern list entry and add to tail of patlist.
 */
   if ((pe = malloc(sizeof(struct pattern_list))) == NULL)
      err_sys("malloc");
   pe->next = NULL;
   pe->recv_times = NULL;
   p = patlist;
   if (p == NULL) {
      patlist = pe;
   } else {
      while (p->next != NULL)
         p = p->next;
      p->next = pe;
   }
/*
 *	Seperate line from patterns file into name and pattern.
 */
   tabseen = 0;
   cp = line;
   np = name;
   pp = pat;
   while (*cp != '\0' && *cp != '\n') {
      if (*cp == '\t') {
         tabseen++;
         cp++;
      }
      if (tabseen) {
         *pp++ = *cp++;
      } else {
         *np++ = *cp++;
      }
   }
   *np = '\0';
   *pp = '\0';
/*
 *	Copy name into malloc'ed storage and set pl->name to point to this.
 */
   if ((cp = malloc(strlen(name)+1)) == NULL)
      err_sys("malloc");
   strcpy(cp, name);
   pe->name = cp;
/*
 *	Process and store the backoff pattern.
 */
   i=0;
   endp=pat;
   while (*endp != '\0') {
      back=strtod(endp, &endp);
      if ((te = malloc(sizeof(struct time_list))) == NULL)
         err_sys("malloc");
      te->next=NULL;
      te->time.tv_sec = floor(back);
      te->time.tv_usec = (back - te->time.tv_sec) * 1000000;
      tp = pe->recv_times;
      if (tp == NULL) {
         pe->recv_times = te;
      } else {
         while (tp->next != NULL)
            tp = tp->next;
         tp->next = te;
      }
      if (*endp == ',')
         endp++;
      i++;
   }
   pe->num_times=i;
}

/*
 *	usage -- display usage message and exit
 */
void
usage(void) {
   fprintf(stderr, "Usage: ike-scan [options] [hosts...]\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "Hosts are specified on the command line unless the --file option is specified.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "Options:\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "--help or -h\t\tDisplay this usage message and exit.\n");
   fprintf(stderr, "\n--file=<fn> or -f <fn>\tRead hostnames or addresses from the specified file\n");
   fprintf(stderr, "\t\t\tinstead of from the command line. One name or IP\n");
   fprintf(stderr, "\t\t\taddress per line.  Use \"-\" for standard input.\n");
   fprintf(stderr, "\n--sport=<p> or -s p\tSet UDP source port to <p>, default=%d, 0=random.\n", DEFAULT_SOURCE_PORT);
   fprintf(stderr, "\t\t\tNote that superuser privileges are normally required\n");
   fprintf(stderr, "\t\t\tto use non-zero source ports below 1024.\n");
   fprintf(stderr, "\n--dport=<p> or -d p\tSet UDP destination port to <p>, default=%d.\n", DEFAULT_DEST_PORT);
   fprintf(stderr, "\n--retry=<n> or -r n\tSet total number of attempts per host to <n>,\n");
   fprintf(stderr, "\t\t\tdefault=%d.\n", DEFAULT_RETRY);
   fprintf(stderr, "\n--timeout=<n> or -t n\tSet initial per host timeout to <n> ms, default=%d.\n", DEFAULT_TIMEOUT);
   fprintf(stderr, "\t\t\tThis timeout is for the first packet sent to each host.\n");
   fprintf(stderr, "\t\t\tsubsequent timeouts are multiplied by the backoff\n");
   fprintf(stderr, "\t\t\tfactor which is set with --backoff.\n");
   fprintf(stderr, "\n--interval=<n> or -i <n> Set minimum packet interval to <n> ms, default=%d.\n", DEFAULT_INTERVAL);
   fprintf(stderr, "\t\t\tThis controls the outgoing bandwidth usage by limiting\n");
   fprintf(stderr, "\t\t\tthe rate at which packets can be sent.  The packet\n");
   fprintf(stderr, "\t\t\tinterval will be greater than or equal to this number\n");
   fprintf(stderr, "\t\t\tand will be a multiple of the select wait specified\n");
   fprintf(stderr, "\t\t\twith --selectwait.  Thus --interval=75 --selectwait=10\n");
   fprintf(stderr, "\t\t\twill result in a packet interval of 80ms.\n");
   fprintf(stderr, "\t\t\tThe outgoing packets have a total size of 364 bytes\n");
   fprintf(stderr, "\t\t\t(20 bytes IP hdr + 8 bytes UDP hdr + 336 bytes data)\n");
   fprintf(stderr, "\t\t\twhen the default transform set is used, or 112 bytes\n");
   fprintf(stderr, "\t\t\tif a custom transform is specified.  Therefore\n");
   fprintf(stderr, "\t\t\tfor default transform set: 50=58240bps, 80=36400bps and\n");
   fprintf(stderr, "\t\t\tfor custom transform: 15=59733bps, 30=35840bps.\n");
   fprintf(stderr, "\n--backoff=<b> or -b <b>\tSet timeout backoff factor to <b>, default=%.2f.\n", DEFAULT_BACKOFF_FACTOR);
   fprintf(stderr, "\t\t\tThe per-host timeout is multiplied by this factor\n");
   fprintf(stderr, "\t\t\tafter each timeout.  So, if the number of retrys\n");
   fprintf(stderr, "\t\t\tis 3, the initial per-host timeout is 500ms and the\n");
   fprintf(stderr, "\t\t\tbackoff factor is 1.5, then the first timeout will be\n");
   fprintf(stderr, "\t\t\t500ms, the second 750ms and the third 1125ms.\n");
   fprintf(stderr, "\n--selectwait=<n> or -w <n> Set select wait to <n> ms, default=%d.\n", DEFAULT_SELECT_TIMEOUT);
   fprintf(stderr, "\t\t\tThis controls the timeout used in the select(2) call.\n");
   fprintf(stderr, "\t\t\tIt defines the lower bound and granularity of the\n");
   fprintf(stderr, "\t\t\tpacket interval set with --interval.  Smaller values\n");
   fprintf(stderr, "\t\t\tallow more accurate and lower packet intervals;\n");
   fprintf(stderr, "\t\t\tlarger values reduce CPU usage.  You don't need\n");
   fprintf(stderr, "\t\t\tto change this unless you want to reduce the packet\n");
   fprintf(stderr, "\t\t\tinterval close to or below the default selectwait time.\n");
   fprintf(stderr, "\n--verbose or -v\t\tDisplay verbose progress messages.\n");
   fprintf(stderr, "\t\t\tUse more than once for greater effect:\n");
   fprintf(stderr, "\t\t\t1 - Show when hosts are removed from the list and\n");
   fprintf(stderr, "\t\t\t    when packets with invalid cookies are received.\n");
   fprintf(stderr, "\t\t\t2 - Show each packet sent and received.\n");
   fprintf(stderr, "\t\t\t3 - Display the host list before scanning starts.\n");
   fprintf(stderr, "\n--lifetime=<s> or -l <s> Set IKE lifetime to <s> seconds, default=%d.\n", DEFAULT_LIFETIME);
   fprintf(stderr, "\t\t\tRFC 2407 specifies 28800 as the default, but some\n");
   fprintf(stderr, "\t\t\timplementations may require different values.\n");
   fprintf(stderr, "\n--auth=<n> or -m <n>\tSet auth. method to <n>, default=%d (%s).\n", DEFAULT_AUTH_METHOD, auth_methods[DEFAULT_AUTH_METHOD]);
   fprintf(stderr, "\t\t\tRFC defined values are 1 to 5.  See RFC 2409 Appendix A.\n");
   fprintf(stderr, "\n--version or -V\t\tDisplay program version and exit.\n");
   fprintf(stderr, "\n--vendor=<v> or -e <v>\tSet vendor id string to MD5 hash of <v>.\n");
   fprintf(stderr, "\t\t\tNote: this is currently experimental.\n");
   fprintf(stderr, "\n--trans=<t> or -a <t>\tUse custom transform <t> instead of default set.\n");
   fprintf(stderr, "\t\t\t<t> is specified as enc,hash,auth,group. e.g. 2,3,1,5.\n");
   fprintf(stderr, "\t\t\tSee RFC 2409 Appendix A for details of which values\n");
   fprintf(stderr, "\t\t\tto use.  For example, --trans=2,3,1,5 specifies\n");
   fprintf(stderr, "\t\t\tEnc=IDEA-CBC, Hash=Tiger, Auth=shared key, DH Group=5\n");
   fprintf(stderr, "\t\t\tIf this option is specified, then only the single\n");
   fprintf(stderr, "\t\t\tcustom transform is used rather than the default set\n");
   fprintf(stderr, "\t\t\tof 8 transforms.  As a result, the IP packet size\n");
   fprintf(stderr, "\t\t\tis 112 bytes rather than the default of 364.\n");
   fprintf(stderr, "\n--showbackoff[=<n>] or -o[<n>]\tDisplay the backoff fingerprint table.\n");
   fprintf(stderr, "\t\t\tDisplay the backoff table to fingerprint the IKE\n");
   fprintf(stderr, "\t\t\timplementation on the remote hosts.\n");
   fprintf(stderr, "\t\t\tThe optional argument specifies time to wait in seconds\n");
   fprintf(stderr, "\t\t\tafter receiving the last packet, default=%d.\n", DEFAULT_END_WAIT);
   fprintf(stderr, "\t\t\tIf you are using the short form of the option (-o)\n");
   fprintf(stderr, "\t\t\tthen the value must immediately follow the option\n");
   fprintf(stderr, "\t\t\tletter with no spaces, e.g. -o25 not -o 25.\n");
   fprintf(stderr, "\n--fuzz=<n> or -u <n>\tSet pattern matching fuzz to <n> ms, default=%d.\n", DEFAULT_PATTERN_FUZZ);
   fprintf(stderr, "\t\t\tThis sets the maximum acceptable difference between\n");
   fprintf(stderr, "\t\t\tthe observed backoff times and the reference times in\n");
   fprintf(stderr, "\t\t\tthe backoff patterns file.  Larger values allow for\n");
   fprintf(stderr, "\t\t\thigher variance but also increase the risk of\n");
   fprintf(stderr, "\t\t\tfalse positive identifications.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "%s\n", rcsid);
   fprintf(stderr, "\n");
   exit(1);
}
