/*
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
 * ike-scan sends IKE main mode requests to the specified hosts and displays
 * any responses that are received.  It handles retry and retransmission with
 * backoff to cope with packet loss.
 *
 * Change History:
 *
 * $Log$
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
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>

#include "global.h"
#include "md5.h"
#include "ike-scan.h"

#define VERSION "ike-scan $Revision$ $Date$ <Roy.Hills@nta-monitor.com>"
#define MAX_PAYLOAD 13	/* Maximum defined payload number */
static char rcsid[] = "$Id$";   /* RCS ID for ident(1) */

/* Global variables */
struct host_entry *rrlist = NULL;	/* Round-robin linked list "the list" */
struct host_entry *cursor;		/* Pointer to current list entry */
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
int verbose=0;
char vendor_id[MAXLINE];		/* Vendor ID string */
int vendor_id_flag = 0;			/* Indicates if VID to be used */
struct timeval last_packet_time;	/* Time last packet was sent */
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

int main(int argc, char *argv[]) {
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
      {0, 0, 0, 0}
   };
   char *short_options = "f:hr:t:i:b:w:vl:m:Ve:";
   int arg;
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
   unsigned long loop_timediff;
   unsigned long host_timediff;
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
         default:
            usage();
            break;
      }
   }
/*
 *	If we're not reading from a file, then we must have some hosts
 *	given as command line arguments.
 */
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
 *	Check that we have at least one entry in the list.
 */
   if (!num_hosts)
      err_msg("No hosts to process.");
/*
 *	Create UDP socket and bind to local source port.
 */
   if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
      err_sys("socket");

   bzero(&sa_local, sizeof(sa_local));
   sa_local.sin_family = AF_INET;
   sa_local.sin_addr.s_addr = htonl(INADDR_ANY);
   sa_local.sin_port = htons(source_port);

   if ((bind(sockfd, (struct sockaddr *)&sa_local, sizeof(sa_local))) < 0) {
      perror("bind");
      exit(1);
   }
/*
 *	Set current host pointer (cursor) to start of list, zero
 *	last packet sent time and initialise static IKE header fields.
 */
   live_count = num_hosts;
   cursor = rrlist;
   last_packet_time.tv_sec=0;
   last_packet_time.tv_usec=0;
   initialise_ike_packet();
/*
 *	Display the list if verbose setting is 2 or more.
 */
   if (verbose > 1)
      dump_list();
/*
 *	Main loop: send packets to all hosts in order until a response
 *	has been received or the host has exhausted it's retry limit.
 *	The loop exits when all hosts have either responded or timed out.
 */
   while (live_count) {
/*
 *	Obtain current time and calculate deltas since last packet and
 *	last packet to this host.
 */
      if ((gettimeofday(&now, NULL)) != 0) {
         err_sys("gettimeofday");
      }
/*
 *	If the last packet was sent more than interval ms ago, then we can
 *	potentially send a packet to the current host.
 */
      loop_timediff=timeval_diff(&now, &last_packet_time);
      if (loop_timediff > interval) {
/*
 *	If the last packet to this host was sent more than the current
 *	timeout for this host ms ago, then we can potentially send a packet
 *	to it.
 */
         host_timediff=timeval_diff(&now, &(cursor->last_send_time));
         if (host_timediff > cursor->timeout) {
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
 *	We've received a packet.  Try to locate the IP address of the
 *	respondant in the list.
 */
         temp_cursor=find_host_by_ip(cursor, &(sa_peer.sin_addr));
         if (temp_cursor == NULL) {
/*
 *	We've received a response, but the IP address doesn't match any host
 *	in our list.  Try to match up the packet by cookie instead in case
 *	the response is from a multi-homed system which has replied from a
 *	different interface to that which we sent to.  Some systems do this.
 */
            temp_cursor=find_host_by_cookie(cursor, packet_in, n);
            if (temp_cursor) {
/*
 *	We found a cookie match for the returned packet.
 */
               temp_cursor->num_recv++;
               if (temp_cursor->live) {
                  display_packet(n, packet_in, temp_cursor, &(sa_peer.sin_addr));
               }
               if (verbose)
                  warn_msg("---\tRemoving host entry %d (%s) - Received %d bytes", temp_cursor->n, inet_ntoa(sa_peer.sin_addr), n);
               remove_host(temp_cursor);
            } else {
/*
 *	Neither the IP address nor the cookie matches any hosts in the list,
 *	so just issue a message to that effect and ignore the packet.
 */
               warn_msg("---\tReceived %d bytes from unknown host (%s)", n, inet_ntoa(sa_peer.sin_addr));
            }
         } else {
/*
 *	The IP address of the packet reveived matches a host in the list.
 */
            temp_cursor->num_recv++;
            if (temp_cursor->live) {
               display_packet(n, packet_in, temp_cursor, NULL);
               if (verbose)
                  warn_msg("---\tRemoving host entry %d (%s) - Received %d bytes", temp_cursor->n, inet_ntoa(sa_peer.sin_addr), n);
               remove_host(temp_cursor);
            } /* End If */
         } /* End If */
      } /* End If */
   } /* End While */

   close(sockfd);
   return(0);
}

/*
 *	add_host -- Add a host name and associated address to the list
 */
void add_host(char *name) {
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
 *	Updates cursor so that it points to the next entry or NULL if the
 *	list is empty after the removal.
 */
void remove_host(struct host_entry *he) {
   he->live = 0;
   live_count--;
   if (live_count) {
      do {
         cursor = cursor->next;
      } while (!cursor->live);
   } else {
      cursor = NULL;
   }
}

/*
 *	advance_cursor -- Advance the cursor to point at next live entry
 */
void advance_cursor(void) {
   if (live_count) {
      do {
         cursor = cursor->next;
      } while (!cursor->live);
   } /* End If */
}

/*
 *	find_host_by_ip	-- Find a host in the list by IP address
 *
 *	he points to current position in list.  Search runs backwards
 *	starting from this point.
 *
 *	addr points to the IP address to find in the list.
 *
 *	Returns a pointer to the host entry associated with the specified IP
 *	or NULL if no match found.
 */
struct host_entry *find_host_by_ip(struct host_entry *he,struct in_addr *addr) {
   struct host_entry *p;
   int found;

   p = he;
   found = 0;

   do {
      if (p->addr.s_addr == addr->s_addr) {
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
struct host_entry *find_host_by_cookie(struct host_entry *he, char *packet_in, int n) {
   struct host_entry *p;
   int found;
   struct isakmp_hdr hdr_in;
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
void display_packet(int n, char *packet_in, struct host_entry *he, struct in_addr *recv_addr) {
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
   if (recv_addr)
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
void decode_transform(char *packet_in, int n, int ntrans) {
   if (ntrans <=0)
      return;	/* Nothing to do if no transforms */
/*
 *	Body of function has not been written yet.
 */
}

/*
 *	send_packet -- Construct and send a packet to the specified host
 */
void send_packet(int s, struct host_entry *he) {
   struct sockaddr_in sa_peer;
   char buf[MAXUDP];
   int buflen;
   int sa_peer_len;
   char *cp;
/*
 *	Set up the sockaddr_in structure for the host.
 */
   bzero(&sa_peer, sizeof(sa_peer));
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
   memcpy(cp,&trans,sizeof(trans));
   cp += sizeof(trans);
   buflen = sizeof(hdr)+sizeof(sa_hdr)+sizeof(sa_prop)+sizeof(trans);
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
   if (verbose)
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
int recvfrom_wto(int s, char *buf, int len, struct sockaddr *saddr, int tmo) {
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
 *	Returns the difference in milliseconds between the two
 *	specified time values.  return = a - b.
 */
int timeval_diff(struct timeval *a,struct timeval *b) {
   struct timeval diff;
   int result;

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
   diff.tv_sec = a->tv_sec - b->tv_sec;
   diff.tv_usec = a->tv_usec - b->tv_usec;

   result = 1000*diff.tv_sec + diff.tv_usec/1000;

   return result;
}

/*
 *	initialise_ike_packet	-- Initialise IKE packet structures
 */
void initialise_ike_packet(void) {
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
   if (vendor_id_flag) {
      hdr.isa_length = htonl(sizeof(hdr)+sizeof(sa_hdr)+sizeof(sa_prop)+sizeof(trans)+sizeof(vid_hdr)+sizeof(vid_md5));
   } else {
      hdr.isa_length = htonl(sizeof(hdr)+sizeof(sa_hdr)+sizeof(sa_prop)+sizeof(trans));
   }
/*
 *	SA Header
 */
   if (vendor_id_flag) {
      sa_hdr.isasa_np = ISAKMP_NEXT_VID;  /* Next payload is Vendor ID */
   } else {
      sa_hdr.isasa_np = ISAKMP_NEXT_NONE;  /* No Next payload */
   }
   sa_hdr.isasa_length = htons(sizeof(sa_hdr)+sizeof(sa_prop)+sizeof(trans));
   sa_hdr.isasa_doi = htonl(ISAKMP_DOI_IPSEC);  /* IPsec DOI */
   sa_hdr.isasa_situation = htonl(SIT_IDENTITY_ONLY);
/*
 *	Proposal payload
 */
   sa_prop.isap_np = 0;                 /* No more proposals */
   sa_prop.isap_length = htons(sizeof(sa_prop)+sizeof(trans));
   sa_prop.isap_proposal = 1;           /* Proposal #1 (should this start at 0)*/
   sa_prop.isap_protoid = PROTO_ISAKMP;
   sa_prop.isap_spisize = 0;            /* No SPI */
   sa_prop.isap_notrans = 8;            /* Eight Transforms */
/*
 *	Transform payload
 */
   trans[0].trans_hdr.isat_np = 3;                      /* More transforms */
   trans[0].trans_hdr.isat_length = htons(sizeof(trans[0]));
   trans[0].trans_hdr.isat_transnum = 1;                /* Transform #1 */
   trans[0].trans_hdr.isat_transid = KEY_IKE;
   trans[0].attr[0].isaat_af_type = htons(0x8001);      /* Encrypt */
   trans[0].attr[0].isaat_lv = htons(OAKLEY_3DES_CBC);
   trans[0].attr[1].isaat_af_type = htons(0x8002);      /* Hash */
   trans[0].attr[1].isaat_lv = htons(OAKLEY_SHA);
   trans[0].attr[2].isaat_af_type = htons(0x8003);      /* Auth */
   trans[0].attr[2].isaat_lv = htons(auth_method);
   trans[0].attr[3].isaat_af_type = htons(0x8004);      /* Group */
   trans[0].attr[3].isaat_lv = htons(2);                /* group 2 */
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
void dump_list(void) {
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
 *	usage -- display usage message and exit
 */
void usage(void) {
   fprintf(stderr, "Usage: ike-scan [options] [hosts...]\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "Hosts are specified on the command line unless the --file option is specified.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "Options:\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "--help or -h\t\tDisplay this usage message and exit.\n");
   fprintf(stderr, "--file=<fn> or -f <fn>\tRead hostnames or addresses from the specified file\n");
   fprintf(stderr, "\t\t\tinstead of from the command line. One name or address\n");
   fprintf(stderr, "\t\t\tper line.  Use \"-\" for standard input.\n");
   fprintf(stderr, "--sport=<p> or -s p\tSet UDP source port to <p>, default=%d, 0=random.\n", DEFAULT_SOURCE_PORT);
   fprintf(stderr, "--dport=<p> or -d p\tSet UDP destination port to <p>, default=%d\n", DEFAULT_DEST_PORT);
   fprintf(stderr, "--retry=<n> or -r n\tSet number of attempts per host to <n>, default=%d\n", DEFAULT_RETRY);
   fprintf(stderr, "--timeout=<n> or -t n\tSet per host timeout to <n> ms, default=%d\n", DEFAULT_TIMEOUT);
   fprintf(stderr, "--interval=<n> or -i <n> Set packet interval to <n> ms, default=%d\n", DEFAULT_INTERVAL);
   fprintf(stderr, "--backoff=<b> or -b <b>\tSet backoff factor to <b>, default=%.2f\n", DEFAULT_BACKOFF_FACTOR);
   fprintf(stderr, "--selectwait=<n> or -w <n> Set select wait to <n> ms, default=%d\n", DEFAULT_SELECT_TIMEOUT);
   fprintf(stderr, "--verbose or -v\t\tDisplay verbose progress messages.\n");
   fprintf(stderr, "--lifetime=<s> or -l <s> Set IKE lifetime to <s> seconds, default=%d\n", DEFAULT_LIFETIME);
   fprintf(stderr, "--auth=<n> or -m <n>\tSet auth. method to <n>, default=%d (%s)\n", DEFAULT_AUTH_METHOD, auth_methods[DEFAULT_AUTH_METHOD]);
   fprintf(stderr, "\t\t\tRFC defined values are 1 to 5.  See RFC 2409 Appendix A.\n");
   fprintf(stderr, "--version or -V\t\tDisplay program version and exit.\n");
   fprintf(stderr, "--vendor or -e\t\tSet vendor id string (experimental).\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "%s\n", rcsid);
   fprintf(stderr, "\n");
   exit(1);
}
