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
 * Change History:
 *
 * $Log$
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

#include "ike-scan.h"

/* Global variables */
struct host_entry *rrlist = NULL;	/* Round-robin linked list "the list" */
struct host_entry *cursor;		/* Pointer to current entry */
unsigned num_hosts = 0;			/* Number of entries in the list */
unsigned retry = DEFAULT_RETRY;		/* Number of retries */
unsigned timeout = DEFAULT_TIMEOUT;	/* Per-host timeout */
unsigned interval = DEFAULT_INTERVAL;	/* Interval between packets */
unsigned select_timeout = DEFAULT_SELECT_TIMEOUT;	/* Select timeout */
float backoff = DEFAULT_BACKOFF_FACTOR;	/* Backoff factor */
int source_port = DEFAULT_SOURCE_PORT;	/* UDP source port */
int dest_port = DEFAULT_DEST_PORT;	/* UDP destination port */
int verbose=0;
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
struct transform trans[4];		/* Transform payload */

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
      {"random", required_argument, 0, 'a'},
      {"verbose", no_argument, 0, 'v'},
      {"version", no_argument, 0, 'V'},
      {0, 0, 0, 0}
   };
   char *short_options = "f:hr:t:i:b:a:vV";
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
   unsigned long loop_timediff;
   unsigned long host_timediff;
   struct host_entry *temp_cursor;
   unsigned seed = 0;
/*
 *	Process options and arguments.
 */
   while ((arg=getopt_long_only(argc, argv, short_options, long_options, &options_index)) != -1) {
      switch (arg) {
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
         case 'a':
            seed=atoi(optarg);
            break;
         case 'v':
            verbose++;
            break;
         case 'V':
            fprintf(stderr, "%s\n", VERSION);
            exit(0);
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
 *	Seed RNG using the specified seed or time since epoch if random
 *	seed was not specified.
 */
   if (!seed) {
      if ((gettimeofday(&now,NULL)) != 0) {
         err_sys("gettimeofday");
      }
      seed=(now.tv_sec & 0xffff) + (now.tv_usec & 0xffff);
   }
   srandom(seed);
/*
 *	Populate the list from the specified file if --file was specified, or
 *	otherwise from the remaining command line arguments.
 */
   if (filename_flag) {	/* Populate list from file */
      FILE *fp;
      char line[MAXLINE];
      char host[MAXLINE];
      char *p;

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
            p=cpystr(host);
            add_host(p);
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
   cursor = rrlist;
   last_packet_time.tv_sec=0;
   last_packet_time.tv_usec=0;
   initialise_ike_packet();
/*
 *	Main loop: send packets to all hosts in order until a response
 *	has been received or the host has exhausted it's retry limit.
 *	The loop exits when all hosts have either responded or timed out.
 */
   while (num_hosts) {
/*
 *	Obtain current time and calculate deltas since last packet and
 *	last packet to this host.
 */
      if ((gettimeofday(&now, NULL)) != 0) {
         err_sys("gettimeofday");
      }
      loop_timediff=timeval_diff(&now, &last_packet_time);
      host_timediff=timeval_diff(&now, &(cursor->last_send_time));
/*
 *	If the last packet was sent more than interval ms ago, then we can
 *	potentially send a packet to the current host.
 */
      if (loop_timediff > interval) {
/*
 *	If the last packet to this host was sent more than the current
 *	timeout for this host ms ago, then we can potentially send a packet
 *	to it.
 */
         if (host_timediff > cursor->timeout) {
/*
 *	If we've exceeded our retry limit, then this host has timed out so
 *	remove it from the list.  Otherwise, increase the timeout by the
 *	backoff factor if this is not the first packet sent to this host
 *	and send a packet.
 */
            if (cursor->num_sent >= retry) {
               if (verbose)
                  warn_msg("Removing host entry %d (%s) - Timeout", cursor->n, inet_ntoa(cursor->addr));
               temp_cursor = cursor;
               if (num_hosts) {
                  cursor = cursor->next;
               } else {
                  cursor = NULL;
               }
               remove_host(temp_cursor);
            } else {	/* Retry limit not reached for this host */
               if (cursor->num_sent) {
                  cursor->timeout *= backoff;
               }
               send_packet(sockfd, cursor);
            }
         } else {	/* We can't send a packet to this host yet */
            cursor = cursor->next;
         }
      } else {	/* We can't send another packet yet */
         if ((n=recvfrom_wto(sockfd, packet_in, MAXUDP, (struct sockaddr *)&sa_peer, select_timeout)) > 0) {
            if ((temp_cursor=find_host_by_ip(cursor, &(sa_peer.sin_addr))) == NULL) {
               warn_msg("Received %d bytes from unknown host (%s) - unexpected!", n, inet_ntoa(sa_peer.sin_addr));
            } else {	/* Received a packet from a host in our list */
               display_packet(n, packet_in, temp_cursor);
               if (verbose)
                  warn_msg("Removing host entry %d (%s) - Received %d bytes", temp_cursor->n, inet_ntoa(sa_peer.sin_addr), n);
               temp_cursor = cursor;
               if (num_hosts) {
                  cursor = cursor->next;
               } else {
                  cursor = NULL;
               }
               remove_host(temp_cursor);
            }
         } else if (n == -2) {	/* Connection refused - remove entry */
            if (verbose)
               warn_msg("Removing host entry %d (%s) - Connection refused", cursor->n, inet_ntoa(cursor->addr));
            temp_cursor = cursor;
            if (num_hosts) {
               cursor = cursor->next;
            } else {
               cursor = NULL;
            }
            remove_host(temp_cursor);
         }
      }
   }	/* End While */

   close(sockfd);
   return(0);
}

/*
 *	add_host -- Add a host name and associated address to the list
 */
void add_host(char *name) {
   struct hostent *hp;
   struct host_entry *he;

   if ((hp = gethostbyname(name)) == NULL)
      err_sys("gethostbyname");

   if ((he = malloc(sizeof(struct host_entry))) == NULL)
      err_sys("malloc");

   num_hosts++;

   he->n = num_hosts;
   he->name = name;
   memcpy(&(he->addr), hp->h_addr_list[0], sizeof(struct in_addr));
   he->timeout = timeout;
   he->num_sent = 0;
   he->num_recv = 0;
   he->last_send_time.tv_sec=0;
   he->last_send_time.tv_usec=0;
   he->icookie[0] = random();
   he->icookie[1] = random();

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
 */
void remove_host(struct host_entry *he) {
   if (num_hosts) {	/* List has more than one entry */
      he->prev->next = he->next;
      he->next->prev = he->prev;
   } else {		/* Last entry is being removed */
      rrlist = NULL;
   }
   free(he);
   num_hosts--;
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
 *	display_packet -- Display received IKE packet
 */
void display_packet(int n, char *packet_in, struct host_entry *he) {
   struct isakmp_hdr hdr_in;
/*
 *	Check that the received packet is at least as big as the ISAKMP
 *	header.
 */
   if (n < sizeof(hdr_in)) {
      printf("%s\tShort packet returned (len < ISAKMP header length)\n", inet_ntoa(he->addr));
      return;
   }
/*
 *	Copy packet into ISAKMP header structure and examine contents.
 */
   memcpy(&hdr_in, packet_in, sizeof(hdr_in));

   if (hdr_in.isa_np == ISAKMP_NEXT_SA) {
      printf("%s\tIKE Handshake returned\n", inet_ntoa(he->addr));
   } else if (hdr_in.isa_np == ISAKMP_NEXT_N) {
      printf("%s\tIKE Notification returned\n", inet_ntoa(he->addr));
   } else {
      printf("%s\tUnknown IKE packet returned (%d)\n", inet_ntoa(he->addr), hdr_in.isa_np);
   }
}

/*
 *	cpystr -- Copy a string into malloc'ed memory and return pointer
 */
char *cpystr(char *str) {
   char *p;

   if (str) {
      if ((p = (char *) malloc(strlen(str)+1)) == NULL)
         err_sys("malloc");
      strcpy(p, str);
      return(p);
   } else {
      return(NULL);
   }
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
      warn_msg("Sending packet #%d to host entry %d (%s) tmo %d", he->num_sent, he->n, inet_ntoa(he->addr), he->timeout);
   if ((sendto(s, buf, buflen, 0, (struct sockaddr *) &sa_peer, sa_peer_len)) < 0) {
      err_sys("sendto");
   }
}

/*
 *	recvfrom_wto -- Receive packet with timeout
 *
 *	Returns number of characters received, or -1 for timeout or
 *	-2 for connection refused.
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
         return -2;
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
unsigned long timeval_diff(struct timeval *a,struct timeval *b) {
   double temp;
   temp = (((a->tv_sec*1000000)+ a->tv_usec) -
           ((b->tv_sec*1000000)+ b->tv_usec)) / 1000;

   return (long) temp;
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
   hdr.isa_length = htonl(sizeof(hdr)+sizeof(sa_hdr)+sizeof(sa_prop)+sizeof(trans));
/*
 *	SA Header
 */
   sa_hdr.isasa_np = ISAKMP_NEXT_NONE;  /* No Next payload */
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
   sa_prop.isap_notrans = 4;            /* Four Transforms */
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
   trans[0].attr[2].isaat_lv = htons(1);                /* Shared Key */
   trans[0].attr[3].isaat_af_type = htons(0x8004);      /* Group */
   trans[0].attr[3].isaat_lv = htons(2);                /* group 2 */
   trans[0].attr[4].isaat_af_type = htons(0x800b);      /* Life Type */
   trans[0].attr[4].isaat_lv = htons(1);                /* Seconds */
   trans[0].attr2.isaat_af_type = htons(0x000c);        /* Life Duration */
   trans[0].attr2.isaat_l = htons(4);                   /* 4 Bytes- CANT CHANGE*/
   trans[0].attr2.isaat_v = htonl(0x00015180);          /* 86400 */

   trans[1].trans_hdr.isat_np = 3;                      /* More transforms */
   trans[1].trans_hdr.isat_length = htons(sizeof(trans[1]));
   trans[1].trans_hdr.isat_transnum = 2;                /* Transform #2 */
   trans[1].trans_hdr.isat_transid = KEY_IKE;
   trans[1].attr[0].isaat_af_type = htons(0x8001);      /* Encrypt */
   trans[1].attr[0].isaat_lv = htons(OAKLEY_3DES_CBC);
   trans[1].attr[1].isaat_af_type = htons(0x8002);      /* Hash */
   trans[1].attr[1].isaat_lv = htons(OAKLEY_MD5);
   trans[1].attr[2].isaat_af_type = htons(0x8003);      /* Auth */
   trans[1].attr[2].isaat_lv = htons(1);                /* Shared Key */
   trans[1].attr[3].isaat_af_type = htons(0x8004);      /* Group */
   trans[1].attr[3].isaat_lv = htons(2);                /* group 2 */
   trans[1].attr[4].isaat_af_type = htons(0x800b);      /* Life Type */
   trans[1].attr[4].isaat_lv = htons(1);                /* Seconds */
   trans[1].attr2.isaat_af_type = htons(0x000c);        /* Life Duration */
   trans[1].attr2.isaat_l = htons(4);                   /* 4 Bytes- CANT CHANGE*/
   trans[1].attr2.isaat_v = htonl(0x00015180);          /* 86400 */

   trans[2].trans_hdr.isat_np = 3;                      /* More transforms */
   trans[2].trans_hdr.isat_length = htons(sizeof(trans[2]));
   trans[2].trans_hdr.isat_transnum = 3;                /* Transform #3 */
   trans[2].trans_hdr.isat_transid = KEY_IKE;
   trans[2].attr[0].isaat_af_type = htons(0x8001);      /* Encrypt */
   trans[2].attr[0].isaat_lv = htons(OAKLEY_DES_CBC);
   trans[2].attr[1].isaat_af_type = htons(0x8002);      /* Hash */
   trans[2].attr[1].isaat_lv = htons(OAKLEY_SHA);
   trans[2].attr[2].isaat_af_type = htons(0x8003);      /* Auth */
   trans[2].attr[2].isaat_lv = htons(1);                /* Shared Key */
   trans[2].attr[3].isaat_af_type = htons(0x8004);      /* Group */
   trans[2].attr[3].isaat_lv = htons(2);                /* group 2 */
   trans[2].attr[4].isaat_af_type = htons(0x800b);      /* Life Type */
   trans[2].attr[4].isaat_lv = htons(1);                /* Seconds */
   trans[2].attr2.isaat_af_type = htons(0x000c);        /* Life Duration */
   trans[2].attr2.isaat_l = htons(4);                   /* 4 Bytes- CANT CHANGE*/
   trans[2].attr2.isaat_v = htonl(0x00015180);          /* 86400 */

   trans[3].trans_hdr.isat_np = 0;                      /* No more transforms */
   trans[3].trans_hdr.isat_length = htons(sizeof(trans[3]));
   trans[3].trans_hdr.isat_transnum = 4;                /* Transform #4 */
   trans[3].trans_hdr.isat_transid = KEY_IKE;
   trans[3].attr[0].isaat_af_type = htons(0x8001);      /* Encrypt */
   trans[3].attr[0].isaat_lv = htons(OAKLEY_DES_CBC);
   trans[3].attr[1].isaat_af_type = htons(0x8002);      /* Hash */
   trans[3].attr[1].isaat_lv = htons(OAKLEY_MD5);
   trans[3].attr[2].isaat_af_type = htons(0x8003);      /* Auth */
   trans[3].attr[2].isaat_lv = htons(1);                /* Shared Key */
   trans[3].attr[3].isaat_af_type = htons(0x8004);      /* Group */
   trans[3].attr[3].isaat_lv = htons(2);                /* group 2 */
   trans[3].attr[4].isaat_af_type = htons(0x800b);      /* Life Type */
   trans[3].attr[4].isaat_lv = htons(1);                /* Seconds */
   trans[3].attr2.isaat_af_type = htons(0x000c);        /* Life Duration */
   trans[3].attr2.isaat_l = htons(4);                   /* 4 Bytes- CANT CHANGE*/
   trans[3].attr2.isaat_v = htonl(0x00015180);          /* 86400 */
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
   fprintf(stderr, "\t\t\tper line.\n");
   fprintf(stderr, "--sport=<p> or -s p\tSet UDP source port to <p>, default=%d, 0=random.\n", DEFAULT_SOURCE_PORT);
   fprintf(stderr, "--dport=<p> or -d p\tSet UDP destination port to <p>, default=%d\n", DEFAULT_DEST_PORT);
   fprintf(stderr, "--retry=<n> or -r n\tSet number of attempts per host to <n>, default=%d\n", DEFAULT_RETRY);
   fprintf(stderr, "--timeout=<n> or -t n\tSet per host timeout to <n> ms, default=%d\n", DEFAULT_TIMEOUT);
   fprintf(stderr, "--interval=<n> or -i <n>\tSet packet interval to <n> ms, default=%d\n", DEFAULT_INTERVAL);
   fprintf(stderr, "--backoff=<b> or -b <b>\tSet backoff factor to <b>, default=%.2f\n", DEFAULT_BACKOFF_FACTOR);
   fprintf(stderr, "--random=<n> or -a <n>\tSet random seed to <n>.  Default is based on time\n");
   fprintf(stderr, "--verbose or -v\t\tDisplay verbose progress messages.\n");
   fprintf(stderr, "--version or -V\t\tDisplay program version and exit.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "%s\n", VERSION);
   fprintf(stderr, "\n");
   exit(1);
}
