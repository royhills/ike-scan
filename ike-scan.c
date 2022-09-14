/*
 * The IKE Scanner (ike-scan) is Copyright (C) 2003-2013 Roy Hills,
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
 * ike-scan -- The IKE Scanner
 *
 * Author:	Roy Hills
 * Date:	11 September 2002
 *
 * Usage:
 *    ike-scan [options] [host...]
 *
 * Description:
 *
 * ike-scan - The IKE Scanner
 *
 * ike-scan sends IKE Phase 1 requests to the specified hosts and displays
 * any responses that are received.  It handles retry and retransmission with
 * backoff to cope with packet loss.
 *
 * Use ike-scan --help to display information on the usage and options.
 * See the README file for full details.
 *
 */

#include "ike-scan.h"
#include "hash_functions.h"

/* Global variables */
host_entry *helist = NULL;	/* Dynamic array of host entries */
host_entry **helistptr;		/* Array of pointers to host entries */
host_entry **cursor;		/* Pointer to current list entry */
pattern_list *patlist = NULL;	/* Backoff pattern list */
vid_pattern_list *vidlist = NULL;	/* Vendor ID pattern list */
char **idlist = NULL;		/* Array of pointers to ID strings */
static int verbose=0;			/* Verbose level */
unsigned experimental_value=0;		/* Experimental value */
int tcp_flag=0;				/* TCP flag */
int psk_crack_flag=0;			/* Pre-shared key cracking flag */
psk_crack psk_values = {		/* Pre-shared key values */
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
   0, 0, 0, 0, 0, 0, 0, 0, 0
};
int no_dns_flag=0;			/* No DNS flag */
int mbz_value=0;			/* Value for MBZ fields */
uint32_t lifetime_be;	/* Default lifetime in big endian format */
uint32_t lifesize_be;	/* Default lifesize in big endian format */
int write_pkt_to_file=0;	/* Write packet to file for debugging */
int read_pkt_from_file=0;	/* Read packet from file for debugging */
int timestamp_flag=0;		/* Timestamp flag */
int randsrc_flag=0;		/* Randomise source IP address flag */
int sourceip_flag=0;		/* Set source IP address flag */
uint32_t src_ip_val;		/* Specified source IP */
int shownum_flag=0;		/* Display packet number */
int nat_t_flag=0;		/* RFC 3947 NAT Traversal */
int bindip_flag=0;             /* Set bind IP address flag */
uint32_t bind_ip_val;		/* IP address to bind to */

extern const id_name_map notification_map[];
extern const id_name_map attr_map[];
extern const id_name_map enc_map[];
extern const id_name_map hash_map[];
extern const id_name_map auth_map[];
extern const id_name_map dh_map[];
extern const id_name_map life_map[];
extern const id_name_map payload_map[];
extern const id_name_map doi_map[];
extern const id_name_map protocol_map[];
extern const id_name_map id_map[];
extern const id_name_map cert_map[];

int
main(int argc, char *argv[]) {
/*
 * long_options can be const because the flag is always set to zero (NULL)
 * and is never changed.
 */
   const struct option long_options[] = {
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
      {"lifesize", required_argument, 0, 'z'},
      {"auth", required_argument, 0, 'm'},
      {"version", no_argument, 0, 'V'},
      {"vendor", required_argument, 0, 'e'},
      {"trans", required_argument, 0, 'a'},
      {"showbackoff", optional_argument, 0, 'o'},
      {"fuzz", required_argument, 0, 'u'},
      {"id", required_argument, 0, 'n'},
      {"idtype", required_argument, 0, 'y'},
      {"dhgroup", required_argument, 0, 'g'},
      {"patterns", required_argument, 0, 'p'},
      {"aggressive", no_argument, 0, 'A'},
      {"gssid", required_argument, 0, 'G'},
      {"vidpatterns", required_argument, 0, 'I'},
      {"quiet", no_argument, 0, 'q'},
      {"multiline", no_argument, 0, 'M'},
      {"random", no_argument, 0, 'R'},
      {"tcp", optional_argument, 0, 'T'},
      {"pskcrack", optional_argument, 0, 'P'},
      {"tcptimeout", required_argument, 0, 'O'},
      {"nodns", no_argument, 0, 'N'},
      {"noncelen", required_argument, 0, 'c'},
      {"bandwidth", required_argument, 0, 'B'},
      {"headerlen", required_argument, 0, 'L'},
      {"mbz", required_argument, 0, 'Z'},
      {"headerver", required_argument, 0, 'E'},
      {"certreq", required_argument, 0, 'C'},
      {"doi", required_argument, 0, 'D'},
      {"situation", required_argument, 0, 'S'},
      {"protocol", required_argument, 0, 'j'},
      {"transid", required_argument, 0, 'k'},
      {"spisize", required_argument, 0, OPT_SPISIZE},
      {"hdrflags", required_argument, 0, OPT_HDRFLAGS},
      {"hdrmsgid", required_argument, 0, OPT_HDRMSGID},
      {"cookie", required_argument, 0, OPT_COOKIE},
      {"exchange", required_argument, 0, OPT_EXCHANGE},
      {"nextpayload", required_argument, 0, OPT_NEXTPAYLOAD},
      {"writepkttofile", required_argument, 0, OPT_WRITEPKTTOFILE},
      {"randomseed", required_argument, 0, OPT_RANDOMSEED},
      {"timestamp", no_argument, 0, OPT_TIMESTAMP},
      {"sourceip", required_argument, 0, OPT_SOURCEIP},
      {"bindip", required_argument, 0, OPT_BINDIP},
      {"shownum", no_argument, 0, OPT_SHOWNUM},
      {"ikev2", no_argument, 0, '2'},
      {"nat-t", no_argument, 0, OPT_NAT_T},
      {"rcookie", required_argument, 0, OPT_RCOOKIE},
      {"readpktfromfile", required_argument, 0, OPT_READPKTFROMFILE},
      {"experimental", required_argument, 0, 'X'},
      {0, 0, 0, 0}
   };
/*
 * available short option characters:
 *
 * lower:	-----------------------x--
 * UPPER:	-----F-H-JK-----Q---U-W-Y-
 * Digits:	01-3456789
 */
   const char *short_options =
      "f:hs:d:r:t:i:b:w:vl:z:m:Ve:a:o::u:n:y:g:p:AG:I:qMRT::P::O:Nc:B:"
      "L:Z:E:C:D:S:j:k:2X:";
   int arg;
   int options_index=0;
   char filename[MAXLINE];
   int filename_flag=0;
   char pkt_filename[MAXLINE];	/* for --writepkttofile option */
   int pkt_filename_flag=0;
   int pkt_read_filename_flag=0;
   int random_flag=0;		/* Should we randomise the list? */
   int sockfd;			/* UDP socket file descriptor */
   unsigned source_port = DEFAULT_SOURCE_PORT;	/* UDP source port */
   unsigned dest_port = DEFAULT_DEST_PORT;	/* UDP destination port */
   unsigned retry = DEFAULT_RETRY;	/* Number of retries */
   unsigned interval = 0;	/* Interval between packets */
   double backoff_factor = DEFAULT_BACKOFF_FACTOR;	/* Backoff factor */
   unsigned end_wait = 1000 * DEFAULT_END_WAIT; /* Time to wait after all done in ms */
   unsigned timeout = DEFAULT_TIMEOUT;	/* Per-host timeout in ms */
   ike_packet_params ike_params = {
      NULL,			/* Lifetime in seconds */
      0,			/* Lifetime data length */
      NULL,			/* Lifesize in KB */
      0,			/* Lifesize data length */
      DEFAULT_AUTH_METHOD,	/* Authentication method */
      DEFAULT_DH_GROUP,		/* Diffie Hellman Group */
      DEFAULT_IDTYPE,		/* IKE Identification type */
      NULL,			/* Identity data */
      0,			/* Identity data length */
      0,			/* Indicates if VID to be used */
      0,			/* Indicates custom transform */
      DEFAULT_EXCHANGE_TYPE, 	/* Main or Aggressive mode */
      0,			/* Indicates if GSSID to be used */
      NULL,			/* Binary GSSID data */
      0,			/* GSSID data length */
      DEFAULT_NONCE_LEN,	/* Nonce data length */
      NULL,			/* ISAKMP header length modifier */
      NULL,			/* Cert req. data */
      0,			/* cd_data_len */
      DEFAULT_HEADER_VERSION,	/* header_version */
      DEFAULT_DOI,		/* SA DOI */
      DEFAULT_SITUATION,	/* SA Situation */
      DEFAULT_PROTOCOL,		/* Proposal Protocol ID */
      DEFAULT_TRANS_ID,		/* Transform ID */
      0,			/* Proposal SPI Size */
      0,			/* ISAKMP Header Flags */
      0,			/* ISAKMP Header Message ID */
      0,			/* ISAKMP Header Next Payload */
      0,			/* advanced_trans_flag */
      DEFAULT_IKE_VERSION,	/* IKE Version */
      NULL,			/* rcookie data */
      0				/* rcookie data length */
   };
   unsigned pattern_fuzz = DEFAULT_PATTERN_FUZZ; /* Pattern matching fuzz in ms */
   unsigned tcp_connect_timeout = DEFAULT_TCP_CONNECT_TIMEOUT;
   struct sockaddr_in sa_local;
   struct sockaddr_in sa_peer;
   struct timeval now;
   unsigned char packet_in[MAXUDP];	/* Received packet */
   int n;
   host_entry *temp_cursor;
   struct timeval diff;		/* Difference between two timevals */
   IKE_UINT64 loop_timediff;	/* Time since last packet sent in us */
   IKE_UINT64 host_timediff;	/* Time since last packet sent to this host */
   unsigned long end_timediff=0; /* Time since last packet received in ms */
   int req_interval;		/* Requested per-packet interval */
   int select_timeout;		/* Select timeout */
   int cum_err=0;		/* Cumulative timing error */
   static int reset_cum_err;
   struct timeval start_time;	/* Program start time */
   struct timeval end_time;	/* Program end time */
   struct timeval last_packet_time; /* Time last packet was sent */
   struct timeval elapsed_time;	/* Elapsed time as timeval */
   double elapsed_seconds;	/* Elapsed time in seconds */
   char patfile[MAXLINE];	/* IKE Backoff pattern file name */
   char vidfile[MAXLINE];	/* IKE Vendor ID pattern file name */
   char psk_crack_file[MAXLINE];/* PSK crack data output file name */
   unsigned pass_no=0;
   int first_timeout=1;
   unsigned char *vid_data;	/* Binary Vendor ID data */
   size_t vid_data_len;		/* Vendor ID data length */
   int showbackoff_flag = 0;	/* Display backoff table? */
   struct timeval last_recv_time;	/* Time last packet was received */
   unsigned char *packet_out;	/* IKE packet to send */
   size_t packet_out_len;	/* Length of IKE packet to send */
   unsigned sa_responders = 0;	/* Number of hosts giving handshake */
   unsigned notify_responders = 0;	/* Number of hosts giving notify msg */
   unsigned num_hosts = 0;	/* Number of entries in the list */
   unsigned live_count;		/* Number of entries awaiting reply */
   int quiet=0;			/* Only print the basic info if nonzero */
   int multiline=0;		/* Split decodes across lines if nonzero */
   unsigned hostno;
   unsigned bandwidth=DEFAULT_BANDWIDTH; /* Bandwidth in bits per sec */
   unsigned char *cookie_data=NULL;
   size_t cookie_data_len;
   unsigned int random_seed=0;
/*
 *      Get program start time for statistics displayed on completion.
 */
   Gettimeofday(&start_time);
/*
 *	Initialise file names to the empty string.
 */
   patfile[0] = '\0';
   vidfile[0] = '\0';
/*
 *	Set lifetime and lifesize parameters to the default.
 */
   if (DEFAULT_LIFETIME) {
      lifetime_be = htonl(DEFAULT_LIFETIME);
      ike_params.lifetime_data = (unsigned char *) &lifetime_be;
      ike_params.lifetime_data_len = 4;
   }
   if (DEFAULT_LIFESIZE) {
      lifesize_be = htonl(DEFAULT_LIFETIME);
      ike_params.lifesize_data = (unsigned char *) &lifesize_be;
      ike_params.lifesize_data_len = 4;
   }
/*
 *	Process options and arguments.
 */
   while ((arg=getopt_long_only(argc, argv, short_options, long_options, &options_index)) != -1) {
      switch (arg) {
         unsigned trans_enc;	/* Custom transform cipher */
         unsigned trans_keylen;	/* Custom transform cipher key length */
         unsigned trans_hash;	/* Custom transform hash */
         unsigned trans_auth;	/* Custom transform auth */
         unsigned trans_group;	/* Custom transform DH group */
         char trans_str[MAXLINE];	/* Custom transform string */
         struct in_addr src_ip_struct;
         struct in_addr bind_ip_struct;
         case 'f':	/* --file */
            strlcpy(filename, optarg, sizeof(filename));
            filename_flag=1;
            break;
         case 'h':	/* --help */
            usage(EXIT_SUCCESS, 1);	/* Doesn't return */
            break;	/* Not required but prevents fall through warning */
         case 's':	/* --sport */
            source_port=Strtoul(optarg, 10);
            break;
         case 'd':	/* --dport */
            dest_port=Strtoul(optarg, 10);
            break;
         case 'r':	/* --retry */
            retry=Strtoul(optarg, 10);
            break;
         case 't':	/* --timeout */
            timeout=Strtoul(optarg, 10);
            break;
         case 'i':	/* --interval */
            interval=str_to_interval(optarg);
            break;
         case 'b':	/* --backoff */
            backoff_factor=atof(optarg);
            break;
         case 'w':	/* --selectwait */
            fprintf(stderr, "--selectwait option ignored - no longer needed\n");
            break;
         case 'v':	/* --verbose */
            verbose++;
            break;
         case 'l':	/* --lifetime */
            if ((strcmp(optarg, "none")) == 0) {
               ike_params.lifetime_data = NULL;
               ike_params.lifetime_data_len = 0;
            } else {
               ike_params.lifetime_data=
                  hex_or_num(optarg, &(ike_params.lifetime_data_len));
            }
            break;
         case 'z':	/* --lifesize */
            if ((strcmp(optarg, "none")) == 0) {
               ike_params.lifesize_data = NULL;
               ike_params.lifesize_data_len = 0;
            } else {
               ike_params.lifesize_data=
                  hex_or_num(optarg, &(ike_params.lifesize_data_len));
            }
            break;
         case 'm':	/* --auth */
            ike_params.auth_method=name_or_number(optarg, auth_map);
            break;
         case 'V':	/* --version */
            fprintf(stderr, "%s\n\n", PACKAGE_STRING);
            fprintf(stderr, "Copyright (C) 2003-2013 Roy Hills, NTA Monitor Ltd.\n");
            fprintf(stderr, "ike-scan comes with NO WARRANTY to the extent permitted by law.\n");
            fprintf(stderr, "You may redistribute copies of ike-scan under the terms of the GNU\n");
            fprintf(stderr, "General Public License.\n");
            fprintf(stderr, "For more information about these matters, see the file named COPYING.\n");
            fprintf(stderr, "\n");
            exit(EXIT_SUCCESS);	/* Doesn't return */
         case 'e':	/* --vendor */
            if (strlen(optarg) % 2)	/* Length is odd */
               err_msg("ERROR: Length of --vendor argument must be even (multiple of 2).");
            ike_params.vendor_id_flag=1;
            vid_data=hex2data(optarg, &vid_data_len);
            add_vid(0, NULL, vid_data, vid_data_len, ike_params.ike_version, 0);
            free(vid_data);
            break;
         case 'a':	/* --trans */
            strlcpy(trans_str, optarg, sizeof(trans_str));
            ike_params.trans_flag++;
            if (trans_str[0] == '(') {	/* Advanced transform specification */
               unsigned char *attr=NULL;
               size_t attr_len;

               attr = decode_transform(trans_str, &attr_len);
               add_transform(0, NULL, ike_params.trans_id, attr, attr_len);
               ike_params.advanced_trans_flag = 1;
            } else {	/* Simple transform specification */
               decode_trans_simple(trans_str, &trans_enc, &trans_keylen,
                                   &trans_hash, &trans_auth, &trans_group);
               add_trans_simple(0, NULL, trans_enc, trans_keylen, trans_hash,
                                trans_auth, trans_group,
                                ike_params.lifetime_data,
                                ike_params.lifetime_data_len,
                                ike_params.lifesize_data,
                                ike_params.lifesize_data_len,
                                ike_params.gss_id_flag,
                                ike_params.gss_data, ike_params.gss_data_len,
                                ike_params.trans_id);
            }
            break;
         case 'o':	/* --showbackoff */
            showbackoff_flag=1;
            if (optarg == NULL || *optarg == '\0') {
               end_wait=1000 * DEFAULT_END_WAIT;
            } else {
               end_wait=1000 * Strtoul(optarg, 10);
            }
            break;
         case 'u':	/* --fuzz */
            pattern_fuzz=Strtoul(optarg, 10);
            break;
         case 'n':	/* --id */
            if (ike_params.id_data)
               err_msg("ERROR: You may only specify one identity payload with --id");
            ike_params.id_data=hex_or_str(optarg, &(ike_params.id_data_len));
            break;
         case 'y':	/* --idtype */
            ike_params.idtype = Strtoul(optarg, 10);
            break;
         case 'g':	/* --dhgroup */
            ike_params.dhgroup = Strtoul(optarg, 10);
            break;
         case 'p':	/* --patterns */
            strlcpy(patfile, optarg, sizeof(patfile));
            break;
         case 'A':	/* --aggressive */
            ike_params.exchange_type = ISAKMP_XCHG_AGGR;
            break;
         case 'G':	/* --gssid */
            if (strlen(optarg) % 2) {	/* Length is odd */
               err_msg("ERROR: Length of --gssid argument must be even (multiple of 2).");
            }
            ike_params.gss_id_flag=1;
            ike_params.gss_data=hex2data(optarg, &(ike_params.gss_data_len));
            break;
         case 'I':	/* --vidpatterns */
            strlcpy(vidfile, optarg, sizeof(vidfile));
            break;
         case 'q':	/* --quiet */
            quiet=1;
            break;
         case 'M':	/* --multiline */
            multiline=1;
            break;
         case 'R':      /* --random */
            random_flag=1;
            break;
         case 'T':	/* --tcp */
            if (optarg == NULL || *optarg == '\0') {
               tcp_flag = TCP_PROTO_RAW;
            } else {
               tcp_flag = Strtoul(optarg, 10);
            }
            break;
         case 'P':	/* --pskcrack */
            psk_crack_flag=1;
            if (optarg == NULL || *optarg == '\0') {
               psk_crack_file[0] = '\0'; /* use stdout */
            } else {
               strlcpy(psk_crack_file, optarg, sizeof(psk_crack_file));
            }
            break;
         case 'O':	/* --tcptimeout */
            tcp_connect_timeout = Strtoul(optarg, 10);
            break;
         case 'N':	/* --nodns */
            no_dns_flag=1;
            break;
         case 'c':	/* --noncelen */
            ike_params.nonce_data_len = Strtoul(optarg, 10);
            break;
         case 'B':	/* --bandwidth */
            bandwidth=str_to_bandwidth(optarg);
            break;
         case 'L':	/* --headerlen */
            ike_params.header_length = dupstr(optarg);
            break;
         case 'Z':	/* --mbz */
            mbz_value = Strtoul(optarg, 0);
            break;
         case 'E':	/* --headerver */
            ike_params.header_version = Strtoul(optarg, 0);
            break;
         case 'C':	/* --certreq */
            if (strlen(optarg) % 2)	/* Length is odd */
               err_msg("ERROR: Length of --certreq argument must be even (multiple of 2).");
            ike_params.cr_data=hex2data(optarg, &(ike_params.cr_data_len));
            break;
         case 'D':	/* --doi */
            ike_params.doi = Strtoul(optarg, 0);
            break;
         case 'S':	/* --situation */
            ike_params.situation = Strtoul(optarg, 0);
            break;
         case 'j':	/* --protocol */
            ike_params.protocol = Strtoul(optarg, 0);
            break;
         case 'k':	/* --transid */
            ike_params.trans_id = Strtoul(optarg, 0);
            break;
         case OPT_SPISIZE:	/* --spisize */
            ike_params.spi_size=Strtoul(optarg, 0);
            break;
         case OPT_HDRFLAGS:	/* --hdrflags */
            ike_params.hdr_flags=Strtoul(optarg, 0);
            break;
         case OPT_HDRMSGID:	/* --hdrmsgid */
            ike_params.hdr_msgid=Strtoul(optarg, 0);
            break;
         case OPT_COOKIE:	/* --cookie */
            if (strlen(optarg) % 2)	/* Length is odd */
               err_msg("ERROR: Length of --cookie argument must be even (multiple of 2).");
            cookie_data=hex2data(optarg, &cookie_data_len);
            if (cookie_data_len > 8)
               cookie_data_len = 8;
            break;
         case OPT_EXCHANGE:	/* --exchange */
            ike_params.exchange_type=Strtoul(optarg, 0);
            break;
         case OPT_NEXTPAYLOAD:	/* --nextpayload */
            ike_params.hdr_next_payload=Strtoul(optarg, 0);
            break;
         case OPT_WRITEPKTTOFILE: /* --writepkttofile */
            strlcpy(pkt_filename, optarg, sizeof(pkt_filename));
            pkt_filename_flag=1;
            break;
         case OPT_RANDOMSEED: /* --randomseed */
            random_seed=Strtoul(optarg, 0);
            break;
         case OPT_TIMESTAMP: /* --timestamp */
            timestamp_flag = 1;
            break;
         case OPT_SOURCEIP: /* --sourceip */
            sourceip_flag = 1;
            if ((strcmp(optarg, "random")) == 0) {
               randsrc_flag = 1;
            } else {
               if (!(inet_aton(optarg, &src_ip_struct)))
                  err_msg("ERROR: %s is not a valid IP address", optarg);
               src_ip_val=src_ip_struct.s_addr;
            }
            break;
         case OPT_BINDIP: /* --bindip */
            bindip_flag = 1;
	    if (!(inet_aton(optarg, &bind_ip_struct)))
                  err_msg("ERROR: %s is not a valid IP address", optarg);
               bind_ip_val=bind_ip_struct.s_addr;
            break;
         case OPT_SHOWNUM: /* --shownum */
            shownum_flag = 1;
            break;
         case '2':	/* --ikev2 */
            ike_params.ike_version = 2;
            ike_params.header_version = 0x20;	/* v2.0 */
            ike_params.hdr_flags=0x08;	/* Set Initiator bit */
            ike_params.exchange_type = ISAKMP_XCHG_IKE_SA_INIT;
            break;
         case OPT_NAT_T:	/* --nat-t */
            nat_t_flag = 1;
            source_port = DEFAULT_NAT_T_SOURCE_PORT;
            dest_port = DEFAULT_NAT_T_DEST_PORT;
            break;
         case OPT_RCOOKIE:	/* --rcookie */
            if (strlen(optarg) % 2)	/* Length is odd */
               err_msg("ERROR: Length of --rcookie argument must be even (multiple of 2).");
            ike_params.rcookie_data=hex2data(optarg,
                                             &(ike_params.rcookie_data_len));
            if (ike_params.rcookie_data_len > 8)
               ike_params.rcookie_data_len = 8;
            break;
         case OPT_READPKTFROMFILE: /* --readpktfromfile */
            strlcpy(pkt_filename, optarg, sizeof(pkt_filename));
            pkt_read_filename_flag=1;
            break;
         case 'X':	/* --experimental */
            experimental_value = Strtoul(optarg, 0);
            break;
         default:	/* Unknown option */
            usage(EXIT_FAILURE, 0);	/* Doesn't return */
      }
   }
/*
 *	Seed random number generator.
 *	If the random seed has been specified (is non-zero), then use that.
 *	Otherwise, seed the RNG with an unpredictable value.
 */
   if (!random_seed) {
      struct timeval tv;

      Gettimeofday(&tv);
      random_seed = ((unsigned) tv.tv_usec ^ (unsigned) getpid());
   }
   init_genrand(random_seed);
/*
 *	Create network socket and bind to local source port.
 */
   if (tcp_flag) {
      const int on = 1;	/* for setsockopt() */

      if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
         err_sys("ERROR: socket");
      if ((setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on))) < 0)
         err_sys("ERROR: setsockopt() failed");
      if ((setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0)
         err_sys("ERROR: setsockopt() failed");
   } else if (sourceip_flag) {	/* Raw IP socket */
      const int on = 1;	/* for setsockopt() */

      if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
         err_sys("socket");
      if ((setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on))) != 0)
         err_sys("setsockopt");
      if ((setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on))) != 0)
         err_sys("setsockopt");
   } else {
      const int on = 1;	/* for setsockopt() */

      if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
         err_sys("ERROR: socket");
      if ((setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on))) != 0)
         err_sys("setsockopt");
   }

   memset(&sa_local, '\0', sizeof(sa_local));
   sa_local.sin_family = AF_INET;
   if (bindip_flag)
     sa_local.sin_addr.s_addr = bind_ip_val;
   else
     sa_local.sin_addr.s_addr = htonl(INADDR_ANY);
   sa_local.sin_port = htons(source_port);

   if ((bind(sockfd, (struct sockaddr *)&sa_local, sizeof(sa_local))) < 0) {
      warn_msg("ERROR: Could not bind network socket to local port %u", source_port);
      if (errno == EACCES)
         warn_msg("You need to be root, or ike-scan must be suid root to bind to ports below 1024.");
      if (errno == EADDRINUSE)
         warn_msg("Only one process may bind to the source port at any one time.");
      err_sys("ERROR: bind");
   }
/*
 *      Drop privileges if we are SUID.
 */
   if ((setuid(getuid())) < 0) {
      err_sys("setuid");
   }
/*
 *	If we're not reading from a file, then we must have some hosts
 *	given as command line arguments.
 */
   if (!filename_flag)
      if ((argc - optind) < 1)
         usage(EXIT_FAILURE, 0);
/*
 *	Populate the list from the specified file if --file was specified, or
 *	otherwise from the remaining command line arguments.
 */
   if (filename_flag) {	/* Populate list from file */
      FILE *fp;
      char line[MAXLINE];
      char *cp;

      if ((strcmp(filename, "-")) == 0) {	/* Filename "-" means stdin */
         fp = stdin;
      } else {
         if ((fp = fopen(filename, "r")) == NULL) {
            err_sys("ERROR: fopen");
         }
      }

      while (fgets(line, MAXLINE, fp)) {
         for (cp = line; !isspace((unsigned char)*cp) && *cp != '\0'; cp++)
            ;
         *cp = '\0';
         add_host_pattern(line, timeout, &num_hosts,
                          cookie_data, cookie_data_len);
      }
      if (fp != stdin)
         fclose(fp);
   } else {		/* Populate list from command line arguments */
      argv = &argv[optind];
      while (*argv) {
         add_host_pattern(*argv, timeout, &num_hosts,
                          cookie_data, cookie_data_len);
         argv++;
      }
   }
/*
 *	If we are using TCP transport, then connect the socket to the peer.
 *	We know that there is only one entry in the host list if we're using
 *	TCP.
 */
   if (tcp_flag) {
      struct sockaddr_in sa_tcp;
      NET_SIZE_T sa_tcp_len;
      struct sigaction act, oact;  /* For sigaction */
/*
 *      Set signal handler for alarm.
 *      Must use sigaction() rather than signal() to prevent SA_RESTART
 */
      act.sa_handler=sig_alarm;
      sigemptyset(&act.sa_mask);
      act.sa_flags=0;
      sigaction(SIGALRM,&act,&oact);
/*
 *	Set alarm
 */
      alarm(tcp_connect_timeout);
/*
 *	Connect to peer
 */
      memset(&sa_tcp, '\0', sizeof(sa_tcp));
      sa_tcp.sin_family = AF_INET;
      sa_tcp.sin_addr.s_addr = helist->addr.s_addr;
      sa_tcp.sin_port = htons(dest_port);
      sa_tcp_len = sizeof(sa_tcp);
      if ((connect(sockfd, (struct sockaddr *) &sa_tcp, sa_tcp_len)) != 0) {
         if (errno == EINTR)
            errno = ETIMEDOUT;
         err_sys("ERROR: TCP connect");
      }
/*
 *	Cancel alarm
 */
      alarm(0);
   }
/*
 *	If we are displaying the backoff table, load known backoff
 *	patterns from the backoff patterns file.
 */
   if (showbackoff_flag) {
      load_backoff_patterns(patfile, pattern_fuzz);
   }
/*
 *	Load known Vendor ID patterns from the Vendor ID file.
 */
   load_vid_patterns(vidfile);
/*
 *	Check that we have at least one entry in the list.
 */
   if (!num_hosts)
      err_msg("ERROR: No hosts to process.");
/*
 *	If --writepkttofile was specified, open the specified output file.
 */
   if (pkt_filename_flag) {
      write_pkt_to_file = open(pkt_filename, O_WRONLY|O_CREAT|O_TRUNC, 0666);
      if (write_pkt_to_file == -1)
         err_sys("open %s", pkt_filename);
   }
/*
 *	If --readpktfromfile was specified, open the specified input file.
 */
   if (pkt_read_filename_flag) {
      read_pkt_from_file = open(pkt_filename, O_RDONLY);
      if (read_pkt_from_file == -1)
         err_sys("open %s", pkt_filename);
   }
/*
 *	Check that the combination of specified options and arguments is
 *	valid.
 */
   if (cookie_data && num_hosts > 1)
      err_msg("ERROR: You can only specify one target host with the --cookie option.");
   if (tcp_flag && num_hosts > 1)
      err_msg("ERROR: You can only specify one target host with the --tcp option.");
   if (*patfile != '\0' && !showbackoff_flag)
      warn_msg("WARNING: Specifying a backoff pattern file with --patterns or -p does not\n"
               "         have any effect unless you also specify --showbackoff or -o\n");
   if (ike_params.id_data && ike_params.exchange_type != ISAKMP_XCHG_AGGR)
      warn_msg("WARNING: Specifying an identification payload with --id or -n does not have\n"
               "         any effect unless you also specify aggressive mode with --aggressive\n"
               "         or -A\n");
   if (ike_params.idtype != DEFAULT_IDTYPE &&
       ike_params.exchange_type != ISAKMP_XCHG_AGGR)
      warn_msg("WARNING: Specifying an idtype payload with --idtype or -y does not have any\n"
               "         effect unless you also specify aggressive mode with --aggressive or -A\n");
   if (ike_params.nonce_data_len != DEFAULT_NONCE_LEN &&
       ike_params.exchange_type != ISAKMP_XCHG_AGGR &&
       ike_params.ike_version == 1)
      warn_msg("WARNING: Specifying the nonce payload length with --noncelen or -c does not\n"
               "         have any effect unless you also specify aggressive mode with\n"
               "         --aggressive or -A, or IKEv2 with --ikev2 or -2\n");
   if (ike_params.dhgroup != DEFAULT_DH_GROUP &&
       ike_params.exchange_type != ISAKMP_XCHG_AGGR &&
       ike_params.ike_version == 1)
      warn_msg("WARNING: Specifying the DH Group with --dhgroup or -g does not have any effect\n"
               "         unless you also specify aggressive mode with --aggressive or -A, or\n"
               "         IKEv2 with --ikev2 or -2\n");
   if (psk_crack_flag && ike_params.exchange_type != ISAKMP_XCHG_AGGR) {
      warn_msg("WARNING: The --pskcrack (-P) option is only relevant for aggressive mode.\n");
      psk_crack_flag=0;
   }
   if (psk_crack_flag && num_hosts > 1)
      err_msg("ERROR: You can only specify one target host with the --pskcrack (-P) option.");
   if (interval && bandwidth != DEFAULT_BANDWIDTH)
      err_msg("ERROR: You cannot specify both --bandwidth and --interval.");
   if (ike_params.trans_flag != 0 && ike_params.ike_version == 2)
      warn_msg("WARNING: IKEv2 does not support custom proposals.");
   if (ike_params.ike_version == 2 &&
       ike_params.exchange_type == ISAKMP_XCHG_AGGR)
      err_msg("ERROR: You can not specify both aggressive mode and IKEv2.\n"
              "       Aggressive mode is only applicable to IKEv1.");
/*
 *      Create and initialise array of pointers to host entries.
 */
   helistptr = Malloc(num_hosts * sizeof(host_entry *));
   for (hostno=0; hostno<num_hosts; hostno++)
      helistptr[hostno] = &helist[hostno];
/*
 *      Randomise the list if required.
 *	Uses Knuth's shuffle algorithm.
 */
   if (random_flag) {
      int i;
      int r;
      host_entry *temp;

      for (i=num_hosts-1; i>0; i--) {
         r = (int)(genrand_real2() * i);  /* 0<=r<i */
         temp = helistptr[i];
         helistptr[i] = helistptr[r];
         helistptr[r] = temp;
      }
   }
/*
 *	Set current host pointer (cursor) to start of list, zero
 *	last packet sent time, set last receive time to now and
 *	initialise static IKE header fields.
 */
   live_count = num_hosts;
   cursor = helistptr;
   last_packet_time.tv_sec=0;
   last_packet_time.tv_usec=0;
   Gettimeofday(&last_recv_time);
   packet_out=initialise_ike_packet(&packet_out_len, &ike_params);
/*
 *	Calculate the appropriate interval to achieve the required outgoing
 *	bandwidth unless an interval was specified.
 */
   if (!interval) {
      interval = ((IKE_UINT64)(packet_out_len+PACKET_OVERHEAD) * 8 * 1000000) /
                 bandwidth;
      if (verbose) {
         warn_msg("DEBUG: pkt len=%zu bytes, bandwidth=%u bps, int=%u us",
                  packet_out_len, bandwidth, interval);
      }
   }
/*
 *	Display initial message.
 */
   printf("Starting %s with %u hosts (http://www.nta-monitor.com/tools/ike-scan/)\n", PACKAGE_STRING, num_hosts);
/*
 *	Display the lists if verbose setting is 3 or more.
 */
   if (verbose > 2) {
      dump_list(num_hosts);
      if (showbackoff_flag)
         dump_backoff(pattern_fuzz);
      dump_vid();
   }
/*
 *	Main loop: send packets to all hosts in order until a response
 *	has been received or the host has exhausted its retry limit.
 *
 *	The loop exits when all hosts have either responded or timed out
 *	and, if showbackoff_flag is set, at least end_wait ms have elapsed
 *	since the last packet was received and we have received at least one
 *	transform response.
 */
   reset_cum_err = 1;
   req_interval = interval;
   while (live_count ||
          (showbackoff_flag && sa_responders && (end_timediff < end_wait))) {
/*
 *	Obtain current time and calculate deltas since last packet and
 *	last packet to this host.
 */
      Gettimeofday(&now);
      timeval_diff(&now, &last_recv_time, &diff);
      end_timediff = 1000*diff.tv_sec + diff.tv_usec/1000;
/*
 *	If the last packet was sent more than interval us ago, then we can
 *	potentially send a packet to the current host.
 */
      timeval_diff(&now, &last_packet_time, &diff);
      loop_timediff = (IKE_UINT64)1000000*diff.tv_sec + diff.tv_usec;
      if (loop_timediff >= (unsigned)req_interval) {
/*
 *	If the last packet to this host was sent more than the current
 *	timeout for this host us ago, then we can potentially send a packet
 *	to it.
 */
         timeval_diff(&now, &((*cursor)->last_send_time), &diff);
         host_timediff = (IKE_UINT64)1000000*diff.tv_sec + diff.tv_usec;
         if (host_timediff >= (*cursor)->timeout && (*cursor)->live) {
            if (reset_cum_err) {
               cum_err = 0;
               req_interval = interval;
               reset_cum_err = 0;
            } else {
               cum_err += loop_timediff - interval;
               if (req_interval > cum_err) {
                  req_interval = req_interval - cum_err;
               } else {
                  req_interval = 0;
               }
            }
            select_timeout = req_interval;
/*
 *	If we've exceeded our retry limit, then this host has timed out so
 *	remove it from the list.  Otherwise, increase the timeout by the
 *	backoff factor if this is not the first packet sent to this host
 *	and send a packet.
 */

/* This message only works if the list is not empty */
            if (verbose && (*cursor)->num_sent > pass_no)
               warn_msg("---\tPass %d of %u completed", ++pass_no, retry);
            if ((*cursor)->num_sent >= retry) {
               if (verbose > 1)
                  warn_msg("---\tRemoving host entry %u (%s) - Timeout", (*cursor)->n, inet_ntoa((*cursor)->addr));
               remove_host(cursor, &live_count, num_hosts);	/* Automatically calls advance_cursor() */
               if (first_timeout) {
                  timeval_diff(&now, &((*cursor)->last_send_time), &diff);
                  host_timediff = (IKE_UINT64)1000000*diff.tv_sec +
                                  diff.tv_usec;
                  while (host_timediff >= (*cursor)->timeout && live_count) {
                     if ((*cursor)->live) {
                        if (verbose > 1)
                           warn_msg("---\tRemoving host %u (%s) - Timeout",
                                    (*cursor)->n, inet_ntoa((*cursor)->addr));
                        remove_host(cursor, &live_count, num_hosts);
                     } else {
                        advance_cursor(live_count, num_hosts);
                     }
                     timeval_diff(&now, &((*cursor)->last_send_time), &diff);
                     host_timediff = (IKE_UINT64)1000000*diff.tv_sec +
                                     diff.tv_usec;
                  }
                  first_timeout=0;
               }
               Gettimeofday(&last_packet_time);
            } else {	/* Retry limit not reached for this host */
               if ((*cursor)->num_sent)
                  (*cursor)->timeout *= backoff_factor;
               send_packet(sockfd, packet_out, packet_out_len, *cursor,
                           source_port, dest_port, &last_packet_time);
               advance_cursor(live_count, num_hosts);
            }
         } else {	/* We can't send a packet to this host yet */
/*
 *	Note that there is no point calling advance_cursor() here because if
 *	host n is not ready to send, then host n+1 will not be ready either.
 */
            if (live_count)
               select_timeout = (*cursor)->timeout - host_timediff;
            else
               select_timeout = interval;
            reset_cum_err = 1;	/* Zero cumulative error */
         } /* End If */
      } else {		/* We can't send a packet yet */
         select_timeout = req_interval - loop_timediff;
      } /* End If */
#ifdef DEBUG_TIMINGS
      printf("int=%d, loop_t=%llu, req_int=%d, sel=%d, cum_err=%d\n",
             interval, loop_timediff, req_interval, select_timeout, cum_err);
#endif
      n=recvfrom_wto(sockfd, packet_in, MAXUDP, (struct sockaddr *)&sa_peer,
                     select_timeout);
      if (n != -1) {
/*
 *	We've received a response try to match up the packet by cookie
 *
 *	Note: We start at cursor->prev because we call advance_cursor() after
 *	      each send_packet().
 */
         temp_cursor=find_host_by_cookie(cursor, packet_in, n, num_hosts);
         if (temp_cursor) {
/*
 *	We found a cookie match for the returned packet.
 */
            add_recv_time(temp_cursor, &last_recv_time);
            if (verbose > 1)
               warn_msg("---\tReceived packet #%u from %s",temp_cursor->num_recv ,inet_ntoa(sa_peer.sin_addr));
            if (temp_cursor->live) {
               display_packet(n, packet_in, temp_cursor, &(sa_peer.sin_addr),
                              &sa_responders, &notify_responders, quiet,
                              multiline);
               if (verbose > 1)
                  warn_msg("---\tRemoving host entry %u (%s) - Received %d bytes", temp_cursor->n, inet_ntoa(sa_peer.sin_addr), n);
               remove_host(&temp_cursor, &live_count, num_hosts);
            }
         } else {
            struct isakmp_hdr hdr_in;
/*
 *	The received cookie doesn't match any entry in the list.
 *	Issue a message to that effect if verbose is on and ignore the packet.
 */
            if (verbose && (unsigned)n >= sizeof(hdr_in)) {
               char *cp;
               memcpy(&hdr_in, packet_in, sizeof(hdr_in));
               cp = hexstring((unsigned char *)hdr_in.isa_icookie,
                              sizeof(hdr_in.isa_icookie));
               warn_msg("---\tIgnoring %d bytes from %s with unknown cookie %s",
                        n, inet_ntoa(sa_peer.sin_addr), cp);
               free(cp);
            }
         }
      } /* End If */
   } /* End While */
   close(sockfd);
   if (write_pkt_to_file)
      close(write_pkt_to_file);
   if (read_pkt_from_file)
      close(read_pkt_from_file);
/*
 *	Display the backoff times if --showbackoff option was specified
 *	and we have at least one system returning a handshake.
 */
   printf("\n");	/* Ensure we have a blank line */
   if (showbackoff_flag && sa_responders) {
      dump_times(num_hosts);
   }
/*
 *	Display PSK crack values if applicable
 */
   if (psk_crack_flag && psk_values.hash_r != NULL) {
      print_psk_crack_values(psk_crack_file);
   }
/*
 *	Get program end time and calculate elapsed time.
 */
   Gettimeofday(&end_time);
   timeval_diff(&end_time, &start_time, &elapsed_time);
   elapsed_seconds = (elapsed_time.tv_sec*1000 +
                      elapsed_time.tv_usec/1000.0) / 1000.0;

   printf("Ending %s: %u hosts scanned in %.3f seconds (%.2f hosts/sec).  %u returned handshake; %u returned notify\n",
          PACKAGE_STRING, num_hosts, elapsed_seconds,
          num_hosts/elapsed_seconds,sa_responders, notify_responders);

   return 0;
}

/*
 *	add_host_pattern -- Add one or more new host to the list.
 *
 *	Inputs:
 *
 *	pattern	= The host pattern to add.
 *	timeout	= Per-host timeout in ms.
 *	num_hosts = The number of entries in the host list.
 *	cookie_data = Data for static cookie value, or NULL
 *	cookie_data_len = Length of cookie_data value;
 *
 *	Returns: None
 *
 *	This adds one or more new hosts to the list.  The pattern argument
 *	can either be a single host or IP address, in which case one host
 *	will be added to the list, or it can specify a number of hosts with
 *	the IPnet/bits, IPnet:mask or IPstart-IPend formats.
 *
 *	The timeout, num_hosts, cookie_data and cookie_data_len arguments
 *	are passed unchanged to add_host().
 */
void
add_host_pattern(const char *pattern, unsigned timeout, unsigned *num_hosts,
                 unsigned char *cookie_data, size_t cookie_data_len) {
   char *patcopy;
   struct in_addr in_val;
   struct in_addr mask_val;
   unsigned numbits;
   char *cp;
   uint32_t ipnet_val;
   uint32_t network;
   uint32_t mask;
   unsigned long hoststart;
   unsigned long hostend;
   unsigned i;
   uint32_t x;
   static int first_call=1;
   static regex_t iprange_pat;
   static regex_t ipslash_pat;
   static regex_t ipmask_pat;
   static const char *iprange_pat_str =
      "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+-[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+";
   static const char *ipslash_pat_str =
      "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+";
   static const char *ipmask_pat_str =
      "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+";
/*
 *	Compile regex patterns if this is the first time we've been called.
 */
   if (first_call) {
      int result;

      first_call = 0;
      if ((result=regcomp(&iprange_pat, iprange_pat_str,
                          REG_EXTENDED|REG_NOSUB))) {
         char errbuf[MAXLINE];
         regerror(result, &iprange_pat, errbuf, MAXLINE);
         err_msg("ERROR: cannot compile regex pattern \"%s\": %s",
                 iprange_pat_str, errbuf);
      }
      if ((result=regcomp(&ipslash_pat, ipslash_pat_str,
                          REG_EXTENDED|REG_NOSUB))) {
         char errbuf[MAXLINE];
         regerror(result, &ipslash_pat, errbuf, MAXLINE);
         err_msg("ERROR: cannot compile regex pattern \"%s\": %s",
                 ipslash_pat_str, errbuf);
      }
      if ((result=regcomp(&ipmask_pat, ipmask_pat_str,
                          REG_EXTENDED|REG_NOSUB))) {
         char errbuf[MAXLINE];
         regerror(result, &ipmask_pat, errbuf, MAXLINE);
         err_msg("ERROR: cannot compile regex pattern \"%s\": %s",
                 ipmask_pat_str, errbuf);
      }
   }
/*
 *	Make a copy of pattern because we don't want to modify our argument.
 */
   patcopy = dupstr(pattern);

   if (!(regexec(&ipslash_pat, patcopy, 0, NULL, 0))) { /* IPnet/bits */
/*
 *	Get IPnet and bits as integers. Perform basic error checking.
 */
      cp=strchr(patcopy, '/');
      *(cp++)='\0';	/* patcopy points to IPnet, cp points to bits */
      if (!(inet_aton(patcopy, &in_val)))
         err_msg("ERROR: %s is not a valid IP address", patcopy);
      ipnet_val=ntohl(in_val.s_addr);	/* We need host byte order */
      numbits=Strtoul(cp, 10);
      if (numbits<3 || numbits>32)
         err_msg("ERROR: Number of bits in %s must be between 3 and 32",
                 pattern);
/*
 *	Construct 32-bit network bitmask from number of bits.
 */
      mask=0;
      for (i=0; i<numbits; i++)
         mask += 1 << i;
      mask = mask << (32-i);
/*
 *	Mask off the network. Warn if the host bits were non-zero.
 */
      network=ipnet_val & mask;
      if (network != ipnet_val)
         warn_msg("WARNING: host part of %s is non-zero", pattern);
/*
 *	Determine maximum and minimum host values. We include the host
 *	and broadcast.
 */
      hoststart=0;
      hostend=(1<<(32-numbits))-1;
/*
 *	Calculate all host addresses in the range and feed to add_host()
 *	in dotted-quad format.
 */
      for (i=hoststart; i<=hostend; i++) {
         uint32_t hostip;
         int b1, b2, b3, b4;
         char ipstr[16];

         hostip = network+i;
         b1 = (hostip & 0xff000000) >> 24;
         b2 = (hostip & 0x00ff0000) >> 16;
         b3 = (hostip & 0x0000ff00) >> 8;
         b4 = (hostip & 0x000000ff);
         snprintf(ipstr, sizeof(ipstr), "%d.%d.%d.%d", b1,b2,b3,b4);
         add_host(ipstr, timeout, num_hosts, cookie_data, cookie_data_len, 1);
      }
   } else if (!(regexec(&ipmask_pat, patcopy, 0, NULL, 0))) { /* IPnet:netmask */
/*
 *	Get IPnet and bits as integers. Perform basic error checking.
 */
      cp=strchr(patcopy, ':');
      *(cp++)='\0';	/* patcopy points to IPnet, cp points to netmask */
      if (!(inet_aton(patcopy, &in_val)))
         err_msg("ERROR: %s is not a valid IP address", patcopy);
      ipnet_val=ntohl(in_val.s_addr);	/* We need host byte order */
      if (!(inet_aton(cp, &mask_val)))
         err_msg("ERROR: %s is not a valid netmask", patcopy);
      mask=ntohl(mask_val.s_addr);	/* We need host byte order */
/*
 *	Calculate the number of bits in the network.
 */
      x = mask;
      for (numbits=0; x != 0; x>>=1) {
         if (x & 0x01) {
            numbits++;
         }
      }
/*
 *	Mask off the network. Warn if the host bits were non-zero.
 */
      network=ipnet_val & mask;
      if (network != ipnet_val)
         warn_msg("WARNING: host part of %s is non-zero", pattern);
/*
 *	Determine maximum and minimum host values. We include the host
 *	and broadcast.
 */
      hoststart=0;
      hostend=(1<<(32-numbits))-1;
/*
 *	Calculate all host addresses in the range and feed to add_host()
 *	in dotted-quad format.
 */
      for (i=hoststart; i<=hostend; i++) {
         uint32_t hostip;
         int b1, b2, b3, b4;
         char ipstr[16];

         hostip = network+i;
         b1 = (hostip & 0xff000000) >> 24;
         b2 = (hostip & 0x00ff0000) >> 16;
         b3 = (hostip & 0x0000ff00) >> 8;
         b4 = (hostip & 0x000000ff);
         snprintf(ipstr, sizeof(ipstr), "%d.%d.%d.%d", b1,b2,b3,b4);
         add_host(ipstr, timeout, num_hosts, cookie_data, cookie_data_len, 1);
      }
   } else if (!(regexec(&iprange_pat, patcopy, 0, NULL, 0))) { /* IPstart-IPend */
/*
 *	Get IPstart and IPend as integers.
 */
      cp=strchr(patcopy, '-');
      *(cp++)='\0';	/* patcopy points to IPstart, cp points to IPend */
      if (!(inet_aton(patcopy, &in_val)))
         err_msg("ERROR: %s is not a valid IP address", patcopy);
      hoststart=ntohl(in_val.s_addr);	/* We need host byte order */
      if (!(inet_aton(cp, &in_val)))
         err_msg("ERROR: %s is not a valid IP address", cp);
      hostend=ntohl(in_val.s_addr);	/* We need host byte order */
/*
 *	Calculate all host addresses in the range and feed to add_host()
 *	in dotted-quad format.
 */
      for (i=hoststart; i<=hostend; i++) {
         int b1, b2, b3, b4;
         char ipstr[16];

         b1 = (i & 0xff000000) >> 24;
         b2 = (i & 0x00ff0000) >> 16;
         b3 = (i & 0x0000ff00) >> 8;
         b4 = (i & 0x000000ff);
         snprintf(ipstr, sizeof(ipstr), "%d.%d.%d.%d", b1,b2,b3,b4);
         add_host(ipstr, timeout, num_hosts, cookie_data, cookie_data_len, 1);
      }
   } else {	/* Single host or IP address */
      add_host(patcopy, timeout, num_hosts, cookie_data, cookie_data_len,
               no_dns_flag);
   }
   free(patcopy);
}

/*
 *	add_host -- Add a new host to the list.
 *
 *	Inputs:
 *
 *	name	= The Name or IP address of the host.
 *	timeout	= Per-host timeout in ms.
 *	num_hosts = The number of entries in the host list.
 *	cookie_data = Data for static cookie value, or NULL
 *	cookie_data_len = Length of cookie_data value;
 *
 *	Returns: None
 */
void
add_host(const char *name, unsigned timeout, unsigned *num_hosts,
         unsigned char *cookie_data, size_t cookie_data_len,
         int numeric_only) {
   struct hostent *hp = NULL;
   host_entry *he;
   struct in_addr inp;
   char str[MAXLINE];
   struct timeval now;
   static int num_left=0;       /* Number of free entries left */

   if (numeric_only) {
      if (!(inet_aton(name, &inp))) {
         warn_msg("WARNING: inet_aton failed for \"%s\" - target ignored",
                  name);
         return;
      }
   } else {
      if ((hp = gethostbyname(name)) == NULL) {
         warn_sys("WARNING: gethostbyname failed for \"%s\" - target ignored",
                  name);
         return;
      }
   }

   if (!num_left) {     /* No entries left, allocate some more */
      if (helist)
         helist=Realloc(helist, ((*num_hosts) * sizeof(host_entry)) +
                        REALLOC_COUNT*sizeof(host_entry));
      else
         helist=Malloc(REALLOC_COUNT*sizeof(host_entry));
      num_left = REALLOC_COUNT;
   }

   he = helist + (*num_hosts);	/* Would array notation be better? */

   (*num_hosts)++;
   num_left--;

   Gettimeofday(&now);

   he->n = *num_hosts;
   if (no_dns_flag || numeric_only)
      memcpy(&(he->addr), &inp, sizeof(struct in_addr));
   else
      memcpy(&(he->addr), hp->h_addr_list[0], sizeof(struct in_addr));
   he->live = 1;
   he->timeout = timeout * 1000;	/* Convert from ms to us */
   he->num_sent = 0;
   he->num_recv = 0;
   he->last_send_time.tv_sec=0;
   he->last_send_time.tv_usec=0;
   he->recv_times = NULL;
   he->extra = NULL;

   if (cookie_data) {
      memset(he->icookie, '\0', sizeof(he->icookie));
      memcpy(he->icookie, cookie_data, cookie_data_len);
   } else {
/*
 * We cast the timeval elements to unsigned long because different vendors
 * use different types for them (int, long, unsigned int and unsigned long).
 * As long is the widest type, and the values should always be positive, it's
 * safe to cast to unsigned long.
 */
      snprintf(str, sizeof(str), "%lu %lu %u %s", (unsigned long) now.tv_sec,
              (unsigned long) now.tv_usec, *num_hosts, inet_ntoa(he->addr));
      memcpy(he->icookie, MD5((unsigned char *)str, strlen(str), NULL),
             sizeof(he->icookie));
   }
}

/*
 * 	remove_host -- Remove the specified host from the list
 *
 *	Inputs:
 *
 *	he		Pointer to host entry to remove.
 *	live_count	Number of hosts awaiting response.
 *	num_hosts	The number of hosts in the list.
 *
 *	Returns:
 *
 *	None.
 *
 *	If the host being removed is the one pointed to by the cursor, this
 *	function updates cursor so that it points to the next entry.
 */
void
remove_host(host_entry **he, unsigned *live_count, unsigned num_hosts) {
   (*he)->live = 0;
   (*live_count)--;
   if (*he == *cursor)
      advance_cursor(*live_count, num_hosts);
}

/*
 *	advance_cursor -- Advance the cursor to point at next live entry
 *
 *	Inputs:
 *
 *	live_count	Number of hosts awaiting reply.
 *	num_hosts	The number of hosts in the list.
 *
 *	Returns:
 *
 *	None.
 *
 *	Does nothing if there are no live entries in the list.
 */
void
advance_cursor(unsigned live_count, unsigned num_hosts) {
   if (live_count) {
      do {
         if (cursor == (helistptr+(num_hosts-1)))
            cursor = helistptr; /* Wrap round to beginning */
         else
            cursor++;
      } while (!(*cursor)->live);
   } /* End If */
}

/*
 *	find_host_by_cookie	-- Find a host in the list by cookie
 *
 *	Inputs:
 *
 *	he 		Pointer to current position in list.  Search runs
 *			backwards starting from this point.
 *
 *	packet_in	points to the received packet containing the cookie.
 *
 *	n 		Size of the received packet in bytes.
 *	num_hosts	The number of hosts in the list.
 *
 *	Returns a pointer to the host entry associated with the specified IP
 *	or NULL if no match found.
 */
host_entry *
find_host_by_cookie(host_entry **he, unsigned char *packet_in, int n,
                    unsigned num_hosts) {
   host_entry **p;
   int found = 0;
   struct isakmp_hdr hdr_in;
/*
 *	Check that the current list position is not null.  Return NULL if it
 *	is.  It's possible for "he" to be NULL if a packet is received just
 *	after the last entry in the list is removed.
 */
   if (*he == NULL)
      return NULL;
/*
 *	Check that the received packet is at least as big as the ISAKMP
 *	header.  Return NULL if not.
 */
   if ((unsigned)n < sizeof(hdr_in))
      return NULL;
/*
 *	Copy packet into ISAKMP header structure.
 */
   memcpy(&hdr_in, packet_in, sizeof(hdr_in));

   p = he;

   do {
      if ((*p)->icookie[0] == hdr_in.isa_icookie[0] &&
          (*p)->icookie[1] == hdr_in.isa_icookie[1]) {
         found = 1;
      } else {
         if (p == helistptr) {
            p = helistptr + (num_hosts-1);      /* Wrap round to end */
         } else {
            p--;
         }
      }
   } while (!found && p != he);

   if (found) {
      return *p;
   } else {
      return NULL;
   }
}

/*
 *	display_packet -- Display received IKE packet
 *
 *	Inputs:
 *	
 *	n               The length of the received packet in bytes
 *	packet_in       The received packet
 *	he              The host entry corresponding to the received packet
 *	recv_addr       IP address that the packet was received from
 *	sa_responders	Number of hosts responding with SA
 *	notify_responders	Number of hosts responding with NOTIFY
 *	quiet		Only display basic info if nonzero
 *	multiline	Split decodes across lines if nonzero
 *	
 *	Returns:
 *	
 *	None.
 *	
 *	This should check the received packet and display details of what
 *	was received in the format: <IP-Address><TAB><Details>.
 */
void
display_packet(int n, unsigned char *packet_in, host_entry *he,
               struct in_addr *recv_addr, unsigned *sa_responders,
               unsigned *notify_responders, int quiet, int multiline) {
   char *cp;			/* Temp pointer */
   size_t bytes_left;		/* Remaining buffer size */
   unsigned next;		/* Next Payload */
   unsigned type;		/* Exchange Type */
   char *msg;			/* Message to display */
   char *msg2;
   unsigned char *pkt_ptr;
   char *hdr_descr;		/* ISAKMP header description */
/*
 *	Set message to the empty string.
 */
   msg = make_message("");
/*
 *	Display the packet number if required.
 */
   if (shownum_flag) {
      cp = msg;
      msg = make_message("%s%u ", cp, he->n);
      free(cp);
   }
/*
 *	Display the time when this packet was received if required.
 */
   if (timestamp_flag) {
      struct tm *time_tm;
      struct timeval time_tv;
      time_t clock_seconds;

      Gettimeofday(&time_tv);
      clock_seconds = time_tv.tv_sec;
      time_tm = localtime(&clock_seconds);
      cp = msg;
      msg = make_message("%s%02d:%02d:%02d.%06ld ", cp,
                         time_tm->tm_hour, time_tm->tm_min, time_tm->tm_sec,
                         time_tv.tv_usec);
      free(cp);
   }
/*
 *	Set msg to the IP address of the host entry, plus the address of the
 *	responder if different, and a tab.
 */
   cp = msg;
   msg = make_message("%s%s\t", cp, inet_ntoa(he->addr));
   free(cp);
   if (((he->addr).s_addr != recv_addr->s_addr) && !tcp_flag) {
      cp = msg;
      msg = make_message("%s(%s) ", cp, inet_ntoa(*recv_addr));
      free(cp);
   }
/*
 *	Process ISAKMP header.
 *	If this returns zero length left, indicating some sort of problem, then
 *	we report a short or malformed packet and return.
 *	If the processing is successful, pkt_ptr points to the next payload.
 */
   bytes_left = n;	/* Set remaining length to total packet len */
   if (psk_crack_flag)
      add_psk_crack_payload(packet_in, 0, 'X');
   pkt_ptr = process_isakmp_hdr(packet_in, &bytes_left, &next, &type,
                                &hdr_descr);
   if (!bytes_left) {
      printf("%sShort or malformed ISAKMP packet returned: %d bytes\n",
             msg, n);
      free(msg);
      return;
   }
/*
 *	Determine the overall type of the packet from the first payload type.
 *	We assume that pkt_ptr is suitably aligned because the ISAKMP header
 *	has a fixed length that is divisible by 4.
 */
   switch (next) {
      case ISAKMP_NEXT_SA:	/* SA */
         if (psk_crack_flag)
            add_psk_crack_payload(pkt_ptr, next, 'R');
         (*sa_responders)++;
         cp = process_sa(pkt_ptr, bytes_left, type, quiet, multiline,
                         hdr_descr);
         break;
      case ISAKMP_NEXT_V2_SA:	/* IKEv2 SA */
         (*sa_responders)++;
         cp = process_sa2(pkt_ptr, bytes_left, type, quiet, multiline,
                          hdr_descr);
         break;
      case ISAKMP_NEXT_N:	/* Notify */
         (*notify_responders)++;
         cp = process_notify(pkt_ptr, bytes_left, quiet, multiline,
                             hdr_descr);
         break;
      case ISAKMP_NEXT_V2_N:	/* IKEv2 Notify */
         (*notify_responders)++;
         cp = process_notify2(pkt_ptr, bytes_left, quiet, multiline,
                              hdr_descr);
         break;
      default:			/* Something else */
         cp=make_message("Unexpected IKE payload returned: %s",
                         id_to_name(next, payload_map));
         break;
   }
   free(hdr_descr);	/* Don't need the ISAKMP header descr string now */
   pkt_ptr = skip_payload(pkt_ptr, &bytes_left, &next);
   msg2=msg;
   msg=make_message("%s%s", msg, cp);
   free(msg2);	/* Free old message (IP address) */
   free(cp);	/* Free 1st payload message */
/*
 *	Process any other interesting payloads if quiet is not in effect.
 */
   if (!quiet) {
      unsigned char *payload_ptr;

      while (bytes_left) {
         payload_ptr = clone_payload(pkt_ptr, bytes_left);
         msg2=msg;
         switch (next) {
            case ISAKMP_NEXT_VID:	/* Vendor ID */
            case ISAKMP_NEXT_V2_VID:	/* IKEv2 Vendor ID */
               cp = process_vid(payload_ptr, bytes_left, vidlist);
               break;
            case ISAKMP_NEXT_ID:	/* ID */
               if (psk_crack_flag)
                  add_psk_crack_payload(payload_ptr, next, 'R');
               cp = process_id(payload_ptr, bytes_left);
               break;
            case ISAKMP_NEXT_CERT:	/* Certificate */
            case ISAKMP_NEXT_CR:	/* Certificate Request */
               cp = process_cert(payload_ptr, bytes_left, next);
               break;
            case ISAKMP_NEXT_D:		/* Delete */
               cp = process_delete(payload_ptr, bytes_left);
               break;
            case ISAKMP_NEXT_N:		/* Notification */
               cp = process_notification(payload_ptr, bytes_left);
               break;
            default:			/* Something else */
               if (psk_crack_flag)
                  add_psk_crack_payload(payload_ptr, next, 'R');
               cp = process_generic(payload_ptr, bytes_left, next);
               break;
         } /* End Switch */
         free(payload_ptr);
         msg=make_message("%s%s%s", msg2, multiline?"\n\t":" ", cp);
         free(msg2);	/* Free old message */
         free(cp);	/* Free payload message */
         pkt_ptr = skip_payload(pkt_ptr, &bytes_left, &next);
      } /* End While */
   } /* End if (!quiet) */
/*
 *	Print the message.
 */
   printf("%s\n", msg);
   free(msg);
}

/*
 *	send_packet -- Construct and send a packet to the specified host
 *	
 *	Inputs:
 *	
 *	s               network socket file descriptor
 *	packet_out	IKE packet to send
 *	packet_out_len	Length of IKE packet to send
 *	he              Host entry to send to
 *	source_port     Source UDP port
 *	dest_port       Destination UDP port
 *	last_packet_time        Time when last packet was sent
 *	
 *	Returns:
 *	
 *	None.
 *	
 *	This must construct an appropriate packet and send it to the host
 *	identified by "he" and UDP port "dest_port" using the socket "s".
 *	It must also update the "last_send_time" field for this host entry.
 */
void
send_packet(int s, unsigned char *packet_out, size_t packet_out_len,
            host_entry *he, unsigned source_port, unsigned dest_port,
            struct timeval *last_packet_time) {
   struct sockaddr_in sa_peer;
   NET_SIZE_T sa_peer_len;
   int nsent;
   struct isakmp_hdr *hdr = (struct isakmp_hdr *) packet_out;
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
   hdr->isa_icookie[0] = he->icookie[0];
   hdr->isa_icookie[1] = he->icookie[1];
/*
 *	Update the last send times for this host.
 */
   Gettimeofday(last_packet_time);
   he->last_send_time.tv_sec  = last_packet_time->tv_sec;
   he->last_send_time.tv_usec = last_packet_time->tv_usec;
   he->num_sent++;
/*
 *	Cisco TCP encapsulation.
 */
   if (tcp_flag == TCP_PROTO_ENCAP) {
      unsigned char *orig_packet_out = packet_out;
      unsigned char *udphdr;
      size_t udphdr_len;
      unsigned char *cp;

/* The two bits of extra data below were observed using Cisco VPN Client */
      unsigned char udpextra[16] = {	/* extra data covered by UDP */
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
      };
      unsigned char tcpextra[16] = {	/* extra data covered by TCP */
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x21,0x45,0x6c,0x69,0x10,0x11,0x01,0x00
      };

      packet_out=Malloc(packet_out_len+40);	/* 8 for udphdr + 32 extra */
      cp = packet_out;

      udphdr = make_udphdr(&udphdr_len, source_port, dest_port,
                           packet_out_len+8+16);
      memcpy(cp, udphdr, udphdr_len);
      cp += udphdr_len;

      memcpy(cp, orig_packet_out, packet_out_len);
      cp += packet_out_len;

      memcpy(cp, udpextra, 16);
      cp += 16;

      memcpy(cp, tcpextra, 16);
      cp += 16;

      packet_out_len += 40;
   }
/*
 *	Spoof source address
 */
   if (sourceip_flag != 0) {
      unsigned char *orig_packet_out = packet_out;
      size_t orig_packet_out_len = packet_out_len;
      struct iphdr *iph;
      struct udphdr *udph;
      struct pseudo_hdr *pseudo;
      uint32_t source_address_host;
      uint32_t source_address;

      if (randsrc_flag) {	/* Random source IP */
         source_address_host = random_ip();
         source_address = htonl(source_address_host);
      } else {			/* Specified source IP */
         source_address = src_ip_val;
      }
      packet_out=Malloc(sizeof(struct iphdr) + sizeof(struct udphdr) +
                        packet_out_len);
      iph = (struct iphdr *) packet_out;
      udph = (struct udphdr *) (packet_out + sizeof(struct iphdr));
      pseudo = (struct pseudo_hdr *) (packet_out + sizeof(struct iphdr) -
                                      sizeof(struct pseudo_hdr));
/*
 *	Copy the data to the new buffer, leaving space for the IP and
 *	UDP headers.
 */
      memcpy(packet_out + sizeof(struct iphdr) + sizeof(struct udphdr),
             orig_packet_out, packet_out_len);
      packet_out_len += sizeof(struct iphdr) + sizeof(struct udphdr);
/*
 *      Construct the pseudo header (for UDP checksum purposes).
 *      Note that this overlaps the IP header and gets overwritten later.
 */
      memset(pseudo, '\0', sizeof(struct pseudo_hdr));
      pseudo->src_addr = source_address;
      pseudo->dst_addr = he->addr.s_addr;
      pseudo->proto    = 17;	/* UDP */
      pseudo->length   = htons(sizeof(struct udphdr) + orig_packet_out_len);
/*
 *      Construct the UDP header.
 */
      memset(udph, '\0', sizeof(struct udphdr));
      udph->source = htons(source_port);
      udph->dest = htons(dest_port);
      udph->len = htons(sizeof(struct udphdr) + orig_packet_out_len);
      udph->check = in_cksum((uint16_t *)pseudo, sizeof(struct pseudo_hdr) +
                             sizeof(struct udphdr) + orig_packet_out_len);
/*
 *      Construct the IP Header.
 *      This overwrites the now unneeded pseudo header.
 */
      memset(iph, '\0', sizeof(struct iphdr));
      iph->ihl = 5;        /* 5 * 32-bit longwords = 20 bytes */
      iph->version = 4;
      iph->tos = 0;
      iph->tot_len = packet_out_len;
      iph->id = 0;         /* Linux kernel fills this in */
      iph->frag_off = htons(0x0);
      iph->ttl = 128;
      iph->protocol = 17;	/* UDP */
      iph->check = 0;      /* Linux kernel fills this in */
      iph->saddr = source_address;
      iph->daddr = he->addr.s_addr;
   }
/*
 *	NAT Traversal
 */
   if (nat_t_flag) {
      unsigned char *orig_packet_out = packet_out;
      unsigned char *cp;

      packet_out=Malloc(packet_out_len+4);	/* 4 extra for non esp marker */
      cp = packet_out;
      memset(cp, '\0', 4);
      cp += 4;
      memcpy(cp, orig_packet_out, packet_out_len);
      packet_out_len += 4;
   }
/*
 *	Send the packet.
 */
   if (verbose > 1)
      warn_msg("---\tSending packet #%u to host entry %u (%s) tmo %d us",
               he->num_sent, he->n, inet_ntoa(he->addr), he->timeout);
   if (write_pkt_to_file) {
      nsent = write(write_pkt_to_file, packet_out, packet_out_len);
   } else {
      nsent = sendto(s, packet_out, packet_out_len, 0,
                     (struct sockaddr *) &sa_peer, sa_peer_len);
   }
   if (nsent < 0) {
      err_sys("ERROR: sendto");
   } else if ((unsigned)nsent != packet_out_len) {
      warn_msg("WARNING: sendto: only %d bytes sent, but %zu requested",
               nsent, packet_out_len);
   }
/*
 *	Free locally allocated memory if required
 */
   if (tcp_flag == TCP_PROTO_ENCAP || sourceip_flag != 0 || nat_t_flag) {
      free(packet_out);
   }
}

/*
 *	recvfrom_wto -- Receive packet with timeout
 *
 *      Inputs:
 *
 *      s       = Socket file descriptor.
 *      buf     = Buffer to receive data read from socket.
 *      len     = Size of buffer.
 *      saddr   = Socket structure.
 *      tmo     = Select timeout in us.
 *
 *	Returns number of characters received, or -1 for timeout.
 */
int
recvfrom_wto(int s, unsigned char *buf, size_t len, struct sockaddr *saddr,
             int tmo) {
   fd_set readset;
   struct timeval to;
   int n;
   NET_SIZE_T saddr_len;

   if (tmo < 0)
     tmo = 0;	/* Negative timeouts not allowed */
   to.tv_sec  = tmo/1000000;
   to.tv_usec = (tmo - 1000000*to.tv_sec);
   if (sourceip_flag) {	/* Source IP spoofing using raw socket */
      n = select(0, NULL, NULL, NULL, &to);
   } else {		/* Normal UDP socket */
      FD_ZERO(&readset);
      FD_SET(s, &readset);
      n = select(s+1, &readset, NULL, NULL, &to);
   }
   if (n < 0) {
      if (errno == EINTR) {
         return -1;	/* Handle "Interrupted System call" as timeout */
      } else {
         err_sys("ERROR: select");
      }
   } else if (n == 0 && read_pkt_from_file == 0) {
      return -1;	/* Timeout reading from network */
   }
   if (read_pkt_from_file == 0) {
      saddr_len = sizeof(struct sockaddr);
      if ((n = recvfrom(s, buf, len, 0, saddr, &saddr_len)) < 0) {
         if (errno == ECONNREFUSED || errno == ECONNRESET) {
/*
 *	Treat connection refused and connection reset as timeout.
 *	It would be nice to remove the associated host, but we can't because
 *	we cannot tell which host the connection refused relates to.
 */
            return -1;
         } else {
            err_sys("ERROR: recvfrom");
         }
      }
#ifdef WRITE_RECEIVED_IKE_PACKET
      {
         int myfd;
         int nbytes;
         myfd = creat(WRITE_RECEIVED_IKE_PACKET, 0666);
         nbytes = write(myfd, buf, n);
         if (nbytes != n) {
            err_msg("ERROR: write() failed");
         }
         close(myfd);
      }
#endif
   } else {	/* Read from file */
      if ((n = read(read_pkt_from_file, buf, len)) < 0) {
         err_sys("ERROR: read");
      }
      memset(saddr, '\0', sizeof(struct sockaddr_in));
   }
/*
 *	Cisco TCP encapsulation.
 *	Remove encapsulated UDP header from TCP segment.
 */
   if (tcp_flag == TCP_PROTO_ENCAP && n > 8) {
      ike_udphdr *udphdr;
      unsigned char *tmpbuf;
      size_t tmpbuf_len;

      udphdr = (ike_udphdr*) buf;
      if (ntohs(udphdr->source) == 500 &&
          ntohs(udphdr->dest) == 500) {
         tmpbuf_len = n - 8;	/* we know that n > 8 at this point */
         tmpbuf=Malloc(tmpbuf_len);	/* could we use memmove() instead ? */
         memcpy(tmpbuf, buf+8, tmpbuf_len);
         memcpy(buf, tmpbuf, tmpbuf_len);
         free(tmpbuf);
      }
   }
/*
 *	RFC 3947 NAT Traversal.
 *	Remove Non ESP marker from NAT-T packet leaving IKE data.
 */
   if (nat_t_flag && n > 4) {
      memmove(buf, buf+4, n-4);
   }

   return n;
}

/*
 *	initialise_ike_packet	-- Initialise IKE packet structures
 *
 *	Inputs:
 *
 *	packet_out_len	Size of output packet.
 *	params		Structure containing the required packet parameters.
 *
 *	Returns:
 *
 *	Pointer to constructed packet.
 *
 *	We build the IKE packet backwards: from the last payload to the first.
 *	This ensures that we know the "next payload" value for the previous
 *	payload, and also that we know the total length for the ISAKMP header.
 */
unsigned char *
initialise_ike_packet(size_t *packet_out_len, ike_packet_params *params) {
   unsigned char *hdr;		/* ISAKMP Header */
   unsigned char *sa;		/* Security Association */
   unsigned char *prop;		/* Proposal */
   unsigned char *transforms;	/* All transforms */
   unsigned char *certreq=NULL;
   unsigned char *vid=NULL;
   unsigned char *id=NULL;
   unsigned char *nonce=NULL;
   unsigned char *ke=NULL;	/* Key Exchange */
   unsigned char *cp;
   unsigned char *packet_out;	/* Constructed IKE packet */
   unsigned char *sa_cp=NULL;	/* For payload printing */
   size_t sa_len;
   size_t prop_len;
   size_t certreq_len;
   size_t vid_len;
   size_t trans_len;
   size_t id_len;
   size_t nonce_len;
   size_t ke_len;
   size_t kx_data_len=0;
   unsigned no_trans=0;	/* Number of transforms */
   unsigned next_payload;
   unsigned header_len;	/* Length in ISAKMP header */

   *packet_out_len = 0;
   next_payload = ISAKMP_NEXT_NONE;
/*
 *	Certificate request payload (Optional)
 */
   if (params->cr_data) {
      certreq = make_cr(&certreq_len, next_payload, params->cr_data,
                        params->cr_data_len);
      *packet_out_len += certreq_len;
      next_payload = ISAKMP_NEXT_CR;
   }
/*
 *	Vendor ID Payload (Optional)
 */
   if (params->vendor_id_flag) {
      vid = add_vid(1, &vid_len, NULL, 0, params->ike_version, next_payload);
      *packet_out_len += vid_len;
      if (params->ike_version == 1) {
         next_payload = ISAKMP_NEXT_VID;
      } else {
         next_payload = ISAKMP_NEXT_V2_VID;
      }
   }
/*
 *	IKEv1 Key Exchange, Nonce and ID for aggressive mode only.
 */
   if (params->exchange_type == ISAKMP_XCHG_AGGR) {
      id = make_id(&id_len, next_payload, params->idtype, params->id_data,
                   params->id_data_len);
      if (params->id_data)
         free(params->id_data);
      *packet_out_len += id_len;
      next_payload = ISAKMP_NEXT_ID;
      nonce = make_nonce(&nonce_len, next_payload, params->nonce_data_len);
      if (psk_crack_flag)
         add_psk_crack_payload(nonce, 10, 'I');
      *packet_out_len += nonce_len;
      next_payload = ISAKMP_NEXT_NONCE;
      switch (params->dhgroup) {
         case 1:
            kx_data_len = 96;	/* Group 1 - 768 bits */
            break;
         case 2:
            kx_data_len = 128;	/* Group 2 - 1024 bits */
            break;
         case 5:
            kx_data_len = 192;	/* Group 5 - 1536 bits */
            break;
         case 14:
            kx_data_len = 256;	/* Group 14 - 2048 bits */
            break;
         case 15:
            kx_data_len = 384;	/* Group 15 - 3072 bits */
            break;
         case 16:
            kx_data_len = 512;	/* Group 16 - 4096 bits */
            break;
         case 17:
            kx_data_len = 768;	/* Group 17 - 6144 bits */
            break;
         case 18:
            kx_data_len = 1024;	/* Group 18 - 8192 bits */
            break;
         case 19:
            kx_data_len = 64;	/* Group 19 - 256+256 bits */
            break;
         case 20:
            kx_data_len = 96;	/* Group 20 - 384+384 bits */
            break;
         case 21:
            kx_data_len = 132;	/* Group 21 - 528+528 bits */
            break;
         default:
            err_msg("ERROR: Bad Diffie Hellman group: %u, "
                    "should be 1,2,5,14,15,16,17,18,19,20 or 21",
                    params->dhgroup);	/* Doesn't return */
      }
      ke = make_ke(&ke_len, next_payload, kx_data_len);
      if (psk_crack_flag)
         add_psk_crack_payload(ke, 4, 'I');
      *packet_out_len += ke_len;
      next_payload = ISAKMP_NEXT_KE;
   }

/* IKEv2 Key Exchange and Nonce Payloads */

   if (params->ike_version == 2) {
      nonce = make_nonce(&nonce_len, next_payload, params->nonce_data_len);
      *packet_out_len += nonce_len;
      next_payload = ISAKMP_NEXT_V2_NONCE;
      switch (params->dhgroup) {
         case 1:
            kx_data_len = 96;	/* Group 1 - 768 bits */
            break;
         case 2:
            kx_data_len = 128;	/* Group 2 - 1024 bits */
            break;
         case 5:
            kx_data_len = 192;	/* Group 5 - 1536 bits */
            break;
         case 14:
            kx_data_len = 256;	/* Group 14 - 2048 bits */
            break;
         case 15:
            kx_data_len = 384;	/* Group 15 - 3072 bits */
            break;
         case 16:
            kx_data_len = 512;	/* Group 16 - 4096 bits */
            break;
         case 17:
            kx_data_len = 768;	/* Group 17 - 6144 bits */
            break;
         case 18:
            kx_data_len = 1024;	/* Group 18 - 8192 bits */
            break;
         case 19:
            kx_data_len = 64;	/* Group 19 - 256+256 bits */
            break;
         case 20:
            kx_data_len = 96;	/* Group 20 - 384+384 bits */
            break;
         case 21:
            kx_data_len = 132;	/* Group 21 - 528+528 bits */
            break;
         default:
            err_msg("ERROR: Bad Diffie Hellman group: %u, "
                    "should be 1,2,5,14,15,16,17,18,19,20 or 21",
                    params->dhgroup);	/* Doesn't return */
      }
      ke = make_ke2(&ke_len, next_payload, params->dhgroup, kx_data_len);
      *packet_out_len += ke_len;
      next_payload = ISAKMP_NEXT_V2_KE;
   }
/*
 *	Transform payloads
 */
   if (!params->trans_flag && params->ike_version==1) {	/* Std IKEv1 trans */
      if (params->exchange_type != ISAKMP_XCHG_AGGR) {	/* Main Mode */
         add_trans_simple(0, NULL, OAKLEY_3DES_CBC, 0, OAKLEY_SHA,
                   params->auth_method, 2, params->lifetime_data,
                   params->lifetime_data_len, params->lifesize_data,
                   params->lifesize_data_len,
                   params->gss_id_flag, params->gss_data, params->gss_data_len,
                   params->trans_id);
         add_trans_simple(0, NULL, OAKLEY_3DES_CBC, 0, OAKLEY_MD5,
                   params->auth_method, 2, params->lifetime_data,
                   params->lifetime_data_len, params->lifesize_data,
                   params->lifesize_data_len,
                   params->gss_id_flag, params->gss_data, params->gss_data_len,
                   params->trans_id);
         add_trans_simple(0, NULL, OAKLEY_DES_CBC,  0, OAKLEY_SHA,
                   params->auth_method, 2, params->lifetime_data,
                   params->lifetime_data_len, params->lifesize_data,
                   params->lifesize_data_len,
                   params->gss_id_flag, params->gss_data, params->gss_data_len,
                   params->trans_id);
         add_trans_simple(0, NULL, OAKLEY_DES_CBC,  0, OAKLEY_MD5,
                   params->auth_method, 2, params->lifetime_data,
                   params->lifetime_data_len, params->lifesize_data,
                   params->lifesize_data_len,
                   params->gss_id_flag, params->gss_data, params->gss_data_len,
                   params->trans_id);
         add_trans_simple(0, NULL, OAKLEY_3DES_CBC, 0, OAKLEY_SHA,
                   params->auth_method, 1, params->lifetime_data,
                   params->lifetime_data_len, params->lifesize_data,
                   params->lifesize_data_len,
                   params->gss_id_flag, params->gss_data, params->gss_data_len,
                   params->trans_id);
         add_trans_simple(0, NULL, OAKLEY_3DES_CBC, 0, OAKLEY_MD5,
                   params->auth_method, 1, params->lifetime_data,
                   params->lifetime_data_len, params->lifesize_data,
                   params->lifesize_data_len,
                   params->gss_id_flag, params->gss_data, params->gss_data_len,
                   params->trans_id);
         add_trans_simple(0, NULL, OAKLEY_DES_CBC,  0, OAKLEY_SHA,
                   params->auth_method, 1, params->lifetime_data,
                   params->lifetime_data_len, params->lifesize_data,
                   params->lifesize_data_len,
                   params->gss_id_flag, params->gss_data, params->gss_data_len,
                   params->trans_id);
         add_trans_simple(0, NULL, OAKLEY_DES_CBC,  0, OAKLEY_MD5,
                   params->auth_method, 1, params->lifetime_data,
                   params->lifetime_data_len, params->lifesize_data,
                   params->lifesize_data_len,
                   params->gss_id_flag, params->gss_data, params->gss_data_len,
                   params->trans_id);
         no_trans=8;
      } else {	/* presumably aggressive mode */
         add_trans_simple(0, NULL, OAKLEY_3DES_CBC, 0, OAKLEY_SHA,
                   params->auth_method, params->dhgroup, params->lifetime_data,
                   params->lifetime_data_len, params->lifesize_data,
                   params->lifesize_data_len, params->gss_id_flag,
                   params->gss_data, params->gss_data_len, params->trans_id);
         add_trans_simple(0, NULL, OAKLEY_3DES_CBC, 0, OAKLEY_MD5,
                   params->auth_method, params->dhgroup, params->lifetime_data,
                   params->lifetime_data_len, params->lifesize_data,
                   params->lifesize_data_len, params->gss_id_flag,
                   params->gss_data, params->gss_data_len, params->trans_id);
         add_trans_simple(0, NULL, OAKLEY_DES_CBC,  0, OAKLEY_SHA,
                   params->auth_method, params->dhgroup, params->lifetime_data,
                   params->lifetime_data_len, params->lifesize_data,
                   params->lifesize_data_len, params->gss_id_flag,
                   params->gss_data, params->gss_data_len, params->trans_id);
         add_trans_simple(0, NULL, OAKLEY_DES_CBC,  0, OAKLEY_MD5,
                   params->auth_method, params->dhgroup, params->lifetime_data,
                   params->lifetime_data_len, params->lifesize_data,
                   params->lifesize_data_len, params->gss_id_flag,
                   params->gss_data, params->gss_data_len, params->trans_id);
         no_trans=4;
      }
      if (params->gss_data)
         free(params->gss_data);
   } else if (params->ike_version==1) {	/* IKEv1 Custom transforms */
      no_trans = params->trans_flag;
   }
   if (params->advanced_trans_flag && params->ike_version==1) {
      transforms = add_transform(1, &trans_len, 0, NULL, 0);
   } else if (params->ike_version==1) {
      transforms = add_trans_simple(1, &trans_len, 0, 0, 0, 0, 0, NULL, 0,
                                    NULL, 0, 0, NULL, 0, 0);
   }

   if (params->ike_version != 1) {	/* IKEv2 Transforms */
      unsigned char *attr;
      size_t attr_len;

      add_attr(0, NULL, 'B', OAKLEY_KEY_LENGTH, 0, 256, NULL);
      attr = add_attr(1, &attr_len, '\0', 0, 0, 0, NULL);
      add_transform2(0, NULL, IKEV2_TYPE_ENCR, IKEV2_ENCR_AES_CBC, attr, attr_len);
      free(attr);
      add_attr(0, NULL, 'B', OAKLEY_KEY_LENGTH, 0, 128, NULL);
      attr = add_attr(1, &attr_len, '\0', 0, 0, 0, NULL);
      add_transform2(0, NULL, IKEV2_TYPE_ENCR, IKEV2_ENCR_AES_CBC, attr, attr_len);
      free(attr);
      add_transform2(0, NULL, IKEV2_TYPE_ENCR, IKEV2_ENCR_3DES, NULL, 0);
      add_transform2(0, NULL, IKEV2_TYPE_ENCR, IKEV2_ENCR_DES, NULL, 0);
      add_transform2(0, NULL, IKEV2_TYPE_PRF, IKEV2_PRF_HMAC_SHA1, NULL, 0);
      add_transform2(0, NULL, IKEV2_TYPE_PRF, IKEV2_PRF_HMAC_MD5, NULL, 0);
      add_transform2(0, NULL, IKEV2_TYPE_INTEG, IKEV2_AUTH_HMAC_SHA1_96, NULL, 0);
      add_transform2(0, NULL, IKEV2_TYPE_INTEG, IKEV2_AUTH_HMAC_MD5_96, NULL, 0);
      add_transform2(0, NULL, IKEV2_TYPE_DH, 2, NULL, 0);
      add_transform2(0, NULL, IKEV2_TYPE_DH, 5, NULL, 0);
      add_transform2(0, NULL, IKEV2_TYPE_DH, 14, NULL, 0);
      transforms = add_transform2(1, &trans_len, 0, 0, NULL, 0);
      no_trans=11;
   }
/*
 *	Proposal payload
 */
   add_prop(0, NULL, no_trans, params->protocol, params->spi_size, transforms,
            trans_len);
   prop = add_prop(1, &prop_len, 0, 0, 0, NULL, 0);
   free(transforms);
/*
 *	SA payload
 */
   if (params->ike_version == 1) {	/* IKEv1 SA */
      sa = make_sa(&sa_len, next_payload, params->doi, params->situation,
                   prop, prop_len);
      next_payload = ISAKMP_NEXT_SA;
   } else {				/* IKEv2 SA */
      sa = make_sa2(&sa_len, next_payload, prop, prop_len);
      next_payload = ISAKMP_NEXT_V2_SA;
   }
   *packet_out_len += sa_len;
   free(prop);
/*
 *	ISAKMP Header
 */
   *packet_out_len += sizeof(struct isakmp_hdr);
   header_len = *packet_out_len;	/* Set header len to correct value */
   if (params->header_length) {	/* Manually specify header length */
      char *temp_cp;

      temp_cp = params->header_length;
      if (*temp_cp == '+') {
         header_len += Strtoul(++temp_cp, 0);
      } else if (*temp_cp == '-') {
         header_len -= Strtoul(++temp_cp, 0);
      } else {
         header_len = Strtoul(temp_cp, 0);
      }
   }
   if (params->hdr_next_payload) {	/* Manually specify next payload */
      next_payload = params->hdr_next_payload;
   }
   hdr = make_isakmp_hdr(params->exchange_type, next_payload,
                         header_len, params->header_version,
                         params->hdr_flags, params->hdr_msgid,
                         params->rcookie_data, params->rcookie_data_len);
/*
 *	Allocate packet and copy payloads into packet.
 */
   packet_out=Malloc(*packet_out_len);
   cp = packet_out;
   memcpy(cp, hdr, sizeof(struct isakmp_hdr));
   free(hdr);
   cp += sizeof(struct isakmp_hdr);
   if (psk_crack_flag)
      sa_cp = cp;	/* Remember position of SA payload */
   memcpy(cp, sa, sa_len);
   free(sa);
   cp += sa_len;
   if (params->exchange_type == ISAKMP_XCHG_AGGR) {
      memcpy(cp, ke, ke_len);
      free(ke);
      cp += ke_len;
      memcpy(cp, nonce, nonce_len);
      free(nonce);
      cp += nonce_len;
      memcpy(cp, id, id_len);
      free(id);
      cp += id_len;
   }
   if (params->ike_version == 2) {
      memcpy(cp, ke, ke_len);
      free(ke);
      cp += ke_len;
      memcpy(cp, nonce, nonce_len);
      free(nonce);
      cp += nonce_len;
   }
   if (params->vendor_id_flag) {
      memcpy(cp, vid, vid_len);
      free(vid);
      cp += vid_len;
   }
   if (params->cr_data) {
      memcpy(cp, certreq, certreq_len);
      free(certreq);
      cp += certreq_len;
   }
   if (psk_crack_flag)
      add_psk_crack_payload(sa_cp, 1, 'I');

   return packet_out;
}

/*
 *	dump_list -- Display contents of host list for debugging
 *
 *      Inputs:
 *
 *      num_hosts	The number of entries in the host list.
 *
 *	Returns:
 *
 *	None.
 */
void
dump_list(unsigned num_hosts) {
   char *cp;
   unsigned i;

   printf("Host List:\n\n");
   printf("Entry\tIP Address\tCookie\n");
   for (i=0; i<num_hosts; i++) {
      cp = hexstring((unsigned char *)helistptr[i]->icookie,
                     sizeof(helistptr[i]->icookie));
      printf("%u\t%s\t%s\n", helistptr[i]->n, inet_ntoa(helistptr[i]->addr),
             cp);
      free(cp);
   }
   printf("\nTotal of %u host entries.\n\n", num_hosts);
}

/*
 *	dump_backoff -- Display contents of backoff list for debugging
 *
 *	Inputs:
 *
 *	pattern_fuzz	Default pattern matching fuzz value in ms.
 *
 *	Returns:
 *
 *	None.
 *
 *	This displays the contents of the backoff pattern list.  It is useful
 *	when debugging to check that the patterns have been loaded correctly
 *	from the backoff patterns file.
 */
void
dump_backoff(unsigned pattern_fuzz) {
   pattern_list *pl;
   pattern_entry_list *pp;
   int i;

   printf("Backoff Pattern List:\n\n");
   printf("Entry\tName\tCount\tBackoff Pattern\n");
   pl = patlist;
   i=1;
   while (pl != NULL) {
      printf("%d\t%s\t%u\t", i, pl->name, pl->num_times);
      pp = pl->recv_times;
      while (pp != NULL) {
/*
 *  Only print the fractional seconds part if required (generally it's not).
 *  We cast to unsigned long because some OSes define tv_sec/tv_usec as long and
 *  others define them as int.
 */
         if (pp->time.tv_usec) {
            printf("%lu.%.6lu", (unsigned long)pp->time.tv_sec,
                   (unsigned long)pp->time.tv_usec);
         } else {
            printf("%lu", (unsigned long)pp->time.tv_sec);
         }
/*
 * Display the fuzz value for this pattern entry if it is not the default.
 */
         if (pp->fuzz != pattern_fuzz)
            printf("/%d", pp->fuzz);
/*
 * Print a newline if we're at the end of this pattern, otherwise print a
 * comma and space before the next time element.
 */
         pp = pp->next;
         if (pp == NULL) {
            printf("\n");
         } else {
            printf(", ");
         }
      }
      pl = pl->next;
      i++;
   } /* End While */
   printf("\nTotal of %d backoff pattern entries.\n\n", i-1);
}

/*
 *	dump_vid -- Display contents of Vendor ID pattern list for debugging
 *
 *	Inputs:
 *
 *	None
 *
 *	Returns:
 *
 *	None.
 *
 *	This displays the contents of the Vendor ID pattern list.  It is useful
 *	when debugging to check that the patterns have been loaded correctly
 *	from the Vendor ID patterns file.
 */
void
dump_vid(void) {
   vid_pattern_list *pl;
   int i;

   printf("Vendor ID Pattern List:\n\n");
   printf("Entry\tName\tVendor ID Pattern\n");
   pl = vidlist;
   i=1;
   while (pl != NULL) {
      printf("%d\t%s\t%s\n", i++, pl->name, pl->pattern);
      pl = pl->next;
   } /* End While */
   printf("\nTotal of %d Vendor ID pattern entries.\n\n", i-1);
}

/*
 *	dump_times -- Display packet times for backoff fingerprinting
 *
 *	Inputs:
 *
 *	num_hosts	The number of hosts in the list.
 *
 *	Returns:
 *
 *	None.
 */
void
dump_times(unsigned num_hosts) {
   time_list *te;
   unsigned i;
   int time_no;
   struct timeval prev_time;
   struct timeval diff;
   char *patname;
   int unknown_patterns = 0;

   printf("IKE Backoff Patterns:\n");
   printf("\nIP Address\tNo.\tRecv time\t\tDelta Time\n");
   for (i=0; i<num_hosts; i++) {
      if (helistptr[i]->recv_times != NULL && helistptr[i]->num_recv > 0) {
         te = helistptr[i]->recv_times;
         time_no = 1;
         diff.tv_sec = 0;
         diff.tv_usec = 0;
         while (te != NULL) {
            if (time_no > 1)
               timeval_diff(&(te->time), &prev_time, &diff);
            printf("%s\t%d\t%lu.%.6lu\t%lu.%.6lu\n",
                   inet_ntoa(helistptr[i]->addr),
                   time_no, (unsigned long)te->time.tv_sec,
                   (unsigned long)te->time.tv_usec,
                   (unsigned long)diff.tv_sec, (unsigned long)diff.tv_usec);
            prev_time = te->time;
            te = te->next;
            time_no++;
         } /* End While te != NULL */
         if ((patname=match_pattern(helistptr[i])) != NULL) {
            printf("%s\tImplementation guess: %s\n",
                   inet_ntoa(helistptr[i]->addr), patname);
         } else {
            if (patlist) {
               printf("%s\tImplementation guess: %s\n",
                      inet_ntoa(helistptr[i]->addr), "UNKNOWN");
            } else {
               printf("%s\tImplementation guess: %s\n",
                      inet_ntoa(helistptr[i]->addr),
                      "UNKNOWN - No patterns available");
            }
            unknown_patterns++;
         }
         printf("\n");
      } /* End If */
   } /* End For */
   if (unknown_patterns && patlist) {
      printf("Some IKE implementations found have unknown backoff fingerprints\n");
      printf("If you know the implementation name, and the pattern is reproducible, you\n");
      printf("are encouraged to submit the pattern and implementation details\n");
      printf("through the github repository at https://github.com/royhills/ike-scan\n");
   }
}

/*
 *	match_pattern -- Find backoff pattern match
 *
 *	Inputs:
 *
 *	he	Pointer to the host entry which we are trying to match.
 *
 *	Returns:
 *
 *	Pointer to the implementation name, or NULL if no match.
 *
 *	Finds the first match for the backoff pattern of the host entry *he.
 */
char *
match_pattern(host_entry *he) {
   pattern_list *pl;
/*
 *	Return NULL immediately if there is no chance of matching.
 */
   if (he == NULL || patlist == NULL)
      return NULL;
   if (he->recv_times == NULL || he->num_recv < 1)
      return NULL;
/*
 *	Try to find a match in the pattern list.
 */
   pl = patlist;
   while (pl != NULL) {
      if (he->num_recv == pl->num_times && pl->recv_times != NULL) {
         time_list *hp;
         pattern_entry_list *pp;
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
            if (!times_close_enough(&(pp->time), &diff, pp->fuzz)) {
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
 *	If we reach here, then we haven't matched the pattern so return NULL.
 */
   return NULL;
}

/*
 *	add_recv_time -- Add current time to the recv_times list
 *
 *	Inputs:
 *
 *	he	Pointer to host entry to add time to
 *	last_recv_time	Time packet was received
 *
 *	Returns:
 *
 *	None.
 */
void
add_recv_time(host_entry *he, struct timeval *last_recv_time) {
   time_list *p;		/* Temp pointer */
   time_list *te;	/* New timeentry pointer */
/*
 *	Allocate and initialise new time structure
 */
   te = Malloc(sizeof(time_list));
   Gettimeofday(&(te->time));
   last_recv_time->tv_sec = te->time.tv_sec;
   last_recv_time->tv_usec = te->time.tv_usec;
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
 *	load_backoff_patterns -- Load UDP backoff patterns from specified file
 *
 *	Inputs:
 *
 *	patfile		Name of the file to load the patterns from
 *	pattern_fuzz	Default fuzz value in ms
 *
 *	Returns:
 *
 *	None.
 */
void
load_backoff_patterns(const char *patfile, unsigned pattern_fuzz) {
   FILE *fp;
   char line[MAXLINE];
   int line_no;
   char *fn;
#ifdef __CYGWIN__
   char fnbuf[MAXLINE];
   int fnbuf_siz;
   int i;
#endif

   if (*patfile == '\0') {	/* If patterns file not specified */
#ifdef __CYGWIN__
      if ((fnbuf_siz=GetModuleFileName(GetModuleHandle(0), fnbuf, MAXLINE)) == 0) {
         err_msg("ERROR: Call to GetModuleFileName failed");
      }
      for (i=fnbuf_siz-1; i>=0 && fnbuf[i] != '/' && fnbuf[i] != '\\'; i--)
         ;
      if (i >= 0) {
         fnbuf[i] = '\0';
      }
      fn = make_message("%s\\%s", fnbuf, PATTERNS_FILE);
#else
      fn = make_message("%s/%s", IKEDATADIR, PATTERNS_FILE);
#endif
   } else {
      fn = make_message("%s", patfile);
   }

   if ((fp = fopen(fn, "r")) == NULL) {
      warn_msg("WARNING: Cannot open IKE backoff patterns file.  ike-scan will still display");
      warn_msg("the backoff patterns, but it will not be able to identify the fingerprints.");
      warn_sys("fopen: %s", fn);
   } else {
      line_no=0;
      while (fgets(line, MAXLINE, fp)) {
         line_no++;
         if (line[0] != '#' && line[0] != '\n' && line[0] != '\r') /* Not comment or empty */
            add_pattern(line, pattern_fuzz);
      }
      fclose(fp);
   }
   free(fn);
}

/*
 *	add_pattern -- add a backoff pattern to the list.
 *
 *	Inputs:
 *
 *	line		Backoff pattern entry from the patterns file
 *	pattern_fuzz	Default fuzz value in ms
 *
 *	Returns:
 *
 *	None.
 */
void
add_pattern(char *line, unsigned pattern_fuzz) {
   char name[MAXLINE];
   char pat[MAXLINE];
   pattern_list *pe;	/* Pattern entry */
   pattern_list *p;	/* Temp pointer */
   pattern_entry_list *te;
   pattern_entry_list *tp;
   char *endp;
   unsigned i;
   long back_sec;
   long back_usec;
   char back_usec_str[7];       /* Backoff microseconds as string */
   int len;
   unsigned fuzz;	/* Pattern matching fuzz in ms */
   static const char *backoff_pat_str = "([^\t]+)\t[\t ]*([^\t\r\n]+)";
   static regex_t backoff_pat;
   static int first_call=1;
   regmatch_t pmatch[3];
   int result;
   size_t name_len;
   size_t pat_len;
/*
 *	Compile the regex if this is the first call.
 *	Die if we cannot compile the regex.
 */
   if (first_call) {
      first_call = 0;
      if ((result=regcomp(&backoff_pat, backoff_pat_str, REG_EXTENDED))) {
         char errbuf[MAXLINE];
         regerror(result, &backoff_pat, errbuf, MAXLINE);
         err_msg("ERROR: cannot compile regex pattern \"%s\": %s",
                 backoff_pat_str, errbuf);
      }
   }
/*
 *	Separate line from patterns file into "name" and "pat" using the
 *	regex pattern.
 *	Issue a warning if we cannot parse the line.  Die if we get a regex
 *	error.
 */
   result = regexec(&backoff_pat, line, 3, pmatch, 0);
   if (result == REG_NOMATCH || pmatch[1].rm_so < 0 || pmatch[2].rm_so < 0) {
      warn_msg("WARNING: Could not parse backoff pattern: %s", line);
      return;
   } else if (result != 0) {
      char errbuf[MAXLINE];
      regerror(result, &backoff_pat, errbuf, MAXLINE);
      err_msg("ERROR: backoff pattern match regexec failed: %s", errbuf);
   }
   name_len = pmatch[1].rm_eo - pmatch[1].rm_so;
   if (name_len >= sizeof(name)) {
      name_len = sizeof(name) - 1;
   }
   pat_len = pmatch[2].rm_eo - pmatch[2].rm_so;
   if (pat_len >= sizeof(pat)) {
      pat_len = sizeof(pat) - 1;
   }
   memcpy(name, line+pmatch[1].rm_so, name_len);
   name[name_len] = '\0';
   memcpy(pat, line+pmatch[2].rm_so, pat_len);
   pat[pat_len] = '\0';
/*
 *	Allocate new pattern list entry and add to tail of patlist.
 */
   pe = Malloc(sizeof(pattern_list));
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
 *	Copy name into malloc'ed storage and set pe->name to point to this.
 */
   pe->name = dupstr(name);
/*
 *	Process and store the backoff pattern.
 */
   i=0;
   endp=pat;
   while (*endp != '\0') {
/*
 *      Convert the integer seconds part of the backoff pattern entry.
 */
      back_sec=strtol(endp, &endp, 10);
/*
 *      If there is a "." after the integer part, then there are fractional
 *      seconds to convert.  Convert the fractional seconds into a string
 *      representation of microseconds by zero-extending to 6 digits and
 *      then convert to long.
 */
      if (*endp == '.') {
         endp++;
         len=0;
         for (len=0; len<6; len++){
            if (isdigit((unsigned char) *endp)) {
               back_usec_str[len] = *endp;
               endp++;
            } else {
               back_usec_str[len] = '0';
            }
         }
         while (isdigit((unsigned char) *endp))
            endp++;	/* Skip any fractional digits past 6th */
         back_usec_str[len] = '\0';
         back_usec=strtol(back_usec_str, NULL, 10);
      } else {	/* No fractional seconds part */
         back_usec=0;
      }
/*
 *      If there is a "/" after the number, this represents a fuzz value
 *      in milliseconds.
 */
      if (*endp == '/') {
         endp++;
         fuzz=strtol(endp, &endp, 10);
      } else {
         fuzz = pattern_fuzz;
      }
/*
 *      Allocate and fill in new pattern_entry_list structure for this backoff
 *      pattern entry and add it onto the tail of this pattern entry.
 */
      te = Malloc(sizeof(pattern_entry_list));
      te->next=NULL;
      te->time.tv_sec = back_sec;
      te->time.tv_usec = back_usec;
      te->fuzz = fuzz;
      tp = pe->recv_times;
      if (tp == NULL) {
         pe->recv_times = te;
      } else {
         while (tp->next != NULL)
            tp = tp->next;
         tp->next = te;
      }
/*
 *	Move on to next pattern entry.
 */
      if (*endp == ',')
         endp++;
      i++;
   }	/* End While */
   pe->num_times=i;
}

/*
 *	load_vid_patterns -- Load Vendor ID Patterns from specified file
 *
 *	Inputs:
 *
 *	vidfile		The name of the file to load the patterns from
 *
 *	Returns:
 *
 *	None
 */
void
load_vid_patterns(const char *vidfile) {
   FILE *fp;
   char line[MAXLINE];
   int line_no;
   char *fn;
#ifdef __CYGWIN__
   char fnbuf[MAXLINE];
   int fnbuf_siz;
   int i;
#endif

   if (*vidfile == '\0') {	/* If patterns file not specified */
#ifdef __CYGWIN__
      if ((fnbuf_siz=GetModuleFileName(GetModuleHandle(0), fnbuf, MAXLINE)) == 0) {
         err_msg("ERROR: Call to GetModuleFileName failed");
      }
      for (i=fnbuf_siz-1; i>=0 && fnbuf[i] != '/' && fnbuf[i] != '\\'; i--)
         ;
      if (i >= 0) {
         fnbuf[i] = '\0';
      }
      fn = make_message("%s\\%s", fnbuf, VID_FILE);
#else
      fn = make_message("%s/%s", IKEDATADIR, VID_FILE);
#endif
   } else {
      fn = make_message("%s", vidfile);
   }

   if ((fp = fopen(fn, "r")) == NULL) {
      warn_msg("WARNING: Cannot open Vendor ID patterns file.  ike-scan will still display");
      warn_msg("the raw Vendor ID data in hex, but it will not be able to display the");
      warn_msg("associated Vendor ID names.");
      warn_sys("fopen: %s", fn);
   } else {
      line_no=0;
      while (fgets(line, MAXLINE, fp)) {
         line_no++;
         if (line[0] != '#' && line[0] != '\n' && line[0] != '\r') /* Not comment or empty */
            add_vid_pattern(line);
      }
      fclose(fp);
   }
   free(fn);
}

/*
 *	add_vid_pattern -- add a Vendor ID pattern to the list.
 *
 *	Inputs:
 *
 *	line		Vendor ID pattern entry from the patterns file
 *
 *	Returns:
 *
 *	None.
 */
void
add_vid_pattern(char *line) {
   regex_t *rep;	/* Compiled regex */
   char name[MAXLINE];
   char pat[MAXLINE];
   vid_pattern_list *pe;     /* Pattern entry */
   vid_pattern_list *p;      /* Temp pointer */
   int result;
   static const char *vid_pat_str = "([^\t]+)\t[\t ]*([^\t\n\r]+)";
   static regex_t vid_pat;
   static int first_call=1;
   regmatch_t pmatch[3];
   size_t name_len;
   size_t pat_len;
/*
 *      Compile the regex if this is the first call.
 *      Die if we cannot compile the regex.
 */
   if (first_call) {
      first_call = 0;
      if ((result=regcomp(&vid_pat, vid_pat_str, REG_EXTENDED))) {
         char errbuf[MAXLINE];
         regerror(result, &vid_pat, errbuf, MAXLINE);
         err_msg("ERROR: cannot compile regex pattern \"%s\": %s",
                 vid_pat_str, errbuf);
      }
   }
/*
 *	Separate line from VID patterns file into name and pattern.
 */
   result = regexec(&vid_pat, line, 3, pmatch, 0);
   if (result == REG_NOMATCH || pmatch[1].rm_so < 0 || pmatch[2].rm_so < 0) {
      warn_msg("WARNING: Could not parse vendor id pattern: %s", line);
      return;
   } else if (result != 0) {
      char errbuf[MAXLINE];
      regerror(result, &vid_pat, errbuf, MAXLINE);
      err_msg("ERROR: vendor id pattern match regexec failed: %s", errbuf);
   }
   name_len = pmatch[1].rm_eo - pmatch[1].rm_so;
   if (name_len >= sizeof(name)) {
      name_len = sizeof(name) - 1;
   }
   pat_len = pmatch[2].rm_eo - pmatch[2].rm_so;
   if (pat_len >= sizeof(pat)) {
      pat_len = sizeof(pat) - 1;
   }
   memcpy(name, line+pmatch[1].rm_so, name_len);
   name[name_len] = '\0';
   memcpy(pat, line+pmatch[2].rm_so, pat_len);
   pat[pat_len] = '\0';
/*
 *      Process and store the Vendor ID pattern.
 *	The pattern in the file is a Posix extended regular expression which is
 *	compiled with "regcomp".  A pointer to this compiled pattern is
 *	stored in pe->regex.  We also store the text pattern in pe->pattern
 *	for dump_vid().
 */
   rep = Malloc(sizeof(regex_t));
   if ((result=regcomp(rep, pat, REG_EXTENDED|REG_ICASE|REG_NOSUB))) {
      char errbuf[MAXLINE];
      regerror(result, rep, errbuf, MAXLINE);
      warn_msg("WARNING: Ignoring invalid Vendor ID pattern \"%s\": %s",
               pat, errbuf);
      free(rep);
      /* Should we call regfree(rep) here? */
   } else {
/*
 *      Allocate new pattern list entry and add to tail of vidlist.
 */
      pe = Malloc(sizeof(vid_pattern_list));
      pe->next = NULL;
      p = vidlist;
      if (p == NULL) {
         vidlist=pe;
      } else {
         while (p->next != NULL)
            p = p->next;
         p->next = pe;
      }
/*
 *	Store compiled regex.
 */
      pe->regex = rep;
/*
 *	Store text regex.
 */
      pe->pattern = dupstr(pat);
/*
 *	Store pattern name.
 */
      pe->name = dupstr(name);
   }
}

/*
 *	load_id_strings -- Load ID strings from file into memory
 *
 *	Inputs:
 *
 *	filename	ID strings file name
 *
 *	Returns:
 *
 *	Pointer to ID strings array.
 */
char **
load_id_strings(char *filename) {
   FILE *fp;
   char line[MAXLINE];
   char *cp;
   int i;
   size_t idstringlist_len = 0;
   size_t old_idstringlist_len = 0;
   int line_count = 0;
   char *idstringlist = NULL;
   char **idstringlist_ptr = NULL;

   if ((fp = fopen(filename, "r")) == NULL)
      err_sys("ERROR: Cannot open ID file %s", filename);
/*
 *	Copy IDs from the file to the list of strings starting at
 *	idstringlist.
 */
   while (fgets(line, MAXLINE, fp)) {
      line_count++;
      for (cp = line; *cp != '\0'; cp++) {
         if (*cp == '\r' || *cp == '\n')
            *cp = '\0';	/* Remove trailing newline */
      }
      old_idstringlist_len = idstringlist_len;
      idstringlist_len += strlen(line)+1;
      if (idstringlist) {
         idstringlist=Realloc(idstringlist, idstringlist_len);
      } else {
         idstringlist=Malloc(idstringlist_len);
      }
      strcpy(idstringlist+old_idstringlist_len, line);
   }
   fclose(fp);
/*
 *	Create array of pointers to ID strings.
 */
   idstringlist_ptr=Malloc(sizeof(char *) * (line_count+1));
   cp = idstringlist;
   for (i=0; i<line_count; i++) {
      idstringlist_ptr[i] = cp;
      cp += strlen(cp)+1;
   }
   idstringlist_ptr[line_count] = NULL;

   return idstringlist_ptr;
}

/*
 *	decode_trans_simple -- Decode a simple custom transform specification
 *
 *	Inputs:
 *
 *	str	Input transform specification
 *	enc	Output cipher algorithm
 *	keylen	Output cipher key length
 *	hash	Output hash algorithm
 *	auth	Output authentication method
 *	group	Output DH Group
 *
 *	Returns: None
 *
 */
void
decode_trans_simple(const char *trans_str, unsigned *enc, unsigned *keylen,
                    unsigned *hash, unsigned *auth, unsigned *group) {
   char *cp;
   char *str;
   char *tok;
   int pos;	/* 1=enc, 2=hash, 3=auth, 4=group */

/*
 *	Make a copy of the transform string, because strtok modifies it's
 *	argument.
 */
   str = dupstr(trans_str);
/*
 *	Split the transform string into comma-separated tokens, and process
 *	each of these tokens in turn.
 */
   pos = 1;
   tok = strtok(str, ",");
   while (tok != NULL) {
/*
 *	Assign value to the appropraite attribute.
 */
      switch(pos) {
         case 1:
            cp = strchr(tok, '/');
            if (cp != NULL) {
               *keylen = Strtoul(cp+1, 0);
               *cp = '\0';
            } else {
               *keylen = 0;
            }
            *enc=name_or_number(tok, enc_map);
            break;
         case 2:
            *hash=name_or_number(tok, hash_map);
            break;
         case 3:
            *auth=name_or_number(tok, auth_map);
            break;
         case 4:
            *group=Strtoul(tok, 0);
            break;
         default:
            warn_msg("WARNING: Ignoring extra transform specifications past 4th");
            break;
      }
/*
 *	Get next token
 */
      pos++;
      tok = strtok(NULL, "(),");
   }
   free(str);
}

/*
 *	decode_transform -- Decode a custom transform specification
 *
 *	Inputs:
 *
 *	trans_str	Input transform specification
 *	attr_len	Output length of attribute list
 *
 *	Returns: Pointer to attribute list
 *
 */
unsigned char *
decode_transform(const char *trans_str, size_t *attr_len) {
   char *str;
   char *tok;
   char *key_str;
   char *value_str;
   char *cp;
   unsigned key;
   unsigned b_value;		/* Basic attr value */
   unsigned char *v_value;	/* Variable attr value */
   size_t v_len;		/* Variable attr length */
   unsigned char *attr;
/*
 *	Make a copy of the transform string, because strtok modifies it's
 *	argument.
 */
   str = dupstr(trans_str);
/*
 *	Split the transform string into key=value tokens, and process each
 *	of these tokens.
 */
   tok = strtok(str, "(),");
   while (tok != NULL) {
/*
 *	Split token into key and value
 */
      cp = strchr(tok, '=');
      if (cp == NULL)
         err_msg("Error in transform attribute specification: %s", tok);
      key_str = tok;
      value_str = cp+1;
      *cp = '\0';
/*
 *	Construct attribute from key and value.
 *	If the value is a decimal number, then construct a basic attribute,
 *	otherwise construct a variable attribute.
 */
      key = Strtoul(key_str, 10);
      if (value_str[0] == '0' && value_str[1] == 'x') { /* Variable Attribute */
         if (strlen(value_str) %2 )	/* length is odd */
            err_msg("Length of variable attribute value must be even");
         v_value=hex2data(value_str+2, &v_len);
         add_attr(0, NULL, 'V', key, v_len, 0, v_value);
      } else {	/* Basic attribute */
         b_value = Strtoul(value_str, 10);
         add_attr(0, NULL, 'B', key, 0, b_value, NULL);
      }
/*
 *	Get next token
 */
      tok = strtok(NULL, "(),");
   }
/*
 *	Finalise attributes.
 */
   free(str);
   attr = add_attr(1, attr_len, '\0', 0, 0, 0, NULL);
   return attr;
}

/*
 *	usage -- display usage message and exit
 *
 *      Inputs:
 *
 *      status		Status value to pass to exit()
 *	detailed	zero for brief output, non-zero for detailed output
 *
 *	Returns:
 *
 *	None (this function never returns).
 */
void
usage(int status, int detailed) {
   fprintf(stderr, "Usage: ike-scan [options] [hosts...]\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "Target hosts must be specified on the command line unless the --file option is\n");
   fprintf(stderr, "given, in which case the targets are read from the specified file instead.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "The target hosts can be specified as IP addresses or hostnames. You can also\n");
   fprintf(stderr, "specify the target as IPnetwork/bits (e.g. 192.168.1.0/24) to specify all hosts\n");
   fprintf(stderr, "in the given network (network and broadcast addresses included), or\n");
   fprintf(stderr, "IPstart-IPend (e.g. 192.168.1.3-192.168.1.27) to specify all hosts in the\n");
   fprintf(stderr, "inclusive range, or IPnetwork:NetMask (e.g. 192.168.1.0:255.255.255.0) to\n");
   fprintf(stderr, "specify all hosts in the given network and mask.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "These different options for specifying target hosts may be used both on the\n");
   fprintf(stderr, "command line, and also in the file specified with the --file option.\n");
   fprintf(stderr, "\n");
   if (detailed) {
      fprintf(stderr, "In the options below a letter or word in angle brackets like <f> denotes a\n");
      fprintf(stderr, "value or string that should be supplied. The corresponding text should\n");
      fprintf(stderr, "indicate the meaning of this value or string. When supplying the value or\n");
      fprintf(stderr, "string, do not include the angle brackets. Text in square brackets like [<f>]\n");
      fprintf(stderr, "mean that the enclosed text is optional. This is used for options which take\n");
      fprintf(stderr, "an optional argument.\n");
      fprintf(stderr, "\n");
      fprintf(stderr, "Options:\n");
      fprintf(stderr, "\n");
      fprintf(stderr, "--help or -h\t\tDisplay this usage message and exit.\n");
      fprintf(stderr, "\n--file=<fn> or -f <fn>\tRead hostnames or addresses from the specified file\n");
      fprintf(stderr, "\t\t\tinstead of from the command line. One name or IP\n");
      fprintf(stderr, "\t\t\taddress per line.  Use \"-\" for standard input.\n");
      fprintf(stderr, "\n--sport=<p> or -s <p>\tSet UDP source port to <p>, default=%u, 0=random.\n", DEFAULT_SOURCE_PORT);
      fprintf(stderr, "\t\t\tSome IKE implementations require the client to use\n");
      fprintf(stderr, "\t\t\tUDP source port 500 and will not talk to other ports.\n");
      fprintf(stderr, "\t\t\tNote that superuser privileges are normally required\n");
      fprintf(stderr, "\t\t\tto use non-zero source ports below 1024.  Also only\n");
      fprintf(stderr, "\t\t\tone process on a system may bind to a given source port\n");
      fprintf(stderr, "\t\t\tat any one time. Use of the --nat-t option changes\n");
      fprintf(stderr, "\t\t\tthe default source port to %u\n", DEFAULT_NAT_T_SOURCE_PORT);
      fprintf(stderr, "\n--dport=<p> or -d <p>\tSet UDP destination port to <p>, default=%u.\n", DEFAULT_DEST_PORT);
      fprintf(stderr, "\t\t\tUDP port 500 is the assigned port number for ISAKMP\n");
      fprintf(stderr, "\t\t\tand this is the port used by most if not all IKE\n");
      fprintf(stderr, "\t\t\timplementations. Use of the --nat-t option changes\n");
      fprintf(stderr, "\t\t\tthe default destination port to %u\n", DEFAULT_NAT_T_DEST_PORT);
      fprintf(stderr, "\n--retry=<n> or -r <n>\tSet total number of attempts per host to <n>,\n");
      fprintf(stderr, "\t\t\tdefault=%d.\n", DEFAULT_RETRY);
      fprintf(stderr, "\n--timeout=<n> or -t <n>\tSet initial per host timeout to <n> ms, default=%d.\n", DEFAULT_TIMEOUT);
      fprintf(stderr, "\t\t\tThis timeout is for the first packet sent to each host.\n");
      fprintf(stderr, "\t\t\tsubsequent timeouts are multiplied by the backoff\n");
      fprintf(stderr, "\t\t\tfactor which is set with --backoff.\n");
      fprintf(stderr, "\n--bandwidth=<n> or -B <n> Set desired outbound bandwidth to <n>, default=%u\n", DEFAULT_BANDWIDTH);
      fprintf(stderr, "\t\t\tThe value is in bits per second by default.  If you\n");
      fprintf(stderr, "\t\t\tappend \"K\" to the value, then the units are kilobits\n");
      fprintf(stderr, "\t\t\tper second; and if you append \"M\" to the value,\n");
      fprintf(stderr, "\t\t\tthe units are megabits per second.\n");
      fprintf(stderr, "\t\t\tThe \"K\" and \"M\" suffixes represent the decimal, not\n");
      fprintf(stderr, "\t\t\tbinary, multiples.  So 64K is 64000, not 65536.\n");
      fprintf(stderr, "\n--interval=<n> or -i <n> Set minimum packet interval to <n> ms.\n");
      fprintf(stderr, "\t\t\tThe packet interval will be no smaller than this number.\n");
      fprintf(stderr, "\t\t\tThe interval specified is in milliseconds by default.\n");
      fprintf(stderr, "\t\t\tif \"u\" is appended to the value, then the interval\n");
      fprintf(stderr, "\t\t\tis in microseconds, and if \"s\" is appended, the\n");
      fprintf(stderr, "\t\t\tinterval is in seconds.\n");
      fprintf(stderr, "\t\t\tIf you want to use up to a given bandwidth, then it is\n");
      fprintf(stderr, "\t\t\teasier to use the --bandwidth option instead.\n");
      fprintf(stderr, "\t\t\tYou cannot specify both --interval and --bandwidth\n");
      fprintf(stderr, "\t\t\tbecause they are just different ways to change the\n");
      fprintf(stderr, "\t\t\tsame underlying variable.\n");
      fprintf(stderr, "\n--backoff=<b> or -b <b>\tSet timeout backoff factor to <b>, default=%.2f.\n", DEFAULT_BACKOFF_FACTOR);
      fprintf(stderr, "\t\t\tThe per-host timeout is multiplied by this factor\n");
      fprintf(stderr, "\t\t\tafter each timeout.  So, if the number of retries\n");
      fprintf(stderr, "\t\t\tis 3, the initial per-host timeout is 500ms and the\n");
      fprintf(stderr, "\t\t\tbackoff factor is 1.5, then the first timeout will be\n");
      fprintf(stderr, "\t\t\t500ms, the second 750ms and the third 1125ms.\n");
      fprintf(stderr, "\n--verbose or -v\t\tDisplay verbose progress messages.\n");
      fprintf(stderr, "\t\t\tUse more than once for greater effect:\n");
      fprintf(stderr, "\t\t\t1 - Show when each pass is completed and when\n");
      fprintf(stderr, "\t\t\t    packets with invalid cookies are received.\n");
      fprintf(stderr, "\t\t\t2 - Show each packet sent and received and when\n");
      fprintf(stderr, "\t\t\t    hosts are removed from the list.\n");
      fprintf(stderr, "\t\t\t3 - Display the host, Vendor ID and backoff lists\n");
      fprintf(stderr, "\t\t\t    before scanning starts.\n");
      fprintf(stderr, "\n--quiet or -q\t\tDon't decode the returned packet.\n");
      fprintf(stderr, "\t\t\tThis prints less protocol information so the\n");
      fprintf(stderr, "\t\t\toutput lines are shorter.\n");
      fprintf(stderr, "\n--multiline or -M\tSplit the payload decode across multiple lines.\n");
      fprintf(stderr, "\t\t\tWith this option, the decode for each payload is\n");
      fprintf(stderr, "\t\t\tprinted on a separate line starting with a TAB.\n");
      fprintf(stderr, "\t\t\tThis option makes the output easier to read, especially\n");
      fprintf(stderr, "\t\t\twhen there are many payloads.\n");
      fprintf(stderr, "\n--lifetime=<s> or -l <s> Set IKE lifetime to <s> seconds, default=%d.\n", DEFAULT_LIFETIME);
      fprintf(stderr, "\t\t\tRFC 2407 specifies 28800 as the default, but some\n");
      fprintf(stderr, "\t\t\timplementations may require different values.\n");
      fprintf(stderr, "\t\t\tIf you specify this as a a decimal integer, e.g.\n");
      fprintf(stderr, "\t\t\t86400, then the attribute will use a 4-byte value.\n");
      fprintf(stderr, "\t\t\tIf you specify it as a hex number, e.g. 0xFF, then\n");
      fprintf(stderr, "\t\t\tthe attribute will use the appropriate size value\n");
      fprintf(stderr, "\t\t\t(one byte for this example).\n");
      fprintf(stderr, "\t\t\tIf you specify the string \"none\" then no lifetime\n");
      fprintf(stderr, "\t\t\tattribute will be added at all.\n");
      fprintf(stderr, "\t\t\tYou can use this option more than once in conjunction\n");
      fprintf(stderr, "\t\t\twith the --trans options to produce multiple transform\n");
      fprintf(stderr, "\t\t\tpayloads with different lifetimes.  Each --trans option\n");
      fprintf(stderr, "\t\t\twill use the previously specified lifetime value.\n");
      fprintf(stderr, "\n--lifesize=<s> or -z <s> Set IKE lifesize to <s> Kilobytes, default=%d.\n", DEFAULT_LIFESIZE);
      fprintf(stderr, "\t\t\tIf you specify this as a a decimal integer, e.g.\n");
      fprintf(stderr, "\t\t\t86400, then the attribute will use a 4-byte value.\n");
      fprintf(stderr, "\t\t\tIf you specify it as a hex number, e.g. 0xFF, then\n");
      fprintf(stderr, "\t\t\tthe attribute will use the appropriate size value\n");
      fprintf(stderr, "\t\t\t(one byte for this example).\n");
      fprintf(stderr, "\t\t\tYou can use this option more than once in conjunction\n");
      fprintf(stderr, "\t\t\twith the --trans options to produce multiple transform\n");
      fprintf(stderr, "\t\t\tpayloads with different lifesizes.  Each --trans option\n");
      fprintf(stderr, "\t\t\twill use the previously specified lifesize value.\n");
      fprintf(stderr, "\n--auth=<n> or -m <n>\tSet auth. method to <n>, default=%u (%s).\n", DEFAULT_AUTH_METHOD, id_to_name(DEFAULT_AUTH_METHOD, auth_map));
      fprintf(stderr, "\t\t\tRFC defined values are 1 to 5.  See RFC 2409 Appendix A.\n");
      fprintf(stderr, "\t\t\tCheckpoint hybrid mode is 64221.\n");
      fprintf(stderr, "\t\t\tGSS (Windows \"Kerberos\") is 65001.\n");
      fprintf(stderr, "\t\t\tXAUTH uses 65001 to 65010.\n");
      fprintf(stderr, "\t\t\tThis is not applicable to IKEv2.\n");
      fprintf(stderr, "\n--version or -V\t\tDisplay program version and exit.\n");
      fprintf(stderr, "\n--vendor=<v> or -e <v>\tSet vendor id string to hex value <v>.\n");
      fprintf(stderr, "\t\t\tYou can use this option more than once to send\n");
      fprintf(stderr, "\t\t\tmultiple vendor ID payloads.\n");
      fprintf(stderr, "\n--trans=<t> or -a <t>\tUse custom transform <t> instead of default set.\n");
      fprintf(stderr, "\t\t\tYou can use this option more than once to send\n");
      fprintf(stderr, "\t\t\tan arbitrary number of custom transforms.\n");
      fprintf(stderr, "\t\t\tThere are two ways to specify the transform:\n");
      fprintf(stderr, "\t\t\tThe new way, where you specify the attribute/value\n");
      fprintf(stderr, "\t\t\tpairs, and the old way where you specify the values\n");
      fprintf(stderr, "\t\t\tfor a fixed list of attributes.\n");
      fprintf(stderr, "\t\t\tFor the new method, the transform <t> is specified as\n");
      fprintf(stderr, "\t\t\t(attr=value, attr=value, ...)\n");
      fprintf(stderr, "\t\t\tWhere \"attr\" is the attribute number, and \"value\" is\n");
      fprintf(stderr, "\t\t\tthe value to assign to that attribute.\n");
      fprintf(stderr, "\t\t\tFor a basic attribute, specify the value as a decimal\n");
      fprintf(stderr, "\t\t\tnumber; for a variable length attribute, specify the\n");
      fprintf(stderr, "\t\t\tvalue as a hex number prefixed with 0x. You can specify\n");
      fprintf(stderr, "\t\t\tan arbitary number of attribute/value pairs.\n");
      fprintf(stderr, "\t\t\tSee RFC 2409 Appendix A for details of the attributes\n");
      fprintf(stderr, "\t\t\tand values.\n");
      fprintf(stderr, "\t\t\tNote that brackets are special to some shells, so you\n");
      fprintf(stderr, "\t\t\tmay need to quote them, e.g.\n");
      fprintf(stderr, "\t\t\t--trans=\"(1=1,2=2,3=3,4=4)\". For example,\n");
      fprintf(stderr, "\t\t\t--trans=(1=1,2=2,3=1,4=2) specifies\n");
      fprintf(stderr, "\t\t\tEnc=DES-CBC, Hash=SHA1, Auth=shared key, DH Group=2;\n");
      fprintf(stderr, "\t\t\t--trans=(1=7,14=128,2=1,3=3,4=5) specifies\n");
      fprintf(stderr, "\t\t\tEnc=AES/128, Hash=MD5, Auth=RSA sig, DH Group=5 and\n");
      fprintf(stderr, "\t\t\t--trans=(1=5,2=1,3=1,4=1,11=1,12=0x00007080) specifies\n");
      fprintf(stderr, "\t\t\tEnc=3DES-CBC, Hash=MD5, Auth=shared key, DH Group=1,\n");
      fprintf(stderr, "\t\t\tLifetime=28800 seconds as a 4-byte variable attribute.\n");
      fprintf(stderr, "\t\t\tFor the old method, the transform <t> is specified as\n");
      fprintf(stderr, "\t\t\tenc[/len],hash,auth,group.\n");
      fprintf(stderr, "\t\t\tWhere enc is the encryption algorithm,\n");
      fprintf(stderr, "\t\t\tlen is the key length for variable length ciphers,\n");
      fprintf(stderr, "\t\t\thash is the hash algorithm, and group is the DH Group.\n");
      fprintf(stderr, "\t\t\tFor example, --trans=5,2,1,2 specifies\n");
      fprintf(stderr, "\t\t\tEnc=3DES-CBC, Hash=SHA1, Auth=shared key, DH Group=2;\n");
      fprintf(stderr, "\t\t\tand --trans=7/256,1,1,5 specifies\n");
      fprintf(stderr, "\t\t\tEnc=AES-256, Hash=MD5, Auth=shared key, DH Group=5.\n");
      fprintf(stderr, "\t\t\tThis option is not yet supported for IKEv2.\n");
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
      fprintf(stderr, "\t\t\tAny per-pattern-entry fuzz specifications in the\n");
      fprintf(stderr, "\t\t\tpatterns file will override the value set here.\n");
   #ifdef __CYGWIN__
      fprintf(stderr, "\n--patterns=<f> or -p <f> Use IKE backoff patterns file <f>,\n");
      fprintf(stderr, "\t\t\tdefault=%s in ike-scan.exe dir.\n", PATTERNS_FILE);
   #else
      fprintf(stderr, "\n--patterns=<f> or -p <f> Use IKE backoff patterns file <f>,\n");
      fprintf(stderr, "\t\t\tdefault=%s/%s.\n", IKEDATADIR, PATTERNS_FILE);
   #endif
      fprintf(stderr, "\t\t\tThis specifies the name of the file containing\n");
      fprintf(stderr, "\t\t\tIKE backoff patterns.  This file is only used when\n");
      fprintf(stderr, "\t\t\t--showbackoff is specified.\n");
   #ifdef __CYGWIN__
      fprintf(stderr, "\n--vidpatterns=<f> or -I <f> Use Vendor ID patterns file <f>,\n");
      fprintf(stderr, "\t\t\tdefault=%s in ike-scan.exe dir.\n", VID_FILE);
   #else
      fprintf(stderr, "\n--vidpatterns=<f> or -I <f> Use Vendor ID patterns file <f>,\n");
      fprintf(stderr, "\t\t\tdefault=%s/%s.\n", IKEDATADIR, VID_FILE);
   #endif
      fprintf(stderr, "\t\t\tThis specifies the name of the file containing\n");
      fprintf(stderr, "\t\t\tVendor ID patterns.  These patterns are used for\n");
      fprintf(stderr, "\t\t\tVendor ID fingerprinting.\n");
      fprintf(stderr, "\n--aggressive or -A\tUse IKE Aggressive Mode (The default is Main Mode)\n");
      fprintf(stderr, "\t\t\tIf you specify --aggressive, then you may also\n");
      fprintf(stderr, "\t\t\tspecify --dhgroup, --id and --idtype.  If you use\n");
      fprintf(stderr, "\t\t\tcustom transforms with aggressive mode with the --trans\n");
      fprintf(stderr, "\t\t\toption, note that all transforms should have the same\n");
      fprintf(stderr, "\t\t\tDH Group and this should match the group specified\n");
      fprintf(stderr, "\t\t\twith --dhgroup or the default if --dhgroup is not used.\n");
      fprintf(stderr, "\n--id=<id> or -n <id>\tUse <id> as the identification value.\n");
      fprintf(stderr, "\t\t\tThis option is only applicable to Aggressive Mode.\n");
      fprintf(stderr, "\t\t\t<id> can be specified as a string, e.g. --id=test or as\n");
      fprintf(stderr, "\t\t\ta hex value with a leading \"0x\", e.g. --id=0xdeadbeef.\n");
      fprintf(stderr, "\n--idtype=<n> or -y <n>\tUse identification type <n>.  Default %u (%s).\n", DEFAULT_IDTYPE, id_to_name(DEFAULT_IDTYPE, id_map));
      fprintf(stderr, "\t\t\tThis option is only applicable to Aggressive Mode.\n");
      fprintf(stderr, "\t\t\tSee RFC 2407 4.6.2 for details of Identification types.\n");
      fprintf(stderr, "\n--dhgroup=<n> or -g <n>\tUse Diffie Hellman Group <n>.  Default %u.\n", DEFAULT_DH_GROUP);
      fprintf(stderr, "\t\t\tThis option is only applicable to Aggressive Mode and\n");
      fprintf(stderr, "\t\t\tIKEv2.  For both of these, it is used to determine the\n");
      fprintf(stderr, "\t\t\tsize of the key exchange payload.\n");
      fprintf(stderr, "\t\t\tIf you use Aggressive Mode with custom transforms, then\n");
      fprintf(stderr, "\t\t\tyou will normally need to use the --dhgroup option\n");
      fprintf(stderr, "\t\t\tunless you are using the default DH group.\n");
      fprintf(stderr, "\t\t\tAcceptable values are 1,2,5,14,15,16,17,18,19,20,21.\n");
      fprintf(stderr, "\n--gssid=<n> or -G <n>\tUse GSS ID <n> where <n> is a hex string.\n");
      fprintf(stderr, "\t\t\tThis uses transform attribute type 16384 as specified\n");
      fprintf(stderr, "\t\t\tin draft-ietf-ipsec-isakmp-gss-auth-07.txt, although\n");
      fprintf(stderr, "\t\t\tWindows-2000 has been observed to use 32001 as well.\n");
      fprintf(stderr, "\t\t\tFor Windows 2000, you'll need to use --auth=65001 to\n");
      fprintf(stderr, "\t\t\tspecify Kerberos (GSS) authentication.\n");
      fprintf(stderr, "\n--random or -R\t\tRandomise the host list.\n");
      fprintf(stderr, "\t\t\tThis option randomises the order of the hosts in the\n");
      fprintf(stderr, "\t\t\thost list, so the IKE probes are sent to the hosts in\n");
      fprintf(stderr, "\t\t\ta random order.  It uses the Knuth shuffle algorithm.\n");
      fprintf(stderr, "\n--tcp[=<n>] or -T[<n>]\tUse TCP transport instead of UDP.\n");
      fprintf(stderr, "\t\t\tThis allows you to test a host running IKE over TCP.\n");
      fprintf(stderr, "\t\t\tYou won't normally need this option because the vast\n");
      fprintf(stderr, "\t\t\tmajority of IPsec systems only support IKE over UDP.\n");
      fprintf(stderr, "\t\t\tThe optional value <n> specifies the type of IKE over\n");
      fprintf(stderr, "\t\t\tTCP.  There are currently two possible values:\n");
      fprintf(stderr, "\t\t\t1 = RAW IKE over TCP as used by Checkpoint (default);\n");
      fprintf(stderr, "\t\t\t2 = Encapsulated IKE over TCP as used by Cisco.\n");
      fprintf(stderr, "\t\t\tIf you are using the short form of the option (-T)\n");
      fprintf(stderr, "\t\t\tthen the value must immediately follow the option\n");
      fprintf(stderr, "\t\t\tletter with no spaces, e.g. -T2 not -T 2.\n");
      fprintf(stderr, "\t\t\tYou can only specify a single target host if you use\n");
      fprintf(stderr, "\t\t\tthis option.\n");
      fprintf(stderr, "\n--tcptimeout=<n> or -O <n> Set TCP connect timeout to <n> seconds (default=%u).\n", DEFAULT_TCP_CONNECT_TIMEOUT);
      fprintf(stderr, "\t\t\tThis is only applicable to TCP transport mode.\n");
      fprintf(stderr, "\n--pskcrack[=<f>] or -P[<f>] Crack aggressive mode pre-shared keys.\n");
      fprintf(stderr, "\t\t\tThis option outputs the aggressive mode pre-shared key\n");
      fprintf(stderr, "\t\t\t(PSK) parameters for offline cracking using the\n");
      fprintf(stderr, "\t\t\t\"psk-crack\" program that is supplied with ike-scan.\n");
      fprintf(stderr, "\t\t\tYou can optionally specify a filename, <f>, to write\n");
      fprintf(stderr, "\t\t\tthe PSK parameters to.  If you do not specify a filename\n");
      fprintf(stderr, "\t\t\tthen the PSK parameters are written to standard output.\n");
      fprintf(stderr, "\t\t\tIf you are using the short form of the option (-P)\n");
      fprintf(stderr, "\t\t\tthen the value must immediately follow the option\n");
      fprintf(stderr, "\t\t\tletter with no spaces, e.g. -Pfile not -P file.\n");
      fprintf(stderr, "\t\t\tYou can only specify a single target host if you use\n");
      fprintf(stderr, "\t\t\tthis option.\n");
      fprintf(stderr, "\t\t\tThis option is only applicable to IKE aggressive mode.\n");
      fprintf(stderr, "\n--nodns or -N\t\tDo not use DNS to resolve names.\n");
      fprintf(stderr, "\t\t\tIf you use this option, then all hosts must be\n");
      fprintf(stderr, "\t\t\tspecified as IP addresses.\n");
      fprintf(stderr, "\n--noncelen=<n> or -c <n> Set the nonce length to <n> bytes. Default=%u\n", DEFAULT_NONCE_LEN);
      fprintf(stderr, "\t\t\tThis option controls the length of the nonce payload\n");
      fprintf(stderr, "\t\t\tthat is sent in an aggressive mode or IKEv2 request.\n");
      fprintf(stderr, "\t\t\tNormally there is no need to use this option unless you\n");
      fprintf(stderr, "\t\t\twant to reduce the nonce size to speed up pre-shared\n");
      fprintf(stderr, "\t\t\tkey cracking, or if you want to see how a particular\n");
      fprintf(stderr, "\t\t\tserver handles different length nonce payloads.\n");
      fprintf(stderr, "\t\t\tRFC 2409 states that the length of nonce payload\n");
      fprintf(stderr, "\t\t\tmust be between 8 and 256 bytes, but ike-scan does\n");
      fprintf(stderr, "\t\t\tnot enforce this.\n");
      fprintf(stderr, "\t\t\tSpecifying a large nonce length will increase the\n");
      fprintf(stderr, "\t\t\tsize of the packet sent by ike-scan. A very large nonce\n");
      fprintf(stderr, "\t\t\tlength may cause fragmentation, or exceed the maximum\n");
      fprintf(stderr, "\t\t\tIP packet size.\n");
      fprintf(stderr, "\t\t\tThis option is only applicable to IKE aggressive mode.\n");
      fprintf(stderr, "\n--headerlen=<n> or -L <n> Set the length in the ISAKMP header to <n> bytes.\n");
      fprintf(stderr, "\t\t\tYou can use this option to manually specify the value\n");
      fprintf(stderr, "\t\t\tto be used for the ISAKMP header length.\n");
      fprintf(stderr, "\t\t\tBy default, ike-scan will fill in the correct value.\n");
      fprintf(stderr, "\t\t\tUse this option to manually specify an incorrect\n");
      fprintf(stderr, "\t\t\tlength.\n");
      fprintf(stderr, "\t\t\t<n> can be specified as \"+n\" which sets the length\n");
      fprintf(stderr, "\t\t\tto n bytes more than it should be, \"-n\" which sets\n");
      fprintf(stderr, "\t\t\tit to n bytes less, or \"n\" which sets it to exactly\n");
      fprintf(stderr, "\t\t\tbytes.\n");
      fprintf(stderr, "\t\t\tChanging the header length to an incorrect value can\n");
      fprintf(stderr, "\t\t\tsometimes disrupt VPN servers.\n");
      fprintf(stderr, "\n--mbz=<n> or -Z <n>\tUse the value <n> for reserved (MBZ) fields, default=0.\n");
      fprintf(stderr, "\t\t\tSpecifying this option makes the outgoing packet\n");
      fprintf(stderr, "\t\t\tnon-RFC compliant, and should only be used if you want\n");
      fprintf(stderr, "\t\t\tto see how a VPN server will respond to invalid packets.\n");
      fprintf(stderr, "\t\t\tThe value of <n> should be in the range 0-255.\n");
      fprintf(stderr, "\n--headerver=<n> or -E <n> Specify the ISAKMP header version.\n");
      fprintf(stderr, "\t\t\tThe default is 0x10 (16) which corresponds to v1.0.\n");
      fprintf(stderr, "\t\t\tSpecifying a non-default value will make the outgoing\n");
      fprintf(stderr, "\t\t\tpacket non-RFC compliant, and should only be used if\n");
      fprintf(stderr, "\t\t\tyou want to see how the VPN server reacts to strange\n");
      fprintf(stderr, "\t\t\tversions.\n");
      fprintf(stderr, "\t\t\tThe value should be in the range 0-255.\n");
      fprintf(stderr, "\n--certreq=<c> or -C <c> Add the CertificateRequest payload <c>.\n");
      fprintf(stderr, "\t\t\t<c> should be specified as a hex value.\n");
      fprintf(stderr, "\t\t\tThe first byte of the hex value will be interpreted as\n");
      fprintf(stderr, "\t\t\tthe certificate type; the remaining bytes as the\n");
      fprintf(stderr, "\t\t\tcertificate authority as described in RFC 2408 3.10.\n");
      fprintf(stderr, "\t\t\tThe certificate types are listed in RFC 2408 sec 3.9.\n");
      fprintf(stderr, "\t\t\tRFC 2408 states \"The Certificate Request payload MUST\n");
      fprintf(stderr, "\t\t\tbe accepted at any point during the exchange\"\n");
      fprintf(stderr, "\n--doi=<d> or -D <d>\tSet the SA DOI to <d>, default %u (%s).\n", DEFAULT_DOI, id_to_name(DEFAULT_DOI, doi_map));
      fprintf(stderr, "\t\t\tYou will not normally want to change this unless you\n");
      fprintf(stderr, "\t\t\twant to see how the VPN server responds to a\n");
      fprintf(stderr, "\t\t\tnon-standard DOI.\n");
      fprintf(stderr, "\n--situation=<s> or -S <s> Set the SA Situation to <d>, default %u.\n", DEFAULT_SITUATION);
      fprintf(stderr, "\t\t\tThe meaning of the situation depends on the DOI, and\n");
      fprintf(stderr, "\t\t\tis detailed in the appropriate DOI document.  For the\n");
      fprintf(stderr, "\t\t\tIPsec DOI, the default Situation of %u represents\n", DEFAULT_SITUATION);
      fprintf(stderr, "\t\t\tSIT_IDENTITY_ONLY.\n");
      fprintf(stderr, "\t\t\tYou will not normally want to change this unless you\n");
      fprintf(stderr, "\t\t\twant to see how the VPN server responds to a\n");
      fprintf(stderr, "\t\t\tnon-standard situation.\n");
      fprintf(stderr, "\n--protocol=<p> or -j <p> Set the Proposal protocol ID to <p>, default %u.\n", DEFAULT_PROTOCOL);
      fprintf(stderr, "\t\t\tThe meaning of the proposal protocol ID depends on\n");
      fprintf(stderr, "\t\t\tthe DOI, and is detailed in the appropriate DOI\n");
      fprintf(stderr, "\t\t\tdocument.  For the IPsec DOI, the default proposal\n");
      fprintf(stderr, "\t\t\tprotocol id of %u represents %s.\n", DEFAULT_PROTOCOL, id_to_name(DEFAULT_PROTOCOL, protocol_map));
      fprintf(stderr, "\t\t\tYou will not normally want to change this unless you\n");
      fprintf(stderr, "\t\t\twant to see how the VPN server responds to a\n");
      fprintf(stderr, "\t\t\tnon-standard protocol ID.\n");
      fprintf(stderr, "\n--transid=<t> or -k <t> Set the Transform ID to <t>, default %u.\n", DEFAULT_TRANS_ID);
      fprintf(stderr, "\t\t\tThe meaning of the transform ID depends on the\n");
      fprintf(stderr, "\t\t\tDOI, and is detailed in the appropriate DOI\n");
      fprintf(stderr, "\t\t\tdocument.  For the IPsec DOI, the default\n");
      fprintf(stderr, "\t\t\ttransform id of %u represents KEY_IKE.\n", DEFAULT_TRANS_ID);
      fprintf(stderr, "\t\t\tYou will not normally want to change this unless you\n");
      fprintf(stderr, "\t\t\twant to see how the VPN server responds to a\n");
      fprintf(stderr, "\t\t\tnon-standard transform ID.\n");
      fprintf(stderr, "\n--spisize=<n>\t\tSet the proposal SPI size to <n>.  Default=0\n");
      fprintf(stderr, "\t\t\tIf this is non-zero, then a random SPI of the\n");
      fprintf(stderr, "\t\t\tspecified size will be added to the proposal payload.\n");
      fprintf(stderr, "\t\t\tThe default of zero means no SPI.\n");
      fprintf(stderr, "\n--hdrflags=<n>\t\tSet the ISAKMP header flags to <n>.  Default=0\n");
      fprintf(stderr, "\t\t\tThe flags are detailed in RFC 2408 section 3.1\n");
      fprintf(stderr, "\n--hdrmsgid=<n>\t\tSet the ISAKMP header message ID to <n>.  Default=0\n");
      fprintf(stderr, "\t\t\tThis should be zero for IKE Phase-1.\n");
      fprintf(stderr, "\n--cookie=<n>\t\tSet the ISAKMP initiator cookie to <n>\n");
      fprintf(stderr, "\t\t\tThe cookie value should be specified in hex.\n");
      fprintf(stderr, "\t\t\tBy default, the cookies are automatically generated\n");
      fprintf(stderr, "\t\t\tand have unique values.  If you specify this option,\n");
      fprintf(stderr, "\t\t\tthen you can only specify a single target, because\n");
      fprintf(stderr, "\t\t\tike-scan requires unique cookie values to match up\n");
      fprintf(stderr, "\t\t\tthe response packets.\n");
      fprintf(stderr, "\n--exchange=<n>\t\tSet the exchange type to <n>\n");
      fprintf(stderr, "\t\t\tThis option allows you to change the exchange type in\n");
      fprintf(stderr, "\t\t\tthe ISAKMP header to an arbitrary value.\n");
      fprintf(stderr, "\t\t\tNote that ike-scan only supports Main and Aggressive\n");
      fprintf(stderr, "\t\t\tmodes (values 2 and 4 respectively).  Specifying\n");
      fprintf(stderr, "\t\t\tother values will change the exchange type value in\n");
      fprintf(stderr, "\t\t\tthe ISAKMP header, but will not adjust the other\n");
      fprintf(stderr, "\t\t\tpayloads.\n");
      fprintf(stderr, "\t\t\tThe exchange types are defined in RFC 2408 sec 3.1.\n");
      fprintf(stderr, "\n--nextpayload=<n>\tSet the next payload in the ISAKMP header to <n>\n");
      fprintf(stderr, "\t\t\tNormally, the next payload is automatically set to the\n");
      fprintf(stderr, "\t\t\tcorrect value.\n");
      fprintf(stderr, "\n--randomseed=<n>\tUse <n> to seed the pseudo random number generator.\n");
      fprintf(stderr, "\t\t\tThis option seeds the PRNG with the specified number,\n");
      fprintf(stderr, "\t\t\twhich can be useful if you want to ensure that the\n");
      fprintf(stderr, "\t\t\tpacket data is exactly repeatable when it includes\n");
      fprintf(stderr, "\t\t\tpayloads with random data such as key exchange or nonce.\n");
      fprintf(stderr, "\t\t\tBy default, the PRNG is seeded with an unpredictable\n");
      fprintf(stderr, "\t\t\tvalue.\n");
      fprintf(stderr, "\n--timestamp\t\tDisplay timestamps for received packets.\n");
      fprintf(stderr, "\t\t\tThis option causes a timestamp to be displayed for\n");
      fprintf(stderr, "\t\t\teach received packet.\n");
      fprintf(stderr, "\n--sourceip=<s>\t\tSet source IP address for outgoing packets to <s>.\n");
      fprintf(stderr, "\t\t\tThis option causes the outgoing IKE packets to have\n");
      fprintf(stderr, "\t\t\tthe specified source IP address.\n");
      fprintf(stderr, "\t\t\tThe address can either be an IP address in dotted\n");
      fprintf(stderr, "\t\t\tquad format, or the string \"random\" which will use\n");
      fprintf(stderr, "\t\t\ta different random source address for each packet that\n");
      fprintf(stderr, "\t\t\tis sent.\n");
      fprintf(stderr, "\t\t\tIf this option is used, no packets will be received\n");
      fprintf(stderr, "\t\t\tThis option requires raw socket support, and you\n");
      fprintf(stderr, "\t\t\twill need superuser privileges to use this option,\n");
      fprintf(stderr, "\t\t\teven if you specify a high source port.\n");
      fprintf(stderr, "\t\t\tThis option does not work on all operating systems.\n");
      fprintf(stderr, "\n--bindip=<s>\t\tSet the IP address to bind to.\n");
      fprintf(stderr, "\t\t\tThis option causes the outgoing IKE packets to originate\n");
      fprintf(stderr, "\t\t\tfrom <s>, and this address will also be used to receive\n");
      fprintf(stderr, "\t\t\tresponses from the target.\n");
      fprintf(stderr, "\n--shownum\t\tDisplay the host number for received packets.\n");
      fprintf(stderr, "\t\t\tThis displays the ordinal host number of the\n");
      fprintf(stderr, "\t\t\tresponding host before the IP address. It can be useful\n");
      fprintf(stderr, "\t\t\twhen sending many packets to the same target IP, to\n");
      fprintf(stderr, "\t\t\tsee if any probes are being ignored.\n");
      fprintf(stderr, "\n--nat-t\t\t\tUse RFC 3947 NAT-Traversal encapsulation.\n");
      fprintf(stderr, "\t\t\tThis option adds the non-ESP marker to the beginning\n");
      fprintf(stderr, "\t\t\tof outgoing packets and strips it from received\n");
      fprintf(stderr, "\t\t\tpackets, as described in RFC 3947. It also changes the\n");
      fprintf(stderr, "\t\t\tdefault source port to %u and the default destination\n", DEFAULT_NAT_T_SOURCE_PORT);
      fprintf(stderr, "\t\t\tport to %u, which are the ports for NAT-T IKE.\n", DEFAULT_NAT_T_DEST_PORT);
      fprintf(stderr, "\t\t\tThese port numbers can be changed with the --sport and\n");
      fprintf(stderr, "\t\t\t--dport options, providing they are used after the\n");
      fprintf(stderr, "\t\t\t--nat-t option.\n");
      fprintf(stderr, "\n--rcookie=<n>\t\tSet the ISAKMP responder cookie to <n>.\n");
      fprintf(stderr, "\t\t\tThis sets the responder cookie to the specified hex\n");
      fprintf(stderr, "\t\t\tvalue.  By default, the responder cookie is set to zero.\n");
      fprintf(stderr, "\n--ikev2 or -2\t\tUse IKE version 2\n");
      fprintf(stderr, "\t\t\tThis causes the outgoing packets to use IKEv2 format\n");
      fprintf(stderr, "\t\t\tas defined in RFC 4306 instead of the default IKEv1\n");
      fprintf(stderr, "\t\t\tformat. Any packets returned are automatically decoded\n");
      fprintf(stderr, "\t\t\tas IKE or IKEv2 depending on their payloads irrespective\n");
      fprintf(stderr, "\t\t\tof this option.\n");
      fprintf(stderr, "\t\t\tThe --ikev2 option is currently experimental. It has not\n");
      fprintf(stderr, "\t\t\tbeen extensively tested, and it only supports sending\n");
      fprintf(stderr, "\t\t\tthe default proposal.\n");
   } else {
      fprintf(stderr, "use \"ike-scan --help\" for detailed information on the available options.\n");
   }
   fprintf(stderr, "\n");
   fprintf(stderr, "Report bugs or send suggestions at %s\n", PACKAGE_BUGREPORT);
   fprintf(stderr, "See the ike-scan homepage at http://www.nta-monitor.com/tools/ike-scan/\n");
   exit(status);
}
