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
 * psk-crack.c -- IKE Aggressive Mode Pre-Shared Key cracker for ike-scan
 *
 * Author: Roy Hills
 * Date: 8 July 2004
 *
 * Usage:
 *	psk-crack <psk-parameters-file> <dictionary-file>
 *
 */
#include "ike-scan.h"
static const char rcsid[] = "$Id$";	/* RCS ID for ident(1) */

#define MAXLEN 4096
#define HASH_TYPE_AUTO 0
#define HASH_TYPE_MD5 1
#define HASH_TYPE_SHA1 2
#define MD5_HASH_LEN 16
#define SHA1_HASH_LEN 20

int
main (int argc, char *argv[]) {
   const struct option long_options[] = {
      {"help", no_argument, 0, 'h'},
      {"verbose", no_argument, 0, 'v'},
      {"version", no_argument, 0, 'V'},
      {"md5", no_argument, 0, 'm'},
      {"sha1", no_argument, 0, 's'},
      {0, 0, 0, 0}
   };
   const char *short_options = "hvVms";
   int arg;
   int options_index=0;
   int verbose=0;
   int hash_type=HASH_TYPE_AUTO;	/* Hash type: Auto, MD5 or SHA1 */
   size_t hash_len=0;	/* Set to 0 to avoid uninitialised warning */
   char *hash_name=NULL; /* Hash name: MD5 or SHA1 */

   FILE *dictionary_file;	/* Dictionary file, one word per line */
   FILE *data_file;	/* PSK parameters in colon separated format */
   int iterations=0;
   int found=0;
   struct timeval start_time;	/* Program start time */
   struct timeval end_time;	/* Program end time */
   struct timeval elapsed_time; /* Elapsed time as timeval */
   double elapsed_seconds;	/* Elapsed time in seconds */
   int n;

   char g_xr_hex[MAXLEN];
   char g_xi_hex[MAXLEN];
   char cky_r_hex[MAXLEN];
   char cky_i_hex[MAXLEN];
   char sai_b_hex[MAXLEN];
   char idir_b_hex[MAXLEN];
   char ni_b_hex[MAXLEN];
   char nr_b_hex[MAXLEN];
   char expected_hash_r_hex[MAXLEN];

   unsigned char *g_xr;
   unsigned char *g_xi;
   unsigned char *cky_r;
   unsigned char *cky_i;
   unsigned char *sai_b;
   unsigned char *idir_b;
   unsigned char *ni_b;
   unsigned char *nr_b;

   size_t g_xr_len;
   size_t g_xi_len;
   size_t cky_r_len;
   size_t cky_i_len;
   size_t sai_b_len;
   size_t idir_b_len;
   size_t ni_b_len;
   size_t nr_b_len;
   size_t expected_hash_r_len;

   unsigned char *skeyid;
   unsigned char *hash_r;
   unsigned char *expected_hash_r;

   char *hash_r_hex;

   unsigned char *skeyid_data;
   unsigned char *hash_r_data;

   size_t skeyid_data_len;
   size_t hash_r_data_len;

   unsigned char *cp;

   char line[MAXLINE];
   char psk_data[MAXLEN];

/*
 *      Process options and arguments.
 */
   while ((arg=getopt_long_only(argc, argv, short_options, long_options, &options_index)) != -1) {
      switch (arg) {
         case 'h':      /* --help */
            psk_crack_usage(EXIT_SUCCESS);
            break;
         case 'v':      /* --verbose */
            verbose++;
            break;
         case 'V':      /* --version */
            fprintf(stderr, "psk-crack (%s)\n\n", PACKAGE_STRING);
            fprintf(stderr, "Copyright (C) 2003-2004 Roy Hills, NTA Monitor Ltd.\n");
            fprintf(stderr, "ike-scan comes with NO WARRANTY to the extent permitted by law.\n");
            fprintf(stderr, "You may redistribute copies of ike-scan under the terms of the GNU\n");
            fprintf(stderr, "General Public License.\n");
            fprintf(stderr, "For more information about these matters, see the file named COPYING.\n");
            fprintf(stderr, "\n");
/* We use rcsid here to prevent it being optimised away */
            fprintf(stderr, "%s\n", rcsid);
            error_use_rcsid();
            utils_use_rcsid();
            wrappers_use_rcsid();
            exit(EXIT_SUCCESS);
            break;
         case 'm':      /* --md5 */
            hash_type=HASH_TYPE_MD5;
            hash_len=MD5_HASH_LEN;
            hash_name="MD5";
            break;
         case 's':      /* --sha1 */
            hash_type=HASH_TYPE_SHA1;
            hash_len=SHA1_HASH_LEN;
            hash_name="SHA1";
            break;
         default:       /* Unknown option */
            psk_crack_usage(EXIT_FAILURE);
            break;
      }
   } /* End While */

   if ((argc - optind) < 2) {
      psk_crack_usage(EXIT_FAILURE);
   }
/*
 *	Open data files.
 */
   if ((data_file = fopen(argv[optind], "r")) == NULL)
      err_sys("fopen data file");
   if ((dictionary_file = fopen(argv[optind+1], "r")) == NULL)
      err_sys("fopen dictionary file");

   fgets(psk_data, MAXLEN, data_file);

   n=sscanf(psk_data,
            "%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:\r\n]",
            g_xr_hex, g_xi_hex, cky_r_hex, cky_i_hex, sai_b_hex,
            idir_b_hex, ni_b_hex, nr_b_hex, expected_hash_r_hex);

   if (n != 9)
      err_msg("Error in data format.  Expected 9 fields, found %d", n);
/*
 *	Convert input fields from ASCII hex to binary.
 */
   g_xr = hex2data(g_xr_hex, &g_xr_len);
   g_xi = hex2data(g_xi_hex, &g_xi_len);
   cky_r = hex2data(cky_r_hex, &cky_r_len);
   cky_i = hex2data(cky_i_hex, &cky_i_len);
   sai_b = hex2data(sai_b_hex, &sai_b_len);
   idir_b = hex2data(idir_b_hex, &idir_b_len);
   ni_b = hex2data(ni_b_hex, &ni_b_len);
   nr_b = hex2data(nr_b_hex, &nr_b_len);
   expected_hash_r = hex2data(expected_hash_r_hex, &expected_hash_r_len);
/*
 *	If the hash type has not been specified, determine it from the
 *	length of the HASH_R payload.
 */
   if (hash_type == HASH_TYPE_AUTO) {
      if (expected_hash_r_len == MD5_HASH_LEN) {
         hash_type=HASH_TYPE_MD5;
         hash_len=MD5_HASH_LEN;
         hash_name="MD5";
      } else if (expected_hash_r_len == SHA1_HASH_LEN) {
         hash_type=HASH_TYPE_SHA1;
         hash_len=SHA1_HASH_LEN;
         hash_name="SHA1";
      } else {
         err_msg("Cannot determine hash type from %u byte HASH_R",
                 expected_hash_r_len);
      }
   }

   skeyid_data_len = ni_b_len + nr_b_len;
   skeyid_data = Malloc(skeyid_data_len);
   cp = skeyid_data;
   memcpy(cp, ni_b, ni_b_len);
   cp += ni_b_len;
   memcpy(cp, nr_b, nr_b_len);
   skeyid = Malloc(hash_len);
   hash_r_data_len = g_xr_len + g_xi_len + cky_r_len + cky_i_len + sai_b_len +
                     idir_b_len;
   hash_r_data = Malloc(hash_r_data_len);
   cp = hash_r_data;
   memcpy(cp, g_xr, g_xr_len);
   cp += g_xr_len;
   memcpy(cp, g_xi, g_xi_len);
   cp += g_xi_len;
   memcpy(cp, cky_r, cky_r_len);
   cp += cky_r_len;
   memcpy(cp, cky_i, cky_i_len);
   cp += cky_i_len;
   memcpy(cp, sai_b, sai_b_len);
   cp += sai_b_len;
   memcpy(cp, idir_b, idir_b_len);
   hash_r = Malloc(hash_len);
/*
 *	Get program start time for statistics displayed on completion
 *	and print starting message.
 */
   Gettimeofday(&start_time);
   printf("Starting psk-crack\n");
/*
 *	Cracking loop.
 */
   while (fgets(line, MAXLINE, dictionary_file)) {
      char *line_p;
      for (line_p = line; !isspace(*line_p) && *line_p != '\0'; line_p++)
         ;
      *line_p = '\0';
      if (hash_type == HASH_TYPE_MD5) {
         hmac_md5(skeyid_data, skeyid_data_len, line, strlen(line), skeyid);
         hmac_md5(hash_r_data, hash_r_data_len, skeyid, hash_len, hash_r);
      } else if (hash_type == HASH_TYPE_SHA1) {
         hmac_sha1(skeyid_data, skeyid_data_len, line, strlen(line), skeyid);
         hmac_sha1(hash_r_data, hash_r_data_len, skeyid, hash_len, hash_r);
      } else {
         err_msg("Unknown hash_type: %d\n", hash_type);
      }
      iterations++;
      if (!memcmp(hash_r, expected_hash_r, expected_hash_r_len)) {
         found=1;
         break;
      }
   }
/*
 *      Get program end time and calculate elapsed time.
 */
   Gettimeofday(&end_time);
   timeval_diff(&end_time, &start_time, &elapsed_time);
   elapsed_seconds = (elapsed_time.tv_sec*1000 +
                      elapsed_time.tv_usec/1000.0) / 1000.0;
   if (found) {
      hash_r_hex = hexstring(hash_r, hash_len);
      printf("key \"%s\" matches %s hash %s\n", line, hash_name, hash_r_hex);
      free(hash_r_hex);
   } else {
      printf("no match found\n");
   }
   printf("Ending psk-crack: %d iterations in %.3f seconds (%.2f iterations/sec)\n",
          iterations, elapsed_seconds, iterations/elapsed_seconds);
   fclose(data_file);
   fclose(dictionary_file);

   return 0;
}

/*
 *	psk_crack_usage -- display usage message and exit
 *
 *      Inputs:
 *
 *      status	Status value to pass to exit()
 *
 *	Returns:
 *
 *	None (this function never returns).
 */
void
psk_crack_usage(int status) {
   fprintf(stderr, "Usage: psk-crack [options] <psk-parameters-file> <dictionary-file>\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "<psk-parameters-file> is a file containing the parameters for the pre-shared\n");
   fprintf(stderr, "key cracking process in the format:\n");
   fprintf(stderr, "g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "<dictionary-file> is a file containing the words to check with one word on each\n");
   fprintf(stderr, "line.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "Options:\n");
   fprintf(stderr, "\n--help or -h\t\tDisplay this usage message and exit.\n");
   fprintf(stderr, "\n--version or -V\t\tDisplay program version and exit.\n");
   fprintf(stderr, "\n--md5 or -m\t\tForce MD5 hash type.\n");
   fprintf(stderr, "\t\t\tNormally this is not required because the hash type\n");
   fprintf(stderr, "\t\t\tis automatically determined from the hash length.\n");
   fprintf(stderr, "\n--sha1 or -s\t\tForce SHA1 hash type.\n");
   fprintf(stderr, "\t\t\tNormally this is not required because the hash type\n");
   fprintf(stderr, "\t\t\tis automatically determined from the hash length.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "Report bugs or send suggestions to %s\n", PACKAGE_BUGREPORT);
   fprintf(stderr, "See the ike-scan homepage at http://www.nta-monitor.com/ike-scan/\n");
   exit(status);
}
