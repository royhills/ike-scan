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
#define MAXLEN 4096

int
main (int argc, char *argv[]) {
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

   if (argc != 3) {
      printf("Usage psk-crack <psk-parameters-file> <dictionary-file>\n");
      printf("\n");
      printf("psk-paramaters-file: g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r\n");
      printf("dictionary file: one word per line\n");
      exit(1);
   }

   if ((data_file = fopen(argv[1], "r")) == NULL) {
      perror("fopen");
      exit(1);
   }
   if ((dictionary_file = fopen(argv[2], "r")) == NULL) {
      perror("fopen");
      exit(1);
   }

   fgets(psk_data, 4096, data_file);

   n=sscanf(psk_data, "%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:\r\n]",
            g_xr_hex, g_xi_hex, cky_r_hex, cky_i_hex, sai_b_hex,
            idir_b_hex, ni_b_hex, nr_b_hex, expected_hash_r_hex);

   if (n != 9) {
      printf("Error in data format.  Expected 9 fields, found %d\n", n);
      exit(1);
   }

   g_xr = hex2data(g_xr_hex, &g_xr_len);
   g_xi = hex2data(g_xi_hex, &g_xi_len);
   cky_r = hex2data(cky_r_hex, &cky_r_len);
   cky_i = hex2data(cky_i_hex, &cky_i_len);
   sai_b = hex2data(sai_b_hex, &sai_b_len);
   idir_b = hex2data(idir_b_hex, &idir_b_len);
   ni_b = hex2data(ni_b_hex, &ni_b_len);
   nr_b = hex2data(nr_b_hex, &nr_b_len);
   expected_hash_r = hex2data(expected_hash_r_hex, &expected_hash_r_len);

   skeyid_data_len = ni_b_len + nr_b_len;
   skeyid_data = Malloc(skeyid_data_len);
   cp = skeyid_data;
   memcpy(cp, ni_b, ni_b_len);
   cp += ni_b_len;
   memcpy(cp, nr_b, nr_b_len);
   skeyid = Malloc(16);
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
   hash_r = Malloc(16);
     
/*
 *	Get program start time for statistics displayed on completion.
 */
   Gettimeofday(&start_time);
   printf("Starting psk-crack\n");
   while (fgets(line, MAXLINE, dictionary_file)) {
      char *line_p;
      for (line_p = line; !isspace(*line_p) && *line_p != '\0'; line_p++)
         ;
      *line_p = '\0';
      hmac_md5(skeyid_data, skeyid_data_len, line, strlen(line), skeyid);
      hmac_md5(hash_r_data, hash_r_data_len, skeyid, 16, hash_r);
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
      hash_r_hex = hexstring(hash_r, 16);
      printf("key \"%s\" matches hash %s\n", line, hash_r_hex);
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
