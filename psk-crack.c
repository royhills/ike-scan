/* $Id$
 *
 * psk-crack.c -- IKE Aggressive Mode Pre-Shared Key cracker
 *
 * Author: Roy Hills
 * Date: 8 July 2004
 */
#include "ike-scan.h"

int
main () {
   FILE *psk_file;
   int iterations=0;
   int found=0;

   char *g_xr_hex = "9c1e0e07828af45086a4eb559ad8dafb7d655bab38656609426653565ef7e332bed7212cf24a05048032240256a169a68ee304ca500abe073d150bc50239350446ab568132aebcf34acd25ce23b30d0de9f8e7a89c22ce0dec2dabf0409bc25f0988d5d956916dce220c630d2a1fda846667fdecb20b2dc2d5c5b8273a07095c";
   char *g_xi_hex = "6f8c74c15bb4dd09b7af8d1c23e7b381a38dddcd4c5afb3b1335ff766f0267df8fdca0ea907ef4482d8164506817d10ba4aed8f108d32c1b082b91772df956bcd5f7a765759bada21c11f28429c48fcd7267be7b3aea96421528b9432110fff607a65b7c41091e5d1a10e143d4701147d7cfc211ba5853cf800d12a11d129724";
   char *cky_r_hex = "6d08132c8abb6931";
   char *cky_i_hex = "eac82ea45cbe59e6";
   char *sai_b_hex = "00000001000000010000002c01010001000000240101000080010001800200018003000180040002800b0001000c000400007080";
   char *idir_b_hex = "01000000ac100202";
   char *ni_b_hex = "64745a975dbcd95c2abf7d2eeeb93ac4633a03f1";
   char *nr_b_hex = "502c0b3872518fa1e7ff8f5a28a3d797f65e2cb1";
   char *expected_hash_r_hex = "f995ec2968f695aeb1d4e4b437f49d26";

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

   print_times();

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

   if ((psk_file = fopen("psk-file.txt", "r")) == NULL) {
      perror("fopen");
      exit(1);
   }
   print_times();
   while (fgets(line, MAXLINE, psk_file)) {
      char *line_p;
      for (line_p = line; !isspace(*line_p) && *line_p != '\0'; line_p++)
         ;
      *line_p = '\0';
      hmac_md5(skeyid_data, skeyid_data_len, line, strlen(line), skeyid);
      hmac_md5(hash_r_data, hash_r_data_len, skeyid, 16, hash_r);
      iterations++;
      if (!memcmp(hash_r, expected_hash_r, expected_hash_r_len)) {
         hash_r_hex = hexstring(hash_r, 16);
         printf("key \"%s\" matches hash %s after %d iterations\n",
                line, hash_r_hex, iterations);
         free(hash_r_hex);
         found=1;
         break;
      }
   }
   if (!found)
      printf("no match found after %d iterations\n", iterations);
   print_times();
   fclose(psk_file);

   return 0;
}

/*

Sample parameters from ike-scan

I 10 (20):	64745a975dbcd95c2abf7d2eeeb93ac4633a03f1
I 4 (128):	6f8c74c15bb4dd09b7af8d1c23e7b381a38dddcd4c5afb3b1335ff766f0267df8fdca0ea907ef4482d8164506817d10ba4aed8f108d32c1b082b91772df956bcd5f7a765759bada21c11f28429c48fcd7267be7b3aea96421528b9432110fff607a65b7c41091e5d1a10e143d4701147d7cfc211ba5853cf800d12a11d129724
I 1 (52):	00000001000000010000002c01010001000000240101000080010001800200018003000180040002800b0001000c000400007080
I CKY (8):	eac82ea45cbe59e6
R CKY (8):	6d08132c8abb6931
R 1 (52):	00000001000000010000002c01010001000000240101000080010001800200018003000180040002800b0001000c000400007080
R 4 (128):	9c1e0e07828af45086a4eb559ad8dafb7d655bab38656609426653565ef7e332bed7212cf24a05048032240256a169a68ee304ca500abe073d150bc50239350446ab568132aebcf34acd25ce23b30d0de9f8e7a89c22ce0dec2dabf0409bc25f0988d5d956916dce220c630d2a1fda846667fdecb20b2dc2d5c5b8273a07095c
R 10 (20):	502c0b3872518fa1e7ff8f5a28a3d797f65e2cb1
R 5 (8):	01000000ac100202
R 8 (16):	f995ec2968f695aeb1d4e4b437f49d26
*/
