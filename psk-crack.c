/* $Id$
 *
 * psk-crack.c -- IKE Aggressive Mode Pre-Shared Key cracker
 *
 * Author: Roy Hills
 * Date: 8 July 2004
 */
#include "ike-scan.h"
#define MAXLEN 4096

int
main (int argc, char *argv[]) {
   FILE *dictionary_file;
   FILE *data_file;	/* PSK parameters in colon separated format */
   int iterations=0;
   int found=0;
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

   print_times();

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

   print_times();
   while (fgets(line, MAXLINE, dictionary_file)) {
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
   fclose(data_file);
   fclose(dictionary_file);

   return 0;
}
