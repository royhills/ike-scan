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
 * check-hash -- Check message digest (HASH) functions
 *
 * Author:	Roy Hills
 * Date:	25 April 2004
 *
 *	Check the various message digest (HASH) functions using the test
 *	vectors given in the appropriate RFC.
 */

#include "ike-scan.h"
#define NUM_HMAC_TESTS 1

int
main(void) {
/*
 *	MD5 test vectors from RFC 1321 "The MD5 Message-Digest Algorithm"
 */
   static const char *md5_tests[] = {
      "",
      "a",
      "abc",
      "message digest",
      "abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      NULL
   };
   static const char *md5_results[] = {
      "d41d8cd98f00b204e9800998ecf8427e",
      "0cc175b9c0f1b6a831c399e269772661",
      "900150983cd24fb0d6963f7d28e17f72",
      "f96b697d7cb7938d525a2f31aaf161d0",
      "c3fcd3d76192e4007dfb496cca67e13b",
      "d174ab98d277d9f5a5611c2c9f419d9f",
      "57edf4a22be3c955ac49da2e2107b67a"
   };
/*
 *	SHA1 test vectors from RFC 3174 "US Secure Hash Algorithm 1 (SHA1)"
 */
   static const char *sha1_tests[] = {
      "abc",
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      NULL
   };
   static const char *sha1_results[] = {
      "a9993e364706816aba3e25717850c26c9cd0d89d",
      "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
   };
/*
 *	HMAC-MD5 test vectors from RFC 2104
 *	"HMAC: Keyed-Hashing for Message Authentication"
 */
   static const struct hmac_md5_test_struct {
      unsigned char key[16];
      int key_len;
      unsigned char data[64];
      int data_len;
      char *digest;
   } hmac_md5_tests[NUM_HMAC_TESTS] = {
      {"Jefe",
       4,
       "what do ya want for nothing?",
       28,
       "750c783e6ab0b503eaa86e310a5db738"}
   };

   unsigned const char **testp;
   const char **resultp;
   int i;

   int error=0;

   printf("\nChecking MD5 hash function...\n");
   testp=(unsigned const char **) md5_tests;
   resultp=md5_results;
   while (*testp != NULL) {
      const char *expected;
      char *actual;
      printf("\"%s\"\t", *testp);
      expected=*resultp;
      actual=hexstring(MD5(*testp, strlen(*testp), NULL), 16);
      if (strcmp(actual, expected)) {
         error++;
         printf("FAIL (expected %s, got %s)\n", expected, actual);
      } else {
         printf("ok\n");
      }
      testp++;
      resultp++;
   }

   printf("\nChecking SHA1 hash function...\n");
   testp=(unsigned const char **) sha1_tests;
   resultp=sha1_results;
   while (*testp != NULL) {
      const char *expected;
      char *actual;
      printf("\"%s\"\t", *testp);
      expected=*resultp;
      actual=hexstring(SHA1(*testp, strlen(*testp), NULL), 20);
      if (strcmp(actual, expected)) {
         error++;
         printf("FAIL (expected %s, got %s)\n", expected, actual);
      } else {
         printf("ok\n");
      }
      testp++;
      resultp++;
   }

   printf("\nChecking HMAC-MD5 keyed hash function...\n");
   for (i=0; i<NUM_HMAC_TESTS; i++) {
      const char *expected;
      char *actual;
      printf("\"%s\" \"%s\"\t", hmac_md5_tests[i].key, hmac_md5_tests[i].data);
      expected=hmac_md5_tests[i].digest;
      actual=hexstring(hmac_md5(hmac_md5_tests[i].data,
                                hmac_md5_tests[i].data_len,
                                hmac_md5_tests[i].key,
                                hmac_md5_tests[i].key_len,
                                NULL), 16);
      if (strcmp(actual, expected)) {
         error++;
         printf("FAIL (expected %s, got %s)\n", expected, actual);
      } else {
         printf("ok\n");
      }
   }

   if (error)
      return EXIT_FAILURE;
   else
      return EXIT_SUCCESS;
}
