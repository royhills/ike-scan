/* $Id$
 *
 * random-dir -- Create random string for directory name.
 *
 * Author: Roy Hills
 * Date: 13 January 2003
 *
 * This program is used to create a 16-character random directory name.
 *
 * The random directory name is used as part of the URL that is Emailed
 * to people who request a download of ike-scan.  This ensures that the
 * Email address that people submit is valid.
 *
 * Although this software is used for ike-scan, it is not part of the ike-scan
 * distribution and should not be distributed.
 */
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include "global.h"
#include "md5.h"

#define MAXLINE 255

int
main () {
   unsigned char md5_digest[16];
   MD5_CTX context;
   struct timeval now;
   char str[MAXLINE];
   char hex_str[MAXLINE];
   char *secret = "There stands the ox, where could he hide?";
   int i;
   char *cp;

   if ((gettimeofday(&now,NULL)) != 0) {
      perror("gettimeofday");
      exit(1);
   }
   sprintf(str, "%lu %lu %s", now.tv_usec, now.tv_sec, secret);
   MD5Init(&context);
   MD5Update(&context, str, strlen(str));
   MD5Final(&md5_digest,&context);
   cp = hex_str;
   for (i=0; i<8; i++) {
      sprintf(cp, "%.2x",md5_digest[i]);
      cp += 2;
   }
   *cp = '\0';
   printf("%s\n", hex_str);
   return 0;
}
