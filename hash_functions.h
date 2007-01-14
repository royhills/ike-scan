/*
 * The IKE Scanner (ike-scan) is Copyright (C) 2003-2007 Roy Hills,
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
 * You are encouraged to send comments, improvements or suggestions to
 * me at ike-scan@nta-monitor.com.
 *
 * $Id$
 *
 * hash_functions.h -- Header file for hash functions
 *
 * Author:	Roy Hills
 * Date:	23 December 2006
 */

#ifndef IKE_SCAN_HASH_H
#define IKE_SCAN_HASH_H 1

#ifndef HAVE_OPENSSL
/*
 *	MD5 -- Calculate MD5 hash of specified data
 *
 *	Inputs:
 *
 *	d	The data to hash
 *	n	The length of the data
 *	md	The resulting MD5 hash
 *
 *	Returns:
 *
 *	The MD5 hash.
 *
 *	This function is a wrapper for the MD5 routines in md5.c.  If ike-scan
 *	was compiled with OpenSSL, then the OpenSSL MD5 routines are used
 *	instead, and this wrapper is not used.
 */
static inline unsigned char *
MD5(const unsigned char *d, size_t n, unsigned char *md) {
   md5_state_t context;
   static unsigned char m[16];

   if (md == NULL)	/* Use static storage if no buffer specified */
      md=m;

   md5_init(&context);
   md5_append(&context, d, n);
   md5_finish(&context, md);

   return md;
}
#endif

#ifndef HAVE_OPENSSL
/*
 *	SHA1 -- Calculate SHA1 hash of specified data
 *
 *	Inputs:
 *
 *	d	The data to hash
 *	n	The length of the data
 *	md	The resulting SHA1 hash
 *
 *	Returns:
 *
 *	The SHA1 hash.
 *
 *	This function is a wrapper for the SHA1 routines in sha1.c.  If ike-scan
 *	was compiled with OpenSSL, then the OpenSSL SHA1 routines are used
 *	instead, and this wrapper is not used.
 */
static inline unsigned char *
SHA1(const unsigned char *d, size_t n, unsigned char *md) {
   SHA1_CTX context;
   static unsigned char m[20];

   if (md == NULL)	/* Use static storage if no buffer specified */
      md=m;

   SHA1Init(&context);
/*
 * SHA1Update's prototype doesn't use "const", so we use a cast to prevent
 * a warning.  It would really be better to fix sha1.[ch] so that they use
 * const, and I may do that some day.
 */
   SHA1Update(&context, (unsigned char *)d, n);
   SHA1Final(md, &context);

   return md;
}
#endif

/*
 *	hmac_md5 -- Calculate HMAC-MD5 keyed hash
 *
 *	Inputs:
 *
 *	text		The data to hash
 *	text_len	Length of the data in bytes
 *	key		The key
 *	key_len		Length of the key in bytes
 *	digest		The resulting HMAC-MD5 digest
 *
 *	Returns:
 *
 *	The HMAC-MD5 hash.
 *
 *	This function is based on the code from the RFC 2104 appendix.
 *
 *	We use #ifdef to select either the OpenSSL MD5 functions or the
 *	built-in MD5 functions depending on whether HAVE_OPENSSL is defined.
 *	This is faster that calling OpenSSL "HMAC" directly.
 */
static inline unsigned char *
hmac_md5(const unsigned char *text, size_t text_len, const unsigned char *key,
         size_t key_len, unsigned char *md) {
   static unsigned char m[16];
#ifdef HAVE_OPENSSL
   MD5_CTX context;
#else
   md5_state_t context;
#endif
   unsigned char k_ipad[65];	/* inner padding -  key XORd with ipad */
   unsigned char k_opad[65];    /* outer padding -  key XORd with opad */
   unsigned char tk[16];
   int i;

   if (md == NULL)	/* Use static storage if no buffer specified */
      md=m;

   /* if key is longer than 64 bytes reset it to key=MD5(key) */
   if (key_len > 64) {
#ifdef HAVE_OPENSSL
      MD5_CTX tctx;

      MD5_Init(&tctx);
      MD5_Update(&tctx, key, key_len);
      MD5_Final(tk, &tctx);
#else
      md5_state_t tctx;

      md5_init(&tctx);
      md5_append(&tctx, key, key_len);
      md5_finish(&tctx, tk);
#endif

      key = tk;
      key_len = 16;
   }
   /*
    * the HMAC_MD5 transform looks like:
    *
    * MD5(K XOR opad, MD5(K XOR ipad, text))
    *
    * where K is an n byte key
    * ipad is the byte 0x36 repeated 64 times
    * opad is the byte 0x5c repeated 64 times
    * and text is the data being protected
    */

   /* start out by storing key in pads */
   memset(k_ipad, '\0', sizeof k_ipad);
   memset(k_opad, '\0', sizeof k_opad);
   memcpy(k_ipad, key, key_len);
   memcpy(k_opad, key, key_len);

   /* XOR key with ipad and opad values */
   for (i=0; i<64; i++) {
      k_ipad[i] ^= 0x36;
      k_opad[i] ^= 0x5c;
   }
#ifdef HAVE_OPENSSL
   /*
    * perform inner MD5
    */
   MD5_Init(&context);			/* init context for 1st pass */
   MD5_Update(&context, k_ipad, 64);	/* start with inner pad */
   MD5_Update(&context, text, text_len); /* then text of datagram */
   MD5_Final(md, &context);		/* finish up 1st pass */
   /*
    * perform outer MD5
    */
   MD5_Init(&context);			/* init context for 2nd pass */
   MD5_Update(&context, k_opad, 64);	/* start with outer pad */
   MD5_Update(&context, md, 16);	/* then results of 1st hash */
   MD5_Final(md, &context);		/* finish up 2nd pass */
#else
   /*
    * perform inner MD5
    */
   md5_init(&context);			/* init context for 1st pass */
   md5_append(&context, k_ipad, 64);	/* start with inner pad */
   md5_append(&context, text, text_len); /* then text of datagram */
   md5_finish(&context, md);		/* finish up 1st pass */
   /*
    * perform outer MD5
    */
   md5_init(&context);			/* init context for 2nd pass */
   md5_append(&context, k_opad, 64);	/* start with outer pad */
   md5_append(&context, md, 16);	/* then results of 1st hash */
   md5_finish(&context, md);		/* finish up 2nd pass */
#endif

   return md;
}

/*
 *	hmac_sha1 -- Calculate HMAC-SHA1 keyed hash
 *
 *	Inputs:
 *
 *	text		The data to hash
 *	text_len	Length of the data in bytes
 *	key		The key
 *	key_len		Length of the key in bytes
 *	digest		The resulting HMAC-SHA1 digest
 *
 *	Returns:
 *
 *	The HMAC-SHA1 hash.
 *
 *	This function is based on the code from the RFC 2104 appendix.
 *
 *	We use #ifdef to select either the OpenSSL SHA1 functions or the
 *	built-in SHA1 functions depending on whether HAVE_OPENSSL is defined.
 *	This is faster that calling OpenSSL "HMAC" directly.
 */
static inline unsigned char *
hmac_sha1(const unsigned char *text, size_t text_len, const unsigned char *key,
          size_t key_len, unsigned char *md) {
   static unsigned char m[20];
#ifdef HAVE_OPENSSL
   SHA_CTX context;
#else
   SHA1_CTX context;
#endif
   unsigned char k_ipad[65];	/* inner padding -  key XORd with ipad */
   unsigned char k_opad[65];    /* outer padding -  key XORd with opad */
   unsigned char tk[20];
   int i;

   if (md == NULL)	/* Use static storage if no buffer specified */
      md=m;

   /* if key is longer than 64 bytes reset it to key=SHA1(key) */
   if (key_len > 64) {
#ifdef HAVE_OPENSSL
      SHA_CTX tctx;

      SHA1_Init(&tctx);
      SHA1_Update(&tctx, key, key_len);
      SHA1_Final(tk, &tctx);
#else
      SHA1_CTX tctx;

      SHA1Init(&tctx);
      SHA1Update(&tctx, (unsigned char *)key, key_len);
      SHA1Final(tk, &tctx);
#endif

      key = tk;
      key_len = 20;
   }
   /*
    * the HMAC_SHA1 transform looks like:
    *
    * SHA1(K XOR opad, SHA1(K XOR ipad, text))
    *
    * where K is an n byte key
    * ipad is the byte 0x36 repeated 64 times
    * opad is the byte 0x5c repeated 64 times
    * and text is the data being protected
    */

   /* start out by storing key in pads */
   memset(k_ipad, '\0', sizeof k_ipad);
   memset(k_opad, '\0', sizeof k_opad);
   memcpy(k_ipad, key, key_len);
   memcpy(k_opad, key, key_len);

   /* XOR key with ipad and opad values */
   for (i=0; i<64; i++) {
      k_ipad[i] ^= 0x36;
      k_opad[i] ^= 0x5c;
   }
#ifdef HAVE_OPENSSL
   /*
    * perform inner SHA1
    */
   SHA1_Init(&context);			/* init context for 1st pass */
   SHA1_Update(&context, k_ipad, 64);	/* start with inner pad */
   SHA1_Update(&context, text, text_len); /* then text of datagram */
   SHA1_Final(md, &context);		/* finish up 1st pass */
   /*
    * perform outer SHA1
    */
   SHA1_Init(&context);			/* init context for 2nd pass */
   SHA1_Update(&context, k_opad, 64);	/* start with outer pad */
   SHA1_Update(&context, md, 20);	/* then results of 1st hash */
   SHA1_Final(md, &context);		/* finish up 2nd pass */
#else
   /*
    * perform inner SHA1
    */
   SHA1Init(&context);			/* init context for 1st pass */
   SHA1Update(&context, k_ipad, 64);	/* start with inner pad */
   SHA1Update(&context, (unsigned char *)text, text_len); /* then text of datagram */
   SHA1Final(md, &context);		/* finish up 1st pass */
   /*
    * perform outer SHA1
    */
   SHA1Init(&context);			/* init context for 2nd pass */
   SHA1Update(&context, k_opad, 64);	/* start with outer pad */
   SHA1Update(&context, md, 20);	/* then results of 1st hash */
   SHA1Final(md, &context);		/* finish up 2nd pass */
#endif

   return md;
}

#endif  /* IKE_SCAN_HASH_H */
