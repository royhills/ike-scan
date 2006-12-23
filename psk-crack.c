/*
 * The IKE Scanner (ike-scan) is Copyright (C) 2003-2005 Roy Hills,
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
 * psk-crack.c -- IKE Aggressive Mode Pre-Shared Key cracker for ike-scan
 *
 * Author: Roy Hills
 * Date: 8 July 2004
 *
 * Usage:
 *	psk-crack [options] <psk-parameters-file>
 *
 */
#include "psk-crack.h"
static const char rcsid[] = "$Id$";	/* RCS ID for ident(1) */

static const char *default_charset =
   "0123456789abcdefghijklmnopqrstuvwxyz"; /* default bruteforce charset */

static psk_entry *psk_list;	/* List of PSK parameters */

int
main (int argc, char *argv[]) {
   const struct option long_options[] = {
      {"help", no_argument, 0, 'h'},
      {"verbose", no_argument, 0, 'v'},
      {"version", no_argument, 0, 'V'},
      {"bruteforce", required_argument, 0, 'B'},
      {"charset", required_argument, 0, 'c'},
      {"dictionary", required_argument, 0, 'd'},
      {"norteluser", required_argument, 0, 'u'},
      {0, 0, 0, 0}
   };
   const char *short_options = "hvVB:c:d:u:";
   int arg;
   int options_index=0;
   int verbose=0;
   unsigned brute_len=0; /* Bruteforce len.  0=dictionary attack (default) */
   const char *charset = NULL;
   char dict_file_name[MAXLINE];	/* Dictionary file name */
   char *nortel_user = NULL; /* For cracking Nortel Contivity passwords only */
   FILE *dictionary_file=NULL;	/* Dictionary file */
   IKE_UINT64 iterations=0;
   int found = 0;
   struct timeval start_time;	/* Program start time */
   struct timeval end_time;	/* Program end time */
   struct timeval elapsed_time; /* Elapsed time as timeval */
   double elapsed_seconds;	/* Elapsed time in seconds */
   int psk_idx;			/* Index into psk list */
   unsigned psk_count;		/* Number of PSK entries in the list */
   unsigned char *hash_r;
   char line[MAXLINE];

   dict_file_name[0] = '\0';	/* Initialise to empty string */
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
            fprintf(stderr, "Copyright (C) 2003-2005 Roy Hills, NTA Monitor Ltd.\n");
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
         case 'B':      /* --bruteforce */
            brute_len=Strtoul(optarg, 10);
            break;
         case 'c':      /* --charset */
            charset=make_message("%s", optarg);
            break;
         case 'd':      /* --dictionary */
            strncpy(dict_file_name, optarg, MAXLINE);
            brute_len = 0;
            break;
         case 'u':      /* --norteluser */
            nortel_user = make_message("%s", optarg);
            break;
         default:       /* Unknown option */
            psk_crack_usage(EXIT_FAILURE);
            break;
      }
   } /* End While */

/*
 *	Check that we've got exactly one argument.
 */
   if ((argc - optind) != 1) {
      psk_crack_usage(EXIT_FAILURE);
   }
/*
 *	Display the starting message.
 */
   printf("Starting psk-crack [%s] (http://www.nta-monitor.com/tools/ike-scan/)\n",
          PACKAGE_STRING);
/*
 *	If the character set has not been specified, use the default one.
 */
   if (!charset)
      charset = default_charset;
/*
 *	Load the PSK entries from the data file.
 */
   psk_count = load_psk_params(argv[optind], nortel_user);
   if (verbose)
      printf("Loaded %u PSK entries from %s\n", psk_count, argv[optind]);
   if (psk_count < 1)
      err_msg("ERROR: No pre-shared keys to crack");
/*
 *	Open dictionary file if required.
 */
   if (!brute_len)	/* If not bruteforcing */
      dictionary_file = open_dict_file(dict_file_name);
/*
 *	Get program start time for statistics displayed on completion.
 */
   if (brute_len) {
      printf("Running in brute-force cracking mode\n");
   } else {
      printf("Running in dictionary cracking mode\n");
   }
   Gettimeofday(&start_time);
/*
 *	Cracking loop.
 */
   for (psk_idx=0; psk_idx<psk_count; psk_idx++) {
      if (brute_len) {	/* Brute force cracking */
         IKE_UINT64 max;
         unsigned base;
         unsigned i;
         IKE_UINT64 loop;
         IKE_UINT64 val;
         unsigned digit;

         base = strlen(charset);
         max = base;
         for (i=1; i<brute_len; i++)
            max *= base;	/* max = base^brute_len without using pow() */
         printf("Brute force with %u chars up to length %u will take up to "
                IKE_UINT64_FORMAT " iterations\n", base, brute_len, max);

         for (loop=0; loop<max; loop++) {
            char *line_p;

            val = loop;
            line_p = line;
            do {
               digit = val % base;
               val /= base;
               *line_p++ = charset[digit];
            } while (val);
            *line_p = '\0';
            if (verbose > 1)
               printf("Trying key \"%s\"\n", line);
            hash_r = compute_hash(&psk_list[psk_idx], line);
            iterations++;
            if (!memcmp(hash_r, psk_list[psk_idx].hash_r,
                psk_list[psk_idx].hash_r_len)) {
               found=1;
               break;
            }
         }
      } else {	/* Dictionary cracking */
         rewind(dictionary_file);
         while (fgets(line, MAXLINE, dictionary_file)) {
            char *line_p;
            for (line_p = line; !isspace((unsigned char)*line_p) &&
                 *line_p != '\0'; line_p++)
               ;
            *line_p = '\0';
            if (verbose > 1)
               printf("Trying key \"%s\"\n", line);
            hash_r = compute_hash(&psk_list[psk_idx], line);
            iterations++;
            if (!memcmp(hash_r, psk_list[psk_idx].hash_r,
                        psk_list[psk_idx].hash_r_len)) {
               found=1;
               break;
            }
         }
      }
      if (found) {
         printf("key \"%s\" matches %s hash %s\n", line,
                psk_list[psk_idx].hash_name, psk_list[psk_idx].hash_r_hex);
      } else {
         printf("no match found for %s hash %s\n", psk_list[psk_idx].hash_name,
                psk_list[psk_idx].hash_r_hex);
      }
   }
/*
 *      Get program end time and calculate elapsed time.
 */
   Gettimeofday(&end_time);
   timeval_diff(&end_time, &start_time, &elapsed_time);
   elapsed_seconds = (elapsed_time.tv_sec*1000 +
                      elapsed_time.tv_usec/1000.0) / 1000.0;
   if (elapsed_seconds < 0.000001)
      elapsed_seconds = 0.000001;	/* Avoid div by zero */
   printf("Ending psk-crack: " IKE_UINT64_FORMAT
          " iterations in %.3f seconds (%.2f iterations/sec)\n",
          iterations, elapsed_seconds, iterations/elapsed_seconds);
  
   if (!brute_len)
      fclose(dictionary_file);

   return 0;
}

/*
 *	load_psk_params -- Load PSK parameters from data file
 *
 *	Inputs:
 *
 *	filename	The name of the data file
 *	nortel_user	The username for Nortel PSK cracking, or NULL
 *
 *	Returns:
 *
 *	The number of PSK parameters successfully loaded into the list.
 *
 *	This function loads the pre-shared key parameters from the input
 *	data file into the psk parameters list, which is an array of structs.
 *
 *	The array is created dynamically with malloc and realloc, as we don't
 *	know in advance how many PSK entries there will be in the file.
 */
static unsigned
load_psk_params(const char *filename, const char *nortel_user) {
   FILE *data_file;		/* PSK parameters in colon separated format */
   char psk_data[MAXLEN];	/* Line read from data file */
   int n;			/* Number of fields read by sscanf() */
   static int num_left=0;       /* Number of free entries left */
   unsigned count=0;		/* Number of entries in the list */
   psk_entry *pe;		/* Pointer to current PSK entry */
   unsigned char *cp;
   unsigned char *skeyid_data;	/* Data for SKEYID hash */
   size_t skeyid_data_len;	/* Length of skeyid data */
   unsigned char *hash_r_data;	/* Data for HASH_R hash */
   size_t hash_r_data_len;	/* Length of hash_r */
   char g_xr_hex[MAXLEN];	/* Individual PSK params as hex */
   char g_xi_hex[MAXLEN];
   char cky_r_hex[MAXLEN];
   char cky_i_hex[MAXLEN];
   char sai_b_hex[MAXLEN];
   char idir_b_hex[MAXLEN];
   char ni_b_hex[MAXLEN];
   char nr_b_hex[MAXLEN];
   char hash_r_hex[MAXLEN];
   unsigned char *g_xr;		/* Individual PSK params as binary */
   unsigned char *g_xi;
   unsigned char *cky_r;
   unsigned char *cky_i;
   unsigned char *sai_b;
   unsigned char *idir_b;
   unsigned char *ni_b;
   unsigned char *nr_b;
   size_t g_xr_len;		/* Lengths of binary PSK params */
   size_t g_xi_len;
   size_t cky_r_len;
   size_t cky_i_len;
   size_t sai_b_len;
   size_t idir_b_len;
   size_t ni_b_len;
   size_t nr_b_len;

/*
 *	Open PSK data file for reading.
 */
   if ((data_file = fopen(filename, "r")) == NULL)
      err_sys("error opening data file %s", filename);
/*
 *	For each line in the data file, read the PSK data, convert to
 *	binary, and store in the PSK list.  We ignore blank lines, and
 *	any lines beginning with '#'.
 */
   while ((fgets(psk_data, MAXLEN, data_file)) != NULL) {
      if (psk_data[0] == '#' || psk_data[0] == '\n' || psk_data[0] == '\r')
         continue;	/* Skip comments and blank lines */
      n=sscanf(psk_data,
               "%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%[^:\r\n]",
               g_xr_hex, g_xi_hex, cky_r_hex, cky_i_hex, sai_b_hex,
               idir_b_hex, ni_b_hex, nr_b_hex, hash_r_hex);
      if (n != 9) {
         warn_msg("ERROR: Format error in PSK data file %s, line %u",
                  filename, count+1);
         err_msg("ERROR: Expected 9 colon-separated fields, found %d", n);
      }
/*
 *	Create or grow the psk list array if required.
 *	We grow the list by PSK_REALLOC_COUNT elements each time.
 */
      if (!num_left) {     /* No entries left, allocate some more */
         if (psk_list)
            psk_list=Realloc(psk_list, (count * sizeof(psk_entry)) +
                             PSK_REALLOC_COUNT*sizeof(psk_entry));
         else
            psk_list=Malloc(PSK_REALLOC_COUNT*sizeof(psk_entry));
         num_left = PSK_REALLOC_COUNT;
      }

      pe = psk_list + count;  /* Would array notation be better? */
      count++;
      num_left--;
/*
 *	Convert hex to binary representation, and construct SKEYID
 *	and HASH_R data.
 */
      g_xr = hex2data(g_xr_hex, &g_xr_len);
      g_xi = hex2data(g_xi_hex, &g_xi_len);
      cky_r = hex2data(cky_r_hex, &cky_r_len);
      cky_i = hex2data(cky_i_hex, &cky_i_len);
      sai_b = hex2data(sai_b_hex, &sai_b_len);
      idir_b = hex2data(idir_b_hex, &idir_b_len);
      ni_b = hex2data(ni_b_hex, &ni_b_len);
      nr_b = hex2data(nr_b_hex, &nr_b_len);

/* skeyid_data = ni_b | nr_b */
      skeyid_data_len = ni_b_len + nr_b_len;
      skeyid_data = Malloc(skeyid_data_len);
      cp = skeyid_data;
      memcpy(cp, ni_b, ni_b_len);
      cp += ni_b_len;
      memcpy(cp, nr_b, nr_b_len);
      free(ni_b);
      free(nr_b);

/* hash_r_data = g_xr | g_xi | cky_r | cky_i | sai_b | idir_b */
      hash_r_data_len = g_xr_len + g_xi_len + cky_r_len + cky_i_len +
                        sai_b_len + idir_b_len;
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
      free(g_xr);
      free(g_xi);
      free(cky_r);
      free(cky_i);
      free(sai_b);
      free(idir_b);
/*
 *	Store the PSK parameters in the current psk list entry.
 */
      pe->skeyid_data = skeyid_data;
      pe->skeyid_data_len = skeyid_data_len;
      pe->hash_r_data = hash_r_data;
      pe->hash_r_data_len = hash_r_data_len;
      pe->hash_r = hex2data(hash_r_hex, &pe->hash_r_len);
      pe->hash_r_hex = Malloc(strlen(hash_r_hex) + 1);
      strcpy(pe->hash_r_hex, hash_r_hex);
      pe->nortel_user = nortel_user;
/*
 *	Determine hash type based on the length of the hash, and
 *	store this in the current psk list entry.
 */
      if (pe->hash_r_len == MD5_HASH_LEN) {
         pe->hash_type=HASH_TYPE_MD5;
         pe->hash_name=make_message("MD5");
      } else if (pe->hash_r_len == SHA1_HASH_LEN) {
         pe->hash_type=HASH_TYPE_SHA1;
         pe->hash_name=make_message("SHA1");
      } else {
         err_msg("Cannot determine hash type from %u byte HASH_R",
                 pe->hash_r_len);
      }
   }	/* End While fgets() */
/*
 *	Close the data file, and return the number of PSK entries
 *	read into the list.
 */
   fclose(data_file);
   return count;
}

/*
 *	compute_hash	-- Compute the hash given a candidate password
 *
 *	Inputs:
 *
 *	psk_params	Pointer to PSK params structure
 *	password	The candidate password
 *
 *	Returns:
 *
 *	Pointer to the computed hash.
 *
 *	This function calculates a hash given the PSK parameters and
 *	a candidate password.
 *
 *	The standard process used to calculate the hash is detailed in
 *	RFC 2409.  The hash used by Nortel Contivity systems use a different,
 *	proprietary, method.
 *
 *	In all cases, the calculation of the hash is a two-stage process:
 *
 *	a) Calculate SKEYID using some of the PSK parameters and the password;
 *	b) Calculate HASH_R using SKEYID and the other PSK parameters.
 *
 */
static inline unsigned char *
compute_hash (const psk_entry *psk_params, const char *password) {
   size_t password_len;
   unsigned char nortel_psk[SHA1_HASH_LEN];
   unsigned char nortel_pwd_hash[SHA1_HASH_LEN];
   unsigned char skeyid[SHA1_HASH_LEN];
   static unsigned char hash_r[SHA1_HASH_LEN];

   password_len = strlen(password);
/*
 *	Calculate SKEYID
 */
   if (psk_params->nortel_user != NULL) {	/* Nortel SKEYID */
      SHA1((const unsigned char *) password, password_len, nortel_pwd_hash);
      hmac_sha1((const unsigned char *)psk_params->nortel_user,
                strlen(psk_params->nortel_user), nortel_pwd_hash,
                SHA1_HASH_LEN, nortel_psk);
      if (psk_params->hash_type == HASH_TYPE_MD5) {
         hmac_md5(psk_params->skeyid_data, psk_params->skeyid_data_len,
                  nortel_psk, SHA1_HASH_LEN, skeyid);
      } else {	/* SHA1 */
         hmac_sha1(psk_params->skeyid_data, psk_params->skeyid_data_len,
                   nortel_psk, SHA1_HASH_LEN, skeyid);
      }
   } else {	/* Standard RFC 2409 SKEYID */
      if (psk_params->hash_type == HASH_TYPE_MD5) {
         hmac_md5(psk_params->skeyid_data, psk_params->skeyid_data_len,
                  (const unsigned char *) password, password_len, skeyid);
      } else {	/* SHA1 */
         hmac_sha1(psk_params->skeyid_data, psk_params->skeyid_data_len,
                   (const unsigned char *) password, password_len, skeyid);
      }
   }
/*
 *	Calculate HASH_R
 */
   if (psk_params->hash_type == HASH_TYPE_MD5) {
      hmac_md5(psk_params->hash_r_data, psk_params->hash_r_data_len, skeyid,
               psk_params->hash_r_len, hash_r);
   } else {	/* SHA1 */
      hmac_sha1(psk_params->hash_r_data, psk_params->hash_r_data_len, skeyid,
                psk_params->hash_r_len, hash_r);
   }
   return hash_r;
}

/*
 *	open_dict_file	-- Open the dictionary file
 *
 *	Inputs:
 *
 *	dict_file_name	The dictionary file name, or NUL for default.
 *
 *	Returns:
 *
 *	The file descriptor of the dictionary file.
 */
static FILE *
open_dict_file(const char *dict_file_name) {
   char *fn;
   FILE *fp;
#ifdef __CYGWIN__
   char fnbuf[MAXLINE];
   int fnbuf_siz;
   int i;
#endif

   if (dict_file_name[0] == '\0') {	/* Dictionary file not specified */
#ifdef __CYGWIN__
      if ((fnbuf_siz=GetModuleFileName(GetModuleHandle(0),
           fnbuf, MAXLINE)) == 0) {
         err_msg("ERROR: Call to GetModuleFileName failed");
      }
      for (i=fnbuf_siz-1; i>=0 && fnbuf[i] != '/' && fnbuf[i] != '\\'; i--)
         ;
      if (i >= 0) {
         fnbuf[i] = '\0';
      }
      fn = make_message("%s\\%s", fnbuf, DICT_FILE);
#else
      fn = make_message("%s/%s", IKEDATADIR, DICT_FILE);
#endif
   } else {		/* Dictionary filename was specified */
      fn = make_message("%s", dict_file_name);
   }
   if ((fp = fopen(fn, "r")) == NULL)
      err_sys("error opening dictionary file %s", fn);
   free(fn);

   return fp;
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
static void
psk_crack_usage(int status) {
   fprintf(stderr, "Usage: psk-crack [options] <psk-parameters-file>\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "<psk-parameters-file> is a file containing the parameters for the pre-shared\n");
   fprintf(stderr, "key cracking process in the format generated by ike-scan with the --pskcrack\n");
   fprintf(stderr, "(-P) option.  This file can contain one or more entries.  For multiple entries,\n");
   fprintf(stderr, "each one must be on a separate line.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "Two SKEYID computation methods are supported: the standard method for pre-\n");
   fprintf(stderr, "shared keys as described in RFC 2409, and the proprietary method used by\n");
   fprintf(stderr, "Nortel Contivity / VPN Router systems.  The standard method is used by default,\n");
   fprintf(stderr, "and the Nortel method can be selected with the --norteluser option.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "The program can crack either MD5 or SHA1-based hashes.  The type of hash is\n");
   fprintf(stderr, "automatically determined from the length of the hash (16 bytes for MD5 or\n");
   fprintf(stderr, "20 bytes for SHA1).  Each entry in the <psk-parameters-file> is handled\n");
   fprintf(stderr, "separately, so it is possible to crack a mixture of MD5 and SHA1 hashes.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "By default, psk-crack will perform dictionary cracking using the default\n");
   fprintf(stderr, "dictionary.  The dictionary can be changed with the --dictionary (-d) option,\n");
   fprintf(stderr, "or brute-force cracking can be selected with the --bruteforce (-B) option.\n");
   fprintf(stderr, "\n");
   fprintf(stderr, "Options:\n");
   fprintf(stderr, "\n--help or -h\t\tDisplay this usage message and exit.\n");
   fprintf(stderr, "\n--version or -V\t\tDisplay program version and exit.\n");
   fprintf(stderr, "\n--verbose or -v\t\tDisplay verbose progress messages.\n");
   fprintf(stderr, "\t\t\tUse more than once for increased verbosity.\n");
   fprintf(stderr, "\n--dictionary=<f> or -d <f> Set dictionary file to <f>\n");
#ifdef __CYGWIN__
   fprintf(stderr, "\t\t\tdefault=%s in psk-crack.exe dir.\n", DICT_FILE);
#else
   fprintf(stderr, "\t\t\tdefault=%s/%s.\n", IKEDATADIR, DICT_FILE);
#endif
   fprintf(stderr, "\n--norteluser=<u> or -u <u> Specify username for Nortel Contivity PSK cracking.\n");
   fprintf(stderr, "\t\t\tThis option is required when cracking pre-shared keys\n");
   fprintf(stderr, "\t\t\ton Nortel Contivity / VPN Router systems.  These\n");
   fprintf(stderr, "\t\t\tsystems use a proprietary method to calculate the hash\n");
   fprintf(stderr, "\t\t\tthat includes a hash of the username.\n");
   fprintf(stderr, "\t\t\tThis option is only needed when cracking Nortel format\n");
   fprintf(stderr, "\t\t\thashes, and should not be used for standard format\n");
   fprintf(stderr, "\t\t\thashes.\n");
   fprintf(stderr, "\t\t\tWhen this option is used, all the PSK entries in the\n");
   fprintf(stderr, "\t\t\tpsk parameters file are assumed to be in Nortel format\n");
   fprintf(stderr, "\t\t\tusing the supplied username. There is currently no way\n");
   fprintf(stderr, "\t\t\tto crack a mixture of Nortel and standard format PSK\n");
   fprintf(stderr, "\t\t\tentries, or Nortel entries with different usernames in\n");
   fprintf(stderr, "\t\t\ta single psk-crack run.\n");
   fprintf(stderr, "\n--bruteforce=<n> or -B <n> Select bruteforce cracking up to <n> characters.\n");
   fprintf(stderr, "\n--charset=<s> or -c <s>\tSet bruteforce character set to <s>\n");
   fprintf(stderr, "\t\t\tDefault is \"%s\"\n", default_charset);
   fprintf(stderr, "\n");
   fprintf(stderr, "Report bugs or send suggestions to %s\n", PACKAGE_BUGREPORT);
   fprintf(stderr, "See the ike-scan homepage at http://www.nta-monitor.com/tools/ike-scan/\n");
   exit(status);
}
