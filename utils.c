/*
 * The IKE Scanner (ike-scan) is Copyright (C) 2003-2009 Roy Hills,
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
 * Author: Roy Hills
 * Date: 5 April 2004
 *
 * This file contains various utility functions used by ike-scan.
 */

#include "ike-scan.h"

/*
 *	timeval_diff -- Calculates the difference between two timevals
 *	and returns this difference in a third timeval.
 *
 *	Inputs:
 *
 *	a       = First timeval
 *	b       = Second timeval
 *	diff    = Difference between timevals (a - b).
 *
 *	Returns:
 *
 *	None.
 */
void
timeval_diff(const struct timeval *a, const struct timeval *b,
             struct timeval *diff) {
   struct timeval temp;

   temp.tv_sec = b->tv_sec;
   temp.tv_usec = b->tv_usec;

   /* Perform the carry for the later subtraction by updating b. */
   if (a->tv_usec < temp.tv_usec) {
     int nsec = (temp.tv_usec - a->tv_usec) / 1000000 + 1;
     temp.tv_usec -= 1000000 * nsec;
     temp.tv_sec += nsec;
   }
   if (a->tv_usec - temp.tv_usec > 1000000) {
     int nsec = (a->tv_usec - temp.tv_usec) / 1000000;
     temp.tv_usec += 1000000 * nsec;
     temp.tv_sec -= nsec;
   }
 
   /* Compute the time difference
      tv_usec is certainly positive. */
   diff->tv_sec = a->tv_sec - temp.tv_sec;
   diff->tv_usec = a->tv_usec - temp.tv_usec;
}

/*
 *	times_close_enough -- Check if two times are less than fuzz ms apart
 *
 *	Inputs:
 *
 *	t1	First time value
 *	t2	Second time value
 *	fuzz	Fuzz value
 *
 *	Returns:
 *
 *	1 if t1 and t2 are within fuzz ms of each other.  Otherwise 0.
 */
int
times_close_enough(struct timeval *t1, struct timeval *t2, unsigned fuzz) {
struct timeval diff;
unsigned diff_ms;

   timeval_diff(t1, t2, &diff);	/* diff = t1 - t2 */
   diff_ms = abs(1000*diff.tv_sec + diff.tv_usec/1000);
   if (diff_ms <= fuzz) {
      return 1;
   } else {
      return 0;
   }
}

/*
 *	hstr_i -- Convert two-digit hex string to unsigned integer
 *
 *	Inputs:
 *
 *	cptr	Two-digit hex string
 *
 *	Returns:
 *
 *	Number corresponding to input hex value.
 *
 *	An input of "0A" or "0a" would return 10.
 *	Note that this function does no sanity checking, it's up to the
 *	caller to ensure that *cptr points to at least two hex digits.
 *
 *	This function is a modified version of hstr_i at www.snippets.org.
 */
unsigned int
hstr_i(const char *cptr)
{
      unsigned int i;
      unsigned int j = 0;
      int k;

      for (k=0; k<2; k++) {
            i = *cptr++ - '0';
            if (9 < i)
                  i -= 7;
            j <<= 4;
            j |= (i & 0x0f);
      }
      return j;
}

/*
 *	hex2data -- Convert hex string to binary data
 *
 *	Inputs:
 *
 *	string		The string to convert
 *	data_len	(output) The length of the resultant binary data
 *
 *	Returns:
 *
 *	Pointer to the binary data.
 *
 *	The returned pointer points to malloc'ed storage which should be
 *	free'ed by the caller when it's no longer needed.  If the length of
 *	the input string is not even, the function will return NULL and
 *	set data_len to 0.
 */
unsigned char *
hex2data(const char *string, size_t *data_len) {
   unsigned char *data;
   unsigned char *cp;
   unsigned i;
   size_t len;

   if (strlen(string) %2 ) {	/* Length is odd */
      *data_len = 0;
      return NULL;
   }

   len = strlen(string) / 2;
   data = Malloc(len);
   cp = data;
   for (i=0; i<len; i++)
      *cp++=hstr_i(&string[i*2]);
   *data_len = len;
   return data;
}

/*
 *	hex_or_str -- Convert hex or string to binary data
 *
 *	Inputs:
 *
 *	string		The hex or string to convert
 *	data_len	(output) The length of the resultant binary data
 *
 *	Returns:
 *
 *	Pointer to the binary data, or NULL if an error occurred.
 *
 *	The input string must be in one of the following two formats:
 *
 *	0x<hex-data>	Input is in hex format
 *	string		Input is in string format
 *
 *	The returned pointer points to malloc'ed storage which should be
 *	free'ed by the caller when it's no longer needed.  If the length of
 *	the input string is not even, the function will return NULL and
 *	set data_len to 0.
 */
unsigned char *
hex_or_str(const char *string, size_t *data_len) {

   if (strlen(string) < 1) {	/* Input string too short */
      *data_len = 0;
      return NULL;
   }

   if (string[0] == '0' && string[1] == 'x') {	/* Hex input format */
      return hex2data((string+2), data_len);
   } else {					/* Assume string input format */
      unsigned char *data;
      size_t len;

      len = strlen(string);
      data = Malloc(len);
      memcpy(data, string, len);
      *data_len = len;
      return data;
   }
}

/*
 *	hex_or_num -- Convert hex or number to binary data
 *
 *	Inputs:
 *
 *	string		The hex or string to convert
 *	data_len	(output) The length of the resultant binary data
 *
 *	Returns:
 *
 *	Pointer to the binary data, or NULL if an error occurred.
 *
 *	The input string must be in one of the following two formats:
 *
 *	0x<hex-data>	Input is in hex format
 *	decimal number	Input is in numeric format
 *
 *	For hex input format, the binary data will have the length required
 *	to hold the specified value. For numeric input, the binary data will
 *	be a 32-bit value.  In either case, the binary data will be in
 *	big endian format.
 *
 *	The returned pointer points to malloc'ed storage which should be
 *	free'ed by the caller when it's no longer needed.  If the length of
 *	the input string is not even, the function will return NULL and
 *	set data_len to 0.
 */
unsigned char *
hex_or_num(const char *string, size_t *data_len) {

   if (strlen(string) < 1) {	/* Input string too short */
      *data_len = 0;
      return NULL;
   }

   if (string[0] == '0' && string[1] == 'x') {	/* Hex input format */
      return hex2data((string+2), data_len);
   } else {					/* Assume number input format */
      unsigned char *data;
      size_t len = 4;	/* 32-bit value */
      unsigned long value;
      unsigned long value_be;

      value = Strtoul(string, 10);
      value_be = htonl(value);
      data = Malloc(len);
      memcpy(data, &value_be, len);
      
      *data_len = len;
      return data;
   }
}

/*
 * make_message -- allocate a sufficiently large string and print into it.
 *
 * Inputs:
 *
 * Format and variable number of arguments.
 *
 * Outputs:
 *
 * Pointer to the string,
 *
 * The code for this function is from the Debian Linux "woody" sprintf man
 * page.  Modified slightly to use wrapper functions for malloc and realloc.
 */
char *
make_message(const char *fmt, ...) {
   int n;
   /* Guess we need no more than 100 bytes. */
   size_t size = 100;
   char *p;
   va_list ap;
   p = Malloc (size);
   while (1) {
      /* Try to print in the allocated space. */
      va_start(ap, fmt);
      n = vsnprintf (p, size, fmt, ap);
      va_end(ap);
      /* If that worked, return the string. */
      if (n > -1 && n < (int) size)
         return p;
      /* Else try again with more space. */
      if (n > -1)    /* glibc 2.1 */
         size = n+1; /* precisely what is needed */
      else           /* glibc 2.0 */
         size *= 2;  /* twice the old size */
      p = Realloc (p, size);
   }
}

/*
 *	numstr -- Convert an unsigned integer to a string
 *
 *	Inputs:
 *
 *	num	The number to convert
 *
 *	Returns:
 *
 *	Pointer to the string representation of the number.
 *
 *	I'm surprised that there is not a standard library function to do this.
 */
char *
numstr(unsigned num) {
   static char buf[21];	/* Large enough for biggest 64-bit integer */

   snprintf(buf, sizeof(buf), "%d", num);
   return buf;
}

/*
 *	printable -- Convert string to printable form using C-style escapes
 *
 *	Inputs:
 *
 *	string	Pointer to input string.
 *	size	Size of input string.  0 means that string is null-terminated.
 *
 *	Returns:
 *
 *	Pointer to the printable string.
 *
 *	Any non-printable characters are replaced by C-Style escapes, e.g.
 *	"\n" for newline.  As a result, the returned string may be longer than
 *	the one supplied.
 *
 *	This function makes two passes through the input string: one to
 *	determine the required output length, then a second to perform the
 *	conversion.
 *
 *	The pointer returned points to malloc'ed storage which should be
 *	free'ed by the caller when it's no longer needed.
 */
char *
printable(const unsigned char *string, size_t size) {
   char *result;
   char *r;
   const unsigned char *cp;
   size_t outlen;
   unsigned i;
/*
 *	If the input string is NULL, return an empty string.
 */
   if (string == NULL) {
      result = Malloc(1);
      result[0] = '\0';
      return result;
   }
/*
 *	Determine required size of output string.
 */
   if (!size)
      size = strlen((const char *) string);

   outlen = size;
   cp = string;
   for (i=0; i<size; i++) {
      switch (*cp) {
         case '\\':
         case '\b':
         case '\f':
         case '\n':
         case '\r':
         case '\t':
         case '\v':
            outlen++;
            break;
         default:
            if(!isprint(*cp))
               outlen += 3;
      }
      cp++;
   }
   outlen++;	/* One more for the ending NULL */

   result = Malloc(outlen);

   cp = string;
   r = result;
   for (i=0; i<size; i++) {
      switch (*cp) {
         case '\\':
            *r++ = '\\';
            *r++ = '\\';
            break;
         case '\b':
            *r++ = '\\';
            *r++ = 'b';
            break;
         case '\f':
            *r++ = '\\';
            *r++ = 'f';
            break;
         case '\n':
            *r++ = '\\';
            *r++ = 'n';
            break;
         case '\r':
            *r++ = '\\';
            *r++ = 'r';
            break;
         case '\t':
            *r++ = '\\';
            *r++ = 't';
            break;
         case '\v':
            *r++ = '\\';
            *r++ = 'v';
            break;
         default:
            if (isprint(*cp)) {
               *r++ = *cp;	/* Printable character */
            } else {
               *r++ = '\\';
               sprintf(r, "%.3o", *cp);
               r += 3;
            }
            break;
      }
      cp++;
   }
   *r = '\0';

   return result;
}

/*
 *	hexstring -- Convert data to printable hex string form
 *
 *	Inputs:
 *
 *	string	Pointer to input data.
 *	size	Size of input data.
 *
 *	Returns:
 *
 *	Pointer to the printable hex string.
 *
 *	Each byte in the input data will be represented by two hex digits
 *	in the output string.  Therefore the output string will be twice
 *	as long as the input data plus one extra byte for the trailing NULL.
 *
 *	The pointer returned points to malloc'ed storage which should be
 *	free'ed by the caller when it's no longer needed.
 */
char *
hexstring(const unsigned char *data, size_t size) {
   char *result;
   char *r;
   const unsigned char *cp;
   unsigned i;
/*
 *	If the input data is NULL, return an empty string.
 */
   if (data == NULL) {
      result = Malloc(1);
      result[0] = '\0';
      return result;
   }
/*
 *	Create and return hex string.
 */
   result = Malloc(2*size + 1);
   cp = data;
   r = result;
   for (i=0; i<size; i++) {
      snprintf(r, 3, "%.2x", *cp++);
      r += 2;
   }
   *r = '\0';

   return result;
}

/*
 *	print_times -- Print absolute and delta time for debugging
 *
 *	Inputs:
 *
 *	None.
 *
 *	Returns:
 *
 *	None.
 *
 *	This function is only used for debugging.  It should not be called
 *	from production code.
 */
void
print_times(void) {
   static struct timeval time_first;    /* When print_times() was first called */
   static struct timeval time_last;     /* When print_times() was last called */
   static int first_call=1;
   struct timeval time_now;
   struct timeval time_delta1;
   struct timeval time_delta2;

   Gettimeofday(&time_now);

   if (first_call) {
      first_call=0;
      time_first.tv_sec  = time_now.tv_sec;
      time_first.tv_usec = time_now.tv_usec;
      printf("%lu.%.6lu (0.000000) [0.000000]\n",
             (unsigned long)time_now.tv_sec, (unsigned long)time_now.tv_usec);
   } else {
      timeval_diff(&time_now, &time_last, &time_delta1);
      timeval_diff(&time_now, &time_first, &time_delta2);
      printf("%lu.%.6lu (%lu.%.6lu) [%lu.%.6lu]\n",
             (unsigned long)time_now.tv_sec,
             (unsigned long)time_now.tv_usec,
             (unsigned long)time_delta1.tv_sec,
             (unsigned long)time_delta1.tv_usec,
             (unsigned long)time_delta2.tv_sec,
             (unsigned long)time_delta2.tv_usec);
   }
   time_last.tv_sec  = time_now.tv_sec;
   time_last.tv_usec = time_now.tv_usec;
}

/*
 *	sig_alarm -- Signal handler for SIGALRM
 *
 *	Inputs:
 *
 *	signo		The signal number (ignored)
 *
 *	Returns:
 *
 *	None.
 *
 *	This function is used as the signal handler for SIGALRM.
 *	It doesn't perform any processing; it merely returns to
 *	interrupt the current system call.
 */
void sig_alarm(int signo ATTRIBUTE_UNUSED) {
   return;      /* just interrupt the current system call */
}

/*
 *	id_to_name -- Return name associated with given id, or id number
 *
 *	Inputs:
 *
 *	id		The id to find in the map
 *	id_name_map	Pointer to the id-to-name map
 *
 *	Returns:
 *
 *	A pointer to the name associated with the id if an association is
 *	found in the map, otherwise the numeric id.  Returns NULL on error.
 *
 *	This function uses a sequential search through the map to find the
 *	ID and associated name.  This is OK when the map is relatively small,
 *	but could be time consuming if the map contains a large number of
 *	entries.
 */
const char *
id_to_name(unsigned id, const id_name_map map[]) {
   int found = 0;
   int i = 0;

   if (map == NULL)
      return NULL;

   while (map[i].id != -1) {
      if (id == (unsigned)map[i].id) {
         found = 1;
         break;
      }
      i++;
   }

   if (found)
      return map[i].name;
   else
      return numstr(id);
}

/*
 *	name_to_id -- Return id associated with given name
 *
 *	Inputs:
 *
 *	name		The name to find in the map
 *	id_name_map	Pointer to the id-to-name map
 *
 *	Returns:
 *
 *	The id associated with the name if an association is found in the
 *	map, otherwise -1.
 *
 *	This function uses a sequential search through the map to find the
 *	ID and associated name.  This is OK when the map is relatively small,
 *	but could be time consuming if the map contains a large number of
 *	entries.
 *
 *	The search is case-blind.
 */
int
name_to_id(const char *name, const id_name_map map[]) {
   int found = 0;
   int i = 0;

   if (map == NULL)
      return -1;

   while (map[i].id != -1) {
      if ((str_ccmp(name,map[i].name)) == 0) {
         found = 1;
         break;
      }
      i++;
   }

   if (found)
      return map[i].id;
   else
      return -1;
}

/* Standard BSD internet checksum routine */
uint16_t
in_cksum(uint16_t *ptr, size_t nbytes) {

   register uint32_t sum;
   uint16_t oddbyte;
   register uint16_t answer;

/*
 * Our algorithm is simple, using a 32-bit accumulator (sum),
 * we add sequential 16-bit words to it, and at the end, fold back
 * all the carry bits from the top 16 bits into the lower 16 bits.
 */

   sum = 0;
   while (nbytes > 1)  {
      sum += *ptr++;
      nbytes -= 2;
   }

/* mop up an odd byte, if necessary */
   if (nbytes == 1) {
      oddbyte = 0;            /* make sure top half is zero */
      *((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
      sum += oddbyte;
   }

/*
 * Add back carry outs from top 16 bits to low 16 bits.
 */

   sum  = (sum >> 16) + (sum & 0xffff);    /* add high-16 to low-16 */
   sum += (sum >> 16);                     /* add carry */
   answer = ~sum;          /* ones-complement, then truncate to 16 bits */
   return(answer);
}

/*
 *	random_byte -- Return a random byte in range 0..255
 *
 *	Inputs:	None
 *
 *	Returns: The random byte
 */
uint8_t
random_byte(void) {
   static union {
      uint32_t longword;
      uint8_t byte[4];
   } random_data;
   static int num_bytes = 0;	/* Number of bytes available */

   if (num_bytes == 0) {
      uint32_t random_value;

      random_value = genrand_int32();
      random_data.longword = htonl(random_value);
      num_bytes = 4;
   }
   return random_data.byte[--num_bytes];
}

/*
 *	random_ip	-- Return a random IP address
 *
 *	Imputs:	None
 *	Returns: A random IP address
 *
 *	This returns a random IP address as a 32-bit value in host byte
 *	order.
 *
 *	It will not return the following IP address ranges, because they
 *	are invalid:
 *
 *	0/8, 1/8 or 2/8 - IANA reserved
 *	127/8 - Localhost
 *	Class D (Multicast)
 *	Class E (Reserved)
 */
uint32_t
random_ip(void) {
   uint32_t random_value;
   int acceptable;

   do {
      random_value = genrand_int32();
      if ((random_value & 0xff000000) == 0x7f000000 ||	/* 127.x.x.x */
          random_value > 0xefffffff ||			/* Class D or E */
          random_value < 0x03000000) {			/* 0/8, 1/8 or 2/8 */
         acceptable = 0;
      } else {
         acceptable = 1;
      }
   } while (!acceptable);

   return random_value;
}

/*
 *	str_ccmp  -- Case-blind string comparison
 *
 *	Inputs:
 *
 *	s1 -- The first input string
 *	s2 -- The second input string
 *
 *	Returns:
 *
 *	An integer indicating whether s1 is less than (-1), the same as (0),
 *	or greater than (1) s2.
 *
 *	This function performs the same function, and takes the same arguments
 *	as the common library function strcasecmp.  This function is used
 *	instead because strcasecmp is not portable.
 */
int
str_ccmp( const char *s1, const char *s2 ) {
   int c1, c2;

   for( ; ; s1++, s2++ ){
      c1 = tolower( (unsigned char) *s1 );
      c2 = tolower( (unsigned char) *s2 );

      if( c1 > c2            )  return   1;
      if( c1 < c2            )  return  -1;
      if( c1 == 0 && c2 == 0 )  return   0;
   }
} 

/*
 *	name_or_number -- Calculate the numeric value of a string containing
 *	                  either a name from a map, or a number.
 *
 *	Inputs:
 *
 *	string		The input string
 *	map		The ID/name map
 */
unsigned
name_or_number(const char *string, const id_name_map map[]) {
   int result;
   char *endptr;

   result=strtoul(string, &endptr, 0);
   if (endptr != string)  /* Successful conversion */
      return result;

   result=name_to_id(string, map);
   if (result == -1)
      err_msg("Invalid value: %s", string);

   return result;
}

/*
 *	str_to_bandwidth -- Convert a bandwidth string to unsigned integer
 *
 *	Inputs:
 *
 *	bandwidth_string	The bandwidth string to convert
 *
 *	Returns:
 *
 *	The bandwidth in bits per second as an unsigned integer
 */
unsigned
str_to_bandwidth(const char *bandwidth_string) {
   char *bandwidth_str;
   size_t bandwidth_len;
   unsigned value;
   int multiplier=1;
   int end_char;

   bandwidth_str=dupstr(bandwidth_string);	/* Writable copy */
   bandwidth_len=strlen(bandwidth_str);
   end_char = bandwidth_str[bandwidth_len-1];
   if (!isdigit(end_char)) {	/* End character is not a digit */
      bandwidth_str[bandwidth_len-1] = '\0';	/* Remove last character */
      switch (end_char) {
         case 'M':
         case 'm':
            multiplier = 1000000;
            break;
         case 'K':
         case 'k':
            multiplier = 1000;
            break;
         default:
            err_msg("ERROR: Unknown bandwidth multiplier character: \"%c\"",
                    end_char);
            break;
      }
   }
   value=Strtoul(bandwidth_str, 10);
   free(bandwidth_str);
   return multiplier * value;
}

/*
 *	str_to_interval -- Convert an interval string to unsigned integer
 *
 *	Inputs:
 *
 *	interval_string		The interval string to convert
 *
 *	Returns:
 *
 *	The interval in microsecons as an unsigned integer
 */
unsigned
str_to_interval(const char *interval_string) {
   char *interval_str;
   size_t interval_len;
   unsigned value;
   int multiplier=1000;
   int end_char;

   interval_str=dupstr(interval_string);	/* Writable copy */
   interval_len=strlen(interval_str);
   end_char = interval_str[interval_len-1];
   if (!isdigit(end_char)) {	/* End character is not a digit */
      interval_str[interval_len-1] = '\0';	/* Remove last character */
      switch (end_char) {
         case 'U':
         case 'u':
            multiplier = 1;
            break;
         case 'S':
         case 's':
            multiplier = 1000000;
            break;
         default:
            err_msg("ERROR: Unknown interval multiplier character: \"%c\"",
                    end_char);
            break;
      }
   }
   value=Strtoul(interval_str, 10);
   free(interval_str);
   return multiplier * value;
}

/*
 *	dupstr -- duplicate a string
 *
 *	Inputs:
 *
 *	str	The string to duplcate
 *
 *	Returns:
 *
 *	A pointer to the duplicate string.
 *
 *	This is a replacement for the common but non-standard "strdup"
 *	function.
 *
 *	The returned pointer points to Malloc'ed memory, which must be
 *	free'ed by the caller.
 */
char *
dupstr(const char *str) {
   char *cp;
   size_t len;

   len = strlen(str) + 1;	/* Allow space for terminating NULL */
   cp = Malloc(len);
   strlcpy(cp, str, len);
   return cp;
}
