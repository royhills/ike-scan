/*
   Copyright (C) 1991, 92, 93, 95, 96, 97 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef NTA_NETINET_UDP_H
#define NTA_NETINET_UDP_H    1

/* UDP header as specified by RFC 768, August 1980. */

struct udphdr {
  uint16_t	source;
  uint16_t	dest;
  uint16_t	len;
  uint16_t	check;
};

/* rsh addition */
struct pseudo_hdr {  /* For computing UDP checksum */
   uint32_t	src_addr;
   uint32_t	dst_addr;
   uint8_t	mbz;
   uint8_t	proto;
   uint16_t	length;
};


#endif /* netinet/udp.h */
