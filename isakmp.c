/*
 * The IKE Scanner (ike-scan) is Copyright (C) 2003 Roy Hills, NTA Monitor Ltd.
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
 * Author: Roy Hills
 * Date: 7 November 2003
 *
 * Functions to construct ISAKMP headers and payloads.
 *
 */

#include "ike-scan.h"

static char rcsid[] = "$Id$";	/* RCS ID for ident(1) */

extern int experimental;

/*
 *	make_isakmp_hdr -- Construct an ISAKMP Header
 *
 *	Inputs:
 *
 *	xchg	Exchange Type (e.g. ISAKMP_XCHG_IDPROT for main mode)
 *	next	Next Payload Type
 *	length	ISAKMP Message total length
 *
 *	Returns:
 *
 *	Pointer to created ISAKMP Header.
 *
 *	This constructs an ISAKMP header.  It fills in the static values.
 *	The initator cookie should be changed to a unique per-host value
 *	before the packet is sent.
 */
struct isakmp_hdr*
make_isakmp_hdr(uint8_t xchg, uint8_t next, uint32_t length) {
   struct isakmp_hdr* hdr;

   hdr = Malloc(sizeof(struct isakmp_hdr));
   memset(hdr, '\0', sizeof(struct isakmp_hdr));

   hdr->isa_icookie[0] = 0xdeadbeef;	/* Initiator cookie */
   hdr->isa_icookie[1] = 0xdeadbeef;
   hdr->isa_rcookie[0] = 0;		/* Set responder cookie to 0 */
   hdr->isa_rcookie[1] = 0;
   hdr->isa_np = next;			/* Next Payload Type */
   hdr->isa_version = 0x10;		/* v1.0 */
   hdr->isa_xchg = xchg;		/* Exchange type */
   hdr->isa_flags = 0;			/* No flags */
   hdr->isa_msgid = 0;			/* MBZ for phase-1 */
   hdr->isa_length = htonl(length);	/* Total ISAKMP message length */

   return hdr;
}

/*
 *	make_sa_hdr -- Construct an SA Header
 *
 *	Inputs:
 *
 *	next    Next Payload Type
 *	length	SA payload length
 *
 *	Returns:
 *
 *	Pointer to SA Header.
 *
 *	This constructs an SA header.  It fills in the static values.
 */
struct isakmp_sa*
make_sa_hdr(uint8_t next, uint32_t length) {
   struct isakmp_sa* hdr;

   hdr = Malloc(sizeof(struct isakmp_sa));
   memset(hdr, '\0', sizeof(struct isakmp_sa));

   hdr->isasa_np = next;		/* Next Payload Type */
   hdr->isasa_length = htons(length);		/* SA Payload length */
   hdr->isasa_doi = htonl(ISAKMP_DOI_IPSEC);	/* IPsec DOI */
   hdr->isasa_situation = htonl(SIT_IDENTITY_ONLY);	/* Exchange type */

   return hdr;
}

/*
 *	make_prop -- Construct a proposal payload
 *
 *	Inputs:
 *
 *	length	Proposal payload length
 *	notrans	Number of transforms in this proposal
 *
 *	Returns:
 *
 *	Pointer to proposal payload.
 *
 *	This constructs a proposal payload.  It fills in the static values.
 *	We assume only one proposal will be created.  I think that ISAKMP SAs
 *	are only allowed to have one proposal anyway.
 */
struct isakmp_proposal*
make_prop(uint32_t length, uint8_t notrans) {
   struct isakmp_proposal* hdr;

   hdr = Malloc(sizeof(struct isakmp_proposal));
   memset(hdr, '\0', sizeof(struct isakmp_proposal));

   hdr->isap_np = 0;			/* No more proposals */
   hdr->isap_length = htons(length);	/* Proposal payload length */
   hdr->isap_proposal = 1;		/* Proposal #1 */
   hdr->isap_protoid = PROTO_ISAKMP;
   hdr->isap_spisize = 0;		/* No SPI */
   hdr->isap_notrans = notrans;		/* Number of transforms */

   return hdr;
}

/*
 *	make_trans -- Construct a single transform payload
 *
 *	Inputs:
 *
 *	length	(output) length of entire transform payload.
 *	next    Next Payload Type (3 = More transforms; 0=No more transforms)
 *	number	Transform number
 *	cipher	The encryption algorithm
 *	keylen	Key length for variable length keys (0=fixed key length)
 *	hash	Hash algorithm
 *	auth	Authentication method
 *	group	DH Group number
 *	lifetime	Lifetime in seconds (0=no lifetime)
 *	lifesize	Life in kilobytes (0=no life)
 *
 *	Returns:
 *
 *	Pointer to transform payload.
 *
 *	This constructs a single transform payload.
 *	Most of the values are defined in RFC 2409 Appendix A.
 */
unsigned char*
make_trans(size_t *length, uint8_t next, uint8_t number, uint16_t cipher,
           uint16_t keylen, uint16_t hash, uint16_t auth, uint16_t group,
           uint32_t lifetime, uint32_t lifesize, int gss_id_flag,
           unsigned char *gss_data, size_t gss_data_len) {

   struct isakmp_transform* hdr;	/* Transform header */
   struct isakmp_attribute* attr1;	/* Mandatory attributes */
   struct isakmp_attribute* attr2=NULL;	/* Optional keylen attribute */
   struct isakmp_attribute* attr3=NULL;	/* Optional lifetype attribute */
   struct isakmp_attribute_l32* attr4=NULL; /* Optional lifetime attribute */
   struct isakmp_attribute* attr5=NULL;	/* Optional lifetype attribute */
   struct isakmp_attribute_l32* attr6=NULL; /* Optional lifesize attribute */
   unsigned char *gssid=NULL;		/* Optional GSSID attribute */
   unsigned char *payload;
   unsigned char *cp;
   size_t len;				/* Payload Length */

/* Allocate and initialise the transform header */

   hdr = Malloc(sizeof(struct isakmp_transform));
   memset(hdr, '\0', sizeof(struct isakmp_transform));

   hdr->isat_np = next;			/* Next payload type */
   hdr->isat_transnum = number;		/* Transform Number */
   hdr->isat_transid = KEY_IKE;

/* Allocate and initialise the mandatory attributes */

   attr1 = Malloc(4 * sizeof(struct isakmp_attribute));

   attr1[0].isaat_af_type = htons(0x8001);	/* Encryption Algorithm */
   attr1[0].isaat_lv = htons(cipher);
   attr1[1].isaat_af_type = htons(0x8002);	/* Hash Algorithm */
   attr1[1].isaat_lv = htons(hash);
   attr1[2].isaat_af_type = htons(0x8003);	/* Authentication Method */
   attr1[2].isaat_lv = htons(auth);
   attr1[3].isaat_af_type = htons(0x8004);	/* Group Description */
   attr1[3].isaat_lv = htons(group);

   len = sizeof(struct isakmp_transform) + 4 * sizeof(struct isakmp_attribute);

/* Allocate and initialise the optional attributes */

   if (keylen) {
      attr2 = Malloc(sizeof(struct isakmp_attribute));
      attr2->isaat_af_type = htons(0x800e);	/* Key Length */
      attr2->isaat_lv = htons(keylen);
      len += sizeof(struct isakmp_attribute);
   }

   if (lifetime) {
      attr3 = Malloc(sizeof(struct isakmp_attribute));
      attr4 = Malloc(sizeof(struct isakmp_attribute_l32));
      attr3->isaat_af_type = htons(0x800b);	/* Life Type */
      attr3->isaat_lv = htons(1);		/* Seconds */
      attr4->isaat_af_type = htons(0x000c);	/* Life Duratiion */
      attr4->isaat_l = htons(4);		/* 4 Bytes- CANT CHANGE */
      attr4->isaat_v = htonl(lifetime);		/* Lifetime in seconds */
      len += sizeof(struct isakmp_attribute) +
             sizeof(struct isakmp_attribute_l32);
   }

   if (lifesize) {
      attr5 = Malloc(sizeof(struct isakmp_attribute));
      attr6 = Malloc(sizeof(struct isakmp_attribute_l32));
      attr5->isaat_af_type = htons(0x800b);	/* Life Type */
      attr5->isaat_lv = htons(2);		/* Kilobytes */
      attr6->isaat_af_type = htons(0x000c);	/* Life Duratiion */
      attr6->isaat_l = htons(4);		/* 4 Bytes- CANT CHANGE */
      attr6->isaat_v = htonl(lifesize);		/* Lifetime in seconds */
      len += sizeof(struct isakmp_attribute) +
             sizeof(struct isakmp_attribute_l32);
   }

   if (gss_id_flag) {
      struct isakmp_attribute *gss_hdr;
      gssid = Malloc(gss_data_len + sizeof(struct isakmp_attribute));
      gss_hdr = (struct isakmp_attribute *) gssid;	/* Overlay */
      gss_hdr->isaat_af_type = htons(16384);	/* GSS ID */
      gss_hdr->isaat_lv = htons(gss_data_len);
      memcpy(gssid+sizeof(struct isakmp_attribute), gss_data, gss_data_len);
      len += gss_data_len + sizeof(struct isakmp_attribute);
   }

/* Fill in length value now we know it */

   hdr->isat_length = htons(len);	/* Transform length */
   *length = len;

/* Allocate memory for payload and copy structures to payload */

   payload = Malloc(len);

   cp = payload;
   memcpy(cp, hdr, sizeof(struct isakmp_transform));
   free(hdr);
   cp += sizeof(struct isakmp_transform);
   memcpy(cp, attr1, 4 * sizeof(struct isakmp_attribute));
   free(attr1);
   cp += 4 * sizeof(struct isakmp_attribute);
   if (keylen) {
      memcpy(cp, attr2, sizeof(struct isakmp_attribute));
      free(attr2);
      cp += sizeof(struct isakmp_attribute);
   }
   if (lifetime) {
      memcpy(cp, attr3, sizeof(struct isakmp_attribute));
      free(attr3);
      cp += sizeof(struct isakmp_attribute);
      memcpy(cp, attr4, sizeof(struct isakmp_attribute_l32));
      free(attr4);
      cp += sizeof(struct isakmp_attribute_l32);
   }
   if (lifesize) {
      memcpy(cp, attr5, sizeof(struct isakmp_attribute));
      free(attr5);
      cp += sizeof(struct isakmp_attribute);
      memcpy(cp, attr6, sizeof(struct isakmp_attribute_l32));
      free(attr6);
      cp += sizeof(struct isakmp_attribute_l32);
   }
   if (gss_id_flag) {
      memcpy(cp, gssid, gss_data_len+sizeof(struct isakmp_attribute));
      free(gssid);
      cp += gss_data_len+sizeof(struct isakmp_attribute);
   }


   return payload;
}

/*
 *	add_trans -- Add a transform payload onto the set of transforms.
 *
 *	Inputs:
 *
 *	finished	0 if adding a new transform; 1 if finalising.
 *	length	(output) length of entire transform payload.
 *	cipher	The encryption algorithm
 *	keylen	Key length for variable length keys (0=fixed key length)
 *	hash	Hash algorithm
 *	auth	Authentication method
 *	group	DH Group number
 *	lifetime	Lifetime in seconds (0=no lifetime)
 *
 *	Returns:
 *
 *	Pointer to new set of transform payloads.
 *
 *	This function can either be called with finished = 0, in which case
 *	cipher, keylen, hash, auth, group and lifetime must be specified, and
 *	the function will return NULL, OR it can be called with finished = 1
 *	in which case cipher, keylen, hash, auth, group and lifetime are
 *	ignored and the function will return a pointer to the finished
 *	payload and will set *length to the length of this payload.
 */
unsigned char*
add_trans(int finished, size_t *length,
          uint16_t cipher, uint16_t keylen, uint16_t hash, uint16_t auth,
          uint16_t group, uint32_t lifetime, uint32_t lifesize,
          int gss_id_flag, unsigned char *gss_data, size_t gss_data_len) {

   static int first_transform = 1;
   static unsigned char *trans_start=NULL;	/* Start of set of transforms */
   static size_t cur_offset;			/* Start of current transform */
   static size_t end_offset;			/* End of transforms */
   static int trans_no=1;
   unsigned char *trans;			/* Transform payload */
   size_t len;					/* Transform length */
/*
 * Construct a transform if we are not finalising.
 * Set next to 3 (more transforms), and increment trans_no for next time round.
 */
   if (!finished) {
      trans = make_trans(&len, 3, trans_no, cipher, keylen, hash, auth,
                         group, lifetime, lifesize, gss_id_flag, gss_data,
                         gss_data_len);
      trans_no++;
      if (first_transform) {
         cur_offset = 0;
         end_offset = len;
         trans_start = Malloc(end_offset);
         memcpy(trans_start, trans, len);
         first_transform = 0;
      } else {
         cur_offset = end_offset;
         end_offset += len;
         trans_start = Realloc(trans_start, end_offset);
         memcpy(trans_start+cur_offset, trans, len);
      }
      return NULL;
   } else {
      struct isakmp_transform* hdr =
         (struct isakmp_transform*) (trans_start+cur_offset);	/* Overlay */

      hdr->isat_np = 0;		/* No more transforms */
      *length = end_offset;
      return trans_start;
   }
}

/*
 *	make_vid -- Construct a vendor id payload
 *
 *	Inputs:
 *
 *	length	(output) length of Vendor ID payload.
 *	next		Next Payload Type
 *	vid_data	Vendor ID data
 *	vid_data_len	Vendor ID data length
 *
 *	Returns:
 *
 *	Pointer to vendor id payload.
 *
 *	This constructs a vendor id payload.  It fills in the static values.
 *	The next pointer value must be filled in later.
 */
unsigned char*
make_vid(size_t *length, uint8_t next, unsigned char *vid_data,
         size_t vid_data_len) {
   unsigned char *payload;
   struct isakmp_vid* hdr;

   payload = Malloc(sizeof(struct isakmp_vid)+vid_data_len);
   hdr = (struct isakmp_vid*) payload;	/* Overlay vid struct on payload */
   memset(hdr, '\0', sizeof(struct isakmp_vid));

   hdr->isavid_np = next;		/* Next payload type */
   hdr->isavid_length = htons(sizeof(struct isakmp_vid)+vid_data_len);

   memcpy(payload+sizeof(struct isakmp_vid), vid_data, vid_data_len);
   *length = sizeof(struct isakmp_vid) + vid_data_len;

   return payload;
}

/*
 *	add_vid -- Add a vendor ID payload to the set of VIDs.
 *
 *	Inputs:
 *
 *      finished        0 if adding a new VIDs; 1 if finalising.
 *      length  (output) length of entire VID payload set.
 *      vid_data        Vendor ID data
 *      vid_data_len    Vendor ID data length
 *
 *	Returns:
 *
 *	Pointer to the VID payload.
 *
 *	This function can either be called with finished = 0, in which case
 *	vid_data and vid_data_len must be specified, and
 *	the function will return NULL, OR it can be called with finished = 1
 *	in which case vid_data and vid_data_len are
 *	ignored and the function will return a pointer to the finished
 *	payload and will set *length to the length of this payload.
 */
unsigned char*
add_vid(int finished, size_t *length, unsigned char *vid_data,
        size_t vid_data_len) {
   static int first_vid = 1;
   static unsigned char *vid_start=NULL;	/* Start of set of VIDs */
   static size_t cur_offset;			/* Start of current VID */
   static size_t end_offset;			/* End of VIDs */
   unsigned char *vid;				/* VID payload */
   size_t len;					/* VID length */
/*
 * Construct a VID if we are not finalising.
 */
   if (!finished) {
      vid = make_vid(&len, ISAKMP_NEXT_VID, vid_data, vid_data_len);
      if (first_vid) {
         cur_offset = 0;
         end_offset = len;
         vid_start = Malloc(end_offset);
         memcpy(vid_start, vid, len);
         first_vid = 0;
      } else {
         cur_offset = end_offset;
         end_offset += len;
         vid_start = Realloc(vid_start, end_offset);
         memcpy(vid_start+cur_offset, vid, len);
      }
      return NULL;
   } else {
      struct isakmp_vid* hdr =
         (struct isakmp_vid*) (vid_start+cur_offset);   /* Overlay */

      hdr->isavid_np = ISAKMP_NEXT_NONE;         /* No more payloads */
      *length = end_offset;
      return vid_start;
   }
}

/*
 *	make_ke	-- Make a Key Exchange payload
 *
 *	Inputs:
 *
 *      length		(output) length of key exchange payload.
 *      next		Next Payload Type
 *      kx_data_len	Key exchange data length
 *
 *	Returns:
 *
 *	Pointer to key exchange payload.
 *
 *	A real implementation would fill in the key exchange payload with the
 *	Diffie Hellman public value.  However, we just use random data.
 */
unsigned char*
make_ke(size_t *length, uint8_t next, size_t kx_data_len) {
   unsigned char *payload;
   struct isakmp_kx* hdr;
   unsigned char *kx_data;
   int i;

   if (kx_data_len % 4)
      err_msg("Key exchange data length %d is not a multiple of 4",
              kx_data_len);

   payload = Malloc(sizeof(struct isakmp_kx)+kx_data_len);
   hdr = (struct isakmp_kx*) payload;	/* Overlay kx struct on payload */
   memset(hdr, '\0', sizeof(struct isakmp_kx));

   kx_data = payload + sizeof(struct isakmp_kx);
   for (i=0; i<kx_data_len; i++)
      *(kx_data++) = (unsigned char) (rand() & 0xff);

   hdr->isakx_np = next;		/* Next payload type */
   hdr->isakx_length = htons(sizeof(struct isakmp_kx)+kx_data_len);

   *length = sizeof(struct isakmp_kx) + kx_data_len;

   return payload;
}

/*
 *	make_nonce	-- Make a Nonce payload
 *
 *	Inputs:
 *
 *	length		(output) length of nonce payload.
 *      next		Next Payload Type
 *	nonce_len	Length of nonce data.
 *
 *	Returns:
 *
 *	Pointer to nonce payload.
 *
 *	For a real implementation, the nonce should use strong random numbers.
 *	However, we just use rand() because we don't care about the quality of
 *	the random numbers for this tool.
 */
unsigned char*
make_nonce(size_t *length, uint8_t next, size_t nonce_len) {
   unsigned char *payload;
   struct isakmp_nonce* hdr;
   unsigned char *cp;
   int i;

   payload = Malloc(sizeof(struct isakmp_nonce)+nonce_len);
   hdr = (struct isakmp_nonce*) payload;  /* Overlay nonce struct on payload */
   memset(hdr, '\0', sizeof(struct isakmp_nonce));

   hdr->isanonce_np = next;		/* Next payload type */
   hdr->isanonce_length = htons(sizeof(struct isakmp_nonce)+nonce_len);

   cp = payload+sizeof(struct isakmp_vid);
   for (i=0; i<nonce_len; i++)
      *(cp++) = (unsigned char) (rand() & 0xff);

   *length = sizeof(struct isakmp_nonce)+nonce_len;
   return payload;
}

/*
 *	make_id	-- Make an Identification payload
 *
 *	Inputs:
 *
 *      length		(output) length of ID payload.
 *      next		Next Payload Type
 *	idtype		Identification Type
 *      id_data		ID data
 *      id_data_len	ID data length
 *
 */
unsigned char*
make_id(size_t *length, uint8_t next, uint8_t idtype, unsigned char *id_data,
        size_t id_data_len) {
   unsigned char *payload;
   struct isakmp_id* hdr;

   payload = Malloc(sizeof(struct isakmp_id)+id_data_len);
   hdr = (struct isakmp_id*) payload;	/* Overlay ID struct on payload */
   memset(hdr, '\0', sizeof(struct isakmp_id));

   hdr->isaid_np = next;		/* Next payload type */
   hdr->isaid_length = htons(sizeof(struct isakmp_id)+id_data_len);
   hdr->isaid_idtype = idtype;
/*
 *	RFC 2407 4.6.2: "During Phase I negotiations, the ID port and protocol
 *	fields MUST be set to zero or to UDP port 500"
 */
   hdr->isaid_doi_specific_a = 17;		/* Protocol: UDP */
   hdr->isaid_doi_specific_b = htons(500);	/* Port: 500 */

   memcpy(payload+sizeof(struct isakmp_id), id_data, id_data_len);
   *length = sizeof(struct isakmp_id) + id_data_len;

   return payload;
}

/*
 *	skip_payload -- Skip an ISAMKP payload
 *
 *	Inputs:
 *
 *	cp	Pointer to start of payload to skip
 *	len	Packet length remaining
 *	next	Next payload type.
 *
 *	Returns:
 *
 *	Pointer to start of next payload, or NULL if no next payload.
 */
unsigned char *
skip_payload(unsigned char *cp, size_t *len, int *next) {
   struct isakmp_generic *hdr = (struct isakmp_generic *) cp;
/*
 *	Signal no more payloads by setting length to zero if:
 *
 *	The packet length is less than the ISAKMP generic header size; or
 *	The payload length is greater than the packet length; or
 *	The payload length is less than the size of the generic header; or
 *	There is no next payload.
 *
 *	Also set *next to none and return null.
 */
   if (*len < sizeof(struct isakmp_generic) ||
       ntohs(hdr->isag_length) >= *len ||
       ntohs(hdr->isag_length) < sizeof(struct isakmp_generic) ||
       hdr->isag_np == ISAKMP_NEXT_NONE) {
      *len=0;
      *next=ISAKMP_NEXT_NONE;
      return NULL;
   }
/*
 *	There is another payload after this one, so adjust length and
 *	return pointer to next payload.
 */
   *len = *len - ntohs(hdr->isag_length);
   *next = hdr->isag_np;
   return cp + ntohs(hdr->isag_length);
}

/*
 *	process_isakmp_hdr -- Process ISAKMP header
 *
 *	Inputs:
 *
 *	cp	Pointer to start of ISAKMP header
 *	len	Packet length remaining
 *	next	Next payload type.
 *	type	Exchange type
 *
 *	Returns:
 *
 *	Pointer to start of next payload, or NULL if no next payload.
 */
unsigned char *
process_isakmp_hdr(unsigned char *cp, size_t *len, int *next, int *type) {
   struct isakmp_hdr *hdr = (struct isakmp_hdr *) cp;
/*
 *	Signal no more payloads by setting length to zero if:
 *
 *	The packet length is less than the ISAKMP header size; or
 *	The payload length is less than the size of the header; or
 *	There is no next payload.
 *
 *	Also set *next to none and return null.
 */
   if (*len < sizeof(struct isakmp_hdr) ||
       ntohl(hdr->isa_length) < sizeof(struct isakmp_hdr) ||
       hdr->isa_np == ISAKMP_NEXT_NONE) {
      *len=0;
      *next=ISAKMP_NEXT_NONE;
      *type=ISAKMP_XCHG_NONE;
      return NULL;
   }
/*
 *	There is another payload after this one, so adjust length and
 *	return pointer to next payload.
 */
   *len = *len - sizeof(struct isakmp_hdr);
   *next = hdr->isa_np;
   *type = hdr->isa_xchg;
   return cp + sizeof(struct isakmp_hdr);
}

/*
 *	process_sa -- Process SA Payload
 *
 *	Inputs:
 *
 *	cp	Pointer to start of SA payload
 *	len	Packet length remaining
 *	type	Exchange type.
 *	quiet	Only print the basic info if nonzero
 *	multiline	Split decodes across lines if nonzero
 *
 *	Returns:
 *
 *	Pointer to SA description string.
 *
 *	The description string pointer returned points to malloc'ed storage
 *	which should be free'ed by the caller when it's no longer needed.
 */
char *
process_sa(unsigned char *cp, size_t len, int type, int quiet, int multiline) {
   struct isakmp_sa *sa_hdr = (struct isakmp_sa *) cp;
   struct isakmp_proposal *prop_hdr =
      (struct isakmp_proposal *) (cp + sizeof(struct isakmp_sa));
   char *msg;
   char *msg2;
   char *msg3;
   unsigned char *attr_ptr;
   size_t safelen;	/* Shorter of actual and claimed length */

   safelen = (ntohs(sa_hdr->isasa_length)<len)?ntohs(sa_hdr->isasa_length):len;
/*
 *	Return with a "too short to decode" message if either the remaining
 *	packet length or the claimed payload length is less than the combined
 *	size of the SA, Proposal, and transform headers.
 */
   if (safelen < sizeof(struct isakmp_sa) + sizeof(struct isakmp_proposal) +
       sizeof(struct isakmp_transform))
      return make_message("IKE Handshake returned (packet too short to decode)");
/*
 *	Build the first part of the message based on the exchange type.
 */
   if (type == ISAKMP_XCHG_IDPROT) {		/* Main Mode */
      msg = make_message("Main Mode Handshake returned");
   } else if (type == ISAKMP_XCHG_AGGR) {	/* Aggressive Mode */
      msg = make_message("Aggressive Mode Handshake returned");
   } else {
      msg = make_message("UNKNOWN Mode Handshake returned (%u)", type);
   }
/*
 *	We should have exactly one transform in the server's response.
 *	If there is not one transform, then add this fact to the message.
 */
   if (prop_hdr->isap_notrans != 1) {
      msg2 = msg;
      msg = make_message("%s (%d transforms)", msg2, prop_hdr->isap_notrans);
      free(msg2);
   }
/*
 *	If quiet is not in effect, add the transform details to the message.
 */
   if (!quiet) {
      int firstloop=1;

      msg2 = msg;
      msg = make_message("%s%sSA=(", msg2, multiline?"\n\t":" ");
      free(msg2);
      attr_ptr = (cp + sizeof(struct isakmp_sa) + sizeof(struct isakmp_proposal) +
                  sizeof(struct isakmp_transform));
      safelen -= sizeof(struct isakmp_sa) + sizeof(struct isakmp_proposal) +
                 sizeof(struct isakmp_transform);

      while (safelen) {
         msg2 = msg;
         msg3 = process_attr(&attr_ptr, &safelen);
         if (firstloop) {	/* Don't need leading space for 1st attr */
            msg = make_message("%s%s", msg2, msg3);
            firstloop=0;
         } else {
            msg = make_message("%s %s", msg2, msg3);
         }
         free(msg2);
         free(msg3);
      }
      msg2 = msg;
      msg = make_message("%s)", msg2);
      free(msg2);
   }

   return msg;
}

/*
 *	process_attr -- Process transform attribute
 *
 *	Inputs:
 *
 *	cp	Pointer to start of attribute
 *	len	Packet length remaining
 *
 *	Returns:
 *
 *	Pointer to attribute description string.
 *
 *	The description string pointer returned points to malloc'ed storage
 *	which should be free'ed by the caller when it's no longer needed.
 */
char *
process_attr(unsigned char **cp, size_t *len) {
   char *msg;
   struct isakmp_attribute *attr_hdr = (struct isakmp_attribute *) *cp;
   char attr_type;	/* B=Basic, V=Variable */
   unsigned attr_class;
   unsigned attr_value=0;
   char *attr_class_str;
   char *attr_value_str;
   size_t value_len;
   size_t size;
   static const char *attr_classes[] = {	/* From RFC 2409 App. A */
      NULL,					/*  0 */
      "Enc",					/*  1 */
      "Hash",					/*  2 */
      "Auth",					/*  3 */
      "Group",					/*  4 */
      "GroupType",				/*  5 */
      "GroupPrime/IrreduciblePolynomial",	/*  6 */
      "GroupGeneratorOne",			/*  7 */
      "GroupGeneratorTwo",			/*  8 */
      "GroupCurve A",				/*  9 */
      "GroupCurve B",				/* 10 */
      "LifeType",				/* 11 */
      "LifeDuration",				/* 12 */
      "PRF",					/* 13 */
      "KeyLength",				/* 14 */
      "FieldSize",				/* 15 */
      "GroupOrder"				/* 16 */
   };
   static const char *enc_names[] = {		/* From RFC 2409 App. A */
      NULL,					/* and RFC 3602 */
      "DES",					/*  1 */
      "IDEA",					/*  2 */
      "Blowfish",				/*  3 */
      "RC5",					/*  4 */
      "3DES",					/*  5 */
      "CAST",					/*  6 */
      "AES"					/*  7 */
   };
   static const char *hash_names[] = {		/* From RFC 2409 App. A */
      NULL,
      "MD5",					/*  1 */
      "SHA1",					/*  2 */
      "Tiger"					/*  3 */
   };
   static const char *auth_names[] = {		/* From RFC 2409 App. A */
      NULL,
      "PSK",					/*  1 */
      "DSS",					/*  2 */
      "RSA_Sig",				/*  3 */
      "RSA_Enc",				/*  4 */
      "RSA_RevEnc"				/*  5 */
   };
   static const char *dh_names[] = {		/* From RFC 2409 App. A */
      NULL,					/* and RFC 3526 */
      "1:modp768",				/*  1 */
      "2:modp1024",				/*  2 */
      "3:ec2n155",				/*  3 */
      "4:ec2n185",				/*  4 */
      "5:modp1536",				/*  5 */
      NULL,					/*  6 */
      NULL,					/*  7 */
      NULL,					/*  8 */
      NULL,					/*  9 */
      NULL,					/* 10 */
      NULL,					/* 11 */
      NULL,					/* 12 */
      NULL,					/* 13 */
      "14:modp2048",				/* 14 */
      "15:modp3072",				/* 15 */
      "16:modp4096",				/* 16 */
      "17:modp6144",				/* 17 */
      "18:modp8192"				/* 18 */
   };
   static const char *life_names[] = {		/* From RFC 2409 App. A */
      NULL,
      "Seconds",				/*  1 */
      "Kilobytes"				/*  2 */
   };

   if (ntohs(attr_hdr->isaat_af_type) & 0x8000) {	/* Basic attribute */
      attr_type = 'B';
      attr_class = ntohs (attr_hdr->isaat_af_type) & 0x7fff;
      attr_value = ntohs (attr_hdr->isaat_lv);
      value_len = 0;	/* Value is in length field */
   } else {					/* Variable attribute */
      attr_type = 'V';
      attr_class = ntohs (attr_hdr->isaat_af_type);
      value_len = ntohs (attr_hdr->isaat_lv);
   }

   attr_class_str = make_message("%s", STR_OR_ID(attr_class, attr_classes));

   if (attr_type == 'B') {
      switch (attr_class) {
      case 1:		/* Encryption Algorithm */
         attr_value_str = make_message("%s", STR_OR_ID(attr_value, enc_names));
         break;
      case 2:		/* Hash Algorithm */
         attr_value_str = make_message("%s", STR_OR_ID(attr_value, hash_names));
         break;
      case 3:		/* Authentication Method */
         attr_value_str = make_message("%s", STR_OR_ID(attr_value, auth_names));
         break;
      case 4:		/* Group Desription */
         attr_value_str = make_message("%s", STR_OR_ID(attr_value, dh_names));
         break;
      case 11:		/* Life Type */
         attr_value_str = make_message("%s", STR_OR_ID(attr_value, life_names));
         break;
      default:
         attr_value_str = make_message("%u", attr_value);
         break;
      }
   } else {
      attr_value_str = hexstring((*cp) + sizeof (struct isakmp_attribute),
                                 value_len);
   }

   if (attr_type == 'B')
      msg = make_message("%s=%s", attr_class_str, attr_value_str);
   else
      msg = make_message("%s(%u)=0x%s", attr_class_str, value_len,
                         attr_value_str);

   free(attr_class_str);
   free(attr_value_str);

   size=sizeof (struct isakmp_attribute) + value_len;
   if (size >= *len) {
      *len=0;
   } else {
      *len -= size;
      (*cp) += size;
   }

   return msg;
}

/*
 *	process_vid -- Process Vendor ID Payload
 *
 *	Inputs:
 *
 *	cp	Pointer to start of Vendor ID payload
 *	len	Packet length remaining
 *	vidlist	List of Vendor ID patterns.
 *
 *	Returns:
 *
 *	Pointer to Vendor ID description string.
 *
 *	The description string pointer returned points to malloc'ed storage
 *	which should be free'ed by the caller when it's no longer needed.
 */
char *
process_vid(unsigned char *cp, size_t len, struct vid_pattern_list *vidlist) {
   struct isakmp_vid *hdr = (struct isakmp_vid *) cp;
   struct vid_pattern_list *ve;
   char *msg;
   char *p;
   unsigned char *vid_data;
   size_t data_len;

   if (len < sizeof(struct isakmp_vid) ||
        ntohs(hdr->isavid_length) < sizeof(struct isakmp_vid))
      return make_message("VID (packet too short to decode)");

   vid_data = cp + sizeof(struct isakmp_vid);  /* Points to start of VID data */
   data_len = ntohs(hdr->isavid_length) < len ? ntohs(hdr->isavid_length) : len;
   data_len -= sizeof(struct isakmp_vid);

   msg = hexstring(vid_data, data_len);
   p = msg;
   msg=make_message("VID=%s", p);
   free(p);
/*
 *	Try to find a match in the Vendor ID pattern list.
 */
   ve = vidlist;
   while(ve != NULL) {
      if (data_len >= ve->len && !(memcmp(vid_data, ve->data, ve->len))) {
         p=msg;
         msg=make_message("%s (%s)", p, ve->name);
         free(p);
         break;	/* Stop looking after first match */
      }
      ve=ve->next;
   }

   return msg;
}

/*
 *	process_notify -- Process notify Payload
 *
 *	Inputs:
 *
 *	cp	Pointer to start of notify payload
 *	len	Packet length remaining
 *
 *	Returns:
 *
 *	Pointer to notify description string.
 *
 *	The description string pointer returned points to malloc'ed storage
 *	which should be free'ed by the caller when it's no longer needed.
 */
char *
process_notify(unsigned char *cp, size_t len) {
   struct isakmp_notification *hdr = (struct isakmp_notification *) cp;
   char *msg;
   int msg_type;
   size_t msg_len;
   unsigned char *msg_data;
   char *notify_msg;
   static const char *notification_msg[] = { /* From RFC 2408 3.14.1 */
      "UNSPECIFIED",                    /* 0 */
      "INVALID-PAYLOAD-TYPE",           /* 1 */
      "DOI-NOT-SUPPORTED",              /* 2 */
      "SITUATION-NOT-SUPPORTED",        /* 3 */
      "INVALID-COOKIE",                 /* 4 */
      "INVALID-MAJOR-VERSION",          /* 5 */
      "INVALID-MINOR-VERSION",          /* 6 */
      "INVALID-EXCHANGE-TYPE",          /* 7 */
      "INVALID-FLAGS",                  /* 8 */
      "INVALID-MESSAGE-ID",             /* 9 */
      "INVALID-PROTOCOL-ID",            /* 10 */
      "INVALID-SPI",                    /* 11 */
      "INVALID-TRANSFORM-ID",           /* 12 */
      "ATTRIBUTES-NOT-SUPPORTED",       /* 13 */
      "NO-PROPOSAL-CHOSEN",             /* 14 */
      "BAD-PROPOSAL-SYNTAX",            /* 15 */
      "PAYLOAD-MALFORMED",              /* 16 */
      "INVALID-KEY-INFORMATION",        /* 17 */
      "INVALID-ID-INFORMATION",         /* 18 */
      "INVALID-CERT-ENCODING",          /* 19 */
      "INVALID-CERTIFICATE",            /* 20 */
      "CERT-TYPE-UNSUPPORTED",          /* 21 */
      "INVALID-CERT-AUTHORITY",         /* 22 */
      "INVALID-HASH-INFORMATION",       /* 23 */
      "AUTHENTICATION-FAILED",          /* 24 */
      "INVALID-SIGNATURE",              /* 25 */
      "ADDRESS-NOTIFICATION",           /* 26 */
      "NOTIFY-SA-LIFETIME",             /* 27 */
      "CERTIFICATE-UNAVAILABLE",        /* 28 */
      "UNSUPPORTED-EXCHANGE-TYPE",      /* 29 */
      "UNEQUAL-PAYLOAD-LENGTHS"         /* 30 */
   };

   if (len < sizeof(struct isakmp_notification) ||
        ntohs(hdr->isan_length) < sizeof(struct isakmp_notification))
      return make_message("Notify message (packet too short to decode)");

   msg_type = ntohs(hdr->isan_type);
   msg_len = ntohs(hdr->isan_length) - sizeof(struct isakmp_notification);
   msg_data = cp + sizeof(struct isakmp_notification);

   if (msg_type == 9101) {	/* Firewall-1 4.x/NG Base message type */
      notify_msg = printable(msg_data, msg_len);
      msg=make_message("Notify message %d (Firewall-1) Message=\"%s\"",
                       msg_type, notify_msg);
      free(notify_msg);
   } else {			/* All other Message Types */
      msg=make_message("Notify message %d (%s)", msg_type,
                       STR_OR_ID(msg_type, notification_msg));
   }

   return msg;
}

/*
 *	process_id -- Process identification Payload
 *
 *	Inputs:
 *
 *	cp	Pointer to start of identification payload
 *	len	Packet length remaining
 *
 *	Returns:
 *
 *	Pointer to identification description string.
 *
 *	The description string pointer returned points to malloc'ed storage
 *	which should be free'ed by the caller when it's no longer needed.
 */
char *
process_id(unsigned char *cp, size_t len) {
   struct isakmp_id *hdr = (struct isakmp_id *) cp;
   int idtype;
   char *msg;
   char *msg2;
   unsigned char *id_data;
   size_t data_len;
   static const char *id_names[] = {	/* From RFC 2407 4.6.2.1 */
      NULL,				/*  0 */
      "ID_IPV4_ADDR",			/*  1 */
      "ID_FQDN",			/*  2 */
      "ID_USER_FQDN",			/*  3 */
      "ID_IPV4_ADDR_SUBNET",		/*  4 */
      "ID_IPV6_ADDR",			/*  5 */
      "ID_IPV6_ADDR_SUBNET",		/*  6 */
      "ID_IPV4_ADDR_RANGE",		/*  7 */
      "ID_IPV6_ADDR_RANGE",		/*  8 */
      "ID_DER_ASN1_DN",			/*  9 */
      "ID_DER_ASN1_GN",			/* 10 */
      "ID_KEY_ID",			/* 11 */
   };

   if (len < sizeof(struct isakmp_id) ||
        ntohs(hdr->isaid_length) < sizeof(struct isakmp_id))
      return make_message("ID (packet too short to decode)");

   id_data = cp + sizeof(struct isakmp_id);  /* Points to start of ID data */
   data_len = ntohs(hdr->isaid_length) < len ? ntohs(hdr->isaid_length) : len;
   data_len -= sizeof(struct isakmp_id);
   idtype = hdr->isaid_idtype;

   switch(idtype) {
      char *id;

      case ID_IPV4_ADDR:
      case ID_IPV4_ADDR_SUBNET:
      case ID_IPV6_ADDR:
      case ID_IPV6_ADDR_SUBNET:
      case ID_IPV4_ADDR_RANGE:
      case ID_IPV6_ADDR_RANGE:
      case ID_DER_ASN1_DN:
      case ID_DER_ASN1_GN:
         msg=make_message("Decode not supported for this type");
         break;
      case ID_FQDN:
      case ID_USER_FQDN:
         id = printable(id_data, data_len);
         msg=make_message("Value=%s", id);
         free(id);
         break;
      case ID_KEY_ID:
         id = hexstring(id_data, data_len);
         msg = make_message("Value=%s", id);
         free(id);
         break;
      default:
         msg = make_message("Unknown ID Type");
         break;
   }

   msg2=msg;
   msg=make_message("ID(Type=%s, %s)", STR_OR_ID(idtype,id_names), msg2);
   free(msg2);

   return msg;
}

void
isakmp_use_rcsid(void) {
   printf("%s\n", rcsid);	/* Use rcsid to stop compiler optimising away */
}
